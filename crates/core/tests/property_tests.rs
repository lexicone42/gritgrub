//! Property-based tests for gritgrub-core using proptest.
//!
//! These tests exercise security-critical invariants that example-based
//! tests miss: roundtrip guarantees, tamper resistance, and edge cases
//! in glob matching, scope logic, and object serialization.

use proptest::prelude::*;
use gritgrub_core::*;
use gritgrub_core::policy::glob_match_ref;

// ── Strategies ──────────────────────────────────────────────────────

/// Generate a random IdentityId.
fn arb_identity_id() -> impl Strategy<Value = IdentityId> {
    any::<[u8; 16]>().prop_map(IdentityId::from_bytes)
}

/// Generate valid scope strings for tokens.
fn arb_scope_string() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("*".to_string()),
        Just("read".to_string()),
        Just("write".to_string()),
        Just("attest".to_string()),
        Just("identity".to_string()),
        "[a-z/\\*]{1,30}".prop_map(|p| format!("ref:{}", p)),
    ]
}

/// Generate a valid TokenScopes.
fn arb_token_scopes() -> impl Strategy<Value = TokenScopes> {
    prop::collection::vec(arb_scope_string(), 1..5)
        .prop_map(|v| TokenScopes::decode(&v.join(",")))
}

/// Generate a non-negative expiry timestamp.
fn arb_expiry() -> impl Strategy<Value = i64> {
    prop_oneof![
        Just(0i64),  // non-expiring
        (1_000_000i64..i64::MAX / 2),  // valid future timestamp
    ]
}

/// Generate ref-like path segments.
fn arb_ref_segment() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_-]{0,15}".prop_map(String::from)
}

/// Generate a ref name like "refs/heads/feature-foo".
fn arb_ref_name() -> impl Strategy<Value = String> {
    prop::collection::vec(arb_ref_segment(), 2..5)
        .prop_map(|parts| parts.join("/"))
}

/// Generate arbitrary blob data.
fn arb_blob() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..1024)
}

/// Generate a tree with a few entries.
fn arb_tree() -> impl Strategy<Value = Tree> {
    prop::collection::btree_map(
        "[a-z][a-z0-9]{0,15}",
        (any::<[u8; 32]>(), any::<bool>()),
        0..10,
    )
    .prop_map(|entries| {
        Tree {
            entries: entries
                .into_iter()
                .map(|(name, (hash, exec))| {
                    let id = ObjectId::from_bytes(hash);
                    (
                        name,
                        TreeEntry {
                            id,
                            kind: EntryKind::File,
                            executable: exec,
                        },
                    )
                })
                .collect(),
        }
    })
}

/// Generate an arbitrary Changeset.
fn arb_changeset() -> impl Strategy<Value = Changeset> {
    (
        prop::collection::vec(any::<[u8; 32]>().prop_map(ObjectId::from_bytes), 0..3),
        any::<[u8; 32]>().prop_map(ObjectId::from_bytes),
        arb_identity_id(),
        any::<i64>(),
        "[a-zA-Z0-9 .,!?\\-]{0,200}",
    )
        .prop_map(|(parents, tree, author, ts, msg)| Changeset {
            parents,
            tree,
            author,
            timestamp: ts,
            message: msg,
            intent: None,
            metadata: std::collections::BTreeMap::new(),
        })
}

// ── Token Tests ─────────────────────────────────────────────────────

proptest! {
    /// Token generation → validation is a roundtrip: valid tokens always validate
    /// back to the same identity with the same scopes.
    #[test]
    fn token_v2_roundtrip(
        seed in any::<[u8; 32]>(),
        expiry in arb_expiry(),
        scopes in arb_token_scopes(),
    ) {
        let id = IdentityId::new();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public_bytes = signing_key.verifying_key().to_bytes();

        let token = generate_token_v2(id, &signing_key, expiry, &scopes);
        let validated = validate_token(&token, 0, |lid| {
            if *lid == id { Some(public_bytes) } else { None }
        }).unwrap();

        prop_assert_eq!(validated.identity, id);
        // Scopes survive roundtrip.
        prop_assert_eq!(validated.scopes.encode(), scopes.encode());
    }

    /// v1 tokens always validate as admin.
    #[test]
    fn token_v1_roundtrip(
        seed in any::<[u8; 32]>(),
        expiry in arb_expiry(),
    ) {
        let id = IdentityId::new();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public_bytes = signing_key.verifying_key().to_bytes();

        let token = generate_token(id, &signing_key, expiry);
        let validated = validate_token(&token, 0, |lid| {
            if *lid == id { Some(public_bytes) } else { None }
        }).unwrap();

        prop_assert_eq!(validated.identity, id);
        prop_assert!(validated.scopes.is_admin());
    }

    /// A valid token validated with the wrong key always fails.
    #[test]
    fn token_wrong_key_always_rejected(
        seed1 in any::<[u8; 32]>(),
        seed2 in any::<[u8; 32]>(),
    ) {
        prop_assume!(seed1 != seed2);
        let id = IdentityId::new();
        let sk1 = ed25519_dalek::SigningKey::from_bytes(&seed1);
        let sk2 = ed25519_dalek::SigningKey::from_bytes(&seed2);
        let wrong_pk = sk2.verifying_key().to_bytes();

        let scopes = TokenScopes::admin();
        let token = generate_token_v2(id, &sk1, 0, &scopes);
        let result = validate_token(&token, 0, |lid| {
            if *lid == id { Some(wrong_pk) } else { None }
        });

        prop_assert!(result.is_err());
    }

    /// Any single-byte mutation in a v2 token either:
    /// (a) invalidates it, or
    /// (b) produces the exact same identity and scopes (delimiter-only mutation).
    /// No mutation can grant access to a different identity or escalate scopes.
    #[test]
    fn token_mutation_preserves_security(
        seed in any::<[u8; 32]>(),
        mutation_pos in 10usize..200usize,
        mutation_byte in any::<u8>(),
    ) {
        let id = IdentityId::new();
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();

        let scopes = TokenScopes::admin();
        let token = generate_token_v2(id, &sk, 0, &scopes);

        if mutation_pos < token.len() {
            let mut tampered = token.clone().into_bytes();
            let original = tampered[mutation_pos];
            if mutation_byte != original {
                tampered[mutation_pos] = mutation_byte;
                if let Ok(tampered_str) = String::from_utf8(tampered) {
                    match validate_token(&tampered_str, 0, |lid| {
                        if *lid == id { Some(pk) } else { None }
                    }) {
                        Err(_) => {} // Expected: tampered token rejected.
                        Ok(validated) => {
                            // If it validates, it MUST be the same identity and scopes.
                            // No mutation should grant different access.
                            prop_assert_eq!(validated.identity, id,
                                "mutation at pos {} changed identity", mutation_pos);
                            prop_assert_eq!(validated.scopes.encode(), scopes.encode(),
                                "mutation at pos {} changed scopes", mutation_pos);
                        }
                    }
                }
            }
        }
    }

    /// Expired tokens are always rejected regardless of other properties.
    #[test]
    fn expired_tokens_always_rejected(
        seed in any::<[u8; 32]>(),
        expiry in 1_000_000i64..1_000_000_000i64,
    ) {
        let id = IdentityId::new();
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();

        let scopes = TokenScopes::admin();
        let token = generate_token_v2(id, &sk, expiry, &scopes);

        // Validate with "now" well past the expiry.
        let result = validate_token(&token, expiry + 1, |lid| {
            if *lid == id { Some(pk) } else { None }
        });
        prop_assert!(matches!(result, Err(TokenError::Expired)));
    }

    /// Unknown identity tokens always fail (no key found).
    #[test]
    fn unknown_identity_rejected(seed in any::<[u8; 32]>()) {
        let id = IdentityId::new();
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);

        let token = generate_token_v2(id, &sk, 0, &TokenScopes::admin());
        let result = validate_token(&token, 0, |_| None);
        prop_assert!(matches!(result, Err(TokenError::UnknownIdentity)));
    }
}

// ── Object Serialization Tests ──────────────────────────────────────

proptest! {
    /// Blob roundtrip: to_tagged_bytes → from_tagged_bytes preserves data.
    #[test]
    fn blob_roundtrip(data in arb_blob()) {
        let obj = Object::Blob(Blob { data: data.clone() });
        let bytes = obj.to_tagged_bytes();
        let restored = Object::from_tagged_bytes(&bytes).unwrap();
        match restored {
            Object::Blob(blob) => prop_assert_eq!(blob.data, data),
            _ => prop_assert!(false, "expected Blob, got different type"),
        }
    }

    /// Tree roundtrip: serialization preserves all entries.
    #[test]
    fn tree_roundtrip(tree in arb_tree()) {
        let obj = Object::Tree(tree.clone());
        let bytes = obj.to_tagged_bytes();
        let restored = Object::from_tagged_bytes(&bytes).unwrap();
        match restored {
            Object::Tree(t) => {
                prop_assert_eq!(t.entries.len(), tree.entries.len());
                for (name, entry) in &tree.entries {
                    let restored_entry = t.entries.get(name).unwrap();
                    prop_assert_eq!(restored_entry.id, entry.id);
                    prop_assert_eq!(restored_entry.kind, entry.kind);
                    prop_assert_eq!(restored_entry.executable, entry.executable);
                }
            }
            _ => prop_assert!(false, "expected Tree"),
        }
    }

    /// Changeset roundtrip.
    #[test]
    fn changeset_roundtrip(cs in arb_changeset()) {
        let obj = Object::Changeset(cs.clone());
        let bytes = obj.to_tagged_bytes();
        let restored = Object::from_tagged_bytes(&bytes).unwrap();
        match restored {
            Object::Changeset(restored_cs) => {
                prop_assert_eq!(restored_cs.parents, cs.parents);
                prop_assert_eq!(restored_cs.tree, cs.tree);
                prop_assert_eq!(restored_cs.author, cs.author);
                prop_assert_eq!(restored_cs.timestamp, cs.timestamp);
                prop_assert_eq!(restored_cs.message, cs.message);
            }
            _ => prop_assert!(false, "expected Changeset"),
        }
    }

    /// Content-addressed IDs are deterministic: same object = same ID.
    #[test]
    fn object_id_deterministic(data in arb_blob()) {
        let obj1 = Object::Blob(Blob { data: data.clone() });
        let obj2 = Object::Blob(Blob { data });
        prop_assert_eq!(obj1.id(), obj2.id());
    }

    /// Different blobs (almost always) produce different IDs.
    #[test]
    fn different_blobs_different_ids(
        data1 in arb_blob(),
        data2 in arb_blob(),
    ) {
        if data1 != data2 {
            let id1 = Object::Blob(Blob { data: data1 }).id();
            let id2 = Object::Blob(Blob { data: data2 }).id();
            prop_assert_ne!(id1, id2);
        }
    }

    /// Random bytes don't panic when passed to from_tagged_bytes.
    /// They either parse successfully or return an error — never panic.
    #[test]
    fn object_parse_never_panics(data in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = Object::from_tagged_bytes(&data);
        // If we get here, no panic occurred. That's the property.
    }

    /// The tag byte encodes type and version correctly.
    #[test]
    fn tag_byte_encoding(data in arb_blob()) {
        let obj = Object::Blob(Blob { data });
        let bytes = obj.to_tagged_bytes();
        prop_assert_eq!(Object::type_tag(&bytes), Some(0x00)); // Blob type
        prop_assert_eq!(Object::format_version(&bytes), Some(1)); // v1
    }
}

// ── Glob Matching Tests ─────────────────────────────────────────────

proptest! {
    /// Exact match: any string matches itself.
    #[test]
    fn glob_exact_match(name in arb_ref_name()) {
        prop_assert!(glob_match_ref(&name, &name));
    }

    /// "*" matches any single segment.
    #[test]
    fn glob_star_matches_single_segment(
        prefix in arb_ref_segment(),
        middle in arb_ref_segment(),
        suffix in arb_ref_segment(),
    ) {
        let name = format!("{}/{}/{}", prefix, middle, suffix);
        let pattern = format!("{}/{}/{}", prefix, "*", suffix);
        prop_assert!(glob_match_ref(&pattern, &name));
    }

    /// "**" matches zero or more segments.
    #[test]
    fn glob_doublestar_matches_any_depth(
        prefix in arb_ref_segment(),
        segments in prop::collection::vec(arb_ref_segment(), 0..5),
    ) {
        let name = if segments.is_empty() {
            prefix.clone()
        } else {
            format!("{}/{}", prefix, segments.join("/"))
        };
        let pattern = format!("{}/**", prefix);
        prop_assert!(glob_match_ref(&pattern, &name));
    }

    /// Non-matching prefix never matches.
    #[test]
    fn glob_different_prefix_never_matches(
        seg1 in arb_ref_segment(),
        seg2 in arb_ref_segment(),
        rest in arb_ref_name(),
    ) {
        prop_assume!(seg1 != seg2);
        let pattern = format!("{}/{}", seg1, rest);
        let name = format!("{}/{}", seg2, rest);
        prop_assert!(!glob_match_ref(&pattern, &name));
    }
}

// ── DSSE Signing Tests ──────────────────────────────────────────────

proptest! {
    /// Sign → verify roundtrip: correctly signed envelopes always verify.
    #[test]
    fn envelope_sign_verify_roundtrip(seed in any::<[u8; 32]>()) {
        let id = IdentityId::new();
        let kp = IdentityKeyPair::from_secret_bytes(id, &seed);

        let statement = Statement::new(
            vec![Subject::from_object_id("test", &ObjectId::ZERO)],
            "https://gritgrub.dev/test/v1",
            Predicate::Other(Default::default()),
        );

        let envelope = kp.sign_envelope(&statement, "application/vnd.in-toto+json");
        let valid = verify_envelope_signature(&envelope, 0, &kp.public_bytes()).unwrap();
        prop_assert!(valid);
    }

    /// Wrong key always fails verification.
    #[test]
    fn envelope_wrong_key_never_verifies(
        seed1 in any::<[u8; 32]>(),
        seed2 in any::<[u8; 32]>(),
    ) {
        prop_assume!(seed1 != seed2);
        let id1 = IdentityId::new();
        let id2 = IdentityId::new();
        let kp1 = IdentityKeyPair::from_secret_bytes(id1, &seed1);
        let kp2 = IdentityKeyPair::from_secret_bytes(id2, &seed2);

        let statement = Statement::new(
            vec![Subject::from_object_id("test", &ObjectId::ZERO)],
            "https://gritgrub.dev/test/v1",
            Predicate::Other(Default::default()),
        );

        let envelope = kp1.sign_envelope(&statement, "application/vnd.in-toto+json");
        let valid = verify_envelope_signature(&envelope, 0, &kp2.public_bytes()).unwrap();
        prop_assert!(!valid);
    }

    /// Keypair save/restore roundtrip: secret bytes reproduce the same public key.
    #[test]
    fn keypair_save_restore_roundtrip(seed in any::<[u8; 32]>()) {
        let id = IdentityId::new();
        let kp = IdentityKeyPair::from_secret_bytes(id, &seed);
        let public = kp.public_bytes();

        let restored = IdentityKeyPair::from_secret_bytes(id, &seed);
        prop_assert_eq!(restored.public_bytes(), public);
    }
}

// ── Scope & Permission Tests ────────────────────────────────────────

proptest! {
    /// Admin scopes allow everything.
    #[test]
    fn admin_scope_allows_all(ref_name in arb_ref_name()) {
        let scopes = TokenScopes::admin();
        prop_assert!(scopes.is_admin());
        prop_assert!(scopes.allows_read());
        prop_assert!(scopes.allows_write());
        prop_assert!(scopes.allows_attest());
        prop_assert!(scopes.allows_identity());
        prop_assert!(scopes.allows_ref(&ref_name));
    }

    /// Read scope implies read, write scope implies read + write.
    #[test]
    fn scope_implications(_dummy in Just(())) {
        let read_only = TokenScopes::decode("read");
        prop_assert!(read_only.allows_read());
        prop_assert!(!read_only.allows_write());

        let write = TokenScopes::decode("write");
        prop_assert!(write.allows_read()); // write implies read
        prop_assert!(write.allows_write());
        prop_assert!(!write.allows_attest()); // but not attest
    }

    /// Scope encode/decode roundtrip.
    #[test]
    fn scope_encode_decode_roundtrip(scopes in arb_token_scopes()) {
        let encoded = scopes.encode();
        let decoded = TokenScopes::decode(&encoded);
        prop_assert_eq!(decoded.encode(), encoded);
    }

    /// Permissions: admin implies all individual permissions.
    #[test]
    fn admin_permission_implies_all(extra_bits in 0u32..32u32) {
        let perms = Permissions(Permissions::ADMIN | extra_bits);
        prop_assert!(perms.can_read());
        prop_assert!(perms.can_write());
        prop_assert!(perms.can_create());
        prop_assert!(perms.can_delete());
        prop_assert!(perms.is_admin());
    }
}

// ── Token Scope Validation Tests ────────────────────────────────────

proptest! {
    /// Valid scope strings are accepted by from_strings.
    #[test]
    fn valid_scopes_accepted(scope in arb_scope_string()) {
        let result = TokenScopes::from_strings(vec![scope]);
        prop_assert!(result.is_ok());
    }

    /// Invalid scope strings are rejected.
    #[test]
    fn invalid_scopes_rejected(
        scope in "[a-z]{2,10}".prop_filter(
            "must not be a valid scope",
            |s| !["read", "write", "attest", "identity"].contains(&s.as_str()) && s != "*"
        )
    ) {
        let result = TokenScopes::from_strings(vec![scope]);
        prop_assert!(result.is_err());
    }
}
