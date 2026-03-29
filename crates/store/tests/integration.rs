//! Integration tests for the Repository layer.
//!
//! Each test creates a temp directory, initializes a repo, and exercises
//! the public API. These tests verify that the full stack (repo → redb
//! backend → filesystem) works correctly together.

use std::fs;
use gritgrub_core::*;
use gritgrub_store::{Repository, MergeResult};
use tempfile::TempDir;

/// Extract the tree ID from a changeset object.
fn tree_of(obj: &Object) -> ObjectId {
    match obj {
        Object::Changeset(cs) => cs.tree,
        other => panic!("expected Changeset, got {:?}", std::mem::discriminant(other)),
    }
}

/// Helper: create a fresh repo in a temp dir, return the dir, repo, and identity.
fn fresh_repo() -> (TempDir, Repository, IdentityId) {
    let dir = TempDir::new().expect("create temp dir");
    let repo = Repository::init(dir.path()).expect("init repo");
    let id = repo.local_identity().expect("get identity");
    (dir, repo, id)
}

// ── Init & Basic Operations ──────────────────────────────────────

#[test]
fn init_creates_forge_dir() {
    let (dir, _repo, _id) = fresh_repo();
    assert!(dir.path().join(".forge").exists());
    assert!(dir.path().join(".forge/store.redb").exists());
}

#[test]
fn init_sets_head_to_main() {
    let (_dir, repo, _id) = fresh_repo();
    assert_eq!(repo.head_branch().unwrap(), Some("main".to_string()));
}

#[test]
fn init_creates_identity() {
    let (_dir, repo, id) = fresh_repo();
    let identity = repo.get_identity(&id).unwrap().unwrap();
    assert!(matches!(identity.kind, IdentityKind::Human));
}

#[test]
fn double_init_fails() {
    let (dir, _repo, _id) = fresh_repo();
    let result = Repository::init(dir.path());
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(err.to_string().contains("already initialized"));
}

#[test]
fn discover_walks_up() {
    let (dir, repo, _id) = fresh_repo();
    let subdir = dir.path().join("a/b/c");
    fs::create_dir_all(&subdir).unwrap();
    let expected = dir.path().canonicalize().unwrap();
    // Drop the original repo to release the redb lock.
    drop(repo);
    let found = Repository::discover(&subdir).unwrap();
    assert_eq!(found.root().canonicalize().unwrap(), expected);
}

// ── Commit & Log ─────────────────────────────────────────────────

#[test]
fn commit_and_log_roundtrip() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("hello.txt"), "world").unwrap();
    let cs_id = repo.commit("first commit", id, None).unwrap();

    let log = repo.log(10).unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].0, cs_id);
    assert_eq!(log[0].1.message, "first commit");
}

#[test]
fn commit_with_intent() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

    let intent = Intent {
        kind: IntentKind::Feature,
        affected_paths: vec!["main.rs".to_string()],
        rationale: "bootstrap".to_string(),
        context_ref: None,
        verifications: vec![],
    };
    repo.commit("add main", id, Some(intent)).unwrap();

    let log = repo.log(1).unwrap();
    assert_eq!(log[0].1.intent.as_ref().unwrap().kind, IntentKind::Feature);
}

#[test]
fn multiple_commits_form_chain() {
    let (dir, repo, id) = fresh_repo();

    fs::write(dir.path().join("a.txt"), "1").unwrap();
    let id1 = repo.commit("first", id, None).unwrap();

    fs::write(dir.path().join("b.txt"), "2").unwrap();
    let id2 = repo.commit("second", id, None).unwrap();

    let log = repo.log(10).unwrap();
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].0, id2);
    assert_eq!(log[1].0, id1);
    assert_eq!(log[0].1.parents, vec![id1]);
}

// ── Status ───────────────────────────────────────────────────────

#[test]
fn status_empty_repo() {
    let (_dir, repo, _id) = fresh_repo();
    let status = repo.status().unwrap();
    assert!(status.is_clean());
}

#[test]
fn status_detects_new_files() {
    let (dir, repo, _id) = fresh_repo();
    fs::write(dir.path().join("new.txt"), "hello").unwrap();
    let status = repo.status().unwrap();
    assert!(status.added.contains(&"new.txt".to_string()));
}

#[test]
fn status_detects_modified() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "v1").unwrap();
    repo.commit("initial", id, None).unwrap();

    fs::write(dir.path().join("a.txt"), "v2").unwrap();
    let status = repo.status().unwrap();
    assert!(status.modified.contains(&"a.txt".to_string()));
}

#[test]
fn status_detects_deleted() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    repo.commit("initial", id, None).unwrap();

    fs::remove_file(dir.path().join("a.txt")).unwrap();
    let status = repo.status().unwrap();
    assert!(status.deleted.contains(&"a.txt".to_string()));
}

#[test]
fn status_clean_after_commit() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    repo.commit("initial", id, None).unwrap();
    assert!(repo.status().unwrap().is_clean());
}

// ── Branches ─────────────────────────────────────────────────────

#[test]
fn create_and_list_branches() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    repo.commit("initial", id, None).unwrap();

    let head = repo.resolve_head().unwrap().unwrap();
    repo.set_ref("refs/heads/feature", &Ref::Direct(head)).unwrap();

    let refs = repo.list_refs("refs/heads/").unwrap();
    let names: Vec<&str> = refs.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains(&"refs/heads/main"));
    assert!(names.contains(&"refs/heads/feature"));
}

#[test]
fn checkout_branch() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    let cs_id = repo.commit("on main", id, None).unwrap();

    repo.set_ref("refs/heads/feature", &Ref::Direct(cs_id)).unwrap();
    repo.set_ref("HEAD", &Ref::Symbolic("refs/heads/feature".into())).unwrap();

    assert_eq!(repo.head_branch().unwrap(), Some("feature".to_string()));
}

// ── Object Store ─────────────────────────────────────────────────

#[test]
fn put_get_object_roundtrip() {
    let (_dir, repo, _id) = fresh_repo();
    let blob = Object::Blob(Blob { data: b"hello world".to_vec() });
    let obj_id = repo.put_object(&blob).unwrap();

    let retrieved = repo.get_object(&obj_id).unwrap().unwrap();
    match retrieved {
        Object::Blob(b) => assert_eq!(b.data, b"hello world"),
        _ => panic!("expected blob"),
    }
}

#[test]
fn find_by_prefix() {
    let (_dir, repo, _id) = fresh_repo();
    let blob = Object::Blob(Blob { data: b"test data".to_vec() });
    let obj_id = repo.put_object(&blob).unwrap();

    let hex = format!("{}", obj_id);
    let prefix = &hex[..8];
    let (found_id, _found_obj) = repo.find_by_prefix(prefix).unwrap();
    assert_eq!(found_id, obj_id);
}

#[test]
fn has_object() {
    let (_dir, repo, _id) = fresh_repo();
    let blob = Object::Blob(Blob { data: b"exists".to_vec() });
    let obj_id = repo.put_object(&blob).unwrap();

    assert!(repo.has_object(&obj_id).unwrap());
    assert!(!repo.has_object(&ObjectId::ZERO).unwrap());
}

// ── Identity & Capabilities ──────────────────────────────────────

#[test]
fn create_agent_identity() {
    let (_dir, repo, _id) = fresh_repo();
    let agent = repo.create_identity("test-agent", IdentityKind::Agent {
        runtime: "claude-code".to_string(),
    }).unwrap();
    assert!(matches!(agent.kind, IdentityKind::Agent { .. }));

    let found = repo.get_identity(&agent.id).unwrap().unwrap();
    assert_eq!(found.name, "test-agent");
}

#[test]
fn list_identities() {
    let (_dir, repo, _id) = fresh_repo();
    repo.create_identity("agent1", IdentityKind::Human).unwrap();
    repo.create_identity("agent2", IdentityKind::Human).unwrap();

    let identities = repo.list_identities().unwrap();
    assert_eq!(identities.len(), 3); // initial + 2 new
}

#[test]
fn grant_and_check_capabilities() {
    let (_dir, repo, _id) = fresh_repo();
    let agent = repo.create_identity("agent", IdentityKind::Agent {
        runtime: "test".to_string(),
    }).unwrap();

    repo.grant_capabilities(&agent.id, &[Capability {
        scope: CapabilityScope::Global,
        permissions: Permissions(Permissions::READ | Permissions::WRITE),
        expires_at: None,
    }]).unwrap();

    let caps = repo.get_capabilities(&agent.id).unwrap();
    assert!(!caps.is_empty());
    assert!(caps[0].permissions.can_read());
    assert!(caps[0].permissions.can_write());
}

// ── Merge ────────────────────────────────────────────────────────

#[test]
fn fast_forward_merge() {
    let (dir, repo, id) = fresh_repo();

    fs::write(dir.path().join("a.txt"), "data").unwrap();
    let base = repo.commit("base", id, None).unwrap();

    // Feature branch.
    repo.set_ref("refs/heads/feature", &Ref::Direct(base)).unwrap();
    repo.set_ref("HEAD", &Ref::Symbolic("refs/heads/feature".into())).unwrap();
    fs::write(dir.path().join("b.txt"), "feature work").unwrap();
    let feature_tip = repo.commit("feature commit", id, None).unwrap();

    // Switch back to main, merge.
    repo.set_ref("HEAD", &Ref::Symbolic("refs/heads/main".into())).unwrap();
    let base_tree = tree_of(&repo.get_object(&base).unwrap().unwrap());
    repo.force_checkout_tree(&base_tree).unwrap();

    let result = repo.merge("feature", id).unwrap();
    assert!(matches!(result, MergeResult::FastForward(tip) if tip == feature_tip));
}

#[test]
fn already_up_to_date() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    let base = repo.commit("base", id, None).unwrap();

    // Feature is behind main (main has an extra commit).
    repo.set_ref("refs/heads/feature", &Ref::Direct(base)).unwrap();
    fs::write(dir.path().join("b.txt"), "main work").unwrap();
    repo.commit("main ahead", id, None).unwrap();

    let result = repo.merge("feature", id).unwrap();
    assert!(matches!(result, MergeResult::AlreadyUpToDate));
}

#[test]
fn three_way_merge() {
    let (dir, repo, id) = fresh_repo();

    fs::write(dir.path().join("shared.txt"), "base").unwrap();
    let base = repo.commit("base", id, None).unwrap();

    // Feature branch (different file).
    repo.set_ref("refs/heads/feature", &Ref::Direct(base)).unwrap();
    repo.set_ref("HEAD", &Ref::Symbolic("refs/heads/feature".into())).unwrap();
    fs::write(dir.path().join("feature.txt"), "feature work").unwrap();
    repo.commit("feature commit", id, None).unwrap();

    // Back to main (different file).
    repo.set_ref("HEAD", &Ref::Symbolic("refs/heads/main".into())).unwrap();
    let base_tree = tree_of(&repo.get_object(&base).unwrap().unwrap());
    repo.force_checkout_tree(&base_tree).unwrap();
    fs::write(dir.path().join("main.txt"), "main work").unwrap();
    repo.commit("main commit", id, None).unwrap();

    let result = repo.merge("feature", id).unwrap();
    assert!(matches!(result, MergeResult::Merged(_)));
}

#[test]
fn merge_conflict() {
    let (dir, repo, id) = fresh_repo();

    fs::write(dir.path().join("conflict.txt"), "base").unwrap();
    let base = repo.commit("base", id, None).unwrap();

    // Feature modifies same file.
    repo.set_ref("refs/heads/feature", &Ref::Direct(base)).unwrap();
    repo.set_ref("HEAD", &Ref::Symbolic("refs/heads/feature".into())).unwrap();
    fs::write(dir.path().join("conflict.txt"), "feature version").unwrap();
    repo.commit("feature edit", id, None).unwrap();

    // Main also modifies same file.
    repo.set_ref("HEAD", &Ref::Symbolic("refs/heads/main".into())).unwrap();
    let base_tree = tree_of(&repo.get_object(&base).unwrap().unwrap());
    repo.force_checkout_tree(&base_tree).unwrap();
    fs::write(dir.path().join("conflict.txt"), "main version").unwrap();
    repo.commit("main edit", id, None).unwrap();

    let result = repo.merge("feature", id).unwrap();
    assert!(matches!(
        result,
        MergeResult::Conflict(ref paths)
            if paths.contains(&"conflict.txt".to_string())
    ));
}

// ── Stash ────────────────────────────────────────────────────────

#[test]
fn stash_save_and_pop() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "committed").unwrap();
    repo.commit("initial", id, None).unwrap();

    fs::write(dir.path().join("a.txt"), "modified").unwrap();
    assert!(!repo.status().unwrap().is_clean());

    let idx = repo.stash_save("wip changes").unwrap();
    assert_eq!(idx, 0);
    assert!(repo.status().unwrap().is_clean());

    fs::write(dir.path().join("a.txt"), "different").unwrap();
    repo.stash_pop().unwrap();
    let content = fs::read_to_string(dir.path().join("a.txt")).unwrap();
    assert_eq!(content, "modified");
}

#[test]
fn stash_list() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    repo.commit("initial", id, None).unwrap();

    fs::write(dir.path().join("a.txt"), "wip1").unwrap();
    repo.stash_save("first stash").unwrap();

    fs::write(dir.path().join("a.txt"), "wip2").unwrap();
    repo.stash_save("second stash").unwrap();

    let list = repo.stash_list().unwrap();
    assert_eq!(list.len(), 2);
}

#[test]
fn stash_pop_empty_fails() {
    let (_dir, repo, _id) = fresh_repo();
    assert!(repo.stash_pop().is_err());
}

// ── Reset ────────────────────────────────────────────────────────

#[test]
fn soft_reset() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "v1").unwrap();
    let id1 = repo.commit("first", id, None).unwrap();

    fs::write(dir.path().join("a.txt"), "v2").unwrap();
    repo.commit("second", id, None).unwrap();

    repo.reset(&id1, false).unwrap();
    assert_eq!(repo.resolve_head().unwrap().unwrap(), id1);

    let content = fs::read_to_string(dir.path().join("a.txt")).unwrap();
    assert_eq!(content, "v2"); // soft — tree unchanged
}

#[test]
fn hard_reset() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "v1").unwrap();
    let id1 = repo.commit("first", id, None).unwrap();

    fs::write(dir.path().join("a.txt"), "v2").unwrap();
    fs::write(dir.path().join("b.txt"), "extra").unwrap();
    repo.commit("second", id, None).unwrap();

    repo.reset(&id1, true).unwrap();
    assert_eq!(repo.resolve_head().unwrap().unwrap(), id1);
    assert_eq!(fs::read_to_string(dir.path().join("a.txt")).unwrap(), "v1");
    assert!(!dir.path().join("b.txt").exists());
}

// ── Remote Config ────────────────────────────────────────────────

#[test]
fn add_and_list_remotes() {
    let (_dir, repo, _id) = fresh_repo();
    repo.add_remote("origin", "https://localhost:50051").unwrap();
    repo.add_remote("backup", "https://backup:50051").unwrap();

    let remotes = repo.list_remotes().unwrap();
    assert_eq!(remotes.len(), 2);
    assert!(remotes.iter().any(|(n, u)| n == "origin" && u == "https://localhost:50051"));
}

#[test]
fn remove_remote() {
    let (_dir, repo, _id) = fresh_repo();
    repo.add_remote("origin", "https://localhost:50051").unwrap();
    repo.remove_remote("origin").unwrap();
    assert!(repo.list_remotes().unwrap().is_empty());
}

#[test]
fn remove_nonexistent_remote_fails() {
    let (_dir, repo, _id) = fresh_repo();
    assert!(repo.remove_remote("nope").is_err());
}

// ── Tags ─────────────────────────────────────────────────────────

#[test]
fn create_and_list_tags() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    let cs_id = repo.commit("release", id, None).unwrap();

    repo.set_ref("refs/tags/v0.1.0", &Ref::Direct(cs_id)).unwrap();
    let refs = repo.list_refs("refs/tags/").unwrap();
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].0, "refs/tags/v0.1.0");
}

#[test]
fn delete_tag() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    let cs_id = repo.commit("release", id, None).unwrap();

    repo.set_ref("refs/tags/v0.1.0", &Ref::Direct(cs_id)).unwrap();
    assert!(repo.delete_ref("refs/tags/v0.1.0").unwrap());
    assert!(repo.list_refs("refs/tags/").unwrap().is_empty());
}

// ── CAS Ref ──────────────────────────────────────────────────────

#[test]
fn cas_ref_succeeds_on_match() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    repo.commit("initial", id, None).unwrap();

    let current = repo.resolve_ref("refs/heads/main").unwrap().map(Ref::Direct);
    let new_ref = current.clone().unwrap();
    assert!(repo.cas_ref("refs/heads/main", current.as_ref(), &new_ref).unwrap());
}

#[test]
fn cas_ref_fails_on_mismatch() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    let cs_id = repo.commit("initial", id, None).unwrap();

    let wrong = Ref::Direct(ObjectId::ZERO);
    let new_ref = Ref::Direct(cs_id);
    assert!(!repo.cas_ref("refs/heads/main", Some(&wrong), &new_ref).unwrap());
}

// ── Forgeignore ──────────────────────────────────────────────────

#[test]
fn forgeignore_excludes_files() {
    let (dir, repo, _id) = fresh_repo();
    fs::write(dir.path().join(".forgeignore"), "*.log\nbuild/\n").unwrap();
    fs::write(dir.path().join("app.log"), "logs").unwrap();
    fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

    let status = repo.status().unwrap();
    assert!(status.added.contains(&"main.rs".to_string()));
    assert!(status.added.contains(&".forgeignore".to_string()));
    assert!(!status.added.iter().any(|f| f.ends_with(".log")));
}

#[test]
fn forgeignore_glob_patterns() {
    let (dir, repo, _id) = fresh_repo();
    fs::write(dir.path().join(".forgeignore"), "*.o\n*.tmp\n").unwrap();
    fs::write(dir.path().join("main.o"), "").unwrap();
    fs::write(dir.path().join("data.tmp"), "").unwrap();
    fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

    let status = repo.status().unwrap();
    assert!(status.added.contains(&"main.rs".to_string()));
    assert!(!status.added.contains(&"main.o".to_string()));
    assert!(!status.added.contains(&"data.tmp".to_string()));
}

// ── Nested Directories ──────────────────────────────────────────

#[test]
fn nested_directory_commit() {
    let (dir, repo, id) = fresh_repo();
    fs::create_dir_all(dir.path().join("src/utils")).unwrap();
    fs::write(dir.path().join("src/main.rs"), "fn main() {}").unwrap();
    fs::write(dir.path().join("src/utils/helpers.rs"), "pub fn help() {}").unwrap();

    let cs_id = repo.commit("nested", id, None).unwrap();
    let obj = repo.get_object(&cs_id).unwrap().unwrap();
    let tree_id = tree_of(&obj);

    let tree = repo.get_object(&tree_id).unwrap().unwrap();
    match tree {
        Object::Tree(t) => assert!(t.entries.contains_key("src")),
        _ => panic!("expected tree"),
    }
}

// ── Key Generation & Signing ─────────────────────────────────────

#[test]
fn generate_and_load_keypair() {
    let (_dir, repo, id) = fresh_repo();
    let kp = repo.generate_keypair(&id).unwrap();
    let loaded = repo.load_keypair(&id).unwrap();
    assert_eq!(kp.public_bytes(), loaded.public_bytes());
}

#[test]
fn public_key_stored_as_ref() {
    let (_dir, repo, id) = fresh_repo();
    repo.generate_keypair(&id).unwrap();
    assert!(repo.get_public_key(&id).unwrap().is_some());
}

// ── Token Revocation ─────────────────────────────────────────────

#[test]
fn revoke_and_check_token() {
    let (_dir, repo, _id) = fresh_repo();
    repo.revoke_token("some-test-token").unwrap();
    assert!(repo.is_token_revoked("some-test-token").unwrap());
    assert!(!repo.is_token_revoked("other-token").unwrap());
}

// ── Event Log ────────────────────────────────────────────────────

#[test]
fn event_log_append_and_read() {
    let (_dir, repo, _id) = fresh_repo();
    let seq1 = repo.log_event(b"event-1").unwrap();
    let seq2 = repo.log_event(b"event-2").unwrap();
    assert!(seq2 > seq1);

    let events = repo.read_events(0, 10).unwrap();
    assert_eq!(events.len(), 2);
}

// ── Config ───────────────────────────────────────────────────────

#[test]
fn config_get_set() {
    let (_dir, repo, _id) = fresh_repo();
    repo.set_config("test.key", "test-value").unwrap();
    assert_eq!(repo.get_config("test.key").unwrap(), Some("test-value".to_string()));
}

#[test]
fn config_missing_returns_none() {
    let (_dir, repo, _id) = fresh_repo();
    assert_eq!(repo.get_config("nonexistent").unwrap(), None);
}
