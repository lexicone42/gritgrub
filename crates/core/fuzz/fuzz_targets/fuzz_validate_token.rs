//! Fuzz target for token validation.
//!
//! Feeds random bytes as a token string to validate_token.
//! The goal: no panics, no UB — malformed tokens must return Err, not crash.

#![no_main]

use libfuzzer_sys::fuzz_target;
use gritgrub_core::validate_token;

fuzz_target!(|data: &[u8]| {
    // Interpret fuzz data as a token string.
    if let Ok(token_str) = std::str::from_utf8(data) {
        // Use a dummy key lookup that always returns a fixed 32-byte key.
        // This lets the fuzzer exercise the full parsing path without
        // requiring real identity lookups.
        let fake_pk = [0x42u8; 32];
        let _ = validate_token(token_str, 0, |_id| Some(fake_pk));

        // Also try with a realistic "now" value.
        let _ = validate_token(token_str, 1_700_000_000_000_000, |_id| Some(fake_pk));

        // And with no key available (exercises UnknownIdentity path).
        let _ = validate_token(token_str, 0, |_| None);
    }
});
