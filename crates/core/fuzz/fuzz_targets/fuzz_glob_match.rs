//! Fuzz target for glob matching.
//!
//! Feeds random pattern/name pairs to glob_match_ref.
//! The goal: no panics, no infinite loops — all inputs must terminate.

#![no_main]

use libfuzzer_sys::fuzz_target;
use gritgrub_core::policy::glob_match_ref;

fuzz_target!(|data: &[u8]| {
    // Split fuzz data into pattern and name at the first null byte.
    if let Some(split_pos) = data.iter().position(|&b| b == 0) {
        if let (Ok(pattern), Ok(name)) = (
            std::str::from_utf8(&data[..split_pos]),
            std::str::from_utf8(&data[split_pos + 1..]),
        ) {
            // The primary property: glob_match_ref must not panic or hang.
            let _ = glob_match_ref(pattern, name);

            // Secondary property: exact match is always true.
            assert!(glob_match_ref(name, name),
                "exact match failed for '{}'", name);
        }
    }
});
