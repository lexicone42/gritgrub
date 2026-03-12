//! Fuzz target for object deserialization.
//!
//! Feeds random bytes to Object::from_tagged_bytes.
//! The goal: no panics — malformed objects must return Err, not crash.
//! Also tests that valid objects survive a roundtrip.

#![no_main]

use libfuzzer_sys::fuzz_target;
use gritgrub_core::{Object, ObjectError};

fuzz_target!(|data: &[u8]| {
    match Object::from_tagged_bytes(data) {
        Ok(obj) => {
            // If parsing succeeded, verify the roundtrip.
            let reserialized = obj.to_tagged_bytes();
            let reparsed = Object::from_tagged_bytes(&reserialized)
                .expect("roundtrip: re-parsing serialized object must not fail");

            // IDs must match — content-addressing is deterministic.
            assert_eq!(obj.id(), reparsed.id(),
                "roundtrip: content-addressed ID changed after re-serialization");
        }
        Err(ObjectError::EmptyData) => {} // Expected for empty input.
        Err(ObjectError::UnknownTag(_)) => {} // Expected for random first byte.
        Err(ObjectError::Deserialize(_)) => {} // Expected for random body.
    }
});
