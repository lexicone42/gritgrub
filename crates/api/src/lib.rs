//! gRPC API layer for gritgrub.
//!
//! Proto definitions live in `proto/gritgrub/v1/`. This crate will wire them
//! up via tonic once we need a running server. For now, it re-exports core
//! types so downstream consumers have a single dependency for the full stack.

pub use gritgrub_core::*;
