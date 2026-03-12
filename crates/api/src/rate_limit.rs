//! Token-bucket rate limiter keyed by authenticated identity.
//!
//! Design for agent ergonomics:
//! - Returns remaining tokens and reset time in gRPC trailing metadata
//!   so agents can self-throttle without guessing.
//! - Unauthenticated requests share a single global bucket.
//! - Per-identity limits configurable in the future.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use gritgrub_core::IdentityId;

/// A token bucket for a single identity (or the anonymous bucket).
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

/// Rate limiter state shared across requests.
pub struct RateLimiter {
    buckets: Mutex<HashMap<Option<IdentityId>, Bucket>>,
    max_tokens: u32,
    window_secs: u32,
}

/// Result of a rate limit check.
pub struct RateCheck {
    /// Whether the request is allowed.
    pub allowed: bool,
    /// Remaining tokens in this window.
    pub remaining: u32,
    /// Seconds until the bucket is fully refilled.
    pub reset_secs: u32,
}

impl RateLimiter {
    /// Create a new rate limiter.
    /// If max_ops is 0, rate limiting is disabled (all requests allowed).
    pub fn new(max_ops: u32, window_secs: u32) -> Arc<Self> {
        Arc::new(Self {
            buckets: Mutex::new(HashMap::new()),
            max_tokens: max_ops,
            window_secs: if window_secs == 0 { 60 } else { window_secs },
        })
    }

    /// Check if a request from this identity is allowed.
    /// Returns rate info for response metadata.
    pub fn check(&self, identity: Option<IdentityId>) -> RateCheck {
        // Rate limiting disabled.
        if self.max_tokens == 0 {
            return RateCheck { allowed: true, remaining: u32::MAX, reset_secs: 0 };
        }

        let now = Instant::now();
        let refill_rate = self.max_tokens as f64 / self.window_secs as f64;

        // SE-16: Don't panic on poisoned mutex — recover gracefully.
        let mut buckets = match self.buckets.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let bucket = buckets.entry(identity).or_insert_with(|| Bucket {
            tokens: self.max_tokens as f64,
            last_refill: now,
        });

        // Refill tokens based on elapsed time.
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill_rate).min(self.max_tokens as f64);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            let reset = if bucket.tokens >= self.max_tokens as f64 {
                0
            } else {
                ((self.max_tokens as f64 - bucket.tokens) / refill_rate).ceil() as u32
            };
            RateCheck {
                allowed: true,
                remaining: bucket.tokens as u32,
                reset_secs: reset,
            }
        } else {
            let wait = ((1.0 - bucket.tokens) / refill_rate).ceil() as u32;
            RateCheck {
                allowed: false,
                remaining: 0,
                reset_secs: wait,
            }
        }
    }

    /// Disabled sentinel — always allows.
    pub fn disabled() -> Arc<Self> {
        Self::new(0, 60)
    }
}
