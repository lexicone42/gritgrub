# gritgrub — Future Architecture

## Current State (2026-03-29)

gritgrub is a working version control system with:
- Content-addressed object store (BLAKE3 + postcard)
- Ed25519 identity + DSSE attestation system
- gRPC server + HTTP/JSON gateway
- CAS-based ref updates (optimistic concurrency)
- 119 tests (unit, property, integration, e2e)

The embedded backend (redb) handles single-user CLI well but hits a wall
at ~10 concurrent writers due to its exclusive write lock.

## Scaling the Current Design

### Near-term improvements (no backend swap)

**1. Read/write split with tokio::sync::RwLock**

Wrap `Arc<Repository>` in `RwLock` so reads don't block on writes:
```rust
struct ServerRepo {
    inner: tokio::sync::RwLock<Repository>,
}
```
Read-heavy endpoints (get_object, list_refs, log) take `read()`.
Write endpoints (commit, set_ref, push_objects) take `write()`.
This alone gets you ~50 concurrent readers with no code changes to Repository.

**2. Object deduplication at the API layer**

Before calling `put_object()`, check `has_object()` first. Content-addressed
objects are immutable — if the hash exists, the write is a no-op. This avoids
acquiring the write lock for duplicate pushes (common when multiple agents
push overlapping DAGs).

**3. Connection limits and request timeouts**

- Add `tower::limit::ConcurrencyLimit` to cap total in-flight requests
- Add `tokio::time::timeout` around streaming RPCs to prevent zombie tasks
- Add `tower::limit::RateLimit` per-connection (not just per-identity)

**4. Background compaction**

redb accumulates write-ahead log entries. Periodic `compact()` in a background
task prevents the database file from growing unbounded under heavy write load.

## Medium-term: Backend Split

The `Backend` trait already decomposes into sub-traits:
```
ObjectStore    — immutable blobs, trees, changesets, envelopes
RefStore       — mutable named pointers (branches, HEAD, tags)
ConfigStore    — key-value config
IdentityStore  — mutable identity records
EventStore     — append-only audit log
RevocationStore — token revocation list
```

These have fundamentally different access patterns:

| Sub-store | Read:Write | Contention | Ideal backend |
|-----------|-----------|------------|---------------|
| ObjectStore | 100:1 | None (content-addressed) | S3, filesystem, KV store |
| RefStore | 10:1 | High (branch tips) | CAS-capable store (etcd, Redis, Postgres) |
| ConfigStore | 100:1 | None | Any KV store |
| IdentityStore | 50:1 | Low | Any KV store |
| EventStore | 1:10 | Append-only | Log store (NATS JetStream, Kafka, Redpanda) |
| RevocationStore | 100:1 | None | Bloom filter + backing store |

### Recommended split

```
CLI (single-user):     SQLite for everything (WAL mode)
Server (multi-agent):  S3 for objects + etcd/Redis for refs + NATS for events
```

The split is invisible to the Repository layer — it still calls trait methods.
Only the backend wiring changes.

### SQLite backend (drop-in redb replacement)

SQLite in WAL mode gives:
- Concurrent readers (no blocking)
- Single writer (but writer doesn't block readers)
- ~50k writes/sec on modern SSDs
- Battle-tested at billions of deployments

Schema:
```sql
CREATE TABLE objects (id BLOB PRIMARY KEY, data BLOB NOT NULL);
CREATE TABLE refs (name TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE identities (id BLOB PRIMARY KEY, data BLOB NOT NULL);
CREATE TABLE capabilities (id BLOB PRIMARY KEY, data BLOB NOT NULL);
CREATE TABLE events (seq INTEGER PRIMARY KEY AUTOINCREMENT, data BLOB NOT NULL);
CREATE TABLE revoked_tokens (hash BLOB PRIMARY KEY);
```

### S3-compatible object store

Objects are content-addressed, so the S3 key IS the BLAKE3 hash:
```
s3://bucket/objects/ab/cdef0123...  (2-char prefix for partitioning)
```

PUT is idempotent (same hash = same content). GET is embarrassingly parallel.
No locking, no transactions, infinite horizontal scale.

For local development, MinIO runs as a single binary and speaks S3 protocol.

### etcd for refs

etcd provides linearizable CAS via transactions:
```
txn(compare: ref == old_value, success: put(ref, new_value), failure: get(ref))
```

This is exactly `cas_ref()`. etcd handles thousands of concurrent CAS
operations per second, with Raft consensus for durability.

### NATS JetStream for events

Replace polling-based event reads with push-based subscriptions:
```
agent subscribes to "repo.events.>" → gets real-time notifications
```

Agents react to events instead of polling the log endpoint.

## Long-term: What Would a Purpose-Built System Look Like?

See the "thinking bigger" section below.

---

## Thinking Bigger: A VCS Built for AI-Native Development

The version control systems we have (git, Mercurial, Perforce) were designed
for humans typing code into editors, collaborating via pull requests, and
deploying on a cadence measured in days or weeks.

AI-native development looks nothing like this:

- **100 agents working simultaneously** on different aspects of a codebase
- **Sub-second commit cycles** — agents commit every successful test run
- **Branch-per-thought** — each exploration gets its own branch, most are discarded
- **Structured metadata** — not commit messages, but typed intents, verification
  results, affected paths, rationale
- **Continuous attestation** — every commit carries provenance, SBOM, and
  verification status as first-class objects
- **Real-time coordination** — agents need to know what other agents are doing,
  not discover it via merge conflicts

### Core design principles

**1. Refs are the only coordination point**

Objects (blobs, trees, changesets) are immutable and content-addressed.
Two agents creating identical objects is harmless — deduplication is free.
The only place agents conflict is when updating refs (branch tips).
Therefore: optimize refs for high-throughput CAS, and make everything else
embarrassingly parallel.

**2. Branches are cheap and disposable**

Git branches are cheap but culturally expensive (naming, review, cleanup).
In an AI-native VCS, branches should be as cheap as function calls:
```
forge explore "try approach A" → auto-creates branch, runs, reports
forge explore "try approach B" → parallel branch, runs, reports
forge pick <branch>            → promotes winner, garbage-collects losers
```

**3. Structured intent replaces commit messages**

Commit messages are unstructured text. Agents produce and consume structured data.
The `Intent` struct (kind, rationale, affected_paths, verifications) should be
the primary metadata, not an optional field.

**4. Verification is continuous, not gated**

Instead of CI/CD running after a PR:
- Every changeset carries its verification status
- Attestations accumulate as the changeset moves through stages
- The ref policy system enforces "branch X requires SLSA L1" at write time
- Agents can query "what's the latest verified commit on main?" directly

**5. The DAG is a coordination protocol**

Agents don't need Slack channels or ticket systems. The DAG itself carries
the coordination:
- Changeset parents show dependency relationships
- Intent.context_ref links related explorations
- Event streams notify agents of relevant changes
- Merge base detection prevents redundant work

### What Rust gives us

**Zero-cost abstractions for the storage layer:**
- `io_uring` for async disk I/O (no thread pool overhead)
- Memory-mapped files for object reads (kernel manages the cache)
- `crossbeam` epoch-based reclamation for lock-free concurrent data structures
- `rayon` for parallel tree diffing and merge computation

**Type safety for correctness:**
- `ObjectId` is a newtype, not `[u8; 32]` — can't mix up hashes
- `Ref::Direct` vs `Ref::Symbolic` is an enum, not a string convention
- `Capability` scopes are typed, not string patterns
- The compiler catches ref update races at the trait level

**Performance where it matters:**
- BLAKE3 hashing at 1GB/s (SIMD-accelerated, parallel for large files)
- postcard serialization is zero-copy for reads
- redb/SQLite give ACID without a separate process
- The binary is a single static executable — no runtime, no GC, no JVM

### The embedded KV question: what's actually optimal?

For an embedded CAS-capable store optimized for this workload:

| Option | Concurrent readers | Concurrent writers | CAS | Embedded | Notes |
|--------|-------------------|-------------------|-----|----------|-------|
| redb | Yes (MVCC) | No (exclusive) | Yes | Yes | Current. Single-writer bottleneck. |
| SQLite WAL | Yes | No (but non-blocking) | Manual | Yes | Proven. Writer doesn't block readers. |
| sled | Yes | Yes (lock-free) | Yes | Yes | Perpetual beta. Data loss warnings. |
| RocksDB | Yes | Yes (per-CF) | Yes | Yes | Battle-tested. C++ dependency. |
| FoundationDB | Yes | Yes (MVCC) | Yes | Client-server | Overkill for embedded, perfect for server. |
| **Custom B+ tree** | Yes | Yes (per-page) | Yes | Yes | Maximum control. Significant engineering. |
| **fjall** | Yes | Yes (LSM) | Yes | Yes | Pure Rust, modern LSM-tree. Worth evaluating. |

**fjall** (https://github.com/fjall-rs/fjall) is interesting: pure Rust,
LSM-tree based, supports concurrent writers, transactions, and is designed
for embedded use. It could be a good redb replacement without the complexity
of SQLite's C FFI or RocksDB's C++ dependency.

### The dream architecture

```
┌─────────────────────────────────────────────────────┐
│                   forge serve                        │
│                                                      │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────┐ │
│  │  gRPC/HTTP  │  │  Agent Pool  │  │  Event Bus │ │
│  │  (tonic +   │  │  (tokio      │  │  (broadcast│ │
│  │   axum)     │  │   tasks)     │  │   channel) │ │
│  └──────┬──────┘  └──────┬───────┘  └─────┬──────┘ │
│         │                │                 │        │
│  ┌──────▼─────────────────▼─────────────────▼──────┐│
│  │              Repository Layer                    ││
│  │  commit() merge() stash() attest() verify()     ││
│  │  ┌─────────────────────────────────────────┐    ││
│  │  │         CAS-based ref protocol          │    ││
│  │  │   (optimistic concurrency everywhere)   │    ││
│  │  └─────────────────────────────────────────┘    ││
│  └──┬──────────────┬──────────────┬────────────────┘│
│     │              │              │                  │
│  ┌──▼────────┐  ┌──▼────────┐  ┌─▼─────────────┐  │
│  │ ObjectPool│  │  RefStore  │  │  EventJournal │  │
│  │           │  │            │  │               │  │
│  │ Sharded   │  │ CAS-native │  │ Append-only   │  │
│  │ by hash   │  │ linearized │  │ ordered       │  │
│  │ prefix    │  │ per-ref    │  │ partitioned   │  │
│  └──┬────────┘  └──┬────────┘  └──┬────────────┘  │
└─────┼──────────────┼──────────────┼────────────────┘
      │              │              │
   ┌──▼────┐     ┌───▼───┐     ┌───▼──────┐
   │ fs/S3 │     │ fjall/ │     │ fjall/   │
   │ MinIO │     │ etcd/  │     │ NATS/    │
   │       │     │ Redis  │     │ Redpanda │
   └───────┘     └────────┘     └──────────┘
```

The key insight: **objects, refs, and events are three fundamentally different
data structures that happen to live in the same system.** Treating them as
one database (redb today, Postgres tomorrow) is always a compromise. The
Backend trait split already reflects this — making it physical is the natural
next step.
