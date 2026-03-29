<p align="center">
  <img src="assets/logo.png" alt="gritgrub" width="600">
</p>

<h1 align="center">gritgrub</h1>

<p align="center">
  A self-hosted code collaboration platform — what GitHub would be if designed today with AI agents as first-class users.
</p>

<p align="center">
  <a href="#architecture">Architecture</a> |
  <a href="#getting-started">Getting Started</a> |
  <a href="#status">Status</a> |
  <a href="#design-philosophy">Design Philosophy</a>
</p>

---

## Why

Git hosting platforms were designed for humans clicking buttons. Agents need machine-readable capabilities, cryptographic attestation of every action, and fine-grained scoped tokens — not OAuth browser flows. gritgrub treats agents and humans as equals.

## Architecture

```
crates/
  core/     Content-addressed object model, identity, signing, tokens, policies
  store/    redb-backed storage, capability system, ref policy engine
  api/      gRPC server, auth middleware, rate limiting, event streaming
  cli/      `forge` command-line interface
```

**Key design decisions:**

- **BLAKE3** for content addressing — 1 GB/s per core, Merkle-tree parallel hashing
- **postcard** for storage (deterministic serialization for reproducible hashes), **protobuf** for wire
- **redb** for embedded storage — ACID, single-file, no external dependencies
- **Ed25519** signing with DSSE envelopes for attestations
- **Scoped tokens** (v2) with per-ref, per-operation permissions and server-enforced lifetime limits

## Getting Started

```bash
# Build
cargo build --release

# Initialize a repository
forge init

# Commit, branch, merge
forge commit -m "initial commit"
forge branch feature
forge checkout feature
forge commit -m "add feature"
forge checkout main
forge merge feature

# Collaborate
forge serve                                    # start gRPC server
forge remote add origin http://[::1]:50051     # add remote
forge push                                     # push to remote
forge pull                                     # pull from remote
forge clone http://remote:50051 myproject      # clone a repo
```

## Design Philosophy

### Agents as First-Class Users

Every API is machine-parseable. Token scopes map directly to capabilities. The event stream lets agents subscribe to repository changes in real time. Attestation records create an auditable trail of every agent action.

### Content-Addressed Everything

Objects (blobs, trees, changesets) are identified by their BLAKE3 hash. References are mutable pointers into the immutable object graph. This gives you deduplication, integrity verification, and natural caching for free.

### Capability-Based Security

No ambient authority. Every operation requires explicit capability grants:

- **Scopes**: `read`, `write`, `attest`, `identity`, `ref:<pattern>`
- **Permissions**: per-scope bitflags (read, write, create, delete, admin)
- **Ref policies**: glob-matched rules with `require_review`, `require_slsa`, `allowed_writers`, `forbid_force_push`

### Concurrent Agent Collaboration

Hundreds of agents can work on the same repository simultaneously — no worktrees, no filesystem locking, no contention:

- **Immutable objects**: blobs, trees, and changesets are content-addressed. Two agents writing the same blob get the same ID — zero coordination needed.
- **Lock-free ref updates**: CAS (compare-and-swap) on branch pointers. An agent reads the current ref, does its work, then atomically swaps. If another agent updated first, the CAS fails and the agent rebases and retries.
- **Agent namespaces**: each agent works in `refs/agents/<agent-id>/`, merging to shared branches through the normal policy engine.
- **Server-side tree building**: agents can create blobs and trees via the gRPC API without any filesystem checkout — pure object manipulation.

### Security Hardening

The codebase has been through a Trail of Bits-style sharp edges analysis. Property-based tests (proptest) and fuzz targets (cargo-fuzz) cover the token parser, object serializer, and glob matcher. The fuzzing campaign has already found and fixed real bugs:

- Token parser panic on multi-byte UTF-8 input
- Token parser panic on corrupted colon structure
- Glob matcher exponential backtracking on adversarial patterns

## Status

**Early development.** The core object model, identity system, capability engine, and ref policy system are functional. The gRPC API layer is in progress.

| Component | Status |
|-----------|--------|
| Object model (blob, tree, changeset) | Working |
| Content-addressed storage (redb) | Working |
| Identity + capability system | Working |
| Token system (v1 admin, v2 scoped) | Working |
| Ed25519 signing + DSSE envelopes | Working |
| Ref policy engine | Working |
| Property tests + fuzz targets | Working |
| gRPC API + auth middleware | Working |
| Merge (three-way, fast-forward) | Working |
| Push / Pull / Clone (gRPC sync) | Working |
| CAS ref updates (lock-free) | Working |
| SBOM + SLSA attestation | Working |
| Git import/export | Working |
| Web UI | Planned |

## License

MIT
