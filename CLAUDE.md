# gritgrub — version control for humans and agents

This is a forge-managed project. Use `forge` commands, NOT git.

## Build & Test

```bash
cargo build --release          # Release binary at target/release/forge
cargo test                     # All tests (173: unit, property, integration, e2e)
cargo test -p gritgrub-store --test integration  # Repository integration tests
cargo test -p gritgrub-cli --test e2e            # CLI + server E2E tests
cargo test -p gritgrub-core                       # Property + unit tests
```

## Architecture

Four crates in a workspace:

- **`crates/core`** — Data model: objects (blob, tree, changeset, envelope), identity, tokens, signing, policy. Pure logic, no I/O.
- **`crates/store`** — Repository layer: redb backend, ref management, merge, stash, reset. Owns `.forge/` directory.
- **`crates/api`** — gRPC server + client + HTTP/JSON gateway: tonic services, axum REST API, auth middleware, rate limiting, TLS, config.
- **`crates/cli`** — The `forge` binary: clap commands that wire store + api together.

## Key design decisions

- **BLAKE3** for content hashing (parallel, 1GB/s, designed for content addressing)
- **postcard** for storage serialization (deterministic → reproducible hashes)
- **protobuf** for wire format (gRPC interop)
- **redb** for embedded storage (ACID, single-file, exclusive write lock)
- **Ed25519** for identity signing (ed25519-dalek)
- Content-addressed immutable objects + mutable refs (like git, but richer)
- Attestations reference changesets, not embedded in them (preserves content hashing)

## Forge commands (instead of git)

```bash
forge status                    # like git status
forge commit -m "msg"           # like git commit -am "msg"
forge log                       # like git log
forge diff                      # like git diff
forge show                      # like git show
forge branch <name>             # like git branch
forge checkout <branch>         # like git checkout
forge merge <branch>            # like git merge
forge stash save / pop / list   # like git stash
forge reset [--hard] <id>       # like git reset
forge tag <name>                # like git tag
forge push / pull               # like git push / pull
forge serve                     # start gRPC server (auto-TLS)
forge serve --http-addr :8080   # also start HTTP/JSON gateway
forge clone <url> <path>        # like git clone
forge log --graph --oneline     # like git log --graph --oneline
forge pipeline run              # run default pipeline (test+lint+build)
forge pipeline define ci --stage test --stage lint  # define custom pipeline
forge pipeline list             # list defined pipelines
forge pipeline show             # show pipeline results for HEAD
forge explore create "goal"     # create exploration goal
forge explore approach <id> --name <n>  # create approach branch
forge explore list              # list active explorations
forge explore show <id>         # detailed goal status
forge explore promote <id> --approach <n>  # merge winner
forge explore abandon <id>      # clean up exploration
forge provision one --name x    # provision single agent (JSON output)
forge provision batch --count 5 --goal <id>  # batch provision
forge watch                     # live event stream (Ctrl+C to stop)
forge collab spawn --task "..." # spawn agent on a branch
forge collab list               # list active agent tasks
forge collab review <branch>    # review agent's work
```
