# Deploying forge

forge is a single static binary. No containers, no service managers, no runtime dependencies.

## Build

```bash
# Standard release build
cargo build --release
# Binary at: target/release/forge

# Static musl build (fully portable, no glibc dependency)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
# Binary at: target/x86_64-unknown-linux-musl/release/forge
```

## Run

```bash
# Initialize a repository
forge init

# Start the server (gRPC + HTTP dashboard)
forge serve --addr 0.0.0.0:50051 --http-addr 0.0.0.0:8080 --no-tls

# With TLS (auto-generates certs via mkcert if installed)
forge serve --addr 0.0.0.0:50051 --http-addr 0.0.0.0:8080
```

Open `http://your-ip:8080` for the dashboard.

## Configuration

Three layers (last wins):
1. Built-in defaults
2. Config file: `.forge/server.toml` (create with `forge serve --init-config`)
3. Environment variables: `FORGE_*`

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FORGE_GRPC_ADDR` | `localhost:50051` | gRPC listen address |
| `FORGE_HTTP_ADDR` | *(disabled)* | HTTP gateway address |
| `FORGE_TLS_CERT` | *(none)* | PEM cert path (enables TLS) |
| `FORGE_TLS_KEY` | *(none)* | PEM key path |
| `FORGE_TLS_CA` | *(none)* | CA cert for mTLS |
| `FORGE_REPO_PATH` | `.` | Repository root |
| `FORGE_REQUIRE_AUTH` | `false` | Require auth for reads |
| `FORGE_MAX_MESSAGE_SIZE` | `16777216` | Max message size (bytes) |

### Rate limiting

Enabled by default: 100 operations per 60 seconds per identity.
Override in `.forge/server.toml`:

```toml
[limits]
default_rate_limit_ops = 200
default_rate_limit_window_secs = 60
```

## Multi-agent workflow

```bash
# 1. Create an exploration goal
forge explore create "implement rate limiting" \
  --constraint "tests:all tests must pass"

# 2. Provision agents (outputs JSON configs)
forge provision batch --count 5 \
  --server https://your-server:50051 \
  --goal <goal-id>

# 3. Pipe configs to agent processes
forge provision batch ... | jq -c '.[]' | while read config; do
  echo "$config" | your-agent-launcher &
done

# 4. Watch progress
forge watch                    # Terminal: live events
open http://your-server:8080   # Browser: dashboard

# 5. Promote the winner
forge explore promote <goal-id> --approach <best>
```

## HTTP API for orchestrators

Create goals and provision agents via HTTP (for minimal.dev integration):

```bash
# Create a goal
curl -X POST http://server:8080/api/v1/explore/goals \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"description": "implement feature X"}'

# Provision agents
curl -X POST http://server:8080/api/v1/provision/batch \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"count": 5, "goal_id": "abc123"}'

# Get full dashboard state (single request)
curl http://server:8080/api/v1/overview

# Stream events (Server-Sent Events)
curl -N http://server:8080/api/v1/events
```

## Verification pipelines

forge has embedded CI — no external CI server needed.

```bash
# Run the default pipeline (test + lint + build)
forge pipeline run

# Define a custom pipeline
forge pipeline define deploy \
  --stage test --stage lint --stage build-release

# Show results
forge pipeline show
```

Pipeline results are stored as signed attestations in the DAG.
Ref policies can require specific pipelines to pass before allowing
ref updates (e.g., main requires test + lint).

## Data

All state lives in `.forge/`:
- `store.redb` — content-addressed object store + refs + config
- `keys/` — Ed25519 signing keys per identity
- `tls/` — auto-generated TLS certificates (if using mkcert)
- `server.toml` — server configuration (optional)

Back up `.forge/` to preserve repository state.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Web dashboard |
| GET | `/health` | Health check |
| GET | `/api/v1/overview` | Full state (dashboard single-request) |
| GET | `/api/v1/log?count=N` | Changeset history |
| GET | `/api/v1/branches` | Branch list |
| GET | `/api/v1/status` | Repo status |
| GET | `/api/v1/explore/goals` | Exploration goals |
| GET | `/api/v1/explore/goals/:id` | Goal detail |
| POST | `/api/v1/explore/goals` | Create goal (auth required) |
| GET | `/api/v1/pipeline/:id` | Pipeline results |
| POST | `/api/v1/provision` | Provision agent (auth required) |
| POST | `/api/v1/provision/batch` | Batch provision (auth required) |
| GET | `/api/v1/events` | SSE live event stream |
| GET | `/api/v1/objects/:id` | Object by ID |
| GET | `/api/v1/refs` | List refs |
| GET | `/api/v1/changesets/:id` | Changeset detail |
| GET | `/api/v1/identities/:id` | Identity detail |
