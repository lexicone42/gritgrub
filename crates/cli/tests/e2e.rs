//! End-to-end tests for the forge CLI binary.
//!
//! These tests run the actual `forge` binary as a subprocess,
//! exercise the full command set, and verify the CLI ↔ server model
//! works correctly over gRPC + TLS.

use std::process::{Command, Stdio};
use std::path::{Path, PathBuf};
use std::fs;
use tempfile::TempDir;

/// Path to the forge binary — built before tests run.
fn forge_bin() -> PathBuf {
    // cargo test builds binaries into target/debug
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove test binary name
    path.pop(); // remove deps/
    path.push("forge");
    path
}

/// Run a forge command and return (stdout, stderr, success).
fn forge(dir: &Path, args: &[&str]) -> (String, String, bool) {
    let output = Command::new(forge_bin())
        .args(args)
        .current_dir(dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to execute forge");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr, output.status.success())
}

/// Run forge and assert success, returning stdout.
fn forge_ok(dir: &Path, args: &[&str]) -> String {
    let (stdout, stderr, success) = forge(dir, args);
    assert!(success, "forge {:?} failed:\nstdout: {}\nstderr: {}", args, stdout, stderr);
    stdout
}

/// Run forge and assert failure, returning stderr.
fn forge_err(dir: &Path, args: &[&str]) -> String {
    let (stdout, stderr, success) = forge(dir, args);
    assert!(!success, "forge {:?} unexpectedly succeeded:\nstdout: {}\nstderr: {}", args, stdout, stderr);
    // Error can be in stdout or stderr depending on how anyhow prints.
    format!("{}{}", stdout, stderr)
}

// ── CLI Basic Commands ───────────────────────────────────────────

#[test]
fn cli_help() {
    let dir = TempDir::new().unwrap();
    let out = forge_ok(dir.path(), &["--help"]);
    assert!(out.contains("gritgrub"));
    assert!(out.contains("init"));
    assert!(out.contains("commit"));
}

#[test]
fn cli_init() {
    let dir = TempDir::new().unwrap();
    let out = forge_ok(dir.path(), &["init", "--name", "test-user"]);
    assert!(out.contains("Initialized forge repository"));
    assert!(dir.path().join(".forge").exists());
}

#[test]
fn cli_init_double_fails() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init"]);
    let err = forge_err(dir.path(), &["init"]);
    assert!(err.contains("already initialized"));
}

#[test]
fn cli_commit_and_log() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init", "--name", "tester"]);
    fs::write(dir.path().join("hello.txt"), "world").unwrap();

    let out = forge_ok(dir.path(), &["commit", "-m", "first commit"]);
    assert!(out.contains("first commit"));

    let log = forge_ok(dir.path(), &["log"]);
    assert!(log.contains("first commit"));
    assert!(log.contains("(main)"));
}

#[test]
fn cli_commit_with_intent() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init"]);
    fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

    let out = forge_ok(dir.path(), &[
        "commit", "-m", "add main", "--intent", "feature", "--rationale", "bootstrap"
    ]);
    assert!(out.contains("add main"));

    let log = forge_ok(dir.path(), &["log"]);
    assert!(log.contains("feature"));
}

#[test]
fn cli_status() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init"]);

    // Clean status.
    let out = forge_ok(dir.path(), &["status"]);
    assert!(out.contains("clean") || out.contains("no changesets"));

    // New file.
    fs::write(dir.path().join("new.txt"), "data").unwrap();
    let out = forge_ok(dir.path(), &["status"]);
    assert!(out.contains("new.txt"));
}

#[test]
fn cli_diff() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init"]);
    fs::write(dir.path().join("a.txt"), "version 1").unwrap();
    forge_ok(dir.path(), &["commit", "-m", "v1"]);

    fs::write(dir.path().join("a.txt"), "version 2").unwrap();
    let out = forge_ok(dir.path(), &["diff"]);
    assert!(out.contains("a.txt"));
}

#[test]
fn cli_show() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init"]);
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    forge_ok(dir.path(), &["commit", "-m", "initial"]);

    let out = forge_ok(dir.path(), &["show"]);
    assert!(out.contains("initial"));
    assert!(out.contains("a.txt"));
}

#[test]
fn cli_cat() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init"]);
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    let commit_out = forge_ok(dir.path(), &["commit", "-m", "initial"]);

    // Extract changeset ID from commit output: "[main XXXX] initial"
    let id = commit_out.split_whitespace()
        .find(|w| w.ends_with(']'))
        .map(|w| w.trim_end_matches(']'))
        .unwrap();

    let out = forge_ok(dir.path(), &["cat", &id[..8]]);
    assert!(out.contains("initial") || out.contains("Changeset"));
}

// ── Branch & Checkout ────────────────────────────────────────────

#[test]
fn cli_branch_list_and_create() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init"]);
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    forge_ok(dir.path(), &["commit", "-m", "initial"]);

    // List branches.
    let out = forge_ok(dir.path(), &["branch"]);
    assert!(out.contains("main"));

    // Create branch.
    forge_ok(dir.path(), &["branch", "feature"]);
    let out = forge_ok(dir.path(), &["branch"]);
    assert!(out.contains("feature"));
}

#[test]
fn cli_checkout_branch() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init"]);
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    forge_ok(dir.path(), &["commit", "-m", "initial"]);

    // Create and checkout.
    forge_ok(dir.path(), &["checkout", "-b", "feature"]);
    let out = forge_ok(dir.path(), &["branch"]);
    assert!(out.contains("* feature") || out.contains("feature"));
}

#[test]
fn cli_branch_delete() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init"]);
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    forge_ok(dir.path(), &["commit", "-m", "initial"]);

    forge_ok(dir.path(), &["branch", "to-delete"]);
    forge_ok(dir.path(), &["branch", "-d", "to-delete"]);

    let out = forge_ok(dir.path(), &["branch"]);
    assert!(!out.contains("to-delete"));
}

// ── Tags ─────────────────────────────────────────────────────────

#[test]
fn cli_tag_create_list_delete() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init"]);
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    forge_ok(dir.path(), &["commit", "-m", "release"]);

    forge_ok(dir.path(), &["tag", "v0.1.0"]);
    let out = forge_ok(dir.path(), &["tag"]);
    assert!(out.contains("v0.1.0"));

    forge_ok(dir.path(), &["tag", "-d", "v0.1.0"]);
    let out = forge_ok(dir.path(), &["tag"]);
    assert!(!out.contains("v0.1.0"));
}

// ── Stash ────────────────────────────────────────────────────────

#[test]
fn cli_stash_save_pop() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init"]);
    fs::write(dir.path().join("a.txt"), "committed").unwrap();
    forge_ok(dir.path(), &["commit", "-m", "initial"]);

    fs::write(dir.path().join("a.txt"), "modified").unwrap();
    let out = forge_ok(dir.path(), &["stash", "save"]);
    assert!(out.contains("stash@{0}"));

    // Working tree should be clean now.
    let status = forge_ok(dir.path(), &["status"]);
    assert!(status.contains("No changes") || status.contains("clean"));

    // Pop restores.
    let out = forge_ok(dir.path(), &["stash", "pop"]);
    assert!(out.contains("Applied stash"));
    let content = fs::read_to_string(dir.path().join("a.txt")).unwrap();
    assert_eq!(content, "modified");
}

#[test]
fn cli_stash_list() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init"]);
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    forge_ok(dir.path(), &["commit", "-m", "initial"]);

    fs::write(dir.path().join("a.txt"), "wip").unwrap();
    forge_ok(dir.path(), &["stash", "save", "-m", "work in progress"]);

    let out = forge_ok(dir.path(), &["stash", "list"]);
    assert!(out.contains("stash@{0}"));
    assert!(out.contains("work in progress"));
}

// ── Reset ────────────────────────────────────────────────────────

#[test]
fn cli_reset_soft() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init"]);
    fs::write(dir.path().join("a.txt"), "v1").unwrap();
    let out1 = forge_ok(dir.path(), &["commit", "-m", "first"]);
    let id1 = extract_changeset_id(&out1);

    fs::write(dir.path().join("a.txt"), "v2").unwrap();
    forge_ok(dir.path(), &["commit", "-m", "second"]);

    let out = forge_ok(dir.path(), &["reset", &id1]);
    assert!(out.contains("soft"));

    // File still has v2 (soft reset).
    let content = fs::read_to_string(dir.path().join("a.txt")).unwrap();
    assert_eq!(content, "v2");
}

#[test]
fn cli_reset_hard() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init"]);
    fs::write(dir.path().join("a.txt"), "v1").unwrap();
    let out1 = forge_ok(dir.path(), &["commit", "-m", "first"]);
    let id1 = extract_changeset_id(&out1);

    fs::write(dir.path().join("a.txt"), "v2").unwrap();
    forge_ok(dir.path(), &["commit", "-m", "second"]);

    let out = forge_ok(dir.path(), &["reset", "--hard", &id1]);
    assert!(out.contains("working tree updated"));

    // File restored to v1.
    let content = fs::read_to_string(dir.path().join("a.txt")).unwrap();
    assert_eq!(content, "v1");
}

// ── Identity ─────────────────────────────────────────────────────

#[test]
fn cli_identity_create_and_list() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init"]);

    let out = forge_ok(dir.path(), &[
        "identity", "create", "--name", "agent-1", "--kind", "agent", "--runtime", "claude-code"
    ]);
    assert!(out.contains("agent-1"));
    assert!(out.contains("agent:claude-code"));

    let out = forge_ok(dir.path(), &["identity", "list"]);
    assert!(out.contains("agent-1"));
}

#[test]
fn cli_identity_keygen_and_token() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init"]);
    forge_ok(dir.path(), &["identity", "keygen"]);

    let out = forge_ok(dir.path(), &["identity", "token"]);
    assert!(out.contains("forge-v1:") || out.contains("forge-v2:"));
}

// ── Config ───────────────────────────────────────────────────────

#[test]
fn cli_config_get_set() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init"]);

    forge_ok(dir.path(), &["config", "test.key", "test-value"]);
    let out = forge_ok(dir.path(), &["config", "test.key"]);
    assert!(out.contains("test-value"));
}

// ── Remote ───────────────────────────────────────────────────────

#[test]
fn cli_remote_add_list_remove() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init"]);

    forge_ok(dir.path(), &["remote", "add", "origin", "https://localhost:50051"]);
    let out = forge_ok(dir.path(), &["remote", "list"]);
    assert!(out.contains("origin"));
    assert!(out.contains("https://localhost:50051"));

    forge_ok(dir.path(), &["remote", "remove", "origin"]);
    let out = forge_ok(dir.path(), &["remote", "list"]);
    assert!(!out.contains("origin"));
}

// ── Merge (CLI) ──────────────────────────────────────────────────

#[test]
fn cli_merge_fast_forward() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init"]);
    fs::write(dir.path().join("a.txt"), "base").unwrap();
    forge_ok(dir.path(), &["commit", "-m", "base"]);

    // Create feature branch and add a commit.
    forge_ok(dir.path(), &["checkout", "-b", "feature"]);
    fs::write(dir.path().join("b.txt"), "feature work").unwrap();
    forge_ok(dir.path(), &["commit", "-m", "feature commit"]);

    // Switch back to main and merge.
    forge_ok(dir.path(), &["checkout", "main"]);
    let out = forge_ok(dir.path(), &["merge", "feature"]);
    assert!(out.to_lowercase().contains("fast-forward") || out.contains("Merged"));
}

// ── Server / Client E2E ─────────────────────────────────────────

/// Helper to start a forge server and return (process, port).
/// Picks a random available port to avoid conflicts between tests.
fn start_server(dir: &Path) -> (std::process::Child, u16) {
    let port = portpicker::pick_unused_port().expect("no free port");
    let addr = format!("127.0.0.1:{}", port);

    let child = Command::new(forge_bin())
        .args(["serve", "--addr", &addr])
        .current_dir(dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start server");

    // Give the server time to bind.
    std::thread::sleep(std::time::Duration::from_secs(2));
    (child, port)
}

#[test]
fn e2e_clone_over_tls() {
    let server_dir = TempDir::new().unwrap();
    let client_dir = TempDir::new().unwrap();

    // Set up server repo.
    forge_ok(server_dir.path(), &["init", "--name", "server"]);
    fs::write(server_dir.path().join("README.md"), "# Test").unwrap();
    fs::write(server_dir.path().join("main.rs"), "fn main() {}").unwrap();
    forge_ok(server_dir.path(), &["commit", "-m", "initial"]);

    let (mut server, port) = start_server(server_dir.path());
    let url = format!("https://localhost:{}", port);

    // Clone.
    let client_path = client_dir.path().join("cloned");
    let (stdout, stderr, success) = forge(
        client_dir.path(),
        &["clone", &url, client_path.to_str().unwrap()],
    );

    server.kill().ok();
    server.wait().ok();

    assert!(success, "clone failed:\nstdout: {}\nstderr: {}", stdout, stderr);
    assert!(client_path.join("README.md").exists());
    assert!(client_path.join("main.rs").exists());
    assert_eq!(
        fs::read_to_string(client_path.join("README.md")).unwrap(),
        "# Test"
    );
}

#[test]
fn e2e_push_over_tls() {
    let server_dir = TempDir::new().unwrap();
    let client_dir = TempDir::new().unwrap();

    // Server setup.
    forge_ok(server_dir.path(), &["init", "--name", "server"]);
    fs::write(server_dir.path().join("base.txt"), "base").unwrap();
    forge_ok(server_dir.path(), &["commit", "-m", "base"]);
    forge_ok(server_dir.path(), &["identity", "keygen"]);
    let token_out = forge_ok(server_dir.path(), &["identity", "token", "--scope", "*"]);
    let token = token_out.lines()
        .find(|l| l.starts_with("forge-"))
        .unwrap()
        .trim();

    let (mut server, port) = start_server(server_dir.path());
    let url = format!("https://localhost:{}", port);

    // Clone.
    let client_path = client_dir.path().join("repo");
    forge_ok(client_dir.path(), &["clone", &url, client_path.to_str().unwrap()]);

    // Make a change and push.
    fs::write(client_path.join("new.txt"), "from client").unwrap();
    forge_ok(&client_path, &["identity", "create", "--name", "client-agent", "--kind", "agent", "--runtime", "test"]);
    forge_ok(&client_path, &["commit", "-m", "client commit"]);
    forge_ok(&client_path, &["config", &format!("remote.origin.token"), token]);
    let (push_stdout, push_stderr, push_ok) = forge(&client_path, &["push"]);

    server.kill().ok();
    server.wait().ok();

    assert!(push_ok, "push failed:\nstdout: {}\nstderr: {}", push_stdout, push_stderr);

    // Verify server has the new changeset.
    let log = forge_ok(server_dir.path(), &["log", "-n", "5"]);
    assert!(log.contains("client commit"));
    assert!(log.contains("base"));
}

#[test]
fn e2e_push_without_token_rejected() {
    let server_dir = TempDir::new().unwrap();
    let client_dir = TempDir::new().unwrap();

    // Server setup.
    forge_ok(server_dir.path(), &["init", "--name", "server"]);
    fs::write(server_dir.path().join("base.txt"), "base").unwrap();
    forge_ok(server_dir.path(), &["commit", "-m", "base"]);

    let (mut server, port) = start_server(server_dir.path());
    let url = format!("https://localhost:{}", port);

    // Clone (no auth needed for reads).
    let client_path = client_dir.path().join("repo");
    forge_ok(client_dir.path(), &["clone", &url, client_path.to_str().unwrap()]);

    // Try pushing without a token — should fail.
    fs::write(client_path.join("new.txt"), "unauthorized").unwrap();
    forge_ok(&client_path, &["identity", "create", "--name", "anon", "--kind", "agent", "--runtime", "test"]);
    forge_ok(&client_path, &["commit", "-m", "unauth commit"]);
    let err = forge_err(&client_path, &["push"]);

    server.kill().ok();
    server.wait().ok();

    // Push should fail (no token → auth error, or no remote token config).
    assert!(
        err.contains("Unauthenticated") || err.contains("token") || err.contains("error"),
        "expected auth error, got: {}", err,
    );
}

#[test]
fn e2e_pull_updates_working_tree() {
    let server_dir = TempDir::new().unwrap();
    let client1_dir = TempDir::new().unwrap();
    let client2_dir = TempDir::new().unwrap();

    // Server setup.
    forge_ok(server_dir.path(), &["init", "--name", "server"]);
    fs::write(server_dir.path().join("base.txt"), "base").unwrap();
    forge_ok(server_dir.path(), &["commit", "-m", "base"]);
    forge_ok(server_dir.path(), &["identity", "keygen"]);
    let token_out = forge_ok(server_dir.path(), &["identity", "token", "--scope", "*"]);
    let token = token_out.lines()
        .find(|l| l.starts_with("forge-"))
        .unwrap()
        .trim();

    let (mut server, port) = start_server(server_dir.path());
    let url = format!("https://localhost:{}", port);

    // Client 1 clones and pushes a change.
    let c1_path = client1_dir.path().join("repo");
    forge_ok(client1_dir.path(), &["clone", &url, c1_path.to_str().unwrap()]);
    fs::write(c1_path.join("from_c1.txt"), "hello from client 1").unwrap();
    forge_ok(&c1_path, &["identity", "create", "--name", "c1", "--kind", "agent", "--runtime", "test"]);
    forge_ok(&c1_path, &["commit", "-m", "c1 commit"]);
    forge_ok(&c1_path, &["config", "remote.origin.token", token]);
    forge_ok(&c1_path, &["push"]);

    // Client 2 clones (should get c1's commit) and verifies.
    let c2_path = client2_dir.path().join("repo");
    forge_ok(client2_dir.path(), &["clone", &url, c2_path.to_str().unwrap()]);

    server.kill().ok();
    server.wait().ok();

    // Client 2 should have client 1's file.
    assert!(c2_path.join("from_c1.txt").exists(),
        "client 2 should have from_c1.txt after clone");
    assert_eq!(
        fs::read_to_string(c2_path.join("from_c1.txt")).unwrap(),
        "hello from client 1"
    );
}

// ── Exploration tree CLI ─────────────────────────────────────────

#[test]
fn cli_explore_create_and_list() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init", "--name", "tester"]);
    fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();
    forge_ok(dir.path(), &["commit", "-m", "initial"]);

    let out = forge_ok(dir.path(), &[
        "explore", "create", "Add rate limiting",
        "--target", "main",
        "--constraint", "tests:all tests pass",
    ]);
    assert!(out.contains("Created exploration goal"));
    assert!(out.contains("Add rate limiting"));

    let list = forge_ok(dir.path(), &["explore", "list"]);
    assert!(list.contains("Add rate limiting"));
    assert!(list.contains("main"));
}

#[test]
fn cli_explore_approach_and_show() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init", "--name", "tester"]);
    fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();
    forge_ok(dir.path(), &["commit", "-m", "initial"]);

    // Create goal — extract goal ID from output.
    let create_out = forge_ok(dir.path(), &[
        "explore", "create", "Improve performance",
    ]);
    let goal_id = create_out.lines()
        .find(|l| l.contains("Created exploration goal"))
        .and_then(|l| l.split_whitespace().last())
        .unwrap_or("");
    assert!(!goal_id.is_empty(), "failed to extract goal ID from: {}", create_out);

    // Create approach.
    let approach_out = forge_ok(dir.path(), &[
        "explore", "approach", goal_id, "--name", "caching",
    ]);
    assert!(approach_out.contains("caching"));

    // Show goal detail.
    let show_out = forge_ok(dir.path(), &["explore", "show", goal_id]);
    assert!(show_out.contains("caching"));
    assert!(show_out.contains("Improve performance"));
}

#[test]
fn cli_explore_abandon() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init", "--name", "tester"]);
    fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();
    forge_ok(dir.path(), &["commit", "-m", "initial"]);

    let create_out = forge_ok(dir.path(), &[
        "explore", "create", "Dead end experiment",
    ]);
    let goal_id = create_out.lines()
        .find(|l| l.contains("Created exploration goal"))
        .and_then(|l| l.split_whitespace().last())
        .unwrap_or("");

    let abandon_out = forge_ok(dir.path(), &["explore", "abandon", goal_id]);
    assert!(abandon_out.contains("Abandoned"));

    let list = forge_ok(dir.path(), &["explore", "list"]);
    assert!(list.contains("No active explorations"));
}

// ── Pipeline CLI ────────────────────────────────────────────────

#[test]
fn cli_pipeline_define_and_list() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init", "--name", "tester"]);

    let out = forge_ok(dir.path(), &[
        "pipeline", "define", "ci",
        "--stage", "test",
        "--stage", "lint",
    ]);
    assert!(out.contains("ci"));
    assert!(out.contains("test"));
    assert!(out.contains("lint"));

    let list = forge_ok(dir.path(), &["pipeline", "list"]);
    assert!(list.contains("ci"));
}

#[test]
fn cli_pipeline_show_no_results() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init", "--name", "tester"]);
    fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();
    forge_ok(dir.path(), &["commit", "-m", "initial"]);

    let out = forge_ok(dir.path(), &["pipeline", "show"]);
    assert!(out.contains("No pipeline results"));
}

// ── Garbage Collection ──────────────────────────────────────────

#[test]
fn cli_gc() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init", "--name", "tester"]);
    fs::write(dir.path().join("hello.txt"), "world").unwrap();
    forge_ok(dir.path(), &["commit", "-m", "initial"]);

    let out = forge_ok(dir.path(), &["gc"]);
    assert!(out.contains("objects total"));
    assert!(out.contains("Nothing to clean up") || out.contains("deleted"));
}

// ── Explore Promote ─────────────────────────────────────────────

#[test]
fn cli_explore_promote() {
    let dir = TempDir::new().unwrap();
    forge_ok(dir.path(), &["init", "--name", "tester"]);
    fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();
    forge_ok(dir.path(), &["commit", "-m", "initial"]);

    // Create goal.
    let create_out = forge_ok(dir.path(), &[
        "explore", "create", "Test promotion",
    ]);
    let goal_id = create_out.lines()
        .find(|l| l.contains("Created exploration goal"))
        .and_then(|l| l.split_whitespace().last())
        .unwrap_or("");

    // Create approach.
    forge_ok(dir.path(), &[
        "explore", "approach", goal_id, "--name", "winner",
    ]);

    // Add a file and commit (this advances main, which the approach also points to).
    fs::write(dir.path().join("feature.rs"), "pub fn feature() {}").unwrap();
    forge_ok(dir.path(), &["commit", "-m", "add feature"]);

    // Promote — the approach tip is behind main now, but promote should still work
    // (main has moved forward, approach tip is an ancestor).
    let promote_out = forge_ok(dir.path(), &[
        "explore", "promote", goal_id, "--approach", "winner",
    ]);
    assert!(
        promote_out.contains("promoted") || promote_out.contains("Fast-forward") || promote_out.contains("Merge"),
        "Expected promotion output, got: {}", promote_out
    );
}

// ── Helpers ──────────────────────────────────────────────────────

/// Extract changeset ID from commit output like "[main abc123def456] message"
fn extract_changeset_id(output: &str) -> String {
    output.split_whitespace()
        .find(|w| w.ends_with(']'))
        .map(|w| w.trim_end_matches(']').to_string())
        .unwrap_or_default()
}
