//! Integration tests for the Repository layer.
//!
//! Each test creates a temp directory, initializes a repo, and exercises
//! the public API. These tests verify that the full stack (repo → redb
//! backend → filesystem) works correctly together.

use std::fs;
use gritgrub_core::*;
use gritgrub_core::policy::RefPolicy;
use gritgrub_store::{Repository, MergeResult};
use tempfile::TempDir;

/// Extract the tree ID from a changeset object.
fn tree_of(obj: &Object) -> ObjectId {
    match obj {
        Object::Changeset(cs) => cs.tree,
        other => panic!("expected Changeset, got {:?}", std::mem::discriminant(other)),
    }
}

/// Helper: create a fresh repo in a temp dir, return the dir, repo, and identity.
fn fresh_repo() -> (TempDir, Repository, IdentityId) {
    let dir = TempDir::new().expect("create temp dir");
    let repo = Repository::init(dir.path()).expect("init repo");
    let id = repo.local_identity().expect("get identity");
    (dir, repo, id)
}

// ── Init & Basic Operations ──────────────────────────────────────

#[test]
fn init_creates_forge_dir() {
    let (dir, _repo, _id) = fresh_repo();
    assert!(dir.path().join(".forge").exists());
    assert!(dir.path().join(".forge/store.redb").exists());
}

#[test]
fn init_sets_head_to_main() {
    let (_dir, repo, _id) = fresh_repo();
    assert_eq!(repo.head_branch().unwrap(), Some("main".to_string()));
}

#[test]
fn init_creates_identity() {
    let (_dir, repo, id) = fresh_repo();
    let identity = repo.get_identity(&id).unwrap().unwrap();
    assert!(matches!(identity.kind, IdentityKind::Human));
}

#[test]
fn double_init_fails() {
    let (dir, _repo, _id) = fresh_repo();
    let result = Repository::init(dir.path());
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(err.to_string().contains("already initialized"));
}

#[test]
fn discover_walks_up() {
    let (dir, repo, _id) = fresh_repo();
    let subdir = dir.path().join("a/b/c");
    fs::create_dir_all(&subdir).unwrap();
    let expected = dir.path().canonicalize().unwrap();
    // Drop the original repo to release the redb lock.
    drop(repo);
    let found = Repository::discover(&subdir).unwrap();
    assert_eq!(found.root().canonicalize().unwrap(), expected);
}

// ── Commit & Log ─────────────────────────────────────────────────

#[test]
fn commit_and_log_roundtrip() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("hello.txt"), "world").unwrap();
    let cs_id = repo.commit("first commit", id, None).unwrap();

    let log = repo.log(10).unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].0, cs_id);
    assert_eq!(log[0].1.message, "first commit");
}

#[test]
fn commit_with_intent() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

    let intent = Intent {
        kind: IntentKind::Feature,
        affected_paths: vec!["main.rs".to_string()],
        rationale: "bootstrap".to_string(),
        context_ref: None,
        verifications: vec![],
    };
    repo.commit("add main", id, Some(intent)).unwrap();

    let log = repo.log(1).unwrap();
    assert_eq!(log[0].1.intent.as_ref().unwrap().kind, IntentKind::Feature);
}

#[test]
fn multiple_commits_form_chain() {
    let (dir, repo, id) = fresh_repo();

    fs::write(dir.path().join("a.txt"), "1").unwrap();
    let id1 = repo.commit("first", id, None).unwrap();

    fs::write(dir.path().join("b.txt"), "2").unwrap();
    let id2 = repo.commit("second", id, None).unwrap();

    let log = repo.log(10).unwrap();
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].0, id2);
    assert_eq!(log[1].0, id1);
    assert_eq!(log[0].1.parents, vec![id1]);
}

// ── Status ───────────────────────────────────────────────────────

#[test]
fn status_empty_repo() {
    let (_dir, repo, _id) = fresh_repo();
    let status = repo.status().unwrap();
    assert!(status.is_clean());
}

#[test]
fn status_detects_new_files() {
    let (dir, repo, _id) = fresh_repo();
    fs::write(dir.path().join("new.txt"), "hello").unwrap();
    let status = repo.status().unwrap();
    assert!(status.added.contains(&"new.txt".to_string()));
}

#[test]
fn status_detects_modified() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "v1").unwrap();
    repo.commit("initial", id, None).unwrap();

    fs::write(dir.path().join("a.txt"), "v2").unwrap();
    let status = repo.status().unwrap();
    assert!(status.modified.contains(&"a.txt".to_string()));
}

#[test]
fn status_detects_deleted() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    repo.commit("initial", id, None).unwrap();

    fs::remove_file(dir.path().join("a.txt")).unwrap();
    let status = repo.status().unwrap();
    assert!(status.deleted.contains(&"a.txt".to_string()));
}

#[test]
fn status_clean_after_commit() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    repo.commit("initial", id, None).unwrap();
    assert!(repo.status().unwrap().is_clean());
}

// ── Branches ─────────────────────────────────────────────────────

#[test]
fn create_and_list_branches() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    repo.commit("initial", id, None).unwrap();

    let head = repo.resolve_head().unwrap().unwrap();
    repo.set_ref("refs/heads/feature", &Ref::Direct(head)).unwrap();

    let refs = repo.list_refs("refs/heads/").unwrap();
    let names: Vec<&str> = refs.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains(&"refs/heads/main"));
    assert!(names.contains(&"refs/heads/feature"));
}

#[test]
fn checkout_branch() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    let cs_id = repo.commit("on main", id, None).unwrap();

    repo.set_ref("refs/heads/feature", &Ref::Direct(cs_id)).unwrap();
    repo.set_ref("HEAD", &Ref::Symbolic("refs/heads/feature".into())).unwrap();

    assert_eq!(repo.head_branch().unwrap(), Some("feature".to_string()));
}

// ── Object Store ─────────────────────────────────────────────────

#[test]
fn put_get_object_roundtrip() {
    let (_dir, repo, _id) = fresh_repo();
    let blob = Object::Blob(Blob { data: b"hello world".to_vec() });
    let obj_id = repo.put_object(&blob).unwrap();

    let retrieved = repo.get_object(&obj_id).unwrap().unwrap();
    match retrieved {
        Object::Blob(b) => assert_eq!(b.data, b"hello world"),
        _ => panic!("expected blob"),
    }
}

#[test]
fn find_by_prefix() {
    let (_dir, repo, _id) = fresh_repo();
    let blob = Object::Blob(Blob { data: b"test data".to_vec() });
    let obj_id = repo.put_object(&blob).unwrap();

    let hex = format!("{}", obj_id);
    let prefix = &hex[..8];
    let (found_id, _found_obj) = repo.find_by_prefix(prefix).unwrap();
    assert_eq!(found_id, obj_id);
}

#[test]
fn has_object() {
    let (_dir, repo, _id) = fresh_repo();
    let blob = Object::Blob(Blob { data: b"exists".to_vec() });
    let obj_id = repo.put_object(&blob).unwrap();

    assert!(repo.has_object(&obj_id).unwrap());
    assert!(!repo.has_object(&ObjectId::ZERO).unwrap());
}

// ── Identity & Capabilities ──────────────────────────────────────

#[test]
fn create_agent_identity() {
    let (_dir, repo, _id) = fresh_repo();
    let agent = repo.create_identity("test-agent", IdentityKind::Agent {
        runtime: "claude-code".to_string(),
    }).unwrap();
    assert!(matches!(agent.kind, IdentityKind::Agent { .. }));

    let found = repo.get_identity(&agent.id).unwrap().unwrap();
    assert_eq!(found.name, "test-agent");
}

#[test]
fn list_identities() {
    let (_dir, repo, _id) = fresh_repo();
    repo.create_identity("agent1", IdentityKind::Human).unwrap();
    repo.create_identity("agent2", IdentityKind::Human).unwrap();

    let identities = repo.list_identities().unwrap();
    assert_eq!(identities.len(), 3); // initial + 2 new
}

#[test]
fn grant_and_check_capabilities() {
    let (_dir, repo, _id) = fresh_repo();
    let agent = repo.create_identity("agent", IdentityKind::Agent {
        runtime: "test".to_string(),
    }).unwrap();

    repo.grant_capabilities(&agent.id, &[Capability {
        scope: CapabilityScope::Global,
        permissions: Permissions(Permissions::READ | Permissions::WRITE),
        expires_at: None,
    }]).unwrap();

    let caps = repo.get_capabilities(&agent.id).unwrap();
    assert!(!caps.is_empty());
    assert!(caps[0].permissions.can_read());
    assert!(caps[0].permissions.can_write());
}

// ── Merge ────────────────────────────────────────────────────────

#[test]
fn fast_forward_merge() {
    let (dir, repo, id) = fresh_repo();

    fs::write(dir.path().join("a.txt"), "data").unwrap();
    let base = repo.commit("base", id, None).unwrap();

    // Feature branch.
    repo.set_ref("refs/heads/feature", &Ref::Direct(base)).unwrap();
    repo.set_ref("HEAD", &Ref::Symbolic("refs/heads/feature".into())).unwrap();
    fs::write(dir.path().join("b.txt"), "feature work").unwrap();
    let feature_tip = repo.commit("feature commit", id, None).unwrap();

    // Switch back to main, merge.
    repo.set_ref("HEAD", &Ref::Symbolic("refs/heads/main".into())).unwrap();
    let base_tree = tree_of(&repo.get_object(&base).unwrap().unwrap());
    repo.force_checkout_tree(&base_tree).unwrap();

    let result = repo.merge("feature", id).unwrap();
    assert!(matches!(result, MergeResult::FastForward(tip) if tip == feature_tip));
}

#[test]
fn already_up_to_date() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    let base = repo.commit("base", id, None).unwrap();

    // Feature is behind main (main has an extra commit).
    repo.set_ref("refs/heads/feature", &Ref::Direct(base)).unwrap();
    fs::write(dir.path().join("b.txt"), "main work").unwrap();
    repo.commit("main ahead", id, None).unwrap();

    let result = repo.merge("feature", id).unwrap();
    assert!(matches!(result, MergeResult::AlreadyUpToDate));
}

#[test]
fn three_way_merge() {
    let (dir, repo, id) = fresh_repo();

    fs::write(dir.path().join("shared.txt"), "base").unwrap();
    let base = repo.commit("base", id, None).unwrap();

    // Feature branch (different file).
    repo.set_ref("refs/heads/feature", &Ref::Direct(base)).unwrap();
    repo.set_ref("HEAD", &Ref::Symbolic("refs/heads/feature".into())).unwrap();
    fs::write(dir.path().join("feature.txt"), "feature work").unwrap();
    repo.commit("feature commit", id, None).unwrap();

    // Back to main (different file).
    repo.set_ref("HEAD", &Ref::Symbolic("refs/heads/main".into())).unwrap();
    let base_tree = tree_of(&repo.get_object(&base).unwrap().unwrap());
    repo.force_checkout_tree(&base_tree).unwrap();
    fs::write(dir.path().join("main.txt"), "main work").unwrap();
    repo.commit("main commit", id, None).unwrap();

    let result = repo.merge("feature", id).unwrap();
    assert!(matches!(result, MergeResult::Merged(_)));
}

#[test]
fn merge_conflict() {
    let (dir, repo, id) = fresh_repo();

    fs::write(dir.path().join("conflict.txt"), "base").unwrap();
    let base = repo.commit("base", id, None).unwrap();

    // Feature modifies same file.
    repo.set_ref("refs/heads/feature", &Ref::Direct(base)).unwrap();
    repo.set_ref("HEAD", &Ref::Symbolic("refs/heads/feature".into())).unwrap();
    fs::write(dir.path().join("conflict.txt"), "feature version").unwrap();
    repo.commit("feature edit", id, None).unwrap();

    // Main also modifies same file.
    repo.set_ref("HEAD", &Ref::Symbolic("refs/heads/main".into())).unwrap();
    let base_tree = tree_of(&repo.get_object(&base).unwrap().unwrap());
    repo.force_checkout_tree(&base_tree).unwrap();
    fs::write(dir.path().join("conflict.txt"), "main version").unwrap();
    repo.commit("main edit", id, None).unwrap();

    let result = repo.merge("feature", id).unwrap();
    assert!(matches!(
        result,
        MergeResult::Conflict(ref paths)
            if paths.contains(&"conflict.txt".to_string())
    ));
}

// ── Stash ────────────────────────────────────────────────────────

#[test]
fn stash_save_and_pop() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "committed").unwrap();
    repo.commit("initial", id, None).unwrap();

    fs::write(dir.path().join("a.txt"), "modified").unwrap();
    assert!(!repo.status().unwrap().is_clean());

    let idx = repo.stash_save("wip changes").unwrap();
    assert_eq!(idx, 0);
    assert!(repo.status().unwrap().is_clean());

    fs::write(dir.path().join("a.txt"), "different").unwrap();
    repo.stash_pop().unwrap();
    let content = fs::read_to_string(dir.path().join("a.txt")).unwrap();
    assert_eq!(content, "modified");
}

#[test]
fn stash_list() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    repo.commit("initial", id, None).unwrap();

    fs::write(dir.path().join("a.txt"), "wip1").unwrap();
    repo.stash_save("first stash").unwrap();

    fs::write(dir.path().join("a.txt"), "wip2").unwrap();
    repo.stash_save("second stash").unwrap();

    let list = repo.stash_list().unwrap();
    assert_eq!(list.len(), 2);
}

#[test]
fn stash_pop_empty_fails() {
    let (_dir, repo, _id) = fresh_repo();
    assert!(repo.stash_pop().is_err());
}

// ── Reset ────────────────────────────────────────────────────────

#[test]
fn soft_reset() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "v1").unwrap();
    let id1 = repo.commit("first", id, None).unwrap();

    fs::write(dir.path().join("a.txt"), "v2").unwrap();
    repo.commit("second", id, None).unwrap();

    repo.reset(&id1, false).unwrap();
    assert_eq!(repo.resolve_head().unwrap().unwrap(), id1);

    let content = fs::read_to_string(dir.path().join("a.txt")).unwrap();
    assert_eq!(content, "v2"); // soft — tree unchanged
}

#[test]
fn hard_reset() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "v1").unwrap();
    let id1 = repo.commit("first", id, None).unwrap();

    fs::write(dir.path().join("a.txt"), "v2").unwrap();
    fs::write(dir.path().join("b.txt"), "extra").unwrap();
    repo.commit("second", id, None).unwrap();

    repo.reset(&id1, true).unwrap();
    assert_eq!(repo.resolve_head().unwrap().unwrap(), id1);
    assert_eq!(fs::read_to_string(dir.path().join("a.txt")).unwrap(), "v1");
    assert!(!dir.path().join("b.txt").exists());
}

// ── Remote Config ────────────────────────────────────────────────

#[test]
fn add_and_list_remotes() {
    let (_dir, repo, _id) = fresh_repo();
    repo.add_remote("origin", "https://localhost:50051").unwrap();
    repo.add_remote("backup", "https://backup:50051").unwrap();

    let remotes = repo.list_remotes().unwrap();
    assert_eq!(remotes.len(), 2);
    assert!(remotes.iter().any(|(n, u)| n == "origin" && u == "https://localhost:50051"));
}

#[test]
fn remove_remote() {
    let (_dir, repo, _id) = fresh_repo();
    repo.add_remote("origin", "https://localhost:50051").unwrap();
    repo.remove_remote("origin").unwrap();
    assert!(repo.list_remotes().unwrap().is_empty());
}

#[test]
fn remove_nonexistent_remote_fails() {
    let (_dir, repo, _id) = fresh_repo();
    assert!(repo.remove_remote("nope").is_err());
}

// ── Tags ─────────────────────────────────────────────────────────

#[test]
fn create_and_list_tags() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    let cs_id = repo.commit("release", id, None).unwrap();

    repo.set_ref("refs/tags/v0.1.0", &Ref::Direct(cs_id)).unwrap();
    let refs = repo.list_refs("refs/tags/").unwrap();
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].0, "refs/tags/v0.1.0");
}

#[test]
fn delete_tag() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    let cs_id = repo.commit("release", id, None).unwrap();

    repo.set_ref("refs/tags/v0.1.0", &Ref::Direct(cs_id)).unwrap();
    assert!(repo.delete_ref("refs/tags/v0.1.0").unwrap());
    assert!(repo.list_refs("refs/tags/").unwrap().is_empty());
}

// ── CAS Ref ──────────────────────────────────────────────────────

#[test]
fn cas_ref_succeeds_on_match() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    repo.commit("initial", id, None).unwrap();

    let current = repo.resolve_ref("refs/heads/main").unwrap().map(Ref::Direct);
    let new_ref = current.clone().unwrap();
    assert!(repo.cas_ref("refs/heads/main", current.as_ref(), &new_ref).unwrap());
}

#[test]
fn cas_ref_fails_on_mismatch() {
    let (dir, repo, id) = fresh_repo();
    fs::write(dir.path().join("a.txt"), "data").unwrap();
    let cs_id = repo.commit("initial", id, None).unwrap();

    let wrong = Ref::Direct(ObjectId::ZERO);
    let new_ref = Ref::Direct(cs_id);
    assert!(!repo.cas_ref("refs/heads/main", Some(&wrong), &new_ref).unwrap());
}

// ── Forgeignore ──────────────────────────────────────────────────

#[test]
fn forgeignore_excludes_files() {
    let (dir, repo, _id) = fresh_repo();
    fs::write(dir.path().join(".forgeignore"), "*.log\nbuild/\n").unwrap();
    fs::write(dir.path().join("app.log"), "logs").unwrap();
    fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

    let status = repo.status().unwrap();
    assert!(status.added.contains(&"main.rs".to_string()));
    assert!(status.added.contains(&".forgeignore".to_string()));
    assert!(!status.added.iter().any(|f| f.ends_with(".log")));
}

#[test]
fn forgeignore_glob_patterns() {
    let (dir, repo, _id) = fresh_repo();
    fs::write(dir.path().join(".forgeignore"), "*.o\n*.tmp\n").unwrap();
    fs::write(dir.path().join("main.o"), "").unwrap();
    fs::write(dir.path().join("data.tmp"), "").unwrap();
    fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

    let status = repo.status().unwrap();
    assert!(status.added.contains(&"main.rs".to_string()));
    assert!(!status.added.contains(&"main.o".to_string()));
    assert!(!status.added.contains(&"data.tmp".to_string()));
}

// ── Nested Directories ──────────────────────────────────────────

#[test]
fn nested_directory_commit() {
    let (dir, repo, id) = fresh_repo();
    fs::create_dir_all(dir.path().join("src/utils")).unwrap();
    fs::write(dir.path().join("src/main.rs"), "fn main() {}").unwrap();
    fs::write(dir.path().join("src/utils/helpers.rs"), "pub fn help() {}").unwrap();

    let cs_id = repo.commit("nested", id, None).unwrap();
    let obj = repo.get_object(&cs_id).unwrap().unwrap();
    let tree_id = tree_of(&obj);

    let tree = repo.get_object(&tree_id).unwrap().unwrap();
    match tree {
        Object::Tree(t) => assert!(t.entries.contains_key("src")),
        _ => panic!("expected tree"),
    }
}

// ── Key Generation & Signing ─────────────────────────────────────

#[test]
fn generate_and_load_keypair() {
    let (_dir, repo, id) = fresh_repo();
    let kp = repo.generate_keypair(&id).unwrap();
    let loaded = repo.load_keypair(&id).unwrap();
    assert_eq!(kp.public_bytes(), loaded.public_bytes());
}

#[test]
fn public_key_stored_as_ref() {
    let (_dir, repo, id) = fresh_repo();
    repo.generate_keypair(&id).unwrap();
    assert!(repo.get_public_key(&id).unwrap().is_some());
}

// ── Token Revocation ─────────────────────────────────────────────

#[test]
fn revoke_and_check_token() {
    let (_dir, repo, _id) = fresh_repo();
    repo.revoke_token("some-test-token").unwrap();
    assert!(repo.is_token_revoked("some-test-token").unwrap());
    assert!(!repo.is_token_revoked("other-token").unwrap());
}

// ── Event Log ────────────────────────────────────────────────────

#[test]
fn event_log_append_and_read() {
    let (_dir, repo, _id) = fresh_repo();
    let seq1 = repo.log_event(b"event-1").unwrap();
    let seq2 = repo.log_event(b"event-2").unwrap();
    assert!(seq2 > seq1);

    let events = repo.read_events(0, 10).unwrap();
    assert_eq!(events.len(), 2);
}

// ── Config ───────────────────────────────────────────────────────

#[test]
fn config_get_set() {
    let (_dir, repo, _id) = fresh_repo();
    repo.set_config("test.key", "test-value").unwrap();
    assert_eq!(repo.get_config("test.key").unwrap(), Some("test-value".to_string()));
}

#[test]
fn config_missing_returns_none() {
    let (_dir, repo, _id) = fresh_repo();
    assert_eq!(repo.get_config("nonexistent").unwrap(), None);
}

// ── Exploration Tree ────────────────────────────────────────────

fn make_goal(author: IdentityId) -> Goal {
    Goal {
        description: "Add rate limiting to the API".to_string(),
        target_branch: "main".to_string(),
        constraints: vec![
            Constraint {
                kind: ConstraintKind::TestsPass,
                description: "all tests must pass".to_string(),
                check_command: None,
            },
        ],
        created_by: author,
        created_at: 1_000_000,
        max_approaches: 0,
        time_budget_secs: 0,
    }
}

/// Helper: create a repo with an initial commit so explore can branch from it.
fn repo_with_commit() -> (TempDir, Repository, IdentityId) {
    let (dir, repo, id) = fresh_repo();
    // Create a file and commit so main has a tip.
    std::fs::write(dir.path().join("README.md"), b"hello").unwrap();
    repo.commit("initial commit", id, None).unwrap();
    (dir, repo, id)
}

#[test]
fn create_goal_and_list() {
    let (_dir, repo, id) = repo_with_commit();
    let goal = make_goal(id);
    let goal_id = repo.create_goal(&goal).unwrap();

    let goals = repo.list_goals().unwrap();
    assert_eq!(goals.len(), 1);
    assert_eq!(goals[0].0, goal_id);
    assert_eq!(goals[0].1.description, "Add rate limiting to the API");
}

#[test]
fn create_goal_duplicate_fails() {
    let (_dir, repo, id) = repo_with_commit();
    let goal = make_goal(id);
    repo.create_goal(&goal).unwrap();
    // Same goal → same blob → same ref → CAS fails.
    assert!(repo.create_goal(&goal).is_err());
}

#[test]
fn create_approach_and_summary() {
    let (_dir, repo, id) = repo_with_commit();
    let goal = make_goal(id);
    let goal_id = repo.create_goal(&goal).unwrap();

    repo.create_approach(&goal_id, "token-bucket", id).unwrap();
    repo.create_approach(&goal_id, "leaky-bucket", id).unwrap();

    let summary = repo.goal_summary(&goal_id).unwrap();
    assert_eq!(summary.approaches.len(), 2);

    let names: Vec<&str> = summary.approaches.iter()
        .map(|a| a.name.as_str())
        .collect();
    assert!(names.contains(&"token-bucket"));
    assert!(names.contains(&"leaky-bucket"));
}

#[test]
fn approach_duplicate_name_fails() {
    let (_dir, repo, id) = repo_with_commit();
    let goal = make_goal(id);
    let goal_id = repo.create_goal(&goal).unwrap();

    repo.create_approach(&goal_id, "same-name", id).unwrap();
    assert!(repo.create_approach(&goal_id, "same-name", id).is_err());
}

#[test]
fn approach_for_nonexistent_goal_fails() {
    let (_dir, repo, id) = repo_with_commit();
    let fake_id = ObjectId::from_bytes([0xAB; 32]);
    assert!(repo.create_approach(&fake_id, "anything", id).is_err());
}

#[test]
fn claim_and_release() {
    let (_dir, repo, id) = repo_with_commit();
    let goal = make_goal(id);
    let goal_id = repo.create_goal(&goal).unwrap();
    repo.create_approach(&goal_id, "approach-a", id).unwrap();

    // Claim is created automatically by create_approach.
    let summary = repo.goal_summary(&goal_id).unwrap();
    assert_eq!(summary.claims.len(), 1);
    assert_eq!(summary.claims[0].approach, "approach-a");

    // Release it.
    repo.release_claim(&goal_id, id).unwrap();
    let summary = repo.goal_summary(&goal_id).unwrap();
    assert_eq!(summary.claims.len(), 0);
}

#[test]
fn refresh_claim_increments_heartbeat() {
    let (_dir, repo, id) = repo_with_commit();
    let goal = make_goal(id);
    let goal_id = repo.create_goal(&goal).unwrap();
    repo.create_approach(&goal_id, "approach-a", id).unwrap();

    // Initial heartbeat is 0.
    let s1 = repo.goal_summary(&goal_id).unwrap();
    assert_eq!(s1.claims[0].heartbeat, 0);

    // Refresh.
    repo.refresh_claim(&goal_id, id).unwrap();
    let s2 = repo.goal_summary(&goal_id).unwrap();
    assert_eq!(s2.claims[0].heartbeat, 1);
}

#[test]
fn promote_approach_fast_forward() {
    let (dir, repo, id) = repo_with_commit();
    let goal = make_goal(id);
    let goal_id = repo.create_goal(&goal).unwrap();
    repo.create_approach(&goal_id, "winner", id).unwrap();

    // Simulate agent work: add a file and create a changeset on the approach.
    let approach_ref = gritgrub_core::exploration::refs::approach_tip(&goal_id, "winner");
    let _approach_tip = repo.resolve_ref(&approach_ref).unwrap().unwrap();

    // Create a new file, snapshot via commit (which updates HEAD/main),
    // then manually move the approach ref to the new commit.
    std::fs::write(dir.path().join("rate_limit.rs"), b"pub fn limit() {}").unwrap();
    let cs_id = repo.commit("add rate limiting", id, None).unwrap();
    // Move the approach ref to the new commit (main also moved, which is fine
    // for this test — promote will be a no-op fast-forward).
    repo.set_ref(&approach_ref, &Ref::Direct(cs_id)).unwrap();

    // Promote — should fast-forward since main hasn't moved.
    let result = repo.promote_approach(&goal_id, "winner", id).unwrap();
    assert!(matches!(result, PromoteResult::FastForward(_)));

    // main should now point to our commit.
    let main_tip = repo.resolve_ref("refs/heads/main").unwrap().unwrap();
    assert_eq!(main_tip, cs_id);
}

#[test]
fn abandon_goal_cleans_refs() {
    let (_dir, repo, id) = repo_with_commit();
    let goal = make_goal(id);
    let goal_id = repo.create_goal(&goal).unwrap();
    repo.create_approach(&goal_id, "approach-a", id).unwrap();
    repo.create_approach(&goal_id, "approach-b", id).unwrap();

    let count = repo.abandon_goal(&goal_id).unwrap();
    assert!(count >= 4); // meta + target + 2 approaches + claims

    let goals = repo.list_goals().unwrap();
    assert_eq!(goals.len(), 0);
}

#[test]
fn max_approaches_enforced() {
    let (_dir, repo, id) = repo_with_commit();
    let mut goal = make_goal(id);
    goal.max_approaches = 2;
    let goal_id = repo.create_goal(&goal).unwrap();

    repo.create_approach(&goal_id, "a", id).unwrap();
    repo.create_approach(&goal_id, "b", id).unwrap();
    // Third should fail.
    assert!(repo.create_approach(&goal_id, "c", id).is_err());
}

// ── Garbage Collection ──────────────────────────────────────────

#[test]
fn gc_no_orphans_when_clean() {
    let (_dir, repo, _id) = repo_with_commit();
    let (total, deleted) = repo.gc().unwrap();
    assert!(total > 0);
    assert_eq!(deleted, 0, "clean repo should have no orphans");
}

#[test]
fn gc_deletes_orphaned_objects() {
    let (_dir, repo, _id) = repo_with_commit();
    // Create an orphan blob (not referenced by any ref).
    let orphan = Object::Blob(Blob { data: b"orphan data".to_vec() });
    let orphan_id = repo.put_object(&orphan).unwrap();

    let (_total, deleted) = repo.gc().unwrap();
    assert_eq!(deleted, 1, "should delete the orphan blob");
    assert!(repo.get_object(&orphan_id).unwrap().is_none(), "orphan should be gone");
}

// ── Tree-to-tree Diff ──────────────────────────────────────────

#[test]
fn diff_changeset_shows_added_files() {
    let (dir, repo, id) = repo_with_commit();
    // Add a new file and commit.
    fs::write(dir.path().join("new_file.txt"), "hello").unwrap();
    let cs_id = repo.commit("add new file", id, None).unwrap();

    let diff = repo.diff_changeset(&cs_id).unwrap();
    assert!(diff.added.contains(&"new_file.txt".to_string()));
    assert!(diff.modified.is_empty() || diff.modified.iter().all(|p| p != "new_file.txt"));
}

#[test]
fn diff_changeset_shows_modified_files() {
    let (dir, repo, id) = repo_with_commit();
    // Modify the existing file.
    fs::write(dir.path().join("README.md"), "updated content").unwrap();
    let cs_id = repo.commit("update readme", id, None).unwrap();

    let diff = repo.diff_changeset(&cs_id).unwrap();
    assert!(diff.modified.contains(&"README.md".to_string()));
}

#[test]
fn diff_changeset_shows_deleted_files() {
    let (dir, repo, id) = repo_with_commit();
    // Delete the file and commit.
    fs::remove_file(dir.path().join("README.md")).unwrap();
    let cs_id = repo.commit("delete readme", id, None).unwrap();

    let diff = repo.diff_changeset(&cs_id).unwrap();
    assert!(diff.deleted.contains(&"README.md".to_string()));
}

// ── RBAC: Capability Scopes ─────────────────────────────────────

#[test]
fn capability_global_covers_everything() {
    let (_dir, repo, id) = fresh_repo();
    // Default identity has global admin.
    assert!(repo.check_permission(
        &id,
        &CapabilityScope::Global,
        Permissions::ADMIN,
    ).unwrap());
    assert!(repo.check_permission(
        &id,
        &CapabilityScope::Repository("any-repo".into()),
        Permissions::WRITE,
    ).unwrap());
    assert!(repo.check_permission(
        &id,
        &CapabilityScope::Branch { repo: "any".into(), pattern: "main".into() },
        Permissions::DELETE,
    ).unwrap());
}

#[test]
fn capability_read_only_cannot_write() {
    let (_dir, repo, _admin) = fresh_repo();
    // Create a read-only identity.
    let reader = repo.create_identity("reader", IdentityKind::Agent { runtime: "test".into() }).unwrap();
    repo.set_capabilities(&reader.id, &[Capability {
        scope: CapabilityScope::Global,
        permissions: Permissions::read_only(),
        expires_at: None,
    }]).unwrap();

    assert!(repo.check_permission(&reader.id, &CapabilityScope::Global, Permissions::READ).unwrap());
    assert!(!repo.check_permission(&reader.id, &CapabilityScope::Global, Permissions::WRITE).unwrap());
    assert!(!repo.check_permission(&reader.id, &CapabilityScope::Global, Permissions::DELETE).unwrap());
    assert!(!repo.check_permission(&reader.id, &CapabilityScope::Global, Permissions::ADMIN).unwrap());
}

#[test]
fn capability_repo_scope_does_not_cover_other_repos() {
    let (_dir, repo, _admin) = fresh_repo();
    let agent = repo.create_identity("agent", IdentityKind::Agent { runtime: "test".into() }).unwrap();
    repo.set_capabilities(&agent.id, &[Capability {
        scope: CapabilityScope::Repository("repo-a".into()),
        permissions: Permissions::all(),
        expires_at: None,
    }]).unwrap();

    // Can access repo-a.
    assert!(repo.check_permission(
        &agent.id,
        &CapabilityScope::Repository("repo-a".into()),
        Permissions::WRITE,
    ).unwrap());
    // Cannot access repo-b.
    assert!(!repo.check_permission(
        &agent.id,
        &CapabilityScope::Repository("repo-b".into()),
        Permissions::WRITE,
    ).unwrap());
    // Cannot access global.
    assert!(!repo.check_permission(
        &agent.id,
        &CapabilityScope::Global,
        Permissions::READ,
    ).unwrap());
}

#[test]
fn capability_branch_scope_glob_matching() {
    let (_dir, repo, _admin) = fresh_repo();
    let agent = repo.create_identity("agent", IdentityKind::Agent { runtime: "test".into() }).unwrap();
    repo.set_capabilities(&agent.id, &[Capability {
        scope: CapabilityScope::Branch {
            repo: "myrepo".into(),
            pattern: "feature/*".into(),
        },
        permissions: Permissions::read_write(),
        expires_at: None,
    }]).unwrap();

    // Matches feature/foo.
    assert!(repo.check_permission(
        &agent.id,
        &CapabilityScope::Branch { repo: "myrepo".into(), pattern: "feature/foo".into() },
        Permissions::WRITE,
    ).unwrap());
    // Does NOT match main.
    assert!(!repo.check_permission(
        &agent.id,
        &CapabilityScope::Branch { repo: "myrepo".into(), pattern: "main".into() },
        Permissions::WRITE,
    ).unwrap());
    // Does NOT match other repo.
    assert!(!repo.check_permission(
        &agent.id,
        &CapabilityScope::Branch { repo: "other-repo".into(), pattern: "feature/foo".into() },
        Permissions::WRITE,
    ).unwrap());
}

#[test]
fn capability_expired_is_rejected() {
    let (_dir, repo, _admin) = fresh_repo();
    let agent = repo.create_identity("agent", IdentityKind::Agent { runtime: "test".into() }).unwrap();
    // Expired 1 hour ago.
    let past = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap()
        .as_micros() as i64 - 3_600_000_000;
    repo.set_capabilities(&agent.id, &[Capability {
        scope: CapabilityScope::Global,
        permissions: Permissions::all(),
        expires_at: Some(past),
    }]).unwrap();

    assert!(!repo.check_permission(
        &agent.id,
        &CapabilityScope::Global,
        Permissions::READ,
    ).unwrap());
}

#[test]
fn capability_non_expired_is_accepted() {
    let (_dir, repo, _admin) = fresh_repo();
    let agent = repo.create_identity("agent", IdentityKind::Agent { runtime: "test".into() }).unwrap();
    // Expires 1 hour from now.
    let future = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap()
        .as_micros() as i64 + 3_600_000_000;
    repo.set_capabilities(&agent.id, &[Capability {
        scope: CapabilityScope::Global,
        permissions: Permissions::all(),
        expires_at: Some(future),
    }]).unwrap();

    assert!(repo.check_permission(
        &agent.id,
        &CapabilityScope::Global,
        Permissions::READ,
    ).unwrap());
}

#[test]
fn capability_no_caps_means_no_access() {
    let (_dir, repo, _admin) = fresh_repo();
    let agent = repo.create_identity("agent", IdentityKind::Agent { runtime: "test".into() }).unwrap();
    // Don't grant any capabilities.
    assert!(!repo.check_permission(
        &agent.id,
        &CapabilityScope::Global,
        Permissions::READ,
    ).unwrap());
}

#[test]
fn capability_grant_appends_not_replaces() {
    let (_dir, repo, _admin) = fresh_repo();
    let agent = repo.create_identity("agent", IdentityKind::Agent { runtime: "test".into() }).unwrap();

    // Grant read first.
    repo.grant_capabilities(&agent.id, &[Capability {
        scope: CapabilityScope::Global,
        permissions: Permissions::read_only(),
        expires_at: None,
    }]).unwrap();

    // Then grant write.
    repo.grant_capabilities(&agent.id, &[Capability {
        scope: CapabilityScope::Repository("myrepo".into()),
        permissions: Permissions(Permissions::WRITE),
        expires_at: None,
    }]).unwrap();

    // Should have both.
    let caps = repo.get_capabilities(&agent.id).unwrap();
    assert_eq!(caps.len(), 2);
    assert!(repo.check_permission(&agent.id, &CapabilityScope::Global, Permissions::READ).unwrap());
    assert!(repo.check_permission(
        &agent.id,
        &CapabilityScope::Repository("myrepo".into()),
        Permissions::WRITE,
    ).unwrap());
}

// ── RBAC: Ref Policies ─────────────────────────────────────────

#[test]
fn ref_policy_forbids_force_push() {
    let (_dir, repo, id) = repo_with_commit();
    repo.set_ref_policies(&[RefPolicy {
        pattern: "refs/heads/main".into(),
        require_review: false,
        require_slsa: None,
        allowed_writers: vec![],
        forbid_force_push: true,
    }]).unwrap();

    // Non-force push should be allowed.
    let cs_id = repo.resolve_head().unwrap().unwrap();
    let denial = repo.check_ref_policy("refs/heads/main", &id, Some(&cs_id), false).unwrap();
    assert!(denial.is_none(), "non-force push should be allowed");

    // Force push should be denied.
    let denial = repo.check_ref_policy("refs/heads/main", &id, Some(&cs_id), true).unwrap();
    assert!(denial.is_some(), "force push should be denied");
}

#[test]
fn ref_policy_allowed_writers_enforced() {
    let (_dir, repo, id) = repo_with_commit();
    let other = repo.create_identity("outsider", IdentityKind::Human).unwrap();

    repo.set_ref_policies(&[RefPolicy {
        pattern: "refs/heads/main".into(),
        require_review: false,
        require_slsa: None,
        allowed_writers: vec![id], // Only `id` can write.
        forbid_force_push: false,
    }]).unwrap();

    let cs_id = repo.resolve_head().unwrap().unwrap();

    // Allowed writer can push.
    let denial = repo.check_ref_policy("refs/heads/main", &id, Some(&cs_id), false).unwrap();
    assert!(denial.is_none());

    // Other writer is blocked.
    let denial = repo.check_ref_policy("refs/heads/main", &other.id, Some(&cs_id), false).unwrap();
    assert!(denial.is_some());
}

#[test]
fn ref_policy_pattern_matching() {
    let (_dir, repo, id) = repo_with_commit();
    repo.set_ref_policies(&[RefPolicy {
        pattern: "refs/heads/release/*".into(),
        require_review: false,
        require_slsa: None,
        allowed_writers: vec![],
        forbid_force_push: true,
    }]).unwrap();

    let cs_id = repo.resolve_head().unwrap().unwrap();

    // Policy applies to release branches.
    let denial = repo.check_ref_policy("refs/heads/release/v1", &id, Some(&cs_id), true).unwrap();
    assert!(denial.is_some(), "force push to release branch should be denied");

    // Policy does NOT apply to main.
    let denial = repo.check_ref_policy("refs/heads/main", &id, Some(&cs_id), true).unwrap();
    assert!(denial.is_none(), "policy should not apply to main");
}

// ── RBAC: Concurrent Capability Stress ──────────────────────────

#[test]
fn stress_concurrent_capability_grants() {
    // 12 threads granting different capabilities to the same identity.
    // Atomic grant must not lose any grants.
    use std::sync::Arc;

    let dir = TempDir::new().unwrap();
    let repo = Arc::new(Repository::init(dir.path()).unwrap());
    let agent = repo.create_identity("agent", IdentityKind::Agent { runtime: "test".into() }).unwrap();

    let mut handles = Vec::new();
    for i in 0..12 {
        let repo = Arc::clone(&repo);
        let agent_id = agent.id;
        handles.push(std::thread::spawn(move || {
            repo.grant_capabilities(&agent_id, &[Capability {
                scope: CapabilityScope::Branch {
                    repo: "repo".into(),
                    pattern: format!("feature/agent-{}", i),
                },
                permissions: Permissions::read_write(),
                expires_at: None,
            }]).unwrap();
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // All 12 grants should be present.
    let caps = repo.get_capabilities(&agent.id).unwrap();
    assert_eq!(caps.len(), 12, "expected 12 capabilities, got {}", caps.len());
}

// ── Concurrency Stress Tests ────────────────────────────────────
//
// These simulate multiple agents hitting the repo simultaneously.
// redb serializes writes but our CAS logic must handle contention correctly.

#[test]
fn stress_concurrent_stash_save() {
    // 12 threads all stash_save at the same time.
    // CAS loop should ensure no two stashes get the same index.
    use std::sync::Arc;

    let dir = TempDir::new().unwrap();
    let repo = Arc::new(Repository::init(dir.path()).unwrap());
    let id = repo.local_identity().unwrap();

    // Need a file to stash.
    fs::write(dir.path().join("work.txt"), "content").unwrap();
    repo.commit("initial", id, None).unwrap();

    // Create 12 threads that each modify the file and stash.
    let mut handles = Vec::new();
    for i in 0..12 {
        let repo = Arc::clone(&repo);
        let path = dir.path().to_path_buf();
        handles.push(std::thread::spawn(move || {
            fs::write(path.join("work.txt"), format!("agent-{}", i)).unwrap();
            repo.stash_save(&format!("agent {} stash", i))
        }));
    }

    let mut successes = 0;
    let mut indices = std::collections::HashSet::new();
    for handle in handles {
        match handle.join().unwrap() {
            Ok(idx) => {
                assert!(indices.insert(idx), "duplicate stash index {}!", idx);
                successes += 1;
            }
            Err(_) => {
                // Some threads may fail with "nothing to stash" if another
                // thread's stash_save restored the working tree between
                // their status check and snapshot. That's correct behavior.
            }
        }
    }
    // At least some should succeed — the first one always does.
    assert!(successes >= 1, "no stash_save succeeded at all");

    // All successful stashes should have unique indices.
    let stash_list = repo.stash_list().unwrap();
    let list_indices: std::collections::HashSet<usize> = stash_list.iter().map(|(i, _)| *i).collect();
    assert_eq!(list_indices.len(), stash_list.len(), "duplicate indices in stash list");
}

#[test]
fn stress_concurrent_object_puts() {
    // 12 threads all putting objects simultaneously.
    // Content-addressed = no conflicts, but tests that redb handles
    // concurrent write transactions without corruption.
    use std::sync::Arc;

    let dir = TempDir::new().unwrap();
    let repo = Arc::new(Repository::init(dir.path()).unwrap());

    let mut handles = Vec::new();
    for i in 0..12 {
        let repo = Arc::clone(&repo);
        handles.push(std::thread::spawn(move || {
            let mut ids = Vec::new();
            for j in 0..50 {
                let blob = Object::Blob(Blob {
                    data: format!("agent-{}-blob-{}", i, j).into_bytes(),
                });
                let id = repo.put_object(&blob).unwrap();
                ids.push(id);
            }
            ids
        }));
    }

    let mut all_ids = std::collections::HashSet::new();
    for handle in handles {
        let ids = handle.join().unwrap();
        assert_eq!(ids.len(), 50);
        for id in ids {
            all_ids.insert(id);
        }
    }

    // 12 agents * 50 unique blobs = 600 unique objects.
    assert_eq!(all_ids.len(), 600);

    // Verify all objects are readable.
    for id in &all_ids {
        assert!(repo.get_object(id).unwrap().is_some());
    }
}

#[test]
fn stress_concurrent_exploration_approaches() {
    // 12 threads all creating approaches on the same goal.
    // CAS ensures no two approaches get the same name
    // (they have different names by design, but this tests
    // contention on the ref namespace).
    use std::sync::Arc;

    let dir = TempDir::new().unwrap();
    let repo = Arc::new(Repository::init(dir.path()).unwrap());
    let id = repo.local_identity().unwrap();

    fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();
    repo.commit("initial", id, None).unwrap();

    let goal = Goal {
        description: "stress test goal".to_string(),
        target_branch: "main".to_string(),
        constraints: vec![],
        created_by: id,
        created_at: 1_000_000,
        max_approaches: 0,
        time_budget_secs: 0,
    };
    let goal_id = repo.create_goal(&goal).unwrap();

    let mut handles = Vec::new();
    for i in 0..12 {
        let repo = Arc::clone(&repo);
        let gid = goal_id;
        handles.push(std::thread::spawn(move || {
            repo.create_approach(&gid, &format!("approach-{}", i), id)
        }));
    }

    let mut successes = 0;
    for handle in handles {
        if handle.join().unwrap().is_ok() {
            successes += 1;
        }
    }

    // All 12 should succeed — different names, no conflicts.
    assert_eq!(successes, 12, "some approaches failed under contention");

    let summary = repo.goal_summary(&goal_id).unwrap();
    assert_eq!(summary.approaches.len(), 12);
}

#[test]
fn stress_concurrent_event_log() {
    // 12 threads appending events simultaneously.
    // Event sequence numbers must be unique and monotonic.
    use std::sync::Arc;

    let dir = TempDir::new().unwrap();
    let repo = Arc::new(Repository::init(dir.path()).unwrap());

    let mut handles = Vec::new();
    for i in 0..12 {
        let repo = Arc::clone(&repo);
        handles.push(std::thread::spawn(move || {
            let mut seqs = Vec::new();
            for j in 0..20 {
                let event = format!("agent-{}-event-{}", i, j);
                let seq = repo.log_event(event.as_bytes()).unwrap();
                seqs.push(seq);
            }
            seqs
        }));
    }

    let mut all_seqs = std::collections::HashSet::new();
    for handle in handles {
        let seqs = handle.join().unwrap();
        assert_eq!(seqs.len(), 20);
        for seq in seqs {
            assert!(all_seqs.insert(seq), "duplicate event seq {}!", seq);
        }
    }

    // 12 * 20 = 240 events, all with unique sequence numbers.
    assert_eq!(all_seqs.len(), 240);

    // Verify events are readable.
    let events = repo.read_events(0, 300).unwrap();
    assert_eq!(events.len(), 240);
}
