//! Purge and restore (FR-13, FR-14, spec §7, §7.3).
//!
//! The two tests that matter most here are `a_manifest_pointing_outside_
//! quarantine_deletes_nothing` and `restore_refuses_rather_than_overwriting`.
//! Everything else is behaviour; those two are the safety guarantees.

use chrono::{Duration, Local};
use sift::action::manifest::Manifest;
use sift::action::{purge, quarantine, restore};
use sift::risk::Risk;
use sift::scan::{Candidate, Target};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct Env {
    _dir: tempfile::TempDir,
    root: PathBuf,
    work: PathBuf,
    prev_state: Option<std::ffi::OsString>,
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl Env {
    fn new() -> Self {
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let prev_state = std::env::var_os("XDG_STATE_HOME");
        std::env::set_var("XDG_STATE_HOME", dir.path().join("state"));

        let work = dir.path().join("work");
        fs::create_dir_all(&work).unwrap();

        Self {
            root: dir.path().to_path_buf(),
            _dir: dir,
            work,
            prev_state,
            _guard: guard,
        }
    }

    fn candidate(&self, name: &str, bytes: usize) -> Candidate {
        let path = self.work.join(name);
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("payload.bin"), vec![0u8; bytes]).unwrap();
        Candidate {
            scanner: "logs",
            target: Target::Path(path),
            bytes_on_disk: bytes as u64,
            bytes_apparent: bytes as u64,
            last_modified: Local::now(),
            risk: Risk::Safe,
            label: name.into(),
            reason: "test".into(),
        }
    }

    fn quarantine_root(&self) -> PathBuf {
        sift::paths::quarantine_dir().unwrap()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        match &self.prev_state {
            Some(v) => std::env::set_var("XDG_STATE_HOME", v),
            None => std::env::remove_var("XDG_STATE_HOME"),
        }
    }
}

fn path_of(c: &Candidate) -> PathBuf {
    match &c.target {
        Target::Path(p) => p.clone(),
        _ => panic!("expected a path target"),
    }
}

/// Recursive content hash including relative paths, so a round trip can be
/// checked for byte-identity rather than merely "the files are there".
fn tree_hash(root: &Path) -> Vec<(String, u64, Vec<u8>)> {
    let mut out = Vec::new();
    let walker = sift::fs::Walker::new(root).unwrap();
    for entry in walker.walk(root).unwrap().entries {
        let rel = entry
            .path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let content = fs::read(&entry.path).unwrap_or_default();
        out.push((rel, content.len() as u64, content));
    }
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// The containment rail
// ---------------------------------------------------------------------------

#[test]
fn a_manifest_pointing_outside_quarantine_deletes_nothing() {
    // THE test for this PR. A manifest is a file on disk: it can be corrupted,
    // hand-edited, or written by an older buggy version. Purge must not take
    // its word for what may be destroyed.
    let env = Env::new();
    let (outcome, _) = quarantine::quarantine(&[env.candidate("thing", 4096)], 0).unwrap();

    // Something precious, outside quarantine, that a tampered manifest points at.
    let precious = env.root.join("precious");
    fs::create_dir_all(&precious).unwrap();
    fs::write(precious.join("irreplaceable.txt"), b"user data").unwrap();

    // Replace the run directory with a symlink to it — the shape a tampered or
    // corrupted manifest would produce.
    //
    // The manifest is copied INTO the symlink target first. Without that, the
    // run has no readable manifest, `runs()` skips it, and this test would pass
    // without ever reaching the containment rail — a vacuous green.
    let run_dir = outcome.run_dir.clone();
    let manifest_json = fs::read(run_dir.join("manifest.json")).unwrap();
    fs::write(precious.join("manifest.json"), &manifest_json).unwrap();
    fs::remove_dir_all(&run_dir).unwrap();
    std::os::unix::fs::symlink(&precious, &run_dir).unwrap();

    // Confirm the premise: the run is now discoverable through the symlink, so
    // purge really does try to delete it.
    assert_eq!(
        quarantine::runs().unwrap().len(),
        1,
        "the tampered run must be discoverable, or this test proves nothing"
    );

    let result = purge::purge_all();

    assert!(
        precious.join("irreplaceable.txt").exists(),
        "purge followed a symlink out of quarantine and destroyed user data"
    );
    // Either a hard refusal or a clean skip is acceptable; a deletion is not.
    if let Ok(o) = &result {
        assert!(
            !o.runs_purged.iter().any(|id| run_dir.ends_with(id)),
            "the escaping run was reported as purged"
        );
    }
}

#[test]
fn purge_never_removes_the_quarantine_root_itself() {
    let env = Env::new();
    quarantine::quarantine(&[env.candidate("thing", 1024)], 0).unwrap();
    let root = env.quarantine_root();

    purge::purge_all().unwrap();
    assert!(root.exists(), "the quarantine root must survive a purge");
}

// ---------------------------------------------------------------------------
// TTL (FR-13)
// ---------------------------------------------------------------------------

#[test]
fn a_run_inside_its_ttl_is_retained_and_one_past_it_is_purged() {
    let env = Env::new();
    let (outcome, _) = quarantine::quarantine(&[env.candidate("thing", 4096)], 7).unwrap();

    // One day before expiry: retained.
    let before = Local::now() + Duration::days(6);
    let o = purge::purge_expired(before).unwrap();
    assert!(o.runs_purged.is_empty(), "purged inside its TTL");
    assert_eq!(o.runs_retained.len(), 1);
    assert!(outcome.run_dir.exists());

    // One day after: purged.
    let after = Local::now() + Duration::days(8);
    let o = purge::purge_expired(after).unwrap();
    assert_eq!(o.runs_purged.len(), 1);
    assert!(o.bytes_purged >= 4096);
    assert!(
        !outcome.run_dir.exists(),
        "the run directory should be gone"
    );
}

#[test]
fn purge_now_ignores_the_ttl() {
    let env = Env::new();
    let (outcome, _) = quarantine::quarantine(&[env.candidate("thing", 4096)], 365).unwrap();

    assert!(purge::purge_expired(Local::now())
        .unwrap()
        .runs_purged
        .is_empty());

    let o = purge::purge_all().unwrap();
    assert_eq!(o.runs_purged.len(), 1);
    assert!(!outcome.run_dir.exists());
}

#[test]
fn purging_an_empty_quarantine_is_a_no_op_not_an_error() {
    let _env = Env::new();
    let o = purge::purge_all().unwrap();
    assert!(!o.anything_purged());
    assert!(purge::render(&o).contains("nothing to purge"));
}

// ---------------------------------------------------------------------------
// Restore (FR-14, spec §7.3)
// ---------------------------------------------------------------------------

#[test]
fn clean_then_restore_round_trips_byte_identically() {
    // The M2 property in miniature. PR-23 does this as a property test over
    // random trees; this pins the basic case.
    let env = Env::new();
    let c = env.candidate("project", 8192);
    let src = path_of(&c);

    // Add structure so the round trip has something to get wrong.
    fs::create_dir_all(src.join("a/b/c")).unwrap();
    fs::write(src.join("a/one.txt"), b"first").unwrap();
    fs::write(src.join("a/b/two.txt"), b"second").unwrap();
    fs::write(src.join("a/b/c/three.bin"), vec![7u8; 3000]).unwrap();

    let before = tree_hash(&src);
    assert!(before.len() >= 4);

    let (outcome, _) = quarantine::quarantine(&[c], 7).unwrap();
    assert!(!src.exists(), "quarantine did not move the source");

    let restored = restore::restore(&outcome.run_id).unwrap();
    assert_eq!(restored.restored.len(), 1, "{restored:?}");
    assert!(restored.fully_restored());

    assert!(src.exists(), "restore did not put it back");
    assert_eq!(tree_hash(&src), before, "the tree is not byte-identical");
}

#[test]
fn restore_refuses_rather_than_overwriting_an_occupied_original() {
    // spec §7.3. The thing at that path now is newer and was created
    // deliberately; replacing it would turn an undo into a second, unrequested
    // deletion.
    let env = Env::new();
    let c = env.candidate("project", 4096);
    let src = path_of(&c);

    let (outcome, _) = quarantine::quarantine(&[c], 7).unwrap();
    assert!(!src.exists());

    // The user rebuilt it.
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("REBUILT.txt"), b"newer, must survive").unwrap();

    let restored = restore::restore(&outcome.run_id).unwrap();

    assert_eq!(restored.restored.len(), 0);
    assert_eq!(restored.conflicts.len(), 1);
    assert!(!restored.fully_restored());

    assert_eq!(
        fs::read(src.join("REBUILT.txt")).unwrap(),
        b"newer, must survive",
        "restore overwrote newer content"
    );
    assert!(
        !src.join("payload.bin").exists(),
        "the quarantined content was merged into the live directory"
    );
}

#[test]
fn a_conflicted_item_stays_in_quarantine_for_a_retry() {
    // Partial restore is a valid outcome, and the user must be able to resolve
    // the conflict and re-run.
    let env = Env::new();
    let c = env.candidate("project", 4096);
    let src = path_of(&c);
    let (outcome, _) = quarantine::quarantine(&[c], 7).unwrap();

    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("blocker.txt"), b"in the way").unwrap();

    let first = restore::restore(&outcome.run_id).unwrap();
    assert_eq!(first.conflicts.len(), 1);

    // Resolve the conflict and retry.
    fs::remove_dir_all(&src).unwrap();
    let second = restore::restore(&outcome.run_id).unwrap();

    assert_eq!(second.restored.len(), 1, "the retry should now succeed");
    assert!(src.join("payload.bin").exists());
}

#[test]
fn restoring_only_retries_what_is_still_outstanding() {
    let env = Env::new();
    let a = env.candidate("alpha", 2048);
    let b = env.candidate("beta", 2048);
    let (a_path, b_path) = (path_of(&a), path_of(&b));

    let (outcome, _) = quarantine::quarantine(&[a, b], 7).unwrap();

    // Block only beta.
    fs::create_dir_all(&b_path).unwrap();
    fs::write(b_path.join("blocker"), b"x").unwrap();

    let first = restore::restore(&outcome.run_id).unwrap();
    assert_eq!(first.restored.len(), 1);
    assert_eq!(first.conflicts.len(), 1);
    assert!(a_path.exists());

    // The manifest should now show alpha as no longer quarantined.
    let m = Manifest::load(&outcome.run_dir).unwrap();
    assert_eq!(m.restorable().count(), 1, "alpha should not be retried");
}

#[test]
fn restoring_a_fully_restored_run_removes_the_empty_shell() {
    // Otherwise `report` and `purge` keep listing a run with nothing in it.
    let env = Env::new();
    let c = env.candidate("project", 2048);
    let (outcome, _) = quarantine::quarantine(&[c], 7).unwrap();

    restore::restore(&outcome.run_id).unwrap();
    assert!(
        !outcome.run_dir.exists(),
        "an empty run directory was left behind"
    );
    assert!(quarantine::runs().unwrap().is_empty());
}

#[test]
fn restore_accepts_a_run_id_prefix() {
    let env = Env::new();
    let (outcome, _) = quarantine::quarantine(&[env.candidate("x", 1024)], 7).unwrap();

    let restored = restore::restore(&outcome.run_id[..8]).unwrap();
    assert_eq!(restored.restored.len(), 1);
}

#[test]
fn restoring_an_unknown_run_is_a_usage_error() {
    let _env = Env::new();
    let err = restore::restore("nope-not-a-run").unwrap_err();
    assert_eq!(err.exit_code(), sift::ExitCode::Usage);
}

#[test]
fn restore_recreates_a_parent_directory_that_was_removed() {
    // The user may have deleted the enclosing directory after the clean. Restore
    // should still be able to put the item back where it came from.
    let env = Env::new();
    let nested = env.work.join("outer/inner");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("payload.bin"), vec![0u8; 2048]).unwrap();

    let c = Candidate {
        scanner: "logs",
        target: Target::Path(nested.clone()),
        bytes_on_disk: 2048,
        bytes_apparent: 2048,
        last_modified: Local::now(),
        risk: Risk::Safe,
        label: "nested".into(),
        reason: "test".into(),
    };

    let (outcome, _) = quarantine::quarantine(&[c], 7).unwrap();
    fs::remove_dir_all(env.work.join("outer")).unwrap();

    let restored = restore::restore(&outcome.run_id).unwrap();
    assert_eq!(restored.restored.len(), 1, "{restored:?}");
    assert!(nested.join("payload.bin").exists());
}
