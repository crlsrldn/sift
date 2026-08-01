//! Quarantine staging (FR-11, FR-12, spec §7.1, §7.2).
//!
//! `$HOME` and `XDG_STATE_HOME` are redirected into a `TempDir`, so no test
//! touches the developer's real quarantine directory.

use chrono::Local;
use sift::action::manifest::Manifest;
use sift::action::quarantine;
use sift::risk::Risk;
use sift::scan::{Candidate, Target};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct Env {
    _dir: tempfile::TempDir,
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
            _dir: dir,
            work,
            prev_state,
            _guard: guard,
        }
    }

    /// A directory of `bytes` under the work area, as a quarantinable candidate.
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

fn path_of(c: &Candidate) -> &Path {
    match &c.target {
        Target::Path(p) => p,
        _ => panic!("expected a path target"),
    }
}

// ---------------------------------------------------------------------------
// The core mechanism
// ---------------------------------------------------------------------------

#[test]
fn quarantining_moves_the_source_and_records_it() {
    let env = Env::new();
    let c = env.candidate("derived", 4096);
    let src = path_of(&c).to_path_buf();

    let (outcome, manifest) = quarantine::quarantine(&[c], 7).unwrap();

    assert_eq!(outcome.renamed, 1);
    assert!(outcome.refused.is_empty(), "{:?}", outcome.refused);
    assert!(!src.exists(), "the source should have moved");

    assert_eq!(manifest.items.len(), 1);
    assert!(manifest.items[0].moved);
    assert_eq!(manifest.items[0].original_path, src);

    let staged = outcome.run_dir.join(&manifest.items[0].quarantine_path);
    assert!(
        staged.join("payload.bin").exists(),
        "content did not arrive"
    );
}

#[test]
fn quarantine_consumes_no_additional_disk_space() {
    // FR-12's central claim, and the reason quarantine is viable for a user at
    // 2 GB free: a same-volume rename is an inode operation, not a copy.
    //
    // Measured as the sum of allocated blocks before and after, which is exact
    // and local. Volume free space would be swamped by unrelated system
    // activity over the same interval.
    let env = Env::new();
    let c = env.candidate("bigtree", 8 * 1024 * 1024);
    let src = path_of(&c).to_path_buf();

    let before = sift::fs::size::measure(&src).unwrap().bytes_on_disk;
    assert!(before >= 8 * 1024 * 1024);

    let (outcome, manifest) = quarantine::quarantine(&[c], 7).unwrap();

    let staged = outcome.run_dir.join(&manifest.items[0].quarantine_path);
    let after = sift::fs::size::measure(&staged).unwrap().bytes_on_disk;

    assert_eq!(
        before, after,
        "a rename must not duplicate blocks: {before} before, {after} after"
    );
}

#[test]
fn two_identically_named_directories_do_not_collide() {
    // spec §7.1. Using only the basename would silently overwrite one with the
    // other — the exact case of two `target/` dirs from different projects.
    let env = Env::new();
    fs::create_dir_all(env.work.join("alpha")).unwrap();
    fs::create_dir_all(env.work.join("beta")).unwrap();

    let a = env.candidate("alpha/target", 2048);
    let b = env.candidate("beta/target", 4096);

    let (outcome, manifest) = quarantine::quarantine(&[a, b], 7).unwrap();

    assert_eq!(outcome.renamed, 2, "{:?}", outcome.refused);
    assert_ne!(
        manifest.items[0].quarantine_path, manifest.items[1].quarantine_path,
        "both landed on the same path"
    );
    for item in &manifest.items {
        assert!(outcome.run_dir.join(&item.quarantine_path).exists());
    }
}

// ---------------------------------------------------------------------------
// Crash safety
// ---------------------------------------------------------------------------

#[test]
fn the_manifest_exists_and_is_valid_before_anything_moves() {
    // The crash-safety ordering. If the process died between the manifest
    // write and the renames, restore must still know what was intended —
    // orphaned quarantine with no restore path is the unrecoverable outcome
    // G2 forbids.
    let env = Env::new();
    let c = env.candidate("thing", 1024);

    let (outcome, _) = quarantine::quarantine(&[c], 7).unwrap();

    let reloaded = Manifest::load(&outcome.run_dir).unwrap();
    assert_eq!(reloaded.items.len(), 1);
    assert!(reloaded.items[0].original_path.is_absolute());
    assert!(reloaded.items[0].quarantine_path.is_relative());
}

#[test]
fn an_item_written_to_the_manifest_but_never_moved_is_not_restorable() {
    // Simulates the crash window: the manifest lists an item, but the rename
    // never happened. Restore must skip it rather than believing it is there.
    let env = Env::new();
    let c = env.candidate("thing", 1024);
    let (outcome, _) = quarantine::quarantine(&[c], 7).unwrap();

    let mut m = Manifest::load(&outcome.run_dir).unwrap();
    m.items[0].moved = false;
    m.save(&outcome.run_dir).unwrap();

    let reloaded = Manifest::load(&outcome.run_dir).unwrap();
    assert_eq!(reloaded.restorable().count(), 0);
    assert_eq!(reloaded.total_bytes(), 0);
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

#[test]
fn a_source_already_inside_quarantine_is_refused() {
    // Without this, feeding quarantine back into a scan would nest runs inside
    // each other and make restore incoherent.
    let env = Env::new();
    let root = env.quarantine_root();
    let inside = root.join("someprev/Users/x/thing");
    fs::create_dir_all(&inside).unwrap();
    fs::write(inside.join("f"), b"x").unwrap();

    let c = Candidate {
        scanner: "logs",
        target: Target::Path(inside.clone()),
        bytes_on_disk: 1,
        bytes_apparent: 1,
        last_modified: Local::now(),
        risk: Risk::Safe,
        label: "x".into(),
        reason: "x".into(),
    };

    let (outcome, _) = quarantine::quarantine(&[c], 7).unwrap();
    assert_eq!(outcome.renamed, 0);
    assert_eq!(outcome.refused.len(), 1);
    assert!(
        outcome.refused[0].1.contains("already inside"),
        "{:?}",
        outcome.refused
    );
    assert!(
        inside.exists(),
        "the source must be untouched after a refusal"
    );
}

#[test]
fn a_vanished_source_is_refused_not_fatal() {
    // A candidate can disappear between scan and clean. That is normal, not an
    // error, and must not abort the rest of the run.
    let env = Env::new();
    let gone = env.candidate("gone", 1024);
    let stays = env.candidate("stays", 1024);
    fs::remove_dir_all(path_of(&gone)).unwrap();

    let (outcome, _) = quarantine::quarantine(&[gone, stays], 7).unwrap();

    assert_eq!(
        outcome.renamed, 1,
        "the surviving candidate must still stage"
    );
    assert_eq!(outcome.refused.len(), 1);
    assert!(
        outcome.refused[0].1.contains("vanished"),
        "{:?}",
        outcome.refused
    );
}

#[test]
fn delegated_targets_never_enter_quarantine() {
    // FR-15: they are irreversible by nature and are handled by the delegate
    // runner, not by staging.
    let env = Env::new();
    let _ = &env;
    let c = Candidate {
        scanner: "homebrew",
        target: Target::Delegated(sift::scan::DelegatedCmd::new("brew", &["cleanup"])),
        bytes_on_disk: 1_000_000,
        bytes_apparent: 1_000_000,
        last_modified: Local::now(),
        risk: Risk::Safe,
        label: "brew".into(),
        reason: "x".into(),
    };

    let (outcome, manifest) = quarantine::quarantine(&[c], 7).unwrap();
    assert_eq!(outcome.renamed, 0);
    assert!(manifest.items.is_empty(), "a delegated target was staged");
}

// ---------------------------------------------------------------------------
// Run discovery
// ---------------------------------------------------------------------------

#[test]
fn runs_are_discoverable_and_resolvable_by_prefix() {
    let env = Env::new();
    let (outcome, _) = quarantine::quarantine(&[env.candidate("a", 512)], 7).unwrap();

    let all = quarantine::runs().unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].run_id, outcome.run_id);

    let by_prefix = quarantine::resolve_run(&outcome.run_id[..8]).unwrap();
    assert_eq!(by_prefix.run_id, outcome.run_id);
}

#[test]
fn an_unmatched_or_ambiguous_prefix_is_a_usage_error() {
    let env = Env::new();
    quarantine::quarantine(&[env.candidate("a", 512)], 7).unwrap();
    quarantine::quarantine(&[env.candidate("b", 512)], 7).unwrap();

    let err = quarantine::resolve_run("zzzzzzzz").unwrap_err();
    assert_eq!(err.exit_code(), sift::ExitCode::Usage);

    // Both run ids are UUID v7, which share a time-ordered prefix.
    let err = quarantine::resolve_run("").unwrap_err();
    assert_eq!(err.exit_code(), sift::ExitCode::Usage);
    assert!(err.to_string().contains("more characters"), "{err}");
}

#[test]
fn a_run_directory_with_an_unreadable_manifest_is_skipped_not_fatal() {
    // One bad run must not make purge or restore unusable for every other run.
    let env = Env::new();
    let (good, _) = quarantine::quarantine(&[env.candidate("a", 512)], 7).unwrap();

    let bad = env.quarantine_root().join("not-a-real-run");
    fs::create_dir_all(&bad).unwrap();
    fs::write(bad.join("manifest.json"), b"{ corrupt").unwrap();

    let all = quarantine::runs().unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].run_id, good.run_id);
}

// ---------------------------------------------------------------------------
// FR-12 — the cross-volume fallback
// ---------------------------------------------------------------------------

/// A mounted APFS image, so a genuinely cross-volume rename can be attempted.
///
/// `EXDEV` only occurs across a real mount, so the Trash fallback cannot be
/// exercised any other way. Without this test `via_trash` is code that has
/// never run.
struct MountedImage {
    mount_point: PathBuf,
    dmg: PathBuf,
}

impl MountedImage {
    fn new() -> Self {
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let base = std::env::temp_dir().join(format!("sift-q-test-{}-{n}", std::process::id()));
        let dmg = base.with_extension("dmg");
        let mount_point = base.with_extension("mnt");

        let create = std::process::Command::new("hdiutil")
            .args([
                "create",
                "-size",
                "20m",
                "-fs",
                "APFS",
                "-volname",
                "SiftQTest",
                "-quiet",
                "-ov",
            ])
            .arg(&dmg)
            .status()
            .expect("hdiutil must be runnable on macOS");
        assert!(create.success(), "hdiutil create failed");

        fs::create_dir_all(&mount_point).unwrap();
        let attach = std::process::Command::new("hdiutil")
            .args(["attach", "-nobrowse", "-quiet", "-mountpoint"])
            .arg(&mount_point)
            .arg(&dmg)
            .status()
            .expect("hdiutil must be runnable on macOS");
        assert!(attach.success(), "hdiutil attach failed");

        Self { mount_point, dmg }
    }
}

impl Drop for MountedImage {
    fn drop(&mut self) {
        let _ = std::process::Command::new("hdiutil")
            .args(["detach", "-quiet", "-force"])
            .arg(&self.mount_point)
            .status();
        let _ = fs::remove_file(&self.dmg);
        let _ = fs::remove_dir(&self.mount_point);
    }
}

#[test]
fn a_cross_volume_candidate_falls_back_to_trash_and_says_so() {
    // FR-12. A rename across volumes returns EXDEV, so quarantine cannot be a
    // rename. The fallback is macOS Trash, and the manifest records it as such
    // — restore cannot undo it, and implying otherwise would be a lie the user
    // discovers only when they need it.
    let env = Env::new();
    let image = MountedImage::new();

    let src = image.mount_point.join("on-other-volume");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("payload.bin"), vec![0u8; 4096]).unwrap();

    // Confirm the premise: this really is a different device.
    let host_dev = sift::fs::volume::device_of(&env.work).unwrap();
    let img_dev = sift::fs::volume::device_of(&src).unwrap();
    assert_ne!(
        host_dev, img_dev,
        "the fixture is not actually cross-volume"
    );

    let c = Candidate {
        scanner: "logs",
        target: Target::Path(src.clone()),
        bytes_on_disk: 4096,
        bytes_apparent: 4096,
        last_modified: Local::now(),
        risk: Risk::Safe,
        label: "cross-volume".into(),
        reason: "test".into(),
    };

    let (outcome, manifest) = quarantine::quarantine(&[c], 7).unwrap();

    assert_eq!(outcome.renamed, 0, "a cross-volume rename must not succeed");
    assert_eq!(
        outcome.trashed, 1,
        "refused instead of trashing: {:?}",
        outcome.refused
    );
    assert!(manifest.items[0].moved);
    assert!(
        manifest.items[0].via_trash,
        "the manifest must record that this went to Trash, not quarantine"
    );
    assert_eq!(
        manifest.restorable().count(),
        0,
        "a trashed item must never be reported as restorable by sift"
    );
    assert!(!src.exists(), "the source should have gone to Trash");
}
