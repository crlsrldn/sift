//! Walker guard tests (FR-7, spec §5.2).
//!
//! The PR plan calls these non-negotiable. Each one corresponds to a specific
//! documented way a naive walk of a macOS filesystem goes wrong: infinite
//! recursion, double-counting the firmlinked Data volume, wandering into a
//! mounted disk image, or ignoring the user's exclude list.

use sift::fs::walk::{SkipReason, Walker};
use std::fs;
use std::os::unix::fs as unixfs;
use std::path::Path;

fn walker_for(root: &Path) -> Walker {
    Walker::new(root).expect("walker should build for a real path")
}

// ---------------------------------------------------------------------------
// Guard 3 — symlinks are never followed
// ---------------------------------------------------------------------------

#[test]
fn a_symlink_cycle_terminates() {
    // The canonical failure: a -> b -> a. With follow_links(false) this is not
    // merely bounded, it is unreachable.
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    fs::create_dir(&a).unwrap();
    fs::create_dir(&b).unwrap();
    unixfs::symlink(&b, a.join("to_b")).unwrap();
    unixfs::symlink(&a, b.join("to_a")).unwrap();
    fs::write(a.join("real.txt"), b"x").unwrap();

    let result = walker_for(dir.path()).walk(dir.path()).unwrap();

    assert_eq!(
        result.entries.len(),
        1,
        "only the real file should be counted"
    );
    assert_eq!(result.count_skipped(SkipReason::Symlink), 2);
}

#[test]
fn a_symlink_pointing_at_its_own_parent_terminates() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("sub");
    fs::create_dir(&sub).unwrap();
    unixfs::symlink(dir.path(), sub.join("up")).unwrap();
    fs::write(sub.join("f.txt"), b"x").unwrap();

    let result = walker_for(dir.path()).walk(dir.path()).unwrap();
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.count_skipped(SkipReason::Symlink), 1);
}

#[test]
fn a_symlink_to_a_file_is_not_counted_as_its_target() {
    // Otherwise a tree full of symlinks into one big file would report that
    // file's size once per link.
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("big.bin");
    fs::write(&target, vec![0u8; 4096]).unwrap();
    for i in 0..5 {
        unixfs::symlink(&target, dir.path().join(format!("link{i}"))).unwrap();
    }

    let result = walker_for(dir.path()).walk(dir.path()).unwrap();
    assert_eq!(
        result.entries.len(),
        1,
        "target counted once, links not at all"
    );
    assert_eq!(result.count_skipped(SkipReason::Symlink), 5);
}

// ---------------------------------------------------------------------------
// Guard 2 — firmlink and the hard deny list
// ---------------------------------------------------------------------------

#[test]
fn the_data_volume_firmlink_is_never_descended() {
    // macOS firmlinks /System/Volumes/Data into /. A naive walk of / traverses
    // every user file twice, under two different paths, and double-counts.
    let w = Walker::with_device(0);
    let path = Path::new("/System/Volumes/Data");
    let meta = fs::symlink_metadata(path).expect("the firmlink should exist on macOS");

    assert_eq!(w.check(path, &meta, 1), Some(SkipReason::Firmlink));
}

#[test]
fn walking_the_firmlink_directly_yields_nothing() {
    let result = walker_for(Path::new("/"))
        .walk(Path::new("/System/Volumes/Data"))
        .unwrap();
    assert!(result.entries.is_empty());
    assert_eq!(result.count_skipped(SkipReason::Firmlink), 1);
}

#[test]
fn system_paths_are_denied() {
    let w = Walker::with_device(0);
    for p in ["/System", "/System/Library"] {
        let path = Path::new(p);
        if let Ok(meta) = fs::symlink_metadata(path) {
            assert_eq!(
                w.check(path, &meta, 1),
                Some(SkipReason::Firmlink),
                "{p} should be denied"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Guard 1 — device check, against a real mounted volume
// ---------------------------------------------------------------------------

/// Creates and mounts a small sparse disk image, then unmounts it on drop.
///
/// A synthetic fixture cannot exercise this guard: `st_dev` only differs across
/// a real mount, so the only honest test is to make one.
struct MountedImage {
    mount_point: std::path::PathBuf,
    dmg: std::path::PathBuf,
}

impl MountedImage {
    /// Panics rather than returning None on failure.
    ///
    /// A device-guard test that silently skips is worse than no test: it
    /// reports green while proving nothing. `hdiutil` is available on every
    /// macOS machine and on the CI runner, so failure here is a real signal.
    fn new() -> Self {
        // Unique per instance, not just per process: integration tests in one
        // binary run in parallel, so a pid-only name makes two concurrent
        // fixtures fight over the same image. That collision is what the
        // earlier silent-skip version was hiding.
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let base = std::env::temp_dir().join(format!("sift-walk-test-{}-{n}", std::process::id()));
        let dmg = base.with_extension("dmg");
        let mount_point = base.with_extension("mnt");

        // 20 MB is the smallest that reliably formats, and this machine is
        // short on space.
        let create = std::process::Command::new("hdiutil")
            .args([
                "create",
                "-size",
                "20m",
                "-fs",
                "APFS",
                "-volname",
                "SiftWalkTest",
                "-quiet",
                "-ov",
            ])
            .arg(&dmg)
            .status()
            .expect("hdiutil create should be runnable on macOS");
        assert!(create.success(), "hdiutil create failed");

        fs::create_dir_all(&mount_point).unwrap();
        let attach = std::process::Command::new("hdiutil")
            .args(["attach", "-nobrowse", "-quiet", "-mountpoint"])
            .arg(&mount_point)
            .arg(&dmg)
            .status()
            .expect("hdiutil attach should be runnable on macOS");
        if !attach.success() {
            let _ = fs::remove_file(&dmg);
            panic!("hdiutil attach failed; the device guard cannot be verified");
        }

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
fn a_mounted_volume_is_not_descended_into() {
    let image = MountedImage::new();

    // Put a file on the mounted volume so descending would visibly find it.
    fs::write(
        image.mount_point.join("should_not_be_seen.txt"),
        vec![0u8; 1024],
    )
    .unwrap();

    // A directory on the host volume that contains the mount point.
    let host_dev = sift::fs::volume::device_of(Path::new("/")).unwrap();
    let mount_dev = sift::fs::volume::device_of(&image.mount_point).unwrap();
    assert_ne!(host_dev, mount_dev, "the image must be a distinct device");

    let w = Walker::with_device(host_dev);
    let meta = fs::symlink_metadata(&image.mount_point).unwrap();
    assert_eq!(
        w.check(&image.mount_point, &meta, 1),
        Some(SkipReason::OtherVolume),
        "the mount point is on a different device and must be refused"
    );

    let result = w.walk(&image.mount_point).unwrap();
    assert!(
        result.entries.is_empty(),
        "walked into another volume: {:?}",
        result.entries
    );
}

#[test]
fn the_device_baseline_is_the_walk_root_not_the_current_directory() {
    // If the guard re-derived st_dev per directory, descending into a mount
    // would adopt the mount's device as the new baseline and the guard would
    // never fire again.
    let image = MountedImage::new();

    let sub = image.mount_point.join("inner");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join("f.txt"), b"x").unwrap();

    let host_dev = sift::fs::volume::device_of(Path::new("/")).unwrap();
    let w = Walker::with_device(host_dev);

    let meta = fs::symlink_metadata(&sub).unwrap();
    assert_eq!(w.check(&sub, &meta, 2), Some(SkipReason::OtherVolume));
}

// ---------------------------------------------------------------------------
// Depth cap
// ---------------------------------------------------------------------------

#[test]
fn the_depth_cap_stops_a_pathological_tree() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = dir.path().to_path_buf();
    for i in 0..30 {
        p = p.join(format!("d{i}"));
    }
    fs::create_dir_all(&p).unwrap();
    fs::write(p.join("deep.txt"), b"x").unwrap();

    let result = walker_for(dir.path())
        .max_depth(5)
        .walk(dir.path())
        .unwrap();

    assert!(
        result.entries.is_empty(),
        "the deep file is past the cap and must not be reached"
    );
    assert!(result.count_skipped(SkipReason::TooDeep) > 0);
    assert!(result.entries.iter().all(|e| e.depth <= 5));
}

// ---------------------------------------------------------------------------
// Guard 5 — exclude globs (FR-24)
// ---------------------------------------------------------------------------

#[test]
fn exclude_globs_veto_paths_every_other_guard_would_admit() {
    let dir = tempfile::tempdir().unwrap();
    let keep = dir.path().join("keep");
    let drop_dir = dir.path().join("secret");
    fs::create_dir(&keep).unwrap();
    fs::create_dir(&drop_dir).unwrap();
    fs::write(keep.join("a.txt"), b"x").unwrap();
    fs::write(drop_dir.join("b.txt"), b"x").unwrap();

    let mut b = globset::GlobSetBuilder::new();
    b.add(globset::Glob::new(&format!("{}/**", drop_dir.display())).unwrap());
    b.add(globset::Glob::new(&drop_dir.display().to_string()).unwrap());

    let result = walker_for(dir.path())
        .excludes(b.build().unwrap())
        .walk(dir.path())
        .unwrap();

    let paths: Vec<String> = result
        .entries
        .iter()
        .map(|e| e.path.display().to_string())
        .collect();

    assert_eq!(paths.len(), 1, "got {paths:?}");
    assert!(paths[0].contains("keep"));
    assert_eq!(result.count_skipped(SkipReason::Excluded), 1);
}

#[test]
fn an_excluded_directory_is_not_descended_into() {
    // A veto must cost one stat, not a traversal of the excluded subtree.
    let dir = tempfile::tempdir().unwrap();
    let excluded = dir.path().join("big");
    fs::create_dir_all(excluded.join("a/b/c")).unwrap();
    for i in 0..10 {
        fs::write(excluded.join(format!("a/b/c/f{i}")), b"x").unwrap();
    }

    let mut b = globset::GlobSetBuilder::new();
    b.add(globset::Glob::new(&excluded.display().to_string()).unwrap());

    let result = walker_for(dir.path())
        .excludes(b.build().unwrap())
        .walk(dir.path())
        .unwrap();

    assert!(result.entries.is_empty());
    assert_eq!(
        result.count_skipped(SkipReason::Excluded),
        1,
        "the subtree should be refused once, not entry by entry"
    );
}

// ---------------------------------------------------------------------------
// Ordinary behaviour
// ---------------------------------------------------------------------------

#[test]
fn a_normal_tree_is_walked_completely() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("a/b")).unwrap();
    fs::write(dir.path().join("root.txt"), b"x").unwrap();
    fs::write(dir.path().join("a/one.txt"), b"x").unwrap();
    fs::write(dir.path().join("a/b/two.txt"), b"x").unwrap();

    let result = walker_for(dir.path()).walk(dir.path()).unwrap();
    assert_eq!(result.entries.len(), 3);
    assert!(result.skipped.is_empty(), "{:?}", result.skipped);
}

#[test]
fn walking_a_single_file_yields_that_file() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("one.txt");
    fs::write(&f, b"x").unwrap();

    let result = walker_for(&f).walk(&f).unwrap();
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].path, f);
}

#[test]
fn an_unreadable_directory_is_recorded_not_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let locked = dir.path().join("locked");
    fs::create_dir(&locked).unwrap();
    fs::write(locked.join("hidden.txt"), b"x").unwrap();
    fs::set_permissions(
        &locked,
        <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o000),
    )
    .unwrap();

    let result = walker_for(dir.path()).walk(dir.path());
    // Restore before asserting so the tempdir can clean itself up.
    let _ = fs::set_permissions(
        &locked,
        <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
    );

    let result = result.expect("an unreadable subdirectory must not abort the walk");
    assert_eq!(result.count_skipped(SkipReason::Unreadable), 1);
}

#[test]
fn newest_mtime_drives_the_liveness_guard() {
    // FR-17: a tree containing anything modified recently is not a candidate.
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.txt"), b"x").unwrap();

    let result = walker_for(dir.path()).walk(dir.path()).unwrap();
    let newest = result.newest_mtime().expect("should have an mtime");
    let age = std::time::SystemTime::now()
        .duration_since(newest)
        .unwrap_or_default();
    assert!(age.as_secs() < 60, "just-written file should be recent");
}

#[test]
fn a_missing_root_is_an_error_not_a_panic() {
    let w = Walker::with_device(0);
    assert!(w.walk(Path::new("/no/such/directory/at/all")).is_err());
}
