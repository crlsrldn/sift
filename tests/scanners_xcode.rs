//! S2/S3/S4 Xcode scanners against fixture trees (spec §6, spec §12).
//!
//! Spec §12: "Each scanner runs against a fixture tree under `tempfile::TempDir`;
//! asserts exact candidate set. **No scanner test touches a real home
//! directory.**" These override `$HOME` so the scanners look inside a temp tree.
//!
//! This is also the *only* validation available for these scanners on the
//! development machine, which has Command Line Tools but no Xcode — there is no
//! `~/Library/Developer/Xcode` to check against.

use chrono::{Duration, Local};
use filetime::FileTime;
use sift::caps::Capabilities;
use sift::config::Config;
use sift::risk::Risk;
use sift::scan::{xcode, ScanCtx, Scanner};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// `$HOME` is process-global, so fixture tests must not run concurrently.
static HOME_LOCK: Mutex<()> = Mutex::new(());

struct Fixture {
    _dir: tempfile::TempDir,
    home: std::path::PathBuf,
    prev_home: Option<std::ffi::OsString>,
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl Fixture {
    fn new() -> Self {
        let guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("HOME", &home);
        fs::create_dir_all(home.join("Library/Developer/Xcode")).unwrap();
        Self {
            _dir: dir,
            home,
            prev_home,
            _guard: guard,
        }
    }

    fn xcode(&self) -> std::path::PathBuf {
        self.home.join("Library/Developer/Xcode")
    }

    fn ctx(&self) -> ScanCtx {
        self.ctx_with(Config::default())
    }

    fn ctx_with(&self, cfg: Config) -> ScanCtx {
        ScanCtx::new(
            Arc::new(cfg),
            sift::fs::volume::root().unwrap(),
            Capabilities::probe(),
        )
        .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        match &self.prev_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
    }
}

/// Create a directory with a file in it, aged `days` old.
fn aged_dir(path: &Path, bytes: usize, days: i64) {
    fs::create_dir_all(path).unwrap();
    let f = path.join("content.bin");
    fs::write(&f, vec![0u8; bytes]).unwrap();
    age(&f, days);
    age(path, days);
}

fn age(path: &Path, days: i64) {
    let when = Local::now() - Duration::days(days);
    let ft = FileTime::from_unix_time(when.timestamp(), 0);
    filetime::set_file_mtime(path, ft).unwrap();
}

// ---------------------------------------------------------------------------
// S2 — DerivedData
// ---------------------------------------------------------------------------

#[test]
fn derived_data_claims_an_idle_project() {
    let f = Fixture::new();
    aged_dir(
        &f.xcode().join("DerivedData/Runyard-abcdef123"),
        200_000,
        31,
    );

    let out = xcode::DerivedData.scan(&f.ctx()).unwrap();
    assert_eq!(out.len(), 1, "{out:#?}");
    assert_eq!(out[0].risk, Risk::Rebuildable);
    // Principle 6: name the project, not the hashed directory.
    assert!(out[0].label.contains("Runyard"), "{}", out[0].label);
    assert!(!out[0].label.contains("abcdef123"), "{}", out[0].label);
}

#[test]
fn derived_data_ignores_a_project_younger_than_the_floor() {
    let f = Fixture::new();
    aged_dir(&f.xcode().join("DerivedData/Fresh-abc"), 200_000, 3);

    let out = xcode::DerivedData.scan(&f.ctx()).unwrap();
    assert!(
        out.is_empty(),
        "3 days old should be under the 14-day floor: {out:#?}"
    );
}

#[test]
fn derived_data_refuses_a_tree_touched_within_the_liveness_window() {
    // FR-17. The directory's own mtime is old, but a file inside was just
    // written — which is exactly what an active build looks like. Trusting the
    // directory mtime here would quarantine a running build.
    let f = Fixture::new();
    let d = f.xcode().join("DerivedData/Building-abc");
    aged_dir(&d, 200_000, 90);

    let live = d.join("Build/Intermediates/live.o");
    fs::create_dir_all(live.parent().unwrap()).unwrap();
    fs::write(&live, b"just written").unwrap();
    age(&d, 90); // directory still looks old

    let out = xcode::DerivedData.scan(&f.ctx()).unwrap();
    assert!(
        out.is_empty(),
        "a tree with a file modified seconds ago must not be a candidate: {out:#?}"
    );
}

#[test]
fn a_small_module_cache_is_preserved() {
    // spec §6 S2: ModuleCache.noindex is shared and expensive to rebuild, so
    // evicting a small one is a bad trade.
    //
    // Only the preserve half is covered. Exercising the >1 GB branch would need
    // a 1 GB fixture, which is not a reasonable thing to write on every test
    // run; the threshold constant itself is pinned by a unit test instead.
    let f = Fixture::new();
    aged_dir(
        &f.xcode().join("DerivedData/ModuleCache.noindex"),
        50_000,
        90,
    );

    let out = xcode::DerivedData.scan(&f.ctx()).unwrap();
    assert!(
        out.is_empty(),
        "a small module cache must be preserved: {out:#?}"
    );
}

#[test]
fn derived_data_respects_a_configured_min_age() {
    let f = Fixture::new();
    aged_dir(&f.xcode().join("DerivedData/Proj-abc"), 100_000, 20);

    let strict = Config::parse("[scanners.xcode-derived]\nmin_age_days = 60\n").unwrap();
    assert!(xcode::DerivedData
        .scan(&f.ctx_with(strict))
        .unwrap()
        .is_empty());

    let loose = Config::parse("[scanners.xcode-derived]\nmin_age_days = 7\n").unwrap();
    assert_eq!(
        xcode::DerivedData.scan(&f.ctx_with(loose)).unwrap().len(),
        1
    );
}

#[test]
fn a_missing_xcode_directory_yields_nothing_and_is_not_an_error() {
    // The state of the development machine, and of any non-developer's Mac.
    let f = Fixture::new();
    fs::remove_dir_all(f.xcode()).unwrap();

    assert!(xcode::DerivedData.scan(&f.ctx()).unwrap().is_empty());
    assert!(xcode::DeviceSupport.scan(&f.ctx()).unwrap().is_empty());
    assert!(xcode::Archives.scan(&f.ctx()).unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// S3 — DeviceSupport
// ---------------------------------------------------------------------------

#[test]
fn device_support_claims_only_bundles_two_majors_behind() {
    let f = Fixture::new();
    let root = f.xcode().join("iOS DeviceSupport");
    for name in [
        "15.0 (19A346)",
        "16.4 (20E247)",
        "17.2 (21C62)",
        "18.1 (22B83)",
    ] {
        aged_dir(&root.join(name), 100_000, 200);
    }

    let out = xcode::DeviceSupport.scan(&f.ctx()).unwrap();
    let labels: Vec<&str> = out.iter().map(|c| c.label.as_str()).collect();

    // Newest is 18. Eligible: major + 2 <= 18, i.e. 15 and 16.
    assert_eq!(out.len(), 2, "got {labels:?}");
    assert!(labels.iter().any(|l| l.contains("15.0")), "{labels:?}");
    assert!(labels.iter().any(|l| l.contains("16.4")), "{labels:?}");
    assert!(!labels.iter().any(|l| l.contains("17.2")), "{labels:?}");
    assert!(!labels.iter().any(|l| l.contains("18.1")), "{labels:?}");
}

#[test]
fn device_support_never_claims_the_newest_bundle() {
    // Deleting the bundle for the device the user is actively debugging is the
    // worst outcome this scanner has available.
    let f = Fixture::new();
    let root = f.xcode().join("iOS DeviceSupport");
    aged_dir(&root.join("18.1 (22B83)"), 100_000, 999);

    let out = xcode::DeviceSupport.scan(&f.ctx()).unwrap();
    assert!(
        out.is_empty(),
        "the only bundle present is the newest and must never be claimed: {out:#?}"
    );
}

#[test]
fn device_support_respects_the_age_floor_even_when_far_behind() {
    let f = Fixture::new();
    let root = f.xcode().join("iOS DeviceSupport");
    aged_dir(&root.join("18.0 (22A1)"), 100_000, 400);
    aged_dir(&root.join("12.0 (16A1)"), 100_000, 5); // ancient version, fresh dir

    let out = xcode::DeviceSupport.scan(&f.ctx()).unwrap();
    assert!(
        out.is_empty(),
        "5 days old is under the 90-day floor regardless of version: {out:#?}"
    );
}

#[test]
fn device_support_skips_unparseable_directory_names() {
    // Principle 7: refuse rather than guess. Xcode drops non-version
    // directories in here, and a wrong guess deletes a real bundle.
    let f = Fixture::new();
    let root = f.xcode().join("iOS DeviceSupport");
    aged_dir(&root.join("18.1 (22B83)"), 100_000, 200);
    aged_dir(&root.join("15.0 (19A346)"), 100_000, 200);
    aged_dir(&root.join("Symbols"), 500_000, 200);
    aged_dir(&root.join(".DS_Store_dir"), 500_000, 200);

    let out = xcode::DeviceSupport.scan(&f.ctx()).unwrap();
    for c in &out {
        assert!(!c.label.contains("Symbols"), "{}", c.label);
        assert!(!c.label.contains("DS_Store"), "{}", c.label);
    }
    assert_eq!(out.len(), 1, "only 15.0 is eligible: {out:#?}");
}

#[test]
fn device_support_handles_multiple_platforms_independently() {
    let f = Fixture::new();
    for (platform, versions) in [
        ("iOS", vec!["15.0", "18.1"]),
        ("watchOS", vec!["9.0", "11.0"]),
    ] {
        let root = f.xcode().join(format!("{platform} DeviceSupport"));
        for v in versions {
            aged_dir(&root.join(v), 100_000, 200);
        }
    }

    let out = xcode::DeviceSupport.scan(&f.ctx()).unwrap();
    assert_eq!(out.len(), 2, "one eligible per platform: {out:#?}");
    assert!(out.iter().any(|c| c.label.contains("iOS")));
    assert!(out.iter().any(|c| c.label.contains("watchOS")));
}

// ---------------------------------------------------------------------------
// S4 — Archives
// ---------------------------------------------------------------------------

#[test]
fn archives_are_destructive_and_say_what_is_lost() {
    let f = Fixture::new();
    aged_dir(
        &f.xcode().join("Archives/2024-01-15/MyApp.xcarchive"),
        400_000,
        400,
    );

    let out = xcode::Archives.scan(&f.ctx()).unwrap();
    assert_eq!(out.len(), 1, "{out:#?}");
    assert_eq!(out[0].risk, Risk::Destructive);
    assert!(
        out[0].reason.contains("symbolication"),
        "the blast radius must be stated: {}",
        out[0].reason
    );
}

#[test]
fn archives_respect_the_180_day_floor() {
    let f = Fixture::new();
    aged_dir(
        &f.xcode().join("Archives/2025-06-01/Recent.xcarchive"),
        400_000,
        30,
    );

    assert!(xcode::Archives.scan(&f.ctx()).unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Registry-level: the destructive gate
// ---------------------------------------------------------------------------

#[test]
fn archives_produce_nothing_through_the_registry_at_default_risk() {
    // S4 is registered so it appears in `doctor` and `config check`, but the
    // registry's risk gate must keep it inert while max_risk is rebuildable.
    // This is the two-switch model enforced at execution.
    let f = Fixture::new();
    aged_dir(
        &f.xcode().join("Archives/2024-01-15/MyApp.xcarchive"),
        400_000,
        400,
    );

    let report = sift::scan::registry().run(&f.ctx(), None);
    assert!(
        report.by_scanner("xcode-archives").is_empty(),
        "archives must be inert at default max_risk: {report:#?}"
    );
    assert!(report.errors.is_empty(), "{:?}", report.errors);
}

#[test]
fn the_registry_runs_all_three_xcode_scanners_without_error() {
    let f = Fixture::new();
    aged_dir(&f.xcode().join("DerivedData/App-abc"), 300_000, 40);
    let ds = f.xcode().join("iOS DeviceSupport");
    aged_dir(&ds.join("18.1 (22B83)"), 100_000, 200);
    aged_dir(&ds.join("15.0 (19A346)"), 200_000, 200);

    let report = sift::scan::registry().run(&f.ctx(), None);
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert_eq!(report.by_scanner("xcode-derived").len(), 1);
    assert_eq!(report.by_scanner("xcode-devicesupport").len(), 1);
    assert!(report.total_bytes() > 0);
}
