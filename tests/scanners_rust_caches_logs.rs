//! S6/S7 Rust, S14 app-caches, S17 logs against fixture trees (spec §12).
//!
//! No test touches a real home directory: `$HOME` is redirected into a
//! `TempDir` and restored on drop.

use chrono::{Duration, Local};
use filetime::FileTime;
use sift::caps::Capabilities;
use sift::config::Config;
use sift::risk::Risk;
use sift::scan::{app_caches, logs, rust, ScanCtx, Scanner};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

static HOME_LOCK: Mutex<()> = Mutex::new(());

struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    prev: Option<std::ffi::OsString>,
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl Fixture {
    fn new() -> Self {
        let guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let prev = std::env::var_os("HOME");
        std::env::set_var("HOME", &home);
        Self {
            _dir: dir,
            home,
            prev,
            _guard: guard,
        }
    }

    fn ctx_with(&self, cfg: Config) -> ScanCtx {
        ScanCtx::new(
            Arc::new(cfg),
            sift::fs::volume::root().unwrap(),
            Capabilities::probe(),
        )
        .unwrap()
    }

    fn ctx(&self) -> ScanCtx {
        self.ctx_with(Config::default())
    }

    /// A config with `projects.roots` pointing into the fixture home.
    fn ctx_with_roots(&self, sub: &str) -> ScanCtx {
        let cfg = Config::parse(&format!(
            "[projects]\nroots = [\"{}\"]\n",
            self.home.join(sub).display()
        ))
        .unwrap();
        self.ctx_with(cfg)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        match &self.prev {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
    }
}

fn age(path: &Path, days: i64) {
    let when = Local::now() - Duration::days(days);
    filetime::set_file_mtime(path, FileTime::from_unix_time(when.timestamp(), 0)).unwrap();
}

fn aged_file(path: &Path, bytes: usize, days: i64) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, vec![0u8; bytes]).unwrap();
    age(path, days);
}

fn aged_dir(path: &Path, bytes: usize, days: i64) {
    aged_file(&path.join("content.bin"), bytes, days);
    age(path, days);
}

// ---------------------------------------------------------------------------
// S6 — rust-targets (FR-25)
// ---------------------------------------------------------------------------

#[test]
fn with_no_configured_roots_rust_targets_finds_nothing() {
    // FR-25, the guarantee. There is no home-directory-wide fallback, so an
    // unconfigured install cannot touch a single target/ directory.
    let f = Fixture::new();
    let proj = f.home.join("dev/mycrate");
    fs::create_dir_all(&proj).unwrap();
    fs::write(proj.join("Cargo.toml"), b"[package]").unwrap();
    aged_dir(&proj.join("target"), 500_000, 90);

    let out = rust::Targets.scan(&f.ctx()).unwrap();
    assert!(out.is_empty(), "roots defaults to empty: {out:#?}");
}

#[test]
fn a_target_directory_with_a_sibling_cargo_toml_is_claimed() {
    let f = Fixture::new();
    let proj = f.home.join("dev/mycrate");
    fs::create_dir_all(&proj).unwrap();
    fs::write(proj.join("Cargo.toml"), b"[package]").unwrap();
    aged_dir(&proj.join("target"), 500_000, 90);

    let out = rust::Targets.scan(&f.ctx_with_roots("dev")).unwrap();
    assert_eq!(out.len(), 1, "{out:#?}");
    assert_eq!(out[0].risk, Risk::Rebuildable);
    assert!(out[0].label.contains("mycrate"), "{}", out[0].label);
}

#[test]
fn a_target_directory_without_a_cargo_toml_is_never_claimed() {
    // The defining rule of S6. Without the sibling check, any directory called
    // "target" — a data directory, another language's build output — qualifies.
    let f = Fixture::new();
    let notrust = f.home.join("dev/somedata");
    fs::create_dir_all(&notrust).unwrap();
    aged_dir(&notrust.join("target"), 500_000, 90);

    let out = rust::Targets.scan(&f.ctx_with_roots("dev")).unwrap();
    assert!(out.is_empty(), "no sibling Cargo.toml: {out:#?}");
}

#[test]
fn a_recently_built_target_is_not_claimed() {
    let f = Fixture::new();
    let proj = f.home.join("dev/active");
    fs::create_dir_all(&proj).unwrap();
    fs::write(proj.join("Cargo.toml"), b"[package]").unwrap();
    aged_dir(&proj.join("target"), 500_000, 2);

    let out = rust::Targets.scan(&f.ctx_with_roots("dev")).unwrap();
    assert!(out.is_empty(), "2 days is under the 30-day floor: {out:#?}");
}

#[test]
fn nested_projects_under_a_root_are_each_found() {
    let f = Fixture::new();
    for name in ["alpha", "nested/beta"] {
        let proj = f.home.join("dev").join(name);
        fs::create_dir_all(&proj).unwrap();
        fs::write(proj.join("Cargo.toml"), b"[package]").unwrap();
        aged_dir(&proj.join("target"), 300_000, 90);
    }

    let out = rust::Targets.scan(&f.ctx_with_roots("dev")).unwrap();
    assert_eq!(out.len(), 2, "{out:#?}");
}

// ---------------------------------------------------------------------------
// S7 — cargo-cache, and the two hard denies
// ---------------------------------------------------------------------------

#[test]
fn cargo_bin_and_rustup_are_never_candidates() {
    // Deleting either is not a cache miss, it is an unusable Rust installation.
    let f = Fixture::new();
    aged_dir(&f.home.join(".cargo/bin"), 50_000_000, 999);
    aged_dir(&f.home.join(".rustup/toolchains/stable"), 900_000_000, 999);
    aged_dir(&f.home.join(".cargo/registry/src"), 100_000, 999);

    let out = rust::CargoCache.scan(&f.ctx()).unwrap();

    for c in &out {
        let p = c.target.display();
        assert!(!p.contains(".cargo/bin"), "claimed .cargo/bin: {p}");
        assert!(!p.contains(".rustup"), "claimed .rustup: {p}");
    }
    assert_eq!(
        out.len(),
        1,
        "only registry/src should be claimed: {out:#?}"
    );
}

#[test]
fn cargo_cache_claims_only_the_three_spec_paths() {
    let f = Fixture::new();
    for sub in ["registry/cache", "registry/src", "git/checkouts"] {
        aged_dir(&f.home.join(".cargo").join(sub), 200_000, 90);
    }
    // Something else under ~/.cargo that is not on the list.
    aged_dir(&f.home.join(".cargo/somethingelse"), 900_000, 90);

    let out = rust::CargoCache.scan(&f.ctx()).unwrap();
    assert_eq!(out.len(), 3, "{out:#?}");
    for c in &out {
        assert!(
            !c.target.display().contains("somethingelse"),
            "claimed an unlisted path: {}",
            c.target.display()
        );
        assert_eq!(c.risk, Risk::Safe);
    }
}

// ---------------------------------------------------------------------------
// S14 — app-caches (Principle 1)
// ---------------------------------------------------------------------------

#[test]
fn a_huge_unlisted_bundle_yields_zero_candidates() {
    // THE Principle 1 test. This is the mitigation for the PRD's High-severity
    // "blanket cache deletion" risk: size is irrelevant, only membership counts.
    let f = Fixture::new();
    aged_dir(
        &f.home.join("Library/Caches/com.someapp.NotOnTheList"),
        50_000_000,
        999,
    );

    let out = app_caches::AppCaches.scan(&f.ctx()).unwrap();
    assert!(
        out.is_empty(),
        "an unlisted bundle must never be touched regardless of size: {out:#?}"
    );
}

#[test]
fn a_listed_bundle_is_claimed_only_on_its_named_subpaths() {
    let f = Fixture::new();
    let chrome = f.home.join("Library/Caches/com.google.Chrome");
    aged_dir(&chrome.join("Default/Cache"), 400_000, 90);
    // Not in the allowlist's subpaths for Chrome — user state, not cache.
    aged_dir(&chrome.join("Default/Cookies"), 400_000, 90);

    let out = app_caches::AppCaches.scan(&f.ctx()).unwrap();
    assert!(!out.is_empty(), "the listed subpath should be claimed");
    for c in &out {
        assert!(
            !c.target.display().contains("Cookies"),
            "claimed profile state: {}",
            c.target.display()
        );
    }
}

#[test]
fn a_listed_bundle_under_its_age_floor_is_not_claimed() {
    let f = Fixture::new();
    let chrome = f.home.join("Library/Caches/com.google.Chrome");
    aged_dir(&chrome.join("Default/Cache"), 400_000, 2);

    let out = app_caches::AppCaches.scan(&f.ctx()).unwrap();
    assert!(out.is_empty(), "{out:#?}");
}

#[test]
fn app_cache_candidates_carry_the_allowlists_explanation() {
    // Principle 6: the reason string tells the user what regenerating costs.
    let f = Fixture::new();
    let chrome = f.home.join("Library/Caches/com.google.Chrome");
    aged_dir(&chrome.join("Default/Cache"), 400_000, 90);

    let out = app_caches::AppCaches.scan(&f.ctx()).unwrap();
    assert!(out[0].reason.contains("regenerates"), "{}", out[0].reason);
}

// ---------------------------------------------------------------------------
// S17 — logs
// ---------------------------------------------------------------------------

#[test]
fn logs_claims_only_entries_past_the_age_floor() {
    let f = Fixture::new();
    let logs_dir = f.home.join("Library/Logs");
    aged_dir(&logs_dir.join("OldApp"), 200_000, 90);
    aged_dir(&logs_dir.join("RecentApp"), 200_000, 3);

    let out = logs::Logs.scan(&f.ctx()).unwrap();
    assert_eq!(out.len(), 1, "{out:#?}");
    assert!(out[0].label.contains("OldApp"), "{}", out[0].label);
    assert_eq!(out[0].risk, Risk::Safe);
}

#[test]
fn a_crash_report_is_labelled_as_one() {
    // Principle 6: "Crash report — Foo.crash" reads differently from "Logs —".
    let f = Fixture::new();
    aged_file(
        &f.home.join("Library/Logs/MyApp-2024-01-01.crash"),
        50_000,
        90,
    );

    let out = logs::Logs.scan(&f.ctx()).unwrap();
    assert_eq!(out.len(), 1, "{out:#?}");
    assert!(out[0].label.contains("Crash report"), "{}", out[0].label);
}

// ---------------------------------------------------------------------------
// Registry-level
// ---------------------------------------------------------------------------

#[test]
fn all_seven_registered_scanners_run_without_error() {
    let f = Fixture::new();
    aged_dir(&f.home.join(".cargo/registry/src"), 300_000, 90);
    aged_dir(&f.home.join("Library/Logs/Old"), 200_000, 90);
    aged_dir(
        &f.home
            .join("Library/Caches/com.google.Chrome/Default/Cache"),
        400_000,
        90,
    );

    let report = sift::scan::registry().run(&f.ctx(), None);
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert!(report.total_bytes() > 0);

    // Every registered scanner either produced candidates or was skipped with
    // a reason. Nothing may vanish silently (PRD §7).
    let accounted: std::collections::HashSet<&str> = report
        .candidates
        .iter()
        .map(|c| c.scanner)
        .chain(report.skipped.iter().map(|(id, _)| *id))
        .chain(report.errors.iter().map(|(id, _)| *id))
        .collect();

    for id in sift::scan::registry().ids() {
        assert!(
            accounted.contains(id),
            "scanner `{id}` vanished from the report"
        );
    }
}
