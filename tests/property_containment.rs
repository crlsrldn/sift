//! The allowlist containment property (G2, spec §12).
//!
//! Spec §12 names this "the single most important test in the suite":
//!
//! > for a randomly generated tree and random config, the set of actioned paths
//! > is always a subset of the scanner's declared allowlist roots.
//!
//! # Why this and not more example tests
//!
//! Every other safety test asserts something specific I thought of. This one
//! asserts the general rule, over trees and configurations nobody chose. It is
//! the only test here capable of catching a scanner reaching somewhere I did
//! not anticipate — which is precisely the failure mode that ends the product.
//!
//! Failing seeds are printed by `proptest` and persisted to
//! `tests/property_containment.proptest-regressions`, so a failure is
//! reproducible rather than a one-off.

use proptest::prelude::*;
use sift::caps::Capabilities;
use sift::config::Config;
use sift::scan::{ScanCtx, Target};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

static HOME_LOCK: Mutex<()> = Mutex::new(());

/// The complete set of roots any scanner is permitted to claim from, relative
/// to `$HOME`.
///
/// This is the *declaration* the property checks against. It is written by
/// hand from the spec §6 scanner definitions rather than derived from the
/// code, deliberately: a list derived from the implementation would agree with
/// the implementation by construction and prove nothing.
const ALLOWLIST_ROOTS: &[&str] = &[
    // S2, S3, S4, S5 — Xcode
    "Library/Developer/Xcode/DerivedData",
    "Library/Developer/Xcode/iOS DeviceSupport",
    "Library/Developer/Xcode/watchOS DeviceSupport",
    "Library/Developer/Xcode/tvOS DeviceSupport",
    "Library/Developer/Xcode/macOS DeviceSupport",
    "Library/Developer/Xcode/Archives",
    "Library/Developer/CoreSimulator/Caches",
    // S6 — rust targets, under configured project roots only
    // (matched structurally below, since the root is user-configured)
    // S7 — cargo caches
    ".cargo/registry/cache",
    ".cargo/registry/src",
    ".cargo/git/checkouts",
    // S10, S11 — node and python
    ".npm/_cacache",
    "Library/Caches/pip",
    // S14 — app caches
    "Library/Caches",
    // S16 — mail
    "Library/Containers/com.apple.mail",
    // S17 — logs
    "Library/Logs",
    // S12, S13, S15 — destructive tier
    ".Trash",
    "Downloads",
    "Library/Application Support/MobileSync/Backup",
];

/// Whether a claimed path is inside a declared allowlist root.
///
/// A `target/` directory is accepted only when it has a sibling `Cargo.toml`,
/// which is S6's own rule — the structural claim, not a fixed path.
fn is_declared(home: &Path, claimed: &Path) -> bool {
    for root in ALLOWLIST_ROOTS {
        let r = home.join(root);
        if claimed == r || claimed.starts_with(&r) {
            return true;
        }
    }

    if claimed.file_name().map(|n| n == "target").unwrap_or(false) {
        if let Some(parent) = claimed.parent() {
            if parent.join("Cargo.toml").is_file() {
                return true;
            }
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

/// A path component that is plausible on a real machine, mixing innocuous
/// names with ones that resemble things scanners look for.
fn component() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("target".to_string()),
        Just("Caches".to_string()),
        Just("DerivedData".to_string()),
        Just("Logs".to_string()),
        Just("Documents".to_string()),
        Just(".ssh".to_string()),
        Just("src".to_string()),
        Just("node_modules".to_string()),
        Just("Library".to_string()),
        Just(".cargo".to_string()),
        Just("registry".to_string()),
        Just("Developer".to_string()),
        Just("Xcode".to_string()),
        "[a-z]{1,8}".prop_map(|s| s),
    ]
}

fn relative_path() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(component(), 1..5)
}

/// Build a config from generated inputs.
///
/// Every scanner is always enabled, because the property must hold for the most
/// permissive arrangement the tool allows — not just the default one.
fn config_toml(home: &Path, max_risk: &str, min_age: u32, roots: bool, window: u32) -> String {
    let mut t = format!(
        "[general]\nmax_risk = \"{max_risk}\"\nmax_bytes_per_run = \"1000GiB\"\n\n\
         [safety]\nactive_window_minutes = {window}\n\n"
    );
    if roots {
        t.push_str(&format!("[projects]\nroots = [\"{}\"]\n\n", home.display()));
    }
    for id in sift::config::defaults::scanner_ids() {
        t.push_str(&format!(
            "[scanners.{id}]\nenabled = true\nmin_age_days = {min_age}\n\n"
        ));
    }
    t
}

// ---------------------------------------------------------------------------
// The property
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        max_shrink_iters: 2000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn every_actioned_path_is_inside_a_declared_allowlist_root(
        paths in prop::collection::vec(relative_path(), 1..12),
        seed in any::<u64>(),
        max_risk in prop::sample::select(vec!["safe", "rebuildable", "destructive"]),
        min_age in 0u32..3650,
        roots in prop::bool::ANY,
        window in 0u32..120,
    ) {
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let prev = std::env::var_os("HOME");
        std::env::set_var("HOME", &home);

        // Build the random tree.
        for parts in &paths {
            let mut p = home.clone();
            for part in parts {
                p.push(part);
            }
            let _ = fs::create_dir_all(&p);
            let _ = fs::write(p.join("file.bin"), vec![0u8; 4096]);
            // Ancient, so no age floor can be the reason nothing is claimed.
            let when = chrono::Local::now() - chrono::Duration::days(3000);
            let ft = filetime::FileTime::from_unix_time(when.timestamp(), 0);
            let _ = filetime::set_file_mtime(p.join("file.bin"), ft);
            let _ = filetime::set_file_mtime(&p, ft);
        }

        // Some `target` directories get a sibling Cargo.toml and some do not,
        // so both branches of S6's rule are exercised.
        if seed % 2 == 0 {
            for parts in &paths {
                if parts.last().map(|s| s == "target").unwrap_or(false) {
                    let mut p = home.clone();
                    for part in &parts[..parts.len() - 1] {
                        p.push(part);
                    }
                    let _ = fs::write(p.join("Cargo.toml"), b"[package]\nname = \"x\"\n");
                }
            }
        }

        let toml = config_toml(&home, max_risk, min_age, roots, window);
        let cfg = Config::parse(&toml).expect("generated config must be valid");

        let ctx = ScanCtx::new(
            Arc::new(cfg),
            sift::fs::volume::root().unwrap(),
            Capabilities::probe(),
        )
        .unwrap();

        let report = sift::scan::registry().run(&ctx, None);
        let filtered = sift::action::filter::apply(&ctx, report.candidates, |c| {
            sift::action::liveness::check(&ctx, c)
        });

        let mut violations: Vec<(String, PathBuf)> = Vec::new();
        for c in &filtered.accepted {
            if let Target::Path(p) = &c.target {
                if !is_declared(&home, p) {
                    violations.push((c.scanner.to_string(), p.clone()));
                }
            }
        }

        match &prev {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }

        prop_assert!(
            violations.is_empty(),
            "scanner(s) claimed paths outside every declared allowlist root:\n{}",
            violations
                .iter()
                .map(|(s, p)| format!("  {s}: {}", p.display()))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

// ---------------------------------------------------------------------------
// The property test's own sanity
// ---------------------------------------------------------------------------

#[test]
fn is_declared_accepts_real_allowlist_paths() {
    let home = Path::new("/Users/x");
    assert!(is_declared(
        home,
        &home.join("Library/Developer/Xcode/DerivedData/App-abc")
    ));
    assert!(is_declared(home, &home.join(".cargo/registry/src")));
    assert!(is_declared(home, &home.join("Library/Logs/MyApp")));
}

#[test]
fn is_declared_rejects_everything_outside_them() {
    // If this were permissive, the property above would pass vacuously.
    let home = Path::new("/Users/x");
    for bad in [
        "Documents/thesis.pdf",
        ".ssh/id_ed25519",
        "dev/myproject/src",
        ".rustup/toolchains",
        ".cargo/bin",
        "Library/Mail/V10",
    ] {
        assert!(
            !is_declared(home, &home.join(bad)),
            "`{bad}` should not be considered declared"
        );
    }
}

#[test]
fn is_declared_applies_the_s6_sibling_rule_rather_than_a_fixed_path() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();

    let with_manifest = home.join("dev/real/target");
    fs::create_dir_all(&with_manifest).unwrap();
    fs::write(home.join("dev/real/Cargo.toml"), b"[package]").unwrap();

    let without = home.join("dev/fake/target");
    fs::create_dir_all(&without).unwrap();

    assert!(is_declared(home, &with_manifest));
    assert!(
        !is_declared(home, &without),
        "a `target` with no sibling Cargo.toml must not be declared"
    );
}
