//! The PRD §7 target report, reproduced from a synthetic candidate set.
//!
//! The PRD specifies an exact report format and calls out its design intent:
//! *"the summary is scannable in three seconds, the risk tier is always
//! visible, and skipped/blocked items are surfaced rather than silently
//! omitted."* This file pins all three, so the format cannot drift without a
//! deliberate decision to change it.

use chrono::{Duration, Local};
use sift::caps::Capabilities;
use sift::config::Config;
use sift::report::human;
use sift::risk::Risk;
use sift::scan::{Candidate, ScanCtx, ScanReport, SkippedScanner, Target};
use std::sync::Arc;

fn ctx() -> ScanCtx {
    ScanCtx::new(
        Arc::new(Config::default()),
        sift::fs::volume::root().unwrap(),
        Capabilities::probe(),
    )
    .unwrap()
}

fn candidate(
    scanner: &'static str,
    label: &str,
    bytes: u64,
    risk: Risk,
    age_days: i64,
) -> Candidate {
    Candidate {
        scanner,
        target: Target::Path(format!("/tmp/{scanner}").into()),
        bytes_on_disk: bytes,
        bytes_apparent: bytes,
        last_modified: Local::now() - Duration::days(age_days),
        risk,
        label: label.into(),
        reason: format!("not modified in {age_days} days"),
    }
}

/// Approximates the PRD §7 example.
fn prd_example() -> ScanReport {
    let mut r = ScanReport {
        duration: std::time::Duration::from_millis(4200),
        ..Default::default()
    };
    r.candidates = vec![
        candidate(
            "xcode-devicesupport",
            "iOS DeviceSupport   iOS 15.x–16.x, 9 bundles",
            22_100_000_000,
            Risk::Rebuildable,
            180,
        ),
        candidate(
            "xcode-derived",
            "DerivedData         14 projects, >14d idle",
            8_400_000_000,
            Risk::Rebuildable,
            31,
        ),
        candidate(
            "simulators",
            "Simulator caches",
            1_200_000_000,
            Risk::Safe,
            0,
        ),
        candidate(
            "rust-targets",
            "target/  6 projects under ~/dev, >30d idle",
            8_800_000_000,
            Risk::Rebuildable,
            45,
        ),
        candidate("cargo-cache", "registry cache", 500_000_000, Risk::Safe, 90),
        candidate(
            "containers",
            "docker: dangling images + build cache",
            6_100_000_000,
            Risk::Rebuildable,
            0,
        ),
        candidate("homebrew", "Homebrew cache", 2_400_000_000, Risk::Safe, 0),
        candidate(
            "app-caches",
            "Browser caches",
            1_100_000_000,
            Risk::Safe,
            40,
        ),
    ];
    r.skipped = vec![
        ("snapshots", SkippedScanner::Disabled),
        ("trash", SkippedScanner::Disabled),
        ("mail-downloads", SkippedScanner::NeedsFda),
    ];
    r
}

#[test]
fn the_report_matches_the_prd_layout() {
    let out = human::render(&prd_example(), &ctx());
    println!("{out}");

    // Header
    assert!(out.starts_with("sift — scan complete in 4.2s"), "{out}");
    assert!(out.contains("Volume:"), "{out}");

    // Families, in PRD order
    for family in ["Xcode", "Rust", "Containers", "Homebrew", "Caches"] {
        assert!(out.contains(family), "missing family `{family}`:\n{out}");
    }
    let xcode = out.find("Xcode").unwrap();
    let rust = out.find("Rust").unwrap();
    let containers = out.find("Containers").unwrap();
    assert!(xcode < rust, "Xcode must lead:\n{out}");
    assert!(rust < containers, "Rust before Containers:\n{out}");

    // Sizes in the PRD's own style
    assert!(out.contains("22.1 GB"), "{out}");
    assert!(out.contains("8.4 GB"), "{out}");
    assert!(out.contains("Total identified"), "{out}");

    // Footer
    assert!(out.contains("Nothing has been deleted"), "{out}");
}

#[test]
fn the_risk_tier_is_visible_on_every_candidate_line() {
    // PRD §7 design intent. Without this the report says "8.4 GB" and the user
    // cannot tell whether that is a cache or their Time Machine history.
    let out = human::render(&prd_example(), &ctx());

    let labelled = out
        .lines()
        .filter(|l| l.contains("GB") || l.contains("MB"))
        .filter(|l| l.starts_with("    ") && !l.contains("Total"))
        .count();
    let with_risk = out
        .lines()
        .filter(|l| l.contains("safe") || l.contains("rebuildable") || l.contains("destructive"))
        .count();

    assert!(labelled > 0, "no candidate lines found:\n{out}");
    assert_eq!(
        labelled, with_risk,
        "every candidate line must carry its risk tier:\n{out}"
    );
}

#[test]
fn skipped_and_blocked_are_surfaced_not_omitted() {
    // The G7 honesty differentiator: the commercial cleaners this tool reacts
    // to are notable for quietly omitting what they could not touch.
    let out = human::render(&prd_example(), &ctx());

    assert!(out.contains("Skipped:"), "{out}");
    assert!(out.contains("snapshots"), "{out}");
    assert!(out.contains("trash"), "{out}");

    assert!(out.contains("Blocked:"), "{out}");
    assert!(out.contains("mail-downloads"), "{out}");
    assert!(out.contains("Full Disk Access"), "{out}");
    assert!(out.contains("sift doctor"), "{out}");
}

#[test]
fn scanner_errors_are_shown_not_buried_in_a_log() {
    // A failed scanner means the total is an undercount. The user must know
    // that from the report itself, not by remembering to check SIFT_LOG.
    let mut r = prd_example();
    r.errors.push(("logs", "permission denied".into()));

    let out = human::render(&r, &ctx());
    assert!(out.contains("Error:"), "{out}");
    assert!(out.contains("logs"), "{out}");
    assert!(out.contains("permission denied"), "{out}");
}

#[test]
fn an_empty_result_reads_as_a_result_not_a_broken_frame() {
    let r = ScanReport {
        duration: std::time::Duration::from_millis(120),
        ..Default::default()
    };
    let out = human::render(&r, &ctx());

    assert!(out.contains("Nothing reclaimable found"), "{out}");
    assert!(out.contains("Nothing has been deleted"), "{out}");
    assert!(!out.contains("Total identified"), "{out}");
}

#[test]
fn an_empty_result_with_blocked_scanners_says_why() {
    // "Found nothing" and "could not look" require completely different user
    // actions, so they must not render identically.
    let r = ScanReport {
        duration: std::time::Duration::from_millis(80),
        skipped: vec![("mail-downloads", SkippedScanner::NeedsFda)],
        ..Default::default()
    };
    let out = human::render(&r, &ctx());

    assert!(out.contains("could not run"), "{out}");
    assert!(out.contains("Blocked:"), "{out}");
}

#[test]
fn the_total_equals_the_sum_of_the_candidates() {
    let r = prd_example();
    let expected: u64 = r.candidates.iter().map(|c| c.bytes_on_disk).sum();
    assert_eq!(r.total_bytes(), expected);

    let out = human::render(&r, &ctx());
    assert!(out.contains(&human::size(expected)), "{out}");
}

#[test]
fn a_pathological_label_cannot_break_the_layout() {
    // Labels derive from filesystem paths, which may contain arbitrary Unicode
    // and arbitrary length.
    let mut r = ScanReport {
        duration: std::time::Duration::from_millis(10),
        ..Default::default()
    };
    r.candidates = vec![
        candidate("logs", &"あ".repeat(400), 1_000_000, Risk::Safe, 40),
        candidate("logs", "", 2_000_000, Risk::Safe, 40),
    ];

    let out = human::render(&r, &ctx());
    for line in out.lines() {
        assert!(
            line.chars().count() < 120,
            "line ran away: {} chars",
            line.chars().count()
        );
    }
}
