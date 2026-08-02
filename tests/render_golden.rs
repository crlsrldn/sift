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

fn ctx_estimating(yes: bool) -> ScanCtx {
    ScanCtx::new(
        Arc::new(Config::default()),
        sift::fs::volume::root().unwrap(),
        Capabilities::probe(),
    )
    .unwrap()
    .with_delegated_estimates(yes)
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
fn a_risk_gated_scanner_is_not_reported_as_disabled() {
    // These two were rendered identically as "(disabled)". A user who had set
    // `enabled = true` and was still told "disabled" would go back to the
    // `enabled` key — which was already correct — instead of to `max_risk`,
    // which is what actually held the scanner back.
    let r = ScanReport {
        duration: std::time::Duration::from_millis(40),
        skipped: vec![
            ("trash", SkippedScanner::Disabled),
            (
                "xcode-archives",
                SkippedScanner::RiskGated {
                    risk: Risk::Destructive,
                    max: Risk::Rebuildable,
                },
            ),
        ],
        ..Default::default()
    };
    let out = human::render(&r, &ctx());

    // The genuinely disabled one still says so.
    assert!(
        out.lines()
            .any(|l| l.contains("trash") && l.contains("(disabled)")),
        "{out}"
    );
    // The risk-gated one names the tier, and never the word "disabled".
    let gated = out
        .lines()
        .find(|l| l.contains("xcode-archives"))
        .unwrap_or_else(|| panic!("{out}"));
    assert!(gated.contains("destructive"), "{gated}");
    assert!(gated.contains("max_risk"), "{gated}");
    assert!(
        !gated.contains("disabled"),
        "a scanner the user enabled must not be called disabled: {gated}"
    );
}

#[test]
fn a_delegated_candidate_with_no_estimate_reads_as_unknown_not_zero() {
    // `--estimate-delegated` is off by default, so delegated candidates carry
    // 0 bytes. Rendering that as "0 B" asserts the opposite of the truth: on a
    // real machine that "0 B" stood in for 403 MB of simulator devices from two
    // uninstalled iOS runtimes.
    let mut r = ScanReport {
        duration: std::time::Duration::from_millis(40),
        ..Default::default()
    };
    r.candidates = vec![Candidate {
        scanner: "simulators",
        target: Target::Delegated(sift::scan::DelegatedCmd::new(
            "xcrun",
            &["simctl", "delete", "unavailable"],
        )),
        bytes_on_disk: 0,
        bytes_apparent: 0,
        last_modified: Local::now(),
        risk: Risk::Rebuildable,
        label: "Simulator devices for uninstalled runtimes".into(),
        reason: "xcrun simctl delete unavailable".into(),
    }];

    let out = human::render(&r, &ctx());
    let line = out
        .lines()
        .find(|l| l.contains("Simulator devices"))
        .unwrap_or_else(|| panic!("{out}"));
    assert!(line.contains("unknown"), "{line}");
    assert!(!line.contains("0 B"), "{line}");

    // And the total must admit that the line is missing from it.
    assert!(out.contains("not in that total"), "{out}");
    assert!(out.contains("--estimate-delegated"), "{out}");
}

#[test]
fn a_measured_delegated_candidate_shows_its_size() {
    // The inverse of the above: with an estimate in hand, nothing says
    // "unknown" and no footnote appears.
    let mut r = ScanReport {
        duration: std::time::Duration::from_millis(40),
        ..Default::default()
    };
    r.candidates = vec![Candidate {
        scanner: "simulators",
        target: Target::Delegated(sift::scan::DelegatedCmd::new(
            "xcrun",
            &["simctl", "delete", "unavailable"],
        )),
        bytes_on_disk: 403_000_000,
        bytes_apparent: 403_000_000,
        last_modified: Local::now(),
        risk: Risk::Rebuildable,
        label: "Simulator devices for uninstalled runtimes".into(),
        reason: "xcrun simctl delete unavailable".into(),
    }];

    let out = human::render(&r, &ctx());
    assert!(out.contains("403 MB"), "{out}");
    assert!(!out.contains("unknown"), "{out}");
    assert!(!out.contains("not in that total"), "{out}");
}

#[test]
fn disabled_findings_are_shown_apart_and_excluded_from_the_total() {
    // `--include-disabled` reports what switched-off scanners hold. The
    // report must make it impossible to read those bytes as reclaimable: they
    // sit in their own block, with their own total, and "Total identified"
    // keeps meaning "what clean would take".
    let mut r = ScanReport {
        duration: std::time::Duration::from_millis(40),
        ..Default::default()
    };
    r.candidates = vec![candidate("logs", "old logs", 1_000_000, Risk::Safe, 40)];
    r.disabled_candidates = vec![
        candidate(
            "simulators",
            "Simulator devices for uninstalled runtimes",
            403_000_000,
            Risk::Rebuildable,
            1,
        ),
        candidate(
            "homebrew",
            "Homebrew — stale downloads",
            38_000_000,
            Risk::Safe,
            1,
        ),
    ];

    let out = human::render(&r, &ctx());

    // The actionable total is untouched by the disabled block.
    assert_eq!(r.total_bytes(), 1_000_000);
    assert_eq!(r.disabled_bytes(), 441_000_000);

    let total_line = out
        .lines()
        .find(|l| l.contains("Total identified"))
        .unwrap_or_else(|| panic!("{out}"));
    assert!(total_line.contains(&human::size(1_000_000)), "{total_line}");
    assert!(
        !total_line.contains(&human::size(441_000_000)),
        "disabled bytes leaked into the actionable total: {total_line}"
    );

    // The disabled block says what it is, and says clean will not act.
    assert!(out.contains("Disabled in config"), "{out}");
    assert!(out.contains("will not touch these"), "{out}");
    assert!(out.contains(&human::size(441_000_000)), "{out}");
    assert!(out.contains(&human::size(403_000_000)), "{out}");

    // The disabled block must come after the real total, so nobody reading
    // top-down mistakes it for part of the answer.
    let total_at = out.find("Total identified").unwrap();
    let disabled_at = out.find("Disabled in config").unwrap();
    assert!(total_at < disabled_at, "{out}");
}

#[test]
fn no_disabled_block_appears_without_the_flag() {
    let mut r = ScanReport {
        duration: std::time::Duration::from_millis(40),
        ..Default::default()
    };
    r.candidates = vec![candidate("logs", "old logs", 1_000_000, Risk::Safe, 40)];

    let out = human::render(&r, &ctx());
    assert!(!out.contains("Disabled in config"), "{out}");
    assert!(!out.contains("Held by disabled scanners"), "{out}");
}

#[test]
fn the_unknown_footnote_does_not_suggest_a_flag_already_given() {
    // Telling someone to re-run with a flag they just used implies the number
    // is retrievable, when the tool has already been asked and had no answer.
    let mut r = ScanReport {
        duration: std::time::Duration::from_millis(40),
        ..Default::default()
    };
    r.candidates = vec![Candidate {
        scanner: "python-caches",
        target: Target::Delegated(sift::scan::DelegatedCmd::new("uv", &["cache", "prune"])),
        bytes_on_disk: 0,
        bytes_apparent: 0,
        last_modified: Local::now(),
        risk: Risk::Safe,
        label: "uv cache".into(),
        reason: "test".into(),
    }];

    let asked = human::render(&r, &ctx_estimating(true));
    assert!(asked.contains("did not report one"), "{asked}");
    assert!(
        !asked.contains("Re-run with --estimate-delegated"),
        "{asked}"
    );

    let not_asked = human::render(&r, &ctx_estimating(false));
    assert!(
        not_asked.contains("Re-run with --estimate-delegated"),
        "{not_asked}"
    );
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
