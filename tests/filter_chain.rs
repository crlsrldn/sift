//! The composed filter chain (FR-16, FR-17, FR-24, spec §7).
//!
//! The unit tests in `action::*` cover each stage. These cover the composition,
//! and specifically the ordering guarantee that makes the circuit breaker worth
//! having: **check, then act.**

use chrono::{Duration, Local};
use sift::action::{breaker, filter, liveness};
use sift::caps::Capabilities;
use sift::config::Config;
use sift::risk::Risk;
use sift::scan::{Candidate, ScanCtx, Target};
use std::sync::Arc;

fn ctx(cfg: Config) -> ScanCtx {
    ScanCtx::new(
        Arc::new(cfg),
        sift::fs::volume::root().unwrap(),
        Capabilities::probe(),
    )
    .unwrap()
}

fn candidate(scanner: &'static str, risk: Risk, bytes: u64, age_days: i64) -> Candidate {
    Candidate {
        scanner,
        target: Target::Path(format!("/tmp/sift-filter-test/{scanner}").into()),
        bytes_on_disk: bytes,
        bytes_apparent: bytes,
        last_modified: Local::now() - Duration::days(age_days),
        risk,
        label: scanner.into(),
        reason: "test".into(),
    }
}

/// The real chain: filter with the real liveness guard, then the breaker.
fn run_chain(
    ctx: &ScanCtx,
    candidates: Vec<Candidate>,
) -> Result<filter::Filtered, sift::SiftError> {
    let filtered = filter::apply(ctx, candidates, |c| liveness::check(ctx, c));
    breaker::enforce(
        &filtered.accepted,
        ctx.config.general.max_bytes_per_run.bytes(),
    )?;
    Ok(filtered)
}

#[test]
fn a_clean_candidate_set_passes_the_whole_chain() {
    let c = ctx(Config::default());
    let out = run_chain(
        &c,
        vec![
            candidate("logs", Risk::Safe, 1_000_000, 90),
            candidate("cargo-cache", Risk::Safe, 2_000_000, 90),
        ],
    )
    .unwrap();

    assert_eq!(out.accepted.len(), 2);
    assert_eq!(out.total_bytes(), 3_000_000);
}

#[test]
fn the_breaker_sees_only_what_survived_filtering() {
    // Ordering matters: if the breaker counted rejected candidates it would
    // trip on bytes that were never going to be actioned, which is a false
    // alarm that trains users to raise the limit.
    let c = ctx(Config::parse("[general]\nmax_bytes_per_run = \"10MB\"\n").unwrap());

    let out = run_chain(
        &c,
        vec![
            candidate("logs", Risk::Safe, 5_000_000, 90),
            // Destructive: rejected before the breaker ever sees it.
            candidate("trash", Risk::Destructive, 900_000_000, 90),
        ],
    )
    .expect("the destructive candidate should not count toward the ceiling");

    assert_eq!(out.accepted.len(), 1);
    assert_eq!(out.total_bytes(), 5_000_000);
}

#[test]
fn exceeding_the_ceiling_aborts_with_exit_four_and_an_empty_action_set() {
    // FR-16. The guarantee is not "stops early" but "acts on nothing at all".
    let c = ctx(Config::parse("[general]\nmax_bytes_per_run = \"1MB\"\n").unwrap());

    let err = run_chain(
        &c,
        vec![
            candidate("logs", Risk::Safe, 900_000, 90),
            candidate("cargo-cache", Risk::Safe, 900_000, 90),
        ],
    )
    .unwrap_err();

    assert_eq!(err.exit_code(), sift::ExitCode::CircuitBreaker);
    assert!(err.to_string().contains("nothing was actioned"));
}

#[test]
fn the_trip_message_names_the_scanner_responsible() {
    // A bare "200 GB exceeds 100 GB" is not actionable. The user needs to know
    // which scanner misbehaved.
    let candidates = vec![
        candidate("logs", Risk::Safe, 1_000, 90),
        candidate("xcode-derived", Risk::Rebuildable, 500_000_000_000, 90),
    ];
    let out = breaker::render_trip(&candidates, 500_000_001_000, 100_000_000_000);

    assert!(out.contains("NOTHING HAS BEEN ACTIONED"), "{out}");
    let xcode_pos = out.find("xcode-derived").expect("scanner not named");
    let logs_pos = out.find("logs").expect("scanner not named");
    assert!(
        xcode_pos < logs_pos,
        "worst offender must be listed first:\n{out}"
    );
}

#[test]
fn an_exclude_pattern_removes_bytes_from_the_breakers_total() {
    // FR-24 and FR-16 compose: excluding a tree must also stop it counting
    // toward the ceiling, or a user's own exclusion could trip the breaker.
    let c = ctx(Config::parse(
        "[general]\nmax_bytes_per_run = \"10MB\"\n\n[safety]\nexclude = [\"/tmp/sift-filter-test/xcode-derived\"]\n",
    )
    .unwrap());

    let out = run_chain(
        &c,
        vec![
            candidate("logs", Risk::Safe, 1_000_000, 90),
            candidate("xcode-derived", Risk::Rebuildable, 900_000_000, 90),
        ],
    )
    .expect("the excluded candidate must not count toward the ceiling");

    assert_eq!(out.accepted.len(), 1);
    assert_eq!(out.rejected_for(&filter::Rejection::Excluded), 1);
}

#[test]
fn a_live_tree_is_rejected_by_the_real_guard() {
    // FR-17 end to end, against an actual filesystem rather than an injected
    // stub: a directory whose top level looks old but which contains a file
    // written seconds ago.
    let dir = tempfile::tempdir().unwrap();
    let deep = dir.path().join("Build/Intermediates/live.o");
    std::fs::create_dir_all(deep.parent().unwrap()).unwrap();
    std::fs::write(&deep, b"an active build").unwrap();

    let old = Local::now() - Duration::days(90);
    let ft = filetime::FileTime::from_unix_time(old.timestamp(), 0);
    filetime::set_file_mtime(dir.path(), ft).unwrap();

    let mut c = candidate("logs", Risk::Safe, 1_000_000, 90);
    c.target = Target::Path(dir.path().to_path_buf());

    let cx = ctx(Config::default());
    let out = run_chain(&cx, vec![c]).unwrap();

    assert!(
        out.accepted.is_empty(),
        "an actively written tree must never be actioned: {:?}",
        out.accepted
    );
    assert!(matches!(
        out.rejected[0].reason,
        filter::Rejection::Active { .. }
    ));
}

#[test]
fn every_rejected_candidate_is_reported_with_a_reason() {
    // PRD §7: nothing vanishes silently. A user who expected something cleaned
    // is owed an answer.
    let c = ctx(Config::default());
    let out = filter::apply(
        &c,
        vec![
            candidate("trash", Risk::Destructive, 1_000, 90), // risk
            candidate("logs", Risk::Safe, 1_000, 1),          // too young
            candidate("logs", Risk::Safe, 0, 90),             // empty
        ],
        |_| None,
    );

    assert!(out.accepted.is_empty());
    assert_eq!(out.rejected.len(), 3);
    for r in &out.rejected {
        assert!(!r.reason.describe().is_empty());
    }
}
