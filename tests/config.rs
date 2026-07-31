//! Config loading, merging, and validation (FR-22 … FR-25, spec §8).

use sift::config::{Config, Provenance};
use sift::{ExitCode, Risk};

// ---------------------------------------------------------------------------
// FR-22 — absence of a file means all defaults, and defaults are conservative
// ---------------------------------------------------------------------------

#[test]
fn empty_config_equals_default_config() {
    let empty = Config::parse("").unwrap();
    let default = Config::default();

    assert_eq!(empty.general.max_risk, default.general.max_risk);
    assert_eq!(
        empty.general.max_bytes_per_run,
        default.general.max_bytes_per_run
    );
    assert_eq!(empty.scanners.len(), default.scanners.len());
    for (id, cfg) in &empty.scanners {
        assert_eq!(cfg.enabled, default.scanners[id].enabled, "scanner {id}");
    }
}

#[test]
fn every_destructive_scanner_is_off_in_an_unconfigured_install() {
    // FR-22. The property that makes an unconfigured install safe.
    let cfg = Config::parse("").unwrap();
    for (id, s) in &cfg.scanners {
        if s.risk == Risk::Destructive {
            assert!(!s.enabled, "destructive scanner `{id}` enabled by default");
        }
    }
}

#[test]
fn enabling_a_destructive_scanner_is_not_enough_to_activate_it() {
    // The two-switch arming model. `enabled = true` without raising max_risk
    // must leave the scanner inactive — one careless config paste should not
    // arm irreversible deletion.
    let cfg = Config::parse(
        r#"
        [scanners.trash]
        enabled = true
        "#,
    )
    .unwrap();

    assert!(cfg.scanner("trash").unwrap().enabled);
    assert!(
        !cfg.active_scanners().iter().any(|s| s.id == "trash"),
        "trash became active without max_risk being raised to destructive"
    );
}

#[test]
fn both_switches_together_do_activate_it() {
    let cfg = Config::parse(
        r#"
        [general]
        max_risk = "destructive"

        [scanners.trash]
        enabled = true
        "#,
    )
    .unwrap();

    assert!(cfg.active_scanners().iter().any(|s| s.id == "trash"));
}

// ---------------------------------------------------------------------------
// Spec §8 — unknown keys are errors, not warnings
// ---------------------------------------------------------------------------

#[test]
fn unknown_top_level_key_is_a_config_error() {
    let err = Config::parse("nonsense = 1").unwrap_err();
    assert_eq!(err.exit_code(), ExitCode::Config);
}

#[test]
fn unknown_nested_key_is_a_config_error_and_names_the_key() {
    let err = Config::parse(
        r#"
        [general]
        max_risk_level = "safe"
        "#,
    )
    .unwrap_err();

    assert_eq!(err.exit_code(), ExitCode::Config);
    assert!(
        err.to_string().contains("max_risk_level"),
        "error should name the offending key, got: {err}"
    );
}

#[test]
fn a_typo_in_min_age_days_does_not_silently_fall_back() {
    // The failure mode this guards: `min_age_day` parsing fine, being ignored,
    // and the scanner quietly using the 14-day default the user meant to change.
    let err = Config::parse(
        r#"
        [scanners.xcode-derived]
        min_age_day = 90
        "#,
    )
    .unwrap_err();

    assert_eq!(err.exit_code(), ExitCode::Config);
    assert!(err.to_string().contains("min_age_day"), "got: {err}");
}

#[test]
fn unknown_scanner_id_is_rejected_and_lists_valid_ids() {
    let err = Config::parse(
        r#"
        [scanners.definitely-not-a-scanner]
        enabled = true
        "#,
    )
    .unwrap_err();

    assert_eq!(err.exit_code(), ExitCode::Config);
    let msg = err.to_string();
    assert!(msg.contains("definitely-not-a-scanner"), "got: {msg}");
    assert!(
        msg.contains("xcode-derived"),
        "should list known ids: {msg}"
    );
}

#[test]
fn scanner_specific_key_on_the_wrong_scanner_is_rejected() {
    // `urgency` is meaningful only for snapshots. On `logs` it would parse and
    // do nothing.
    let err = Config::parse(
        r#"
        [scanners.logs]
        urgency = 3
        "#,
    )
    .unwrap_err();

    assert_eq!(err.exit_code(), ExitCode::Config);
    assert!(err.to_string().contains("urgency"), "got: {err}");
}

#[test]
fn scanner_specific_key_on_the_right_scanner_is_accepted() {
    let cfg = Config::parse(
        r#"
        [scanners.snapshots]
        urgency = 3
        "#,
    )
    .unwrap();
    assert_eq!(cfg.scanner("snapshots").unwrap().urgency, Some(3));
}

// ---------------------------------------------------------------------------
// Value validation
// ---------------------------------------------------------------------------

#[test]
fn out_of_range_values_are_rejected() {
    let cases = [
        ("[schedule]\nhour = 24", "hour"),
        ("[schedule]\nminute = 60", "minute"),
        ("[schedule]\nskip_on_battery_below = 101", "battery"),
        ("[scanners.snapshots]\nurgency = 5", "urgency"),
        ("[scanners.snapshots]\nurgency = 0", "urgency"),
        ("[general]\nquarantine_ttl_days = 0", "ttl"),
        ("[general]\nmax_bytes_per_run = 0", "max_bytes"),
        ("[safety]\nmax_walk_depth = 0", "depth"),
    ];

    for (toml, what) in cases {
        let err = Config::parse(toml)
            .unwrap_err_or_panic(&format!("`{what}` should have been rejected: {toml}"));
        assert_eq!(err.exit_code(), ExitCode::Config, "for {what}");
    }
}

#[test]
fn zero_ttl_is_rejected_with_an_explanation() {
    // A zero TTL would purge quarantine on the run that created it, silently
    // removing the reversibility window G6 promises.
    let err = Config::parse("[general]\nquarantine_ttl_days = 0").unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("reversib") || msg.contains("purge"),
        "got: {msg}"
    );
}

#[test]
fn invalid_risk_tier_is_rejected_and_lists_valid_values() {
    let err = Config::parse("[general]\nmax_risk = \"dangerous\"").unwrap_err();
    assert_eq!(err.exit_code(), ExitCode::Config);
    let msg = err.to_string();
    assert!(
        msg.contains("safe") && msg.contains("destructive"),
        "got: {msg}"
    );
}

#[test]
fn malformed_exclude_glob_is_caught_at_load_not_mid_run() {
    let err = Config::parse(
        r#"
        [safety]
        exclude = ["["]
        "#,
    )
    .unwrap_err();
    assert_eq!(err.exit_code(), ExitCode::Config);
}

// ---------------------------------------------------------------------------
// FR-25 — project roots must be explicit
// ---------------------------------------------------------------------------

#[test]
fn project_roots_are_empty_by_default() {
    // FR-25: there is no "scan my whole home directory for target/" default.
    // S6 and S11 find nothing until the user names their roots.
    let cfg = Config::parse("").unwrap();
    assert!(
        cfg.projects.roots.is_empty(),
        "projects.roots must default to empty, got {:?}",
        cfg.projects.roots
    );
}

#[test]
fn project_roots_expand_tilde() {
    std::env::set_var("HOME", "/Users/testuser");
    let cfg = Config::parse(
        r#"
        [projects]
        roots = ["~/dev", "/abs/src"]
        "#,
    )
    .unwrap();

    assert_eq!(
        cfg.projects.roots[0],
        std::path::Path::new("/Users/testuser/dev")
    );
    assert_eq!(cfg.projects.roots[1], std::path::Path::new("/abs/src"));
}

// ---------------------------------------------------------------------------
// FR-24 — global excludes
// ---------------------------------------------------------------------------

#[test]
fn exclude_globs_compile_and_match() {
    std::env::set_var("HOME", "/Users/testuser");
    let cfg = Config::parse(
        r#"
        [safety]
        exclude = ["~/dev/active-client/**", "**/*.keychain-db"]
        "#,
    )
    .unwrap();

    let set = cfg.exclude_globs().unwrap();
    assert!(set.is_match("/Users/testuser/dev/active-client/src/main.rs"));
    assert!(set.is_match("/anywhere/login.keychain-db"));
    assert!(!set.is_match("/Users/testuser/dev/other/src/main.rs"));
}

// ---------------------------------------------------------------------------
// FR-23 — provenance
// ---------------------------------------------------------------------------

#[test]
fn provenance_distinguishes_a_written_value_from_an_identical_default() {
    // The reason provenance is tracked structurally rather than by comparing
    // against defaults: these two configs produce the same effective value, and
    // `config check` must still report them differently.
    let written = Config::parse("[general]\nquarantine_ttl_days = 7").unwrap();
    let defaulted = Config::parse("").unwrap();

    assert_eq!(
        written.general.quarantine_ttl_days,
        defaulted.general.quarantine_ttl_days
    );

    let find = |c: &Config, key: &str| {
        c.provenance()
            .into_iter()
            .find(|(k, _, _)| k == key)
            .map(|(_, _, p)| p)
            .unwrap()
    };

    assert_eq!(
        find(&written, "general.quarantine_ttl_days"),
        Provenance::File
    );
    assert_eq!(
        find(&defaulted, "general.quarantine_ttl_days"),
        Provenance::Default
    );
}

#[test]
fn provenance_covers_every_general_and_schedule_key() {
    let cfg = Config::parse("").unwrap();
    let keys: Vec<String> = cfg.provenance().into_iter().map(|(k, _, _)| k).collect();

    for expected in [
        "general.max_risk",
        "general.max_bytes_per_run",
        "general.quarantine_ttl_days",
        "general.free_space_floor",
        "safety.active_window_minutes",
        "safety.exclude",
        "projects.roots",
        "schedule.hour",
        "schedule.minute",
        "schedule.skip_on_battery_below",
        "schedule.notify_threshold",
        "schedule.max_days_between_runs",
    ] {
        assert!(
            keys.iter().any(|k| k == expected),
            "missing key: {expected}"
        );
    }
}

#[test]
fn provenance_includes_every_scanner() {
    let cfg = Config::parse("").unwrap();
    let keys: Vec<String> = cfg.provenance().into_iter().map(|(k, _, _)| k).collect();

    for id in sift::config::defaults::scanner_ids() {
        let want = format!("scanners.{id}.enabled");
        assert!(keys.contains(&want), "missing: {want}");
    }
}

// ---------------------------------------------------------------------------
// Full spec §8 example must load
// ---------------------------------------------------------------------------

#[test]
fn the_specs_own_example_config_loads() {
    std::env::set_var("HOME", "/Users/testuser");
    let cfg = Config::parse(
        r#"
        [general]
        max_risk             = "rebuildable"
        max_bytes_per_run    = "100GiB"
        quarantine_ttl_days  = 7
        free_space_floor     = "100GiB"

        [safety]
        active_window_minutes = 60
        exclude = [
          "~/dev/active-client/**",
          "**/*.keychain-db",
        ]

        [projects]
        roots = ["~/dev", "~/src"]

        [scanners.xcode-derived]
        enabled = true
        min_age_days = 14

        [scanners.snapshots]
        enabled = false
        urgency = 1

        [scanners.trash]
        enabled = false
        min_age_days = 30

        [schedule]
        hour = 3
        minute = 0
        skip_on_battery_below = 30
        notify_threshold = "1GiB"
        "#,
    )
    .expect("the technical spec's own §8 example must be valid");

    assert_eq!(cfg.general.max_risk, Risk::Rebuildable);
    assert_eq!(cfg.general.quarantine_ttl_days, 7);
    assert_eq!(cfg.projects.roots.len(), 2);
    assert_eq!(cfg.scanner("xcode-derived").unwrap().min_age_days, Some(14));
    assert_eq!(cfg.scanner("snapshots").unwrap().urgency, Some(1));
    assert_eq!(cfg.schedule.hour, 3);
}

// ---------------------------------------------------------------------------
// Small test helper
// ---------------------------------------------------------------------------

trait UnwrapErrOrPanic<T, E> {
    fn unwrap_err_or_panic(self, msg: &str) -> E;
}

impl<T, E> UnwrapErrOrPanic<T, E> for std::result::Result<T, E> {
    fn unwrap_err_or_panic(self, msg: &str) -> E {
        match self {
            Ok(_) => panic!("{msg}"),
            Err(e) => e,
        }
    }
}
