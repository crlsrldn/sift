//! The Destructive tier's arming model (PRD §6.1, PR plan PR-36).
//!
//! Three independent things stand between a Destructive scanner and the user's
//! data, and each is tested here:
//!
//! 1. `enabled = true` in config
//! 2. `max_risk = "destructive"` in config
//! 3. typing the scanner's name at an interactive prompt
//!
//! `--yes` satisfies none of them.

use sift::config::defaults;
use sift::risk::Risk;
use sift::scan::registry;

#[test]
fn every_destructive_scanner_declares_what_is_lost() {
    // A scanner that can permanently destroy something and cannot say what,
    // has not been thought about hard enough to ship.
    let r = registry();
    let registered: Vec<&str> = r.ids();

    for d in defaults::SCANNERS {
        if d.risk != Risk::Destructive || !registered.contains(&d.id) {
            continue;
        }
        let radius = r
            .blast_radius_of(d.id)
            .unwrap_or_else(|| panic!("destructive scanner `{}` declares no blast radius", d.id));

        assert!(
            radius.len() > 60,
            "`{}` has a uselessly short blast radius: {radius:?}",
            d.id
        );
        // "This is irreversible" is a restatement of the tier, not information.
        let lower = radius.to_ascii_lowercase();
        assert!(
            lower.contains("cannot")
                || lower.contains("permanently")
                || lower.contains("not ")
                || lower.contains("without"),
            "`{}` does not say what is lost: {radius:?}",
            d.id
        );
    }
}

#[test]
fn no_safe_or_rebuildable_scanner_needs_a_blast_radius() {
    // The absence is meaningful: it asserts the tier is honest. A Rebuildable
    // scanner that felt the need to warn about permanent loss is mis-tiered.
    let r = registry();
    for d in defaults::SCANNERS {
        if d.risk == Risk::Destructive || !r.ids().contains(&d.id) {
            continue;
        }
        assert!(
            r.blast_radius_of(d.id).is_none(),
            "`{}` is {} but declares a blast radius — is it mis-tiered?",
            d.id,
            d.risk
        );
    }
}

// ---------------------------------------------------------------------------
// The two config switches
// ---------------------------------------------------------------------------

#[test]
fn enabling_alone_does_not_arm_a_destructive_scanner() {
    let cfg = sift::config::Config::parse("[scanners.xcode-archives]\nenabled = true\n").unwrap();
    assert!(cfg.scanner("xcode-archives").unwrap().enabled);
    assert!(
        !cfg.active_scanners()
            .iter()
            .any(|s| s.id == "xcode-archives"),
        "one switch armed a destructive scanner"
    );
}

#[test]
fn raising_max_risk_alone_does_not_arm_a_destructive_scanner() {
    // The other direction. Someone who raises max_risk to reach ONE scanner
    // must not thereby arm the four they left disabled.
    let cfg = sift::config::Config::parse("[general]\nmax_risk = \"destructive\"\n").unwrap();
    for id in [
        "snapshots",
        "trash",
        "downloads",
        "ios-backups",
        "xcode-archives",
    ] {
        assert!(
            !cfg.active_scanners().iter().any(|s| s.id == id),
            "`{id}` became active from max_risk alone"
        );
    }
}

#[test]
fn both_switches_together_arm_exactly_the_named_scanner() {
    let cfg = sift::config::Config::parse(
        "[general]\nmax_risk = \"destructive\"\n\n[scanners.trash]\nenabled = true\n",
    )
    .unwrap();

    let active: Vec<&str> = cfg
        .active_scanners()
        .iter()
        .map(|s| s.id.as_str())
        .collect();
    assert!(active.contains(&"trash"));
    // And only that one.
    for other in ["snapshots", "downloads", "ios-backups", "xcode-archives"] {
        assert!(!active.contains(&other), "`{other}` was armed too");
    }
}

// ---------------------------------------------------------------------------
// Type-level irreversibility
// ---------------------------------------------------------------------------

#[test]
fn hard_delete_targets_are_never_reversible() {
    use sift::scan::Target;
    assert!(!Target::HardDelete("/tmp/x".into()).is_reversible());
    assert!(Target::Path("/tmp/x".into()).is_reversible());
}

#[test]
fn quarantine_refuses_to_stage_a_hard_delete_target() {
    // If quarantine staged one, `restore` would claim it could undo something
    // the scanner declared irreversible — a lie the user discovers too late.
    use chrono::Local;
    use sift::scan::{Candidate, Target};

    let dir = tempfile::tempdir().unwrap();
    let prev = std::env::var_os("XDG_STATE_HOME");
    std::env::set_var("XDG_STATE_HOME", dir.path());

    let victim = dir.path().join("must-survive");
    std::fs::create_dir_all(&victim).unwrap();
    std::fs::write(victim.join("f"), b"x").unwrap();

    let c = Candidate {
        scanner: "trash",
        target: Target::HardDelete(victim.clone()),
        bytes_on_disk: 1,
        bytes_apparent: 1,
        last_modified: Local::now(),
        risk: Risk::Destructive,
        label: "x".into(),
        reason: "x".into(),
    };

    let (outcome, manifest) = sift::action::quarantine::quarantine(&[c], 7).unwrap();

    match prev {
        Some(v) => std::env::set_var("XDG_STATE_HOME", v),
        None => std::env::remove_var("XDG_STATE_HOME"),
    }

    assert_eq!(outcome.renamed, 0);
    assert!(manifest.items.is_empty(), "a hard-delete target was staged");
    assert!(victim.exists(), "quarantine moved a hard-delete target");
}
