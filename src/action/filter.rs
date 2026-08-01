//! The candidate filter chain (spec §7).
//!
//! ```text
//! scan → filter(risk ≤ max_risk, age ≥ min, !excluded, !dataless)
//!      → liveness_guard(nothing modified within active_window_minutes)
//!      → circuit_breaker(Σ bytes ≤ max_bytes_per_run)
//! ```
//!
//! Everything here is a **pure decision over already-gathered facts**. Nothing
//! in this module opens, renames, or deletes anything. That is deliberate: this
//! is the code that decides what gets destroyed, and it should be reviewable
//! and exhaustively testable without a filesystem in the picture.
//!
//! The one exception is the liveness guard, which must consult the filesystem
//! to know whether a tree is being written to. It is isolated in `liveness.rs`
//! and injected, so the chain itself stays pure.

use crate::risk::Risk;
use crate::scan::{Candidate, ScanCtx, Target};

/// Why a candidate was refused.
///
/// Rejections are values, not silent drops. A user who expected something to be
/// cleaned is owed an answer, and "the exclude glob caught it" and "it was
/// modified 10 minutes ago" call for very different responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    /// Risk tier above `general.max_risk`.
    RiskTooHigh { risk: Risk, max: Risk },
    /// Younger than the scanner's floor.
    TooYoung { age_days: i64, min_days: i64 },
    /// Matched a `safety.exclude` pattern (FR-24).
    Excluded,
    /// Something in the tree was modified inside the liveness window (FR-17).
    Active { minutes_ago: i64 },
    /// Zero reclaimable bytes — nothing to gain, so not worth any risk.
    Empty,
}

impl Rejection {
    pub fn describe(&self) -> String {
        match self {
            Rejection::RiskTooHigh { risk, max } => {
                format!("risk tier {risk} exceeds max_risk {max}")
            }
            Rejection::TooYoung { age_days, min_days } => {
                format!("{age_days}d old, floor is {min_days}d")
            }
            Rejection::Excluded => "matched a safety.exclude pattern".into(),
            Rejection::Active { minutes_ago } => {
                format!("modified {minutes_ago} minutes ago; may be in use")
            }
            Rejection::Empty => "nothing reclaimable".into(),
        }
    }
}

/// A candidate paired with why it was refused.
#[derive(Debug, Clone)]
pub struct Rejected {
    pub candidate: Candidate,
    pub reason: Rejection,
}

/// What survived the chain, and what did not.
#[derive(Debug, Default)]
pub struct Filtered {
    pub accepted: Vec<Candidate>,
    pub rejected: Vec<Rejected>,
}

impl Filtered {
    pub fn total_bytes(&self) -> u64 {
        self.accepted.iter().map(|c| c.bytes_on_disk).sum()
    }

    pub fn rejected_for(&self, reason: &Rejection) -> usize {
        self.rejected.iter().filter(|r| &r.reason == reason).count()
    }
}

/// Decide a single candidate against everything except liveness.
///
/// Order matters only for the quality of the reported reason, not the outcome —
/// a candidate failing several checks is reported by the first, and risk is
/// checked first because it is the most fundamental objection.
pub fn check(ctx: &ScanCtx, c: &Candidate) -> Option<Rejection> {
    if c.risk > ctx.config.general.max_risk {
        return Some(Rejection::RiskTooHigh {
            risk: c.risk,
            max: ctx.config.general.max_risk,
        });
    }

    if let Some(min) = ctx
        .config
        .scanner(c.scanner)
        .and_then(|s| s.min_age_days)
        .map(i64::from)
    {
        let age = c.age_days(ctx.now);
        if age < min {
            return Some(Rejection::TooYoung {
                age_days: age,
                min_days: min,
            });
        }
    }

    // Only path targets are rejected for being empty. A delegated command's
    // reclaim is not knowable without running the tool, and `scan` must not run
    // anything (FR-1) — so a delegated candidate legitimately reports zero and
    // must not be dropped for it.
    if c.bytes_on_disk == 0 && matches!(c.target, Target::Path(_)) {
        return Some(Rejection::Empty);
    }

    // FR-24: the user's exclude list is the final veto over path targets. It is
    // checked last so its rejection is what gets reported when it applies —
    // "you excluded this" is more useful than "it was too young".
    if let Target::Path(p) = &c.target {
        if ctx.excludes.is_match(p) {
            return Some(Rejection::Excluded);
        }
    }

    None
}

/// Run the chain over a candidate set.
///
/// `liveness` is injected so the pure decisions can be tested without a
/// filesystem, and so the real guard can be exercised separately.
pub fn apply<F>(ctx: &ScanCtx, candidates: Vec<Candidate>, liveness: F) -> Filtered
where
    F: Fn(&Candidate) -> Option<i64>,
{
    let mut out = Filtered::default();

    for c in candidates {
        if let Some(reason) = check(ctx, &c) {
            out.rejected.push(Rejected {
                candidate: c,
                reason,
            });
            continue;
        }

        // FR-17. Last, because it is the only check that costs a walk.
        if let Some(minutes_ago) = liveness(&c) {
            out.rejected.push(Rejected {
                candidate: c,
                reason: Rejection::Active { minutes_ago },
            });
            continue;
        }

        out.accepted.push(c);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps::Capabilities;
    use crate::config::Config;
    use chrono::{Duration, Local};
    use std::sync::Arc;

    fn ctx(cfg: Config) -> ScanCtx {
        ScanCtx::new(
            Arc::new(cfg),
            crate::fs::volume::root().unwrap(),
            Capabilities::probe(),
        )
        .unwrap()
    }

    fn candidate(scanner: &'static str, risk: Risk, bytes: u64, age_days: i64) -> Candidate {
        Candidate {
            scanner,
            target: Target::Path(format!("/tmp/sift-test/{scanner}").into()),
            bytes_on_disk: bytes,
            bytes_apparent: bytes,
            last_modified: Local::now() - Duration::days(age_days),
            risk,
            label: scanner.into(),
            reason: "test".into(),
        }
    }

    /// No candidate is ever considered active.
    fn never_active(_: &Candidate) -> Option<i64> {
        None
    }

    #[test]
    fn max_risk_safe_rejects_everything_above_it() {
        let c = ctx(Config::parse("[general]\nmax_risk = \"safe\"\n").unwrap());
        let candidates = vec![
            candidate("logs", Risk::Safe, 1000, 90),
            candidate("xcode-derived", Risk::Rebuildable, 1000, 90),
            candidate("trash", Risk::Destructive, 1000, 90),
        ];

        let out = apply(&c, candidates, never_active);
        assert_eq!(out.accepted.len(), 1);
        assert_eq!(out.accepted[0].risk, Risk::Safe);
        assert_eq!(out.rejected.len(), 2);
    }

    #[test]
    fn the_default_max_risk_rejects_destructive() {
        let c = ctx(Config::default());
        let out = apply(
            &c,
            vec![candidate("trash", Risk::Destructive, 1000, 90)],
            never_active,
        );
        assert!(out.accepted.is_empty());
        assert!(matches!(
            out.rejected[0].reason,
            Rejection::RiskTooHigh { .. }
        ));
    }

    #[test]
    fn a_candidate_under_its_scanners_floor_is_rejected() {
        // logs has a 30-day floor.
        let c = ctx(Config::default());
        let out = apply(
            &c,
            vec![candidate("logs", Risk::Safe, 1000, 5)],
            never_active,
        );
        assert!(out.accepted.is_empty());
        match &out.rejected[0].reason {
            Rejection::TooYoung { age_days, min_days } => {
                assert_eq!(*min_days, 30);
                assert!(*age_days < 30);
            }
            other => panic!("expected TooYoung, got {other:?}"),
        }
    }

    #[test]
    fn a_candidate_past_its_floor_is_accepted() {
        let c = ctx(Config::default());
        let out = apply(
            &c,
            vec![candidate("logs", Risk::Safe, 1000, 45)],
            never_active,
        );
        assert_eq!(out.accepted.len(), 1);
    }

    #[test]
    fn an_exclude_glob_vetoes_a_candidate_that_passes_everything_else() {
        // FR-24: the exclude list is a final veto, not one input among many.
        let c = ctx(Config::parse("[safety]\nexclude = [\"/tmp/sift-test/**\"]\n").unwrap());
        let out = apply(
            &c,
            vec![candidate("logs", Risk::Safe, 1000, 90)],
            never_active,
        );

        assert!(out.accepted.is_empty(), "{:?}", out.accepted);
        assert_eq!(out.rejected[0].reason, Rejection::Excluded);
    }

    #[test]
    fn a_zero_byte_candidate_is_rejected() {
        // No reclaim to gain, so no risk is worth taking.
        let c = ctx(Config::default());
        let out = apply(&c, vec![candidate("logs", Risk::Safe, 0, 90)], never_active);
        assert_eq!(out.rejected[0].reason, Rejection::Empty);
    }

    #[test]
    fn an_active_tree_is_rejected_even_when_everything_else_passes() {
        // FR-17. This is the guard against quarantining a running build.
        let c = ctx(Config::default());
        let out = apply(&c, vec![candidate("logs", Risk::Safe, 1000, 90)], |_| {
            Some(3)
        });

        assert!(out.accepted.is_empty());
        assert_eq!(out.rejected[0].reason, Rejection::Active { minutes_ago: 3 });
    }

    #[test]
    fn every_rejection_carries_a_human_explanation() {
        // A user who expected something to be cleaned is owed an answer.
        for r in [
            Rejection::RiskTooHigh {
                risk: Risk::Destructive,
                max: Risk::Safe,
            },
            Rejection::TooYoung {
                age_days: 5,
                min_days: 30,
            },
            Rejection::Excluded,
            Rejection::Active { minutes_ago: 10 },
            Rejection::Empty,
        ] {
            assert!(!r.describe().is_empty(), "{r:?} has no explanation");
        }
    }

    #[test]
    fn delegated_targets_are_not_subject_to_path_excludes() {
        // An exclude glob is a path pattern; a `brew cleanup` invocation has no
        // path to match against, so it must not be silently vetoed by one.
        let mut c = candidate("homebrew", Risk::Safe, 1000, 90);
        c.target = Target::Delegated(crate::scan::DelegatedCmd::new("brew", &["cleanup"]));

        let ctx = ctx(Config::parse("[safety]\nexclude = [\"/**\"]\n").unwrap());
        let out = apply(&ctx, vec![c], never_active);
        assert_eq!(out.accepted.len(), 1);
    }
}
