//! Circuit breaker (FR-16, spec §7.4).
//!
//! If the total identified exceeds `general.max_bytes_per_run`, the run
//! **aborts before any action**, prints the per-scanner breakdown that tripped
//! it, and exits 4.
//!
//! This exists because a scanner bug that claims the whole disk is a realistic
//! failure — a path-join mistake, a glob that matched `/`, an eligibility rule
//! inverted by a typo. Without a ceiling, the first such bug stages everything
//! the user owns into quarantine before anyone notices.
//!
//! The ordering matters and is the whole point: **check, then act.** A breaker
//! that tripped halfway through quarantining would leave the user worse off
//! than no breaker at all.

use crate::scan::Candidate;
use crate::{Result, SiftError};
use std::collections::BTreeMap;

/// Outcome of the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Proceed { total: u64, limit: u64 },
    Trip { total: u64, limit: u64 },
}

impl Verdict {
    pub fn tripped(&self) -> bool {
        matches!(self, Verdict::Trip { .. })
    }
}

/// Check a candidate set against the ceiling.
pub fn check(candidates: &[Candidate], limit: u64) -> Verdict {
    // saturating_add so a corrupt or absurd byte count cannot wrap to a small
    // total and slip under the limit — the failure mode has to be "trips too
    // often", never "fails to trip".
    let total = candidates
        .iter()
        .fold(0u64, |acc, c| acc.saturating_add(c.bytes_on_disk));

    if total > limit {
        Verdict::Trip { total, limit }
    } else {
        Verdict::Proceed { total, limit }
    }
}

/// Per-scanner totals, largest first, for the abort message.
///
/// A bare "200 GB exceeds 100 GB" tells the user nothing actionable. The
/// breakdown names the scanner that misbehaved, which is the first thing anyone
/// needs in order to respond.
pub fn breakdown(candidates: &[Candidate]) -> Vec<(&'static str, u64)> {
    let mut m: BTreeMap<&'static str, u64> = BTreeMap::new();
    for c in candidates {
        *m.entry(c.scanner).or_insert(0) += c.bytes_on_disk;
    }
    let mut v: Vec<(&'static str, u64)> = m.into_iter().collect();
    v.sort_by_key(|(_, b)| std::cmp::Reverse(*b));
    v
}

/// Enforce the ceiling, returning the exit-4 error if it trips.
pub fn enforce(candidates: &[Candidate], limit: u64) -> Result<u64> {
    match check(candidates, limit) {
        Verdict::Proceed { total, .. } => Ok(total),
        Verdict::Trip { total, limit } => Err(SiftError::CircuitBreaker {
            bytes: total,
            limit,
        }),
    }
}

/// Render the abort message.
pub fn render_trip(candidates: &[Candidate], total: u64, limit: u64) -> String {
    use crate::report::human::size;
    use std::fmt::Write;

    let mut o = String::new();
    let _ = writeln!(
        o,
        "sift — circuit breaker tripped. NOTHING HAS BEEN ACTIONED."
    );
    let _ = writeln!(o);
    let _ = writeln!(
        o,
        "  {} identified exceeds the {} per-run ceiling.",
        size(total),
        size(limit)
    );
    let _ = writeln!(o);
    let _ = writeln!(o, "  by scanner:");
    for (id, bytes) in breakdown(candidates) {
        let _ = writeln!(o, "    {id:<24}{}", size(bytes));
    }
    let _ = writeln!(o);
    let _ = writeln!(
        o,
        "  This ceiling exists to contain a scanner bug. If the figure above is"
    );
    let _ = writeln!(
        o,
        "  genuinely what you meant to reclaim, raise general.max_bytes_per_run."
    );
    let _ = writeln!(
        o,
        "  If it is not, the scanner at the top of that list is the one to look at."
    );
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::Risk;
    use crate::scan::Target;
    use chrono::Local;

    fn c(scanner: &'static str, bytes: u64) -> Candidate {
        Candidate {
            scanner,
            target: Target::Path("/tmp/x".into()),
            bytes_on_disk: bytes,
            bytes_apparent: bytes,
            last_modified: Local::now(),
            risk: Risk::Safe,
            label: "x".into(),
            reason: "x".into(),
        }
    }

    #[test]
    fn under_the_limit_proceeds() {
        let v = check(&[c("logs", 50), c("logs", 40)], 100);
        assert!(!v.tripped());
        assert_eq!(
            v,
            Verdict::Proceed {
                total: 90,
                limit: 100
            }
        );
    }

    #[test]
    fn exactly_at_the_limit_proceeds() {
        // The ceiling is a maximum, not an exclusive bound.
        assert!(!check(&[c("logs", 100)], 100).tripped());
    }

    #[test]
    fn over_the_limit_trips() {
        assert!(check(&[c("logs", 101)], 100).tripped());
    }

    #[test]
    fn tripping_yields_exit_code_four() {
        // spec §11: 4 means "circuit breaker tripped; nothing was actioned".
        let err = enforce(&[c("logs", 200)], 100).unwrap_err();
        assert_eq!(err.exit_code(), crate::ExitCode::CircuitBreaker);
    }

    #[test]
    fn the_error_message_states_nothing_was_actioned() {
        // The user's first question on seeing an abort is "did it delete
        // anything?". The answer must be in the message, not the docs.
        let err = enforce(&[c("logs", 200)], 100).unwrap_err();
        assert!(err.to_string().contains("nothing was actioned"));
    }

    #[test]
    fn an_absurd_byte_count_cannot_wrap_and_slip_under_the_limit() {
        // The failure mode must be "trips too often", never "fails to trip".
        let v = check(&[c("logs", u64::MAX), c("logs", u64::MAX)], 100);
        assert!(v.tripped());
    }

    #[test]
    fn the_breakdown_names_the_worst_offender_first() {
        let candidates = [c("logs", 10), c("xcode-derived", 900), c("cargo-cache", 90)];
        let b = breakdown(&candidates);
        assert_eq!(b[0].0, "xcode-derived");
        assert_eq!(b[0].1, 900);
        assert_eq!(b[2].0, "logs");
    }

    #[test]
    fn the_breakdown_sums_multiple_candidates_per_scanner() {
        let b = breakdown(&[c("logs", 10), c("logs", 20), c("homebrew", 5)]);
        assert_eq!(b[0], ("logs", 30));
    }

    #[test]
    fn the_trip_message_is_actionable() {
        let candidates = [c("xcode-derived", 200_000_000_000)];
        let out = render_trip(&candidates, 200_000_000_000, 100_000_000_000);

        assert!(out.contains("NOTHING HAS BEEN ACTIONED"), "{out}");
        assert!(out.contains("xcode-derived"), "{out}");
        assert!(out.contains("max_bytes_per_run"), "{out}");
    }

    #[test]
    fn an_empty_candidate_set_never_trips() {
        assert!(!check(&[], 0).tripped());
    }
}
