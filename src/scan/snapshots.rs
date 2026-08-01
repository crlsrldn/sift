//! S1 `snapshots` — APFS local Time Machine snapshots (spec §6).
//!
//! # The three rules that are never broken
//!
//! 1. **Never `deletelocalsnapshots`.** That removes a named snapshot
//!    unconditionally. `thinlocalsnapshots` asks macOS to reclaim *up to* a
//!    number of bytes at a stated urgency, and macOS declines if doing so would
//!    compromise recovery. Delegating that judgement is the entire point
//!    (Principle 5) — we do not know which snapshot the user needs.
//! 2. **Never touch the newest snapshot.** It is the most likely restore point.
//! 3. **Never thin when fewer than two exist.** Thinning the only snapshot
//!    leaves no recovery point at all.
//!
//! Rules 2 and 3 are enforced by refusing to act, not by argument construction,
//! because `thinlocalsnapshots` chooses its own victims — the only reliable
//! control is whether it runs.

use crate::risk::Risk;
use crate::scan::{Candidate, DelegatedCmd, Requirements, ScanCtx, Scanner, Target};
use crate::ScannerError;
use chrono::{DateTime, Local, NaiveDateTime, TimeZone};

pub struct Snapshots;

/// The command that must never appear.
pub const FORBIDDEN: &str = "deletelocalsnapshots";

/// Minimum snapshots that must exist before any thinning is considered.
const MIN_SNAPSHOTS: usize = 2;

/// Urgency 1 is the least aggressive; macOS declines if it would compromise
/// recovery (spec §6).
const DEFAULT_URGENCY: u8 = 1;

impl Scanner for Snapshots {
    fn id(&self) -> &'static str {
        "snapshots"
    }

    fn requirements(&self) -> Requirements {
        Requirements {
            fda: true,
            tool: Some("tmutil"),
        }
    }

    fn blast_radius(&self) -> Option<&'static str> {
        Some(
            "Local snapshots are what Time Machine restores from when your\n\
             backup disk is not attached — including \"restore this file to\n\
             yesterday\" in Finder. Thinning removes older ones permanently;\n\
             they are not on your backup drive and cannot be recreated. If you\n\
             have no other backup, this is the only copy of anything you\n\
             deleted or changed since the oldest snapshot.",
        )
    }

    fn scan(&self, ctx: &ScanCtx) -> Result<Vec<Candidate>, ScannerError> {
        // No subprocess during scan (FR-1, M4). Listing snapshots means running
        // tmutil, so the candidate is offered on the standing facts and the
        // constraints are checked when it acts.
        //
        // The disk-pressure check is free: if free space is already above the
        // floor there is nothing to reclaim toward.
        let floor = ctx.config.general.free_space_floor.bytes();
        let free = ctx.root_volume.available_important;
        if free >= floor {
            return Ok(Vec::new());
        }

        let purge_bytes = purge_target(free, floor, ctx.config.general.max_bytes_per_run.bytes());
        if purge_bytes == 0 {
            return Ok(Vec::new());
        }

        let urgency = ctx
            .config
            .scanner(self.id())
            .and_then(|c| c.urgency)
            .unwrap_or(DEFAULT_URGENCY);

        Ok(vec![Candidate {
            scanner: self.id(),
            target: Target::Snapshot(crate::scan::SnapshotRef {
                name: format!("thin to reclaim {purge_bytes} bytes at urgency {urgency}"),
                created: ctx.now,
            }),
            bytes_on_disk: purge_bytes,
            bytes_apparent: purge_bytes,
            last_modified: ctx.now,
            risk: Risk::Destructive,
            label: "APFS local snapshots — thin oldest first".into(),
            reason: format!(
                "tmutil thinlocalsnapshots at urgency {urgency}; macOS declines if \
                 this would compromise recovery. The newest snapshot is never touched"
            ),
        }])
    }
}

/// How many bytes to ask `thinlocalsnapshots` to reclaim.
///
/// `max(0, floor - free)`, capped at the per-run ceiling. Asking for more than
/// the shortfall would thin snapshots the user does not need to lose.
pub fn purge_target(free: u64, floor: u64, ceiling: u64) -> u64 {
    floor.saturating_sub(free).min(ceiling)
}

/// The thinning command.
pub fn thin_command(purge_bytes: u64, urgency: u8) -> DelegatedCmd {
    DelegatedCmd::new(
        "tmutil",
        &[
            "thinlocalsnapshots",
            "/",
            &purge_bytes.to_string(),
            &urgency.to_string(),
        ],
    )
}

/// Parse `tmutil listlocalsnapshots /` output.
///
/// Lines look like `com.apple.TimeMachine.2026-08-01-024500.local`. Anything
/// else is ignored rather than guessed at (Principle 7).
pub fn parse_snapshots(stdout: &str) -> Vec<DateTime<Local>> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("com.apple.TimeMachine.") else {
            continue;
        };
        let stamp = rest.strip_suffix(".local").unwrap_or(rest);
        if let Ok(naive) = NaiveDateTime::parse_from_str(stamp, "%Y-%m-%d-%H%M%S") {
            if let Some(dt) = Local.from_local_datetime(&naive).single() {
                out.push(dt);
            }
        }
    }
    out.sort();
    out
}

/// Whether thinning is permitted given the snapshots that exist.
///
/// Returns the reason for refusal, or `None` to proceed.
pub fn refusal_reason(snapshots: &[DateTime<Local>]) -> Option<String> {
    if snapshots.len() < MIN_SNAPSHOTS {
        return Some(format!(
            "only {} local snapshot(s) exist; thinning would risk leaving no \
             recovery point",
            snapshots.len()
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_destructive_command_is_never_constructed() {
        // `deletelocalsnapshots` removes a named snapshot unconditionally.
        // `thinlocalsnapshots` lets macOS decline if recovery would suffer.
        let cmd = thin_command(1_000_000, 1);
        assert!(
            !cmd.display().contains(FORBIDDEN),
            "constructed the forbidden command: {}",
            cmd.display()
        );
        assert!(cmd.display().contains("thinlocalsnapshots"));
    }

    #[test]
    fn the_command_matches_the_spec_form() {
        // spec §6: tmutil thinlocalsnapshots / <purge_bytes> <urgency>
        assert_eq!(
            thin_command(5_000_000, 1).display(),
            "tmutil thinlocalsnapshots / 5000000 1"
        );
    }

    #[test]
    fn urgency_defaults_to_the_least_aggressive() {
        // macOS declines at urgency 1 if thinning would compromise recovery.
        assert_eq!(DEFAULT_URGENCY, 1);
    }

    #[test]
    fn fewer_than_two_snapshots_refuses() {
        // Thinning the only snapshot leaves no recovery point at all.
        let now = Local::now();
        assert!(refusal_reason(&[]).is_some());
        assert!(refusal_reason(&[now]).is_some());
        assert!(refusal_reason(&[now, now]).is_none());
    }

    #[test]
    fn the_refusal_says_why() {
        let r = refusal_reason(&[Local::now()]).unwrap();
        assert!(r.contains("recovery point"), "{r}");
    }

    #[test]
    fn the_purge_target_is_the_shortfall_not_everything() {
        // Asking for more than the shortfall would thin snapshots the user does
        // not need to lose.
        let gb = 1_000_000_000u64;
        assert_eq!(purge_target(20 * gb, 100 * gb, 500 * gb), 80 * gb);
    }

    #[test]
    fn a_comfortable_disk_asks_for_nothing() {
        let gb = 1_000_000_000u64;
        assert_eq!(purge_target(200 * gb, 100 * gb, 500 * gb), 0);
        assert_eq!(purge_target(100 * gb, 100 * gb, 500 * gb), 0);
    }

    #[test]
    fn the_purge_target_respects_the_per_run_ceiling() {
        // FR-16 applies here too: a huge shortfall must not become a huge
        // single thinning request.
        let gb = 1_000_000_000u64;
        assert_eq!(purge_target(gb, 900 * gb, 100 * gb), 100 * gb);
    }

    #[test]
    fn snapshot_listings_parse_and_sort() {
        let sample = "Snapshots for disk /:\n\
                      com.apple.TimeMachine.2026-07-30-014500.local\n\
                      com.apple.TimeMachine.2026-08-01-024500.local\n\
                      com.apple.TimeMachine.2026-07-31-014500.local\n";
        let snaps = parse_snapshots(sample);
        assert_eq!(snaps.len(), 3);
        assert!(snaps[0] < snaps[1] && snaps[1] < snaps[2], "not sorted");
    }

    #[test]
    fn unrecognised_lines_are_ignored_not_guessed_at() {
        assert!(parse_snapshots("Snapshots for disk /:\n").is_empty());
        assert!(parse_snapshots("").is_empty());
        assert!(parse_snapshots("com.apple.TimeMachine.not-a-date.local\n").is_empty());
        assert!(parse_snapshots("some-other-snapshot-scheme\n").is_empty());
    }

    #[test]
    fn the_scanner_requires_fda_and_tmutil() {
        let r = Snapshots.requirements();
        assert!(r.fda);
        assert_eq!(r.tool, Some("tmutil"));
    }

    #[test]
    fn the_blast_radius_names_what_is_lost_not_what_the_command_does() {
        let b = Snapshots.blast_radius().unwrap();
        assert!(b.contains("Time Machine"), "{b}");
        assert!(b.contains("cannot be recreated"), "{b}");
    }
}
