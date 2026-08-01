//! `sift clean` — scan, then quarantine (FR-11, PRD §7).
//!
//! The full pipeline:
//!
//! ```text
//! purge expired runs  →  scan  →  filter  →  liveness  →  circuit breaker
//!                     →  confirm  →  quarantine  →  manifest  →  history
//! ```
//!
//! Two properties this command must never lose:
//!
//! - **`--dry-run` touches nothing.** Not "almost nothing" — the quarantine
//!   call is not reached at all.
//! - **The undo is always one copy-paste away.** Every run that stages anything
//!   prints its `sift restore <id>` command. A reversibility guarantee the user
//!   cannot find is not a guarantee.

use crate::action::{breaker, filter, liveness, purge, quarantine};
use crate::agent::gates;
use crate::caps::Capabilities;
use crate::config::Config;
use crate::fs::volume;
use crate::report::{history, human};
use crate::scan::{only_filter, Candidate, ScanCtx};
use crate::{Result, SiftError};
use chrono::Local;
use std::io::Write;
use std::sync::Arc;

pub fn run(
    cfg: &Config,
    only: Option<&str>,
    dry_run: bool,
    yes: bool,
    estimate_delegated: bool,
    scheduled: bool,
    json: bool,
) -> Result<()> {
    let ctx = ScanCtx::new(
        Arc::new(cfg.clone()),
        volume::root()?,
        Capabilities::probe(),
    )?
    .with_delegated_estimates(estimate_delegated);

    // FR-20: the scheduling gates run BEFORE anything else in --scheduled
    // mode — before the scan, before the expired-run purge. A gated run must
    // cost nothing, not just decline at the end.
    if scheduled {
        let last = history::recent(365).ok().and_then(|rs| {
            rs.iter()
                .rev()
                .find(|r| r.gated_reason.is_none())
                .map(|r| r.started_at)
        });

        if let Some(gate) = gates::evaluate(cfg, &gates::inputs(&ctx.root_volume, last)) {
            let reason = gate.describe();
            tracing::info!(reason = %reason, "scheduled run gated");

            let mut record =
                history::RunRecord::from_scan(&crate::scan::ScanReport::default(), &ctx, "clean");
            record.gated_reason = Some(reason.clone());
            let _ = history::append(&record);

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "schema_version": 1,
                        "gated": true,
                        "reason": reason,
                    }))?
                );
            } else {
                println!("sift — skipped: {reason}");
            }
            // Exit 0. Declining to work is the correct outcome, and launchd
            // must not see a failure (spec §11).
            return Ok(());
        }
    }

    // FR-13: expired runs are purged at the start of the next run. Skipped
    // under --dry-run, which must not mutate anything at all.
    let purged = if dry_run {
        None
    } else {
        Some(purge::purge_expired(Local::now())?)
    };

    let filter_set = only.map(only_filter).transpose()?;
    let report = crate::scan::registry().run(&ctx, filter_set.as_ref());

    let filtered = filter::apply(&ctx, report.candidates.clone(), |c| {
        liveness::check(&ctx, c)
    });

    // FR-16, before anything is staged.
    let limit = cfg.general.max_bytes_per_run.bytes();
    if let breaker::Verdict::Trip { total, limit } = breaker::check(&filtered.accepted, limit) {
        eprint!("{}", breaker::render_trip(&filtered.accepted, total, limit));
        return Err(SiftError::CircuitBreaker {
            bytes: total,
            limit,
        });
    }

    if filtered.accepted.is_empty() {
        if !json {
            println!("sift — nothing to clean.");
            if let Some(p) = &purged {
                if p.anything_purged() {
                    print!("{}", purge::render(p));
                }
            }
        }
        return Ok(());
    }

    if !json {
        print_plan(&filtered.accepted, dry_run);
    }

    if dry_run {
        // The one branch where nothing is reached. No quarantine call, no
        // history append, no purge.
        if !json {
            println!();
            println!("--dry-run: nothing was moved, quarantined, or deleted.");
        }
        return Ok(());
    }

    // Confirmation. `--scheduled` has no TTY, and the whole point of the
    // scheduled run is that it is unattended — arming it is the config's job,
    // not a prompt's.
    if !yes && !scheduled && !confirm(&filtered.accepted)? {
        println!("Aborted. Nothing was moved.");
        return Ok(());
    }

    let (outcome, _manifest) =
        quarantine::quarantine(&filtered.accepted, cfg.general.quarantine_ttl_days)?;

    // FR-8.
    let mut record = history::RunRecord::from_scan(&report, &ctx, "clean");
    for c in &filtered.accepted {
        record
            .per_scanner
            .entry(c.scanner.to_string())
            .or_default()
            .quarantined += c.bytes_on_disk;
    }
    record.purged_bytes = purged.as_ref().map(|p| p.bytes_purged).unwrap_or(0);
    if let Err(e) = history::append(&record) {
        tracing::warn!(error = %e, "could not append to run history");
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 1,
                "run_id": outcome.run_id,
                "quarantined": outcome.renamed,
                "trashed": outcome.trashed,
                "refused": outcome.refused.len(),
                "bytes_staged": outcome.bytes_staged,
                "restore_command": format!("sift restore {}", &outcome.run_id),
                "ttl_days": cfg.general.quarantine_ttl_days,
            }))?
        );
    } else {
        print_outcome(&outcome, purged.as_ref(), cfg.general.quarantine_ttl_days);
    }

    Ok(())
}

fn print_plan(candidates: &[Candidate], dry_run: bool) {
    let total: u64 = candidates.iter().map(|c| c.bytes_on_disk).sum();

    println!(
        "sift — {} to {}quarantine, {} item(s):",
        human::size(total),
        if dry_run { "would " } else { "" },
        candidates.len()
    );
    println!();
    for c in candidates {
        println!(
            "  {:>10}  {:<12}  {}",
            human::size(c.bytes_on_disk),
            c.risk.as_str(),
            c.label
        );
    }
}

fn print_outcome(
    outcome: &quarantine::Outcome,
    purged: Option<&purge::PurgeOutcome>,
    ttl_days: u32,
) {
    println!();
    println!(
        "Quarantined {} item(s), {}.",
        outcome.renamed,
        human::size(outcome.bytes_staged)
    );

    if outcome.trashed > 0 {
        println!(
            "{} item(s) were on another volume and went to the Trash instead.",
            outcome.trashed
        );
    }

    if !outcome.refused.is_empty() {
        println!();
        for (path, why) in &outcome.refused {
            println!("  Skipped: {} — {why}", path.display());
        }
    }

    if let Some(p) = purged {
        if p.anything_purged() {
            println!();
            println!(
                "Also permanently deleted {} from {} expired run(s).",
                human::size(p.bytes_purged),
                p.runs_purged.len()
            );
        }
    }

    // The undo, always. A reversibility guarantee the user cannot find is not
    // a guarantee.
    println!();
    println!("Nothing has been permanently deleted yet.");
    println!(
        "  Undo:    sift restore {}",
        &outcome.run_id[..outcome.run_id.len().min(8)]
    );
    println!("  Expires: in {ttl_days} days, after which it is purged automatically.");
}

fn confirm(candidates: &[Candidate]) -> Result<bool> {
    let total: u64 = candidates.iter().map(|c| c.bytes_on_disk).sum();

    println!();
    println!(
        "This will move {} into quarantine. It stays recoverable until purged.",
        human::size(total)
    );
    print!("Continue? [y/N] ");
    let _ = std::io::stdout().flush();

    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        // No readable stdin — a pipe, or a terminal that closed. Declining is
        // the only safe reading of "the user did not say yes".
        return Ok(false);
    }
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "Yes"))
}
