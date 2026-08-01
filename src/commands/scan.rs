//! `sift scan` (FR-1).
//!
//! Report only. This command has no path to deletion — not a flag, not a config
//! key. `clean` is a separate command (PR-22).
//!
//! Output here is deliberately plain; the PRD §7 report format lands in PR-10.

use crate::caps::Capabilities;
use crate::config::Config;
use crate::fs::volume;
use crate::scan::{only_filter, ScanCtx, ScanReport};
use crate::{ExitCode, Result, SiftError};
use std::sync::Arc;

pub fn run(cfg: &Config, only: Option<&str>, json: bool) -> Result<()> {
    let filter = only.map(only_filter).transpose()?;
    let ctx = ScanCtx::new(
        Arc::new(cfg.clone()),
        volume::root()?,
        Capabilities::probe(),
    )?;

    let registry = crate::scan::registry();
    let report = registry.run(&ctx, filter.as_ref());

    if json {
        println!("{}", serde_json::to_string_pretty(&to_json(&report, &ctx))?);
    } else {
        print_plain(&report, &ctx);
    }

    // Exit 5 when any scanner failed (spec §11). The run still produced a
    // usable report, so this is not a hard failure — but a caller piping this
    // into a script needs to know the picture is incomplete.
    if report.had_errors() {
        return Err(SiftError::ScannerErrors {
            count: report.errors.len(),
        });
    }
    Ok(())
}

fn print_plain(report: &ScanReport, ctx: &ScanCtx) {
    let gb = |b: u64| format!("{:.2} GB", b as f64 / 1e9);

    println!(
        "sift — scan complete in {:.1}s",
        report.duration.as_secs_f64()
    );
    println!(
        "Volume: {}  ·  {} free of {}",
        ctx.root_volume.name,
        gb(ctx.root_volume.available_important),
        gb(ctx.root_volume.total)
    );
    println!();

    if report.candidates.is_empty() {
        println!("  Nothing reclaimable found.");
    } else {
        for c in &report.candidates {
            println!(
                "  {:<24}{:>12}  {:<12} {}",
                c.scanner,
                gb(c.bytes_on_disk),
                c.risk.as_str(),
                c.label
            );
        }
        println!();
        println!("  Total identified{:>20}", gb(report.total_bytes()));
    }

    // PRD §7: skipped and blocked are surfaced, never silently omitted.
    let disabled: Vec<&str> = report
        .skipped
        .iter()
        .filter(|(_, s)| matches!(s, crate::scan::SkippedScanner::Disabled))
        .map(|(id, _)| *id)
        .collect();
    if !disabled.is_empty() {
        println!();
        println!("  Skipped: {}", disabled.join(", "));
    }

    let blocked = report.blocked();
    if !blocked.is_empty() {
        for (id, why) in blocked {
            println!("  Blocked: {id} — {} (run `sift doctor`)", why.describe());
        }
    }

    if report.had_errors() {
        println!();
        for (id, msg) in &report.errors {
            println!("  Error:   {id} — {msg}");
        }
    }

    println!();
    println!("Run `sift clean` to quarantine. Nothing has been deleted.");
}

fn to_json(report: &ScanReport, ctx: &ScanCtx) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "duration_ms": report.duration.as_millis() as u64,
        "volume": {
            "name": ctx.root_volume.name,
            "available_important_bytes": ctx.root_volume.available_important,
            "total_bytes": ctx.root_volume.total,
        },
        "total_bytes": report.total_bytes(),
        "candidates": report.candidates.iter().map(|c| serde_json::json!({
            "scanner": c.scanner,
            "target": c.target.display(),
            "reversible": c.target.is_reversible(),
            "bytes_on_disk": c.bytes_on_disk,
            "bytes_apparent": c.bytes_apparent,
            "risk": c.risk.as_str(),
            "label": c.label,
            "reason": c.reason,
            "age_days": c.age_days(ctx.now),
        })).collect::<Vec<_>>(),
        "skipped": report.skipped.iter().map(|(id, why)| serde_json::json!({
            "scanner": id,
            "reason": why.describe(),
        })).collect::<Vec<_>>(),
        "errors": report.errors.iter().map(|(id, msg)| serde_json::json!({
            "scanner": id,
            "error": msg,
        })).collect::<Vec<_>>(),
        "exit_code": if report.had_errors() { ExitCode::ScannerErrors.as_i32() } else { 0 },
    })
}
