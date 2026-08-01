//! `sift scan` (FR-1).
//!
//! Report only. This command has no path to deletion — not a flag, not a config
//! key. `clean` is a separate command (PR-22).
//!
//! Output here is deliberately plain; the PRD §7 report format lands in PR-10.

use crate::caps::Capabilities;
use crate::config::Config;
use crate::fs::volume;
use crate::report::{history, human, json};
use crate::scan::{only_filter, ScanCtx};
use crate::{Result, SiftError};
use std::sync::Arc;

pub fn run(
    cfg: &Config,
    only: Option<&str>,
    estimate_delegated: bool,
    json_out: bool,
) -> Result<()> {
    let filter = only.map(only_filter).transpose()?;
    let ctx = ScanCtx::new(
        Arc::new(cfg.clone()),
        volume::root()?,
        Capabilities::probe(),
    )?
    .with_delegated_estimates(estimate_delegated);

    let registry = crate::scan::registry();
    let report = registry.run(&ctx, filter.as_ref());

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&json::scan_report(&report, &ctx))?
        );
    } else {
        print!("{}", human::render(&report, &ctx));
    }

    // FR-8: every run appends a structured record, including a pure scan. The
    // trend in `sift report` is only meaningful if scans are recorded too, not
    // just runs that deleted something. A history write failure must not fail
    // the run — the report the user asked for was already produced.
    if let Err(e) = history::append(&history::RunRecord::from_scan(&report, &ctx, "scan")) {
        tracing::warn!(error = %e, "could not append to run history");
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
