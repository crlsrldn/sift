//! `sift explain` (PRD Open Question 5).

use crate::caps::Capabilities;
use crate::config::Config;
use crate::explain;
use crate::fs::volume;
use crate::scan::ScanCtx;
use crate::Result;
use std::path::Path;
use std::sync::Arc;

pub fn run(cfg: &Config, path: &Path, json: bool) -> Result<()> {
    let ctx = ScanCtx::new(
        Arc::new(cfg.clone()),
        volume::root()?,
        Capabilities::probe(),
    )?;
    let e = explain::explain(&ctx, path)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 1,
                "path": e.path.display().to_string(),
                "exists": e.exists,
                "bytes_on_disk": e.bytes_on_disk,
                "what": e.known.map(|k| k.what),
                "if_deleted": e.known.map(|k| k.cost),
                "sift_policy": e.known.map(|k| k.sift_policy),
                "claimable_by": e.claimed_by
                    .iter()
                    .map(|(id, risk)| serde_json::json!({ "scanner": id, "risk": risk.as_str() }))
                    .collect::<Vec<_>>(),
                "claimed_by_current_config": e.claimed_now,
            }))?
        );
    } else {
        print!("{}", explain::render(&e));
    }
    Ok(())
}
