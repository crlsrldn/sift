//! `sift restore` (FR-14).

use crate::action::restore;
use crate::Result;

pub fn run(run_id: &str, json: bool) -> Result<()> {
    let outcome = restore::restore(run_id)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 1,
                "run_id": outcome.run_id,
                "restored": outcome.restored.len(),
                "conflicts": outcome.conflicts.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                "in_trash": outcome.in_trash.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                "failed": outcome.failed.len(),
                "bytes_restored": outcome.bytes_restored,
                "fully_restored": outcome.fully_restored(),
            }))?
        );
    } else {
        print!("{}", restore::render(&outcome));
    }

    // Exit 0 even on a partial restore. spec §7.3 names partial restore a valid
    // outcome: the conflicts are reported, nothing was damaged, and the user
    // can resolve them and re-run.
    Ok(())
}
