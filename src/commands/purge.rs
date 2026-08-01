//! `sift purge` (FR-13).

use crate::action::purge;
use crate::config::Config;
use crate::Result;
use chrono::Local;

pub fn run(cfg: &Config, now: bool, yes: bool, json: bool) -> Result<()> {
    let _ = cfg;

    if now && !yes && !confirm()? {
        println!("Aborted. Nothing was deleted.");
        return Ok(());
    }

    let outcome = if now {
        purge::purge_all()?
    } else {
        purge::purge_expired(Local::now())?
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 1,
                "runs_purged": outcome.runs_purged,
                "runs_retained": outcome.runs_retained.len(),
                "bytes_purged": outcome.bytes_purged,
                "refused": outcome.refused.len(),
            }))?
        );
    } else {
        print!("{}", purge::render(&outcome));
    }
    Ok(())
}

/// `--now` bypasses the TTL, which is the whole safety window. The prompt
/// states the consequence plainly rather than asking a yes/no question the user
/// can answer reflexively.
fn confirm() -> Result<bool> {
    use std::io::Write;

    let runs = crate::action::quarantine::runs()?;
    let total: u64 = runs.iter().map(|m| m.total_bytes()).sum();

    println!(
        "This will PERMANENTLY delete {} run(s) from quarantine — {}.",
        runs.len(),
        crate::report::human::size(total)
    );
    println!("`sift restore` will not be able to bring any of it back.");
    print!("Type `purge` to confirm: ");
    let _ = std::io::stdout().flush();

    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return Ok(false);
    }
    Ok(line.trim() == "purge")
}
