//! `sift report` (FR-9).

use crate::report::{history, trend};
use crate::Result;

pub fn run(days: u32, json: bool) -> Result<()> {
    let records = history::recent(days)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&trend::to_json(&records, days))?
        );
    } else {
        print!("{}", trend::render(&records, days));
    }
    Ok(())
}
