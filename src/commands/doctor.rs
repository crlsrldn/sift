//! `sift doctor` command (FR-26, FR-27).

use crate::config::Config;
use crate::doctor::{render, to_json, Diagnosis};
use crate::Result;

pub fn run(cfg: &Config, json: bool) -> Result<()> {
    let d = Diagnosis::run(cfg)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&to_json(&d))?);
    } else {
        print!("{}", render(&d));
    }

    // Exits 0 even with blocked scanners. A machine without Docker is not in an
    // error state, and `doctor` is a diagnostic — its job is to report, and a
    // non-zero exit would make it useless in a health-check script that only
    // cares whether sift itself is broken.
    Ok(())
}
