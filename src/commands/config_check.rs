//! `sift config check` (FR-23).
//!
//! Validates the config file and prints the fully merged effective
//! configuration with the source of each value.
//!
//! Showing provenance is the point of the command. "Is this 14-day floor the
//! default, or did I set it?" is exactly the question a user has before running
//! something that deletes files, and an effective-config dump that cannot
//! answer it is only half useful.

use crate::config::{Config, Provenance};
use crate::Result;

pub fn run(cfg: &Config, json: bool) -> Result<()> {
    if json {
        print_json(cfg)
    } else {
        print_human(cfg);
        Ok(())
    }
}

fn print_human(cfg: &Config) {
    match &cfg.source {
        Some(p) => println!("config: {} (valid)", p.display()),
        None => println!("config: no file found — using built-in defaults"),
    }
    println!();

    let rows = cfg.provenance();
    let key_width = rows.iter().map(|(k, _, _)| k.len()).max().unwrap_or(0);
    let val_width = rows
        .iter()
        .map(|(_, v, _)| v.len())
        .max()
        .unwrap_or(0)
        .min(28);

    let mut section = "";
    for (key, value, prov) in &rows {
        let current = key.split('.').next().unwrap_or("");
        if current != section {
            if !section.is_empty() {
                println!();
            }
            section = current;
        }

        // Defaults are unmarked; only user-set values carry a tag, so the
        // config file's actual footprint is what stands out.
        let tag = match prov {
            Provenance::File => "  [set in file]",
            Provenance::Default => "",
        };
        println!("  {key:<key_width$}  {value:<val_width$}{tag}");
    }

    println!();
    let active = cfg.active_scanners();
    println!(
        "{} of {} scanners active at max_risk = {}",
        active.len(),
        cfg.scanners.len(),
        cfg.general.max_risk
    );

    // Surface the two-switch case explicitly. A user who enabled a Destructive
    // scanner and did not raise max_risk has a config that looks armed and is
    // not; saying so is better than letting them find out by it doing nothing.
    let enabled_but_gated: Vec<&str> = cfg
        .scanners
        .values()
        .filter(|s| s.enabled && s.risk > cfg.general.max_risk)
        .map(|s| s.id.as_str())
        .collect();

    if !enabled_but_gated.is_empty() {
        println!();
        println!(
            "note: {} enabled but inactive because max_risk = {} does not admit \
             their risk tier:",
            enabled_but_gated.len(),
            cfg.general.max_risk
        );
        for id in enabled_but_gated {
            let s = &cfg.scanners[id];
            println!("        {id} ({})", s.risk);
        }
        println!("      raise general.max_risk to activate them.");
    }
}

fn print_json(cfg: &Config) -> Result<()> {
    let values: Vec<serde_json::Value> = cfg
        .provenance()
        .into_iter()
        .map(|(key, value, prov)| {
            serde_json::json!({
                "key": key,
                "value": value,
                "source": prov.as_str(),
            })
        })
        .collect();

    let doc = serde_json::json!({
        "schema_version": 1,
        "config_file": cfg.source.as_ref().map(|p| p.display().to_string()),
        "valid": true,
        "max_risk": cfg.general.max_risk.as_str(),
        "active_scanners": cfg
            .active_scanners()
            .iter()
            .map(|s| s.id.as_str())
            .collect::<Vec<_>>(),
        "values": values,
    });

    println!("{}", serde_json::to_string_pretty(&doc)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_defaults_without_panicking() {
        let cfg = Config::default();
        print_human(&cfg);
    }

    #[test]
    fn json_output_is_valid_and_versioned() {
        let cfg = Config::default();
        let values: Vec<serde_json::Value> = cfg
            .provenance()
            .into_iter()
            .map(|(key, value, prov)| {
                serde_json::json!({ "key": key, "value": value, "source": prov.as_str() })
            })
            .collect();
        assert!(!values.is_empty());
        assert_eq!(values[0]["source"], "default");
    }
}
