//! `sift doctor` — what works, what does not, and exactly how to fix it
//! (FR-26, FR-27, spec §10).
//!
//! The design rule here: every line that reports a problem must also say what
//! to do about it. A diagnostic that reports "Full Disk Access: denied" and
//! stops has told the user something they could have guessed.

use crate::caps::{Capabilities, FdaStatus, TOOLS};
use crate::config::{defaults, Config};
use crate::fs::volume::{self, VolumeInfo};
use crate::Result;

/// Whether a scanner can run right now, and why not if it cannot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScannerStatus {
    /// Enabled and everything it needs is present.
    Ready,
    /// Turned off in config. Not a problem.
    Disabled,
    /// Enabled, but `max_risk` does not admit its tier — the two-switch case.
    RiskGated,
    /// Needs Full Disk Access.
    NeedsFda,
    /// Needs an external tool that is not installed.
    NeedsTool(&'static str),
}

impl ScannerStatus {
    pub fn is_ready(&self) -> bool {
        matches!(self, ScannerStatus::Ready)
    }

    /// Whether this is something the user might want to act on. A disabled
    /// scanner is a choice; a blocked one is a problem.
    pub fn is_blocked(&self) -> bool {
        matches!(self, ScannerStatus::NeedsFda | ScannerStatus::NeedsTool(_))
    }

    pub fn describe(&self) -> String {
        match self {
            ScannerStatus::Ready => "ready".into(),
            ScannerStatus::Disabled => "disabled in config".into(),
            ScannerStatus::RiskGated => "enabled, but blocked by max_risk".into(),
            ScannerStatus::NeedsFda => "needs Full Disk Access".into(),
            ScannerStatus::NeedsTool(t) => format!("needs `{t}`, which is not installed"),
        }
    }
}

/// A complete diagnosis.
#[derive(Debug)]
pub struct Diagnosis {
    pub volume: VolumeInfo,
    pub caps: Capabilities,
    pub scanners: Vec<(&'static str, ScannerStatus)>,
    pub config_source: Option<std::path::PathBuf>,
}

impl Diagnosis {
    pub fn run(cfg: &Config) -> Result<Self> {
        let caps = Capabilities::probe();
        let volume = volume::root()?;

        let mut scanners = Vec::new();
        for d in defaults::SCANNERS {
            let sc = cfg
                .scanner(d.id)
                .expect("every default scanner is in config");
            let status = if !sc.enabled {
                ScannerStatus::Disabled
            } else if sc.risk > cfg.general.max_risk {
                ScannerStatus::RiskGated
            } else if d.requires_fda && !caps.fda.is_granted() {
                ScannerStatus::NeedsFda
            } else if let Some(tool) = d.requires_tool.filter(|t| !caps.has_tool(t)) {
                ScannerStatus::NeedsTool(tool)
            } else {
                ScannerStatus::Ready
            };
            scanners.push((d.id, status));
        }

        Ok(Self {
            volume,
            caps,
            scanners,
            config_source: cfg.source.clone(),
        })
    }

    pub fn ready_count(&self) -> usize {
        self.scanners.iter().filter(|(_, s)| s.is_ready()).count()
    }

    pub fn blocked(&self) -> Vec<(&'static str, &ScannerStatus)> {
        self.scanners
            .iter()
            .filter(|(_, s)| s.is_blocked())
            .map(|(id, s)| (*id, s))
            .collect()
    }
}

/// The Full Disk Access remediation text (spec §10, "critical first-run detail").
///
/// The non-obvious part — and the reason this is a paragraph rather than a line
/// — is that FDA must be granted to the `sift` **binary**, not to Terminal.
/// Granting it to Terminal covers interactive runs and silently does nothing
/// for the scheduled one, because launchd is the parent there, not Terminal.
/// That failure mode is invisible until a scheduled run quietly stops finding
/// anything.
pub fn fda_instructions(exe: Option<&std::path::Path>) -> String {
    let path = exe
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "the sift binary".into());

    format!(
        "  To grant Full Disk Access:\n\
         \n\
         \x20   1. Open  System Settings → Privacy & Security → Full Disk Access\n\
         \x20   2. Click +, press Cmd-Shift-G, and enter this exact path:\n\
         \n\
         \x20        {path}\n\
         \n\
         \x20   3. Ensure the toggle next to it is on.\n\
         \n\
         \x20 Grant it to the sift binary itself, NOT to Terminal. FDA granted to\n\
         \x20 Terminal covers interactive runs but does nothing for the scheduled\n\
         \x20 agent, because launchd is that process's parent rather than Terminal.\n\
         \x20 That mismatch is invisible until a scheduled run silently stops\n\
         \x20 finding anything."
    )
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

pub fn render(d: &Diagnosis) -> String {
    use std::fmt::Write;
    let mut o = String::new();

    let _ = writeln!(o, "sift doctor");
    let _ = writeln!(o);

    // Config
    match &d.config_source {
        Some(p) => {
            let _ = writeln!(o, "  config      {} (valid)", p.display());
        }
        None => {
            let _ = writeln!(o, "  config      no file — using built-in defaults");
        }
    }

    // Volume
    let gb = |b: u64| format!("{:.1} GB", b as f64 / 1e9);
    let _ = writeln!(
        o,
        "  volume      {} ({}) — {} free of {}",
        d.volume.name,
        d.volume.fs_type,
        gb(d.volume.available_important),
        gb(d.volume.total)
    );
    if !d.volume.is_apfs() {
        let _ = writeln!(
            o,
            "              WARNING: not APFS. sift's size accounting assumes APFS."
        );
    }
    if d.volume.purgeable() > 1_000_000_000 {
        let _ = writeln!(
            o,
            "              {} of that is purgeable and invisible to `df`",
            gb(d.volume.purgeable())
        );
    }

    // FDA
    let fda_line = match d.caps.fda {
        FdaStatus::Granted => "granted (to this process)",
        FdaStatus::Denied => "DENIED — some scanners cannot run",
        FdaStatus::Unknown => "could not determine",
    };
    let _ = writeln!(o, "  full disk   {fda_line}");

    // The spec §10 trap. A probe can only ever report on the *current* process,
    // and interactively that process inherited its TCC grant from the terminal.
    // The scheduled agent is a different process with a different parent, so
    // "granted" here is not evidence that the agent has it. Saying so costs one
    // line and prevents the failure mode where a scheduled run silently stops
    // finding anything for weeks.
    if d.caps.fda.is_granted() {
        let _ = writeln!(
            o,
            "              note: this reflects the current process, which \
             inherited access\n              from your terminal. It does not \
             prove the scheduled agent has it —\n              see `sift install`."
        );
    }

    // Tools
    let _ = writeln!(o);
    let _ = writeln!(o, "  tools");
    for (key, _, purpose) in TOOLS {
        let mark = if d.caps.has_tool(key) {
            "found  "
        } else {
            "missing"
        };
        let _ = writeln!(o, "    {mark}  {key:<14}{purpose}");
    }

    // Scanners
    let _ = writeln!(o);
    let _ = writeln!(
        o,
        "  scanners ({} of {} ready)",
        d.ready_count(),
        d.scanners.len()
    );
    for (id, status) in &d.scanners {
        let mark = match status {
            ScannerStatus::Ready => "ready  ",
            ScannerStatus::Disabled => "off    ",
            ScannerStatus::RiskGated => "gated  ",
            _ => "BLOCKED",
        };
        let _ = writeln!(o, "    {mark}  {id:<22}{}", status.describe());
    }

    // Remediation. Only shown when there is something to fix — a clean machine
    // should not be handed a wall of instructions it does not need.
    let blocked = d.blocked();
    if !blocked.is_empty() {
        let _ = writeln!(o);
        let _ = writeln!(o, "  {} scanner(s) blocked:", blocked.len());
        let _ = writeln!(o);

        if blocked.iter().any(|(_, s)| **s == ScannerStatus::NeedsFda) {
            let ids: Vec<&str> = blocked
                .iter()
                .filter(|(_, s)| **s == ScannerStatus::NeedsFda)
                .map(|(id, _)| *id)
                .collect();
            let _ = writeln!(o, "  Full Disk Access — blocks: {}", ids.join(", "));
            let _ = writeln!(o);
            let _ = writeln!(o, "{}", fda_instructions(d.caps.exe.as_deref()));
            let _ = writeln!(o);
        }

        for (id, status) in &blocked {
            if let ScannerStatus::NeedsTool(tool) = status {
                let _ = writeln!(
                    o,
                    "  `{tool}` not installed — blocks: {id}. Install it, or set \
                     `[scanners.{id}] enabled = false` to stop being told."
                );
            }
        }
    } else {
        let _ = writeln!(o);
        let _ = writeln!(o, "  No problems found.");
    }

    o
}

pub fn to_json(d: &Diagnosis) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "config_file": d.config_source.as_ref().map(|p| p.display().to_string()),
        "volume": {
            "name": d.volume.name,
            "fs_type": d.volume.fs_type,
            "is_apfs": d.volume.is_apfs(),
            "total_bytes": d.volume.total,
            "available_important_bytes": d.volume.available_important,
            "available_raw_bytes": d.volume.available_raw,
            "purgeable_bytes": d.volume.purgeable(),
        },
        "full_disk_access": d.caps.fda.as_str(),
        "executable": d.caps.exe.as_ref().map(|p| p.display().to_string()),
        "tools": TOOLS.iter().map(|(key, _, purpose)| {
            serde_json::json!({
                "name": key,
                "available": d.caps.has_tool(key),
                "path": d.caps.tool_path(key).map(|p| p.display().to_string()),
                "purpose": purpose,
            })
        }).collect::<Vec<_>>(),
        "scanners": d.scanners.iter().map(|(id, status)| {
            serde_json::json!({
                "id": id,
                "ready": status.is_ready(),
                "blocked": status.is_blocked(),
                "status": status.describe(),
            })
        }).collect::<Vec<_>>(),
        "ready_count": d.ready_count(),
        "blocked_count": d.blocked().len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnosis_covers_every_scanner() {
        let cfg = Config::default();
        let d = Diagnosis::run(&cfg).unwrap();
        assert_eq!(d.scanners.len(), defaults::SCANNERS.len());
    }

    #[test]
    fn disabled_scanners_are_reported_as_disabled_not_blocked() {
        // FR-27: an off scanner is a choice, not a problem. Reporting it as
        // blocked would bury the real problems in noise.
        let cfg = Config::default();
        let d = Diagnosis::run(&cfg).unwrap();

        let trash = d.scanners.iter().find(|(id, _)| *id == "trash").unwrap();
        assert_eq!(trash.1, ScannerStatus::Disabled);
        assert!(!trash.1.is_blocked());
    }

    #[test]
    fn the_two_switch_case_is_reported_as_risk_gated() {
        let cfg = Config::parse("[scanners.trash]\nenabled = true\n").unwrap();
        let d = Diagnosis::run(&cfg).unwrap();

        let trash = d.scanners.iter().find(|(id, _)| *id == "trash").unwrap();
        assert_eq!(trash.1, ScannerStatus::RiskGated);
    }

    #[test]
    fn a_scanner_needing_a_missing_tool_is_blocked_with_the_tool_named() {
        let cfg = Config::default();
        let d = Diagnosis::run(&cfg).unwrap();

        for (id, status) in &d.scanners {
            if let ScannerStatus::NeedsTool(tool) = status {
                assert!(
                    !d.caps.has_tool(tool),
                    "`{id}` reported as needing `{tool}` which is actually present"
                );
                assert!(status.describe().contains(tool));
            }
        }
    }

    #[test]
    fn fda_instructions_name_the_binary_and_warn_about_terminal() {
        // Spec §10's "critical first-run detail". Getting this wrong means the
        // scheduled run silently fails forever.
        let text = fda_instructions(Some(std::path::Path::new("/opt/homebrew/bin/sift")));
        assert!(text.contains("/opt/homebrew/bin/sift"));
        assert!(text.contains("NOT to Terminal"));
        assert!(text.contains("launchd"));
    }

    #[test]
    fn every_blocked_scanner_produces_actionable_text() {
        // FR-26: every unavailable capability must print a next step.
        let cfg = Config::default();
        let d = Diagnosis::run(&cfg).unwrap();
        let out = render(&d);

        for (id, status) in d.blocked() {
            assert!(
                out.contains(id),
                "blocked scanner `{id}` missing from output"
            );
            match status {
                ScannerStatus::NeedsFda => assert!(out.contains("System Settings")),
                ScannerStatus::NeedsTool(t) => {
                    assert!(out.contains(&format!("`{t}` not installed")))
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn granted_fda_still_warns_that_the_agent_may_not_have_it() {
        // Spec §10's trap: a probe can only report on the current process, and
        // interactively that process inherited its grant from the terminal.
        // Reporting a bare "granted" would be true and misleading.
        let cfg = Config::default();
        let d = Diagnosis::run(&cfg).unwrap();
        if d.caps.fda.is_granted() {
            let out = render(&d);
            assert!(out.contains("current process"), "{out}");
            assert!(out.contains("scheduled agent"), "{out}");
        }
    }

    #[test]
    fn render_includes_volume_and_tool_sections() {
        let cfg = Config::default();
        let d = Diagnosis::run(&cfg).unwrap();
        let out = render(&d);

        assert!(out.contains("volume"));
        assert!(out.contains("tools"));
        assert!(out.contains("scanners"));
        assert!(out.contains("full disk"));
    }

    #[test]
    fn json_is_structurally_complete() {
        let cfg = Config::default();
        let d = Diagnosis::run(&cfg).unwrap();
        let j = to_json(&d);

        assert_eq!(j["schema_version"], 1);
        assert_eq!(
            j["scanners"].as_array().unwrap().len(),
            defaults::SCANNERS.len()
        );
        assert_eq!(j["tools"].as_array().unwrap().len(), TOOLS.len());
        assert!(j["volume"]["is_apfs"].is_boolean());
    }
}
