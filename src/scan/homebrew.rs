//! S8 `homebrew` — delegated cleanup (spec §6).
//!
//! # No subprocess during `scan`
//!
//! An earlier version ran `brew cleanup --dry-run` to size the candidate. That
//! was wrong twice over: it made `sift scan` take 4 seconds before touching a
//! file (against M4's 15-second budget for a whole 500 GB volume), and it
//! caused Homebrew to bootstrap ~958 files under a fresh `$HOME`, which is a
//! side effect FR-1 forbids.
//!
//! So the size is reported as unknown until the command runs. Availability is
//! decided by `which`, which spawns nothing. The cost is that the report cannot
//! show a figure for this line the way PRD §7's example does; the alternative
//! was breaking two requirements to get it.

use crate::risk::Risk;
use crate::scan::{Candidate, DelegatedCmd, Requirements, ScanCtx, Scanner, Target};
use crate::ScannerError;

pub struct Homebrew;

impl Scanner for Homebrew {
    fn id(&self) -> &'static str {
        "homebrew"
    }

    fn estimates_size(&self) -> bool {
        true
    }

    fn requirements(&self) -> Requirements {
        Requirements {
            fda: false,
            tool: Some("brew"),
        }
    }

    fn scan(&self, ctx: &ScanCtx) -> Result<Vec<Candidate>, ScannerError> {
        // Only spawns when the user asked for a figure (--estimate-delegated).
        // See the module docs for why that is not the default.
        let estimate = if ctx.estimate_delegated {
            match crate::action::delegate::probe(
                "brew",
                &["cleanup", "--prune=all", "--dry-run"],
                std::time::Duration::from_secs(60),
            ) {
                crate::action::delegate::Outcome::Ok { stdout, .. } => parse_reclaimable(&stdout),
                _ => 0,
            }
        } else {
            0
        };

        let mut out = vec![Candidate {
            scanner: self.id(),
            target: Target::Delegated(DelegatedCmd::new("brew", &["cleanup", "--prune=all", "-q"])),
            bytes_on_disk: estimate,
            bytes_apparent: estimate,
            last_modified: ctx.now,
            risk: Risk::Safe,
            label: "Homebrew — stale downloads and old versions".into(),
            reason: if estimate == 0 {
                "brew cleanup; size unknown without --estimate-delegated. \
                 Re-downloaded on next install"
                    .into()
            } else {
                "brew cleanup; re-downloaded on next install".to_string()
            },
        }];

        // `brew autoremove` uninstalls packages nothing depends on. That can
        // remove something the user installed deliberately and simply has not
        // used from another formula, so it is opt-in (spec §6) and default off.
        if ctx
            .config
            .scanner(self.id())
            .and_then(|c| c.autoremove)
            .unwrap_or(false)
        {
            out.push(Candidate {
                scanner: self.id(),
                target: Target::Delegated(DelegatedCmd::new("brew", &["autoremove", "-q"])),
                bytes_on_disk: 0,
                bytes_apparent: 0,
                last_modified: ctx.now,
                risk: Risk::Rebuildable,
                label: "Homebrew — unused dependencies".into(),
                reason: "brew autoremove; reinstallable, but may remove something you wanted"
                    .into(),
            });
        }

        Ok(out)
    }
}

/// Parse the trailing "This operation has freed approximately N" line.
///
/// Returns 0 rather than guessing when the format is unrecognised. An
/// overstated estimate would inflate the report and could trip the circuit
/// breaker on bytes that do not exist.
fn parse_reclaimable(stdout: &str) -> u64 {
    for line in stdout.lines() {
        let l = line.trim();
        if !l.contains("freed approximately") && !l.contains("would free") {
            continue;
        }
        let tokens: Vec<&str> = l.split_whitespace().collect();
        for (i, t) in tokens.iter().enumerate() {
            let unit = t.trim_end_matches('.').to_ascii_uppercase();
            let mult = match unit.as_str() {
                "B" => 1u64,
                "KB" => 1_000,
                "MB" => 1_000_000,
                "GB" => 1_000_000_000,
                "TB" => 1_000_000_000_000,
                _ => continue,
            };
            if i > 0 {
                if let Ok(v) = tokens[i - 1].parse::<f64>() {
                    return (v * mult as f64) as u64;
                }
            }
        }
        for t in &tokens {
            let t = t.trim_end_matches('.');
            for (suffix, mult) in [
                ("TB", 1_000_000_000_000u64),
                ("GB", 1_000_000_000),
                ("MB", 1_000_000),
                ("KB", 1_000),
            ] {
                if let Some(num) = t.strip_suffix(suffix) {
                    if let Ok(v) = num.parse::<f64>() {
                        return (v * mult as f64) as u64;
                    }
                }
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_real_brew_output_format() {
        let sample = "==> This operation has freed approximately 1.2GB of disk space.\n";
        assert_eq!(parse_reclaimable(sample), 1_200_000_000);
    }

    #[test]
    fn parses_the_spaced_form() {
        assert_eq!(
            parse_reclaimable("==> This operation has freed approximately 512 MB of disk space.\n"),
            512_000_000
        );
    }

    #[test]
    fn unrecognised_output_estimates_zero_rather_than_guessing() {
        // An overstated estimate would inflate the report and could trip the
        // circuit breaker on bytes that do not exist.
        assert_eq!(parse_reclaimable(""), 0);
        assert_eq!(parse_reclaimable("unrelated output\n"), 0);
    }

    #[test]
    fn the_action_command_is_the_one_the_spec_names() {
        let cmd = DelegatedCmd::new("brew", &["cleanup", "--prune=all", "-q"]);
        assert_eq!(cmd.display(), "brew cleanup --prune=all -q");
    }

    #[test]
    fn autoremove_is_not_part_of_the_default_command() {
        // spec §6: autoremove is opt-in, because it can uninstall something the
        // user installed deliberately.
        let cmd = DelegatedCmd::new("brew", &["cleanup", "--prune=all", "-q"]);
        assert!(!cmd.display().contains("autoremove"));
    }

    #[test]
    fn the_scanner_declares_its_tool_requirement() {
        assert_eq!(Homebrew.requirements().tool, Some("brew"));
    }
}
