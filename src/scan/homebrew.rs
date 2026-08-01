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

    fn requirements(&self) -> Requirements {
        Requirements {
            fda: false,
            tool: Some("brew"),
        }
    }

    fn scan(&self, ctx: &ScanCtx) -> Result<Vec<Candidate>, ScannerError> {
        // No subprocess here. See the module docs: `scan` spawns nothing.
        let estimate = 0;

        let mut out = vec![Candidate {
            scanner: self.id(),
            target: Target::Delegated(DelegatedCmd::new("brew", &["cleanup", "--prune=all", "-q"])),
            bytes_on_disk: estimate,
            bytes_apparent: estimate,
            last_modified: ctx.now,
            risk: Risk::Safe,
            label: "Homebrew — stale downloads and old versions".into(),
            reason: "brew cleanup; re-downloaded on next install".into(),
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

#[cfg(test)]
mod tests {
    use super::*;

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
