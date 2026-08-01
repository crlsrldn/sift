//! S5 `simulators` — delegated simulator cleanup (spec §6, Principle 5).
//!
//! # The hard deny
//!
//! `~/Library/Developer/CoreSimulator/Devices` is owned by `simctl`, which
//! keeps a plist index alongside it. **Deleting a device directory by hand
//! corrupts that index**, and the user's simulators stop working in a way that
//! is confusing to diagnose and annoying to repair.
//!
//! So the devices themselves are only ever removed by `simctl delete
//! unavailable`, and the path is a hard-coded deny with its own test rather
//! than a convention we intend to follow.

use crate::fs::size;
use crate::risk::Risk;
use crate::scan::{Candidate, DelegatedCmd, Requirements, ScanCtx, Scanner, Target};
use crate::ScannerError;
use chrono::{DateTime, Local};
use std::path::{Path, PathBuf};

pub struct Simulators;

/// Never touched directly, whatever else changes.
const SIMCTL_OWNED: &str = "Library/Developer/CoreSimulator/Devices";

/// Whether a path falls inside the directory `simctl` owns.
pub fn is_simctl_owned(path: &Path) -> bool {
    path.to_string_lossy().contains(SIMCTL_OWNED)
}

impl Scanner for Simulators {
    fn id(&self) -> &'static str {
        "simulators"
    }

    fn requirements(&self) -> Requirements {
        Requirements {
            fda: false,
            tool: Some("xcrun"),
        }
    }

    fn scan(&self, ctx: &ScanCtx) -> Result<Vec<Candidate>, ScannerError> {
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
            return Ok(Vec::new());
        };
        let coresim = home.join("Library/Developer/CoreSimulator");
        if !coresim.is_dir() {
            return Ok(Vec::new());
        }

        let mut out = Vec::new();

        // Unavailable devices — runtimes that are no longer installed. Only
        // simctl may remove these. Offered unconditionally when xcrun exists:
        // asking simctl whether any are unavailable costs a subprocess, and
        // `scan` spawns nothing (FR-1, M4). `simctl delete unavailable` is a
        // no-op when there are none.
        {
            out.push(Candidate {
                scanner: self.id(),
                target: Target::Delegated(DelegatedCmd::new(
                    "xcrun",
                    &["simctl", "delete", "unavailable"],
                )),
                bytes_on_disk: 0,
                bytes_apparent: 0,
                last_modified: ctx.now,
                risk: Risk::Rebuildable,
                label: "Simulator devices for uninstalled runtimes".into(),
                reason: "xcrun simctl delete unavailable; recreated on demand".into(),
            });
        }

        // The dyld cache is not indexed by simctl, so it can be reclaimed as a
        // path — and unlike Devices, deleting it corrupts nothing.
        let caches = coresim.join("Caches");
        if caches.is_dir() && !is_simctl_owned(&caches) {
            if let Ok(m) = size::measure_with(&ctx.walker(), &caches) {
                if m.bytes_on_disk > 0 {
                    let modified = std::fs::symlink_metadata(&caches)
                        .ok()
                        .and_then(|md| md.modified().ok())
                        .map(DateTime::<Local>::from)
                        .unwrap_or(ctx.now);

                    out.push(Candidate {
                        scanner: self.id(),
                        target: Target::Path(caches),
                        bytes_on_disk: m.bytes_on_disk,
                        bytes_apparent: m.bytes_apparent,
                        last_modified: modified,
                        risk: Risk::Rebuildable,
                        label: "Simulator caches".into(),
                        reason: "CoreSimulator dyld caches; rebuilt on next simulator launch"
                            .into(),
                    });
                }
            }
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_simctl_owned_directory_is_recognised() {
        // Deleting a device directory by hand corrupts simctl's plist index.
        assert!(is_simctl_owned(Path::new(
            "/Users/x/Library/Developer/CoreSimulator/Devices"
        )));
        assert!(is_simctl_owned(Path::new(
            "/Users/x/Library/Developer/CoreSimulator/Devices/ABC-123/data"
        )));
    }

    #[test]
    fn the_caches_directory_is_not_simctl_owned() {
        assert!(!is_simctl_owned(Path::new(
            "/Users/x/Library/Developer/CoreSimulator/Caches"
        )));
        assert!(!is_simctl_owned(Path::new(
            "/Users/x/Library/Developer/CoreSimulator/Caches/dyld"
        )));
    }

    #[test]
    fn devices_are_only_ever_removed_through_simctl() {
        // The command is delegated, so simctl maintains its own index.
        let cmd = DelegatedCmd::new("xcrun", &["simctl", "delete", "unavailable"]);
        assert_eq!(cmd.display(), "xcrun simctl delete unavailable");
    }

    #[test]
    fn the_scanner_declares_its_tool_requirement() {
        assert_eq!(Simulators.requirements().tool, Some("xcrun"));
    }
}
