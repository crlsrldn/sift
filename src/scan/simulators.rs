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

/// Total `dataPathSize` of every device simctl reports as unavailable.
///
/// The figure comes from simctl rather than from walking
/// `CoreSimulator/Devices` ourselves, for the same reason the deletion is
/// delegated: simctl's plist index is the authority on which devices belong to
/// an uninstalled runtime, and a directory listing is not.
///
/// Any failure — simctl missing, timing out, changing its JSON — yields 0,
/// which the caller renders as "size unknown". Guessing a number here would be
/// worse than admitting we do not have one (Principle 7).
fn unavailable_bytes() -> u64 {
    let out = crate::action::delegate::probe(
        "xcrun",
        &["simctl", "list", "devices", "--json"],
        std::time::Duration::from_secs(30),
    );
    let stdout = match out {
        crate::action::delegate::Outcome::Ok { stdout, .. } => stdout,
        _ => return 0,
    };
    parse_unavailable_bytes(&stdout)
}

/// Sum `dataPathSize` over devices with `isAvailable == false`.
fn parse_unavailable_bytes(json: &str) -> u64 {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return 0;
    };
    let Some(runtimes) = v.get("devices").and_then(|d| d.as_object()) else {
        return 0;
    };
    runtimes
        .values()
        .filter_map(|devs| devs.as_array())
        .flatten()
        .filter(|d| d.get("isAvailable").and_then(|a| a.as_bool()) == Some(false))
        .filter_map(|d| d.get("dataPathSize").and_then(|s| s.as_u64()))
        .sum()
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
            // Without --estimate-delegated this stays 0, exactly as the
            // Homebrew and container scanners behave — and, as there, the
            // reason has to say the figure is unknown rather than let a bare
            // "0 B" read as "nothing to reclaim". On the machine this was first
            // measured against, that silent zero was hiding 384 MB across 22
            // devices from two uninstalled iOS runtimes.
            let estimate = if ctx.estimate_delegated {
                unavailable_bytes()
            } else {
                0
            };

            out.push(Candidate {
                scanner: self.id(),
                target: Target::Delegated(DelegatedCmd::new(
                    "xcrun",
                    &["simctl", "delete", "unavailable"],
                )),
                bytes_on_disk: estimate,
                bytes_apparent: estimate,
                last_modified: ctx.now,
                risk: Risk::Rebuildable,
                label: "Simulator devices for uninstalled runtimes".into(),
                reason: if estimate == 0 {
                    "xcrun simctl delete unavailable; size unknown without \
                     --estimate-delegated. Recreated on demand"
                        .into()
                } else {
                    "xcrun simctl delete unavailable; recreated on demand".to_string()
                },
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

    /// Trimmed from real `xcrun simctl list devices --json` output on
    /// Xcode 26.6, keeping one available and two unavailable devices.
    const REAL_SIMCTL_JSON: &str = r#"{
      "devices" : {
        "com.apple.CoreSimulator.SimRuntime.iOS-26-0" : [
          {
            "availabilityError" : "runtime profile not found using \"System\" match policy",
            "dataPath" : "/Users/x/Library/Developer/CoreSimulator/Devices/76F9/data",
            "dataPathSize" : 18337792,
            "udid" : "76F92C4F-74A5-4DB7-BB15-A008CA85AA87",
            "isAvailable" : false,
            "state" : "Shutdown",
            "name" : "iPhone 17 Pro"
          },
          {
            "dataPathSize" : 1000000,
            "udid" : "1BE8E420-4B16-43AF-8A9C-762A4F239EF6",
            "isAvailable" : false,
            "state" : "Shutdown",
            "name" : "iPhone Air"
          }
        ],
        "com.apple.CoreSimulator.SimRuntime.iOS-18-4" : [
          {
            "dataPathSize" : 999999999,
            "udid" : "C4D3CC51-4637-4BF5-8FA2-CA18B9C9E9DA",
            "isAvailable" : true,
            "state" : "Shutdown",
            "name" : "iPhone 16e"
          }
        ]
      }
    }"#;

    #[test]
    fn only_unavailable_devices_are_counted() {
        // The available device is nearly a gigabyte. Counting it would report
        // space that deleting unavailable runtimes cannot possibly free.
        assert_eq!(
            parse_unavailable_bytes(REAL_SIMCTL_JSON),
            18337792 + 1000000
        );
    }

    #[test]
    fn unparseable_simctl_output_estimates_nothing() {
        // Principle 7: a changed JSON shape must produce "unknown", never a
        // number that happens to parse.
        for bad in ["", "not json", "{}", r#"{"devices": null}"#, "[]"] {
            assert_eq!(parse_unavailable_bytes(bad), 0, "`{bad}` should yield 0");
        }
    }

    #[test]
    fn a_device_missing_its_size_does_not_abort_the_sum() {
        // Older simctl builds omit dataPathSize. The others still count.
        let json = r#"{"devices":{"rt":[
            {"isAvailable":false},
            {"isAvailable":false,"dataPathSize":4096}
        ]}}"#;
        assert_eq!(parse_unavailable_bytes(json), 4096);
    }
}
