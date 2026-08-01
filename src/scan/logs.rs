//! S17 `logs` — user log files and crash reports (spec §6).

use crate::fs::size;
use crate::risk::Risk;
use crate::scan::{Candidate, ScanCtx, Scanner, Target};
use crate::ScannerError;
use chrono::{DateTime, Local};
use std::path::PathBuf;

pub struct Logs;

/// Only these roots, and only under the user's own Library. `/var/log` and
/// `/Library/Logs` are system-owned and out of scope (Principle 8: no root).
const LOG_ROOTS: &[&str] = &["Library/Logs"];

/// Crash and diagnostic report extensions.
const REPORT_EXTENSIONS: &[&str] = &["crash", "diag", "ips", "hang", "spin"];

impl Scanner for Logs {
    fn id(&self) -> &'static str {
        "logs"
    }

    fn scan(&self, ctx: &ScanCtx) -> Result<Vec<Candidate>, ScannerError> {
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
            return Ok(Vec::new());
        };

        let min_age = ctx
            .config
            .scanner(self.id())
            .and_then(|c| c.min_age_days)
            .unwrap_or(30) as i64;

        let mut out = Vec::new();
        for root in LOG_ROOTS {
            let dir = home.join(root);
            if !dir.is_dir() {
                continue;
            }

            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };

            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(meta) = std::fs::symlink_metadata(&path) else {
                    continue;
                };
                if meta.is_symlink() {
                    continue;
                }

                // Per-subdirectory rather than the whole Logs tree, so one
                // recently-active app's logs do not protect everything else.
                let (modified, m) = if meta.is_dir() {
                    let Ok((m, newest_raw)) = size::measure_and_newest(&ctx.walker(), &path) else {
                        continue;
                    };
                    let Some(newest) = newest_raw.map(DateTime::<Local>::from) else {
                        continue;
                    };
                    (newest, m)
                } else {
                    let Some(t) = meta.modified().ok().map(DateTime::<Local>::from) else {
                        continue;
                    };
                    let mut mm = size::Measurer::new();
                    mm.add(&meta);
                    (t, mm.finish())
                };

                let age = ctx.age_days(modified);
                if age < min_age || m.bytes_on_disk == 0 {
                    continue;
                }

                let name = entry.file_name().to_string_lossy().into_owned();
                let is_report = path
                    .extension()
                    .map(|e| REPORT_EXTENSIONS.contains(&e.to_string_lossy().as_ref()))
                    .unwrap_or(false);

                out.push(Candidate {
                    scanner: "logs",
                    target: Target::Path(path),
                    bytes_on_disk: m.bytes_on_disk,
                    bytes_apparent: m.bytes_apparent,
                    last_modified: modified,
                    risk: Risk::Safe,
                    label: if is_report {
                        format!("Crash report — {name}")
                    } else {
                        format!("Logs — {name}")
                    },
                    reason: format!("last written {age} days ago"),
                });
            }
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_users_own_log_directory_is_in_scope() {
        // /var/log and /Library/Logs are system-owned. Touching them would
        // require root, which is out of scope permanently (Principle 8).
        assert_eq!(LOG_ROOTS, &["Library/Logs"]);
        for r in LOG_ROOTS {
            assert!(!r.starts_with('/'), "`{r}` is an absolute system path");
        }
    }

    #[test]
    fn report_extensions_cover_the_macos_set() {
        for ext in ["crash", "diag", "ips"] {
            assert!(REPORT_EXTENSIONS.contains(&ext), "missing `{ext}`");
        }
    }
}
