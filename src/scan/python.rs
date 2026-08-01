//! S11 `python-caches` — pip, uv, and stray `__pycache__` (spec §6).
//!
//! Virtualenvs are never candidates. A `.venv` is a project's installed
//! environment, not a cache: deleting it breaks the project until someone
//! reinstalls, and for a project without a lockfile the reinstall may not
//! reproduce it.

use crate::fs::size;
use crate::risk::Risk;
use crate::scan::{Candidate, DelegatedCmd, ScanCtx, Scanner, Target};
use crate::ScannerError;
use chrono::{DateTime, Local};
use std::path::{Path, PathBuf};

pub struct PythonCaches;

/// Directory names that are environments, not caches.
const VIRTUALENV_NAMES: &[&str] = &[
    ".venv",
    "venv",
    "env",
    ".env",
    "virtualenv",
    ".tox",
    "conda",
];

pub fn is_virtualenv(path: &Path) -> bool {
    path.components().any(|c| {
        VIRTUALENV_NAMES
            .iter()
            .any(|n| c.as_os_str() == std::ffi::OsStr::new(n))
    })
}

impl Scanner for PythonCaches {
    fn id(&self) -> &'static str {
        "python-caches"
    }

    fn scan(&self, ctx: &ScanCtx) -> Result<Vec<Candidate>, ScannerError> {
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
            return Ok(Vec::new());
        };
        let min_age = ctx
            .config
            .scanner(self.id())
            .and_then(|c| c.min_age_days)
            .unwrap_or(60) as i64;

        let mut out = Vec::new();

        let pip = home.join("Library/Caches/pip");
        if pip.is_dir() && !is_virtualenv(&pip) {
            if let Ok(meta) = std::fs::symlink_metadata(&pip) {
                if let Some(modified) = meta.modified().ok().map(DateTime::<Local>::from) {
                    let age = ctx.age_days(modified);
                    if age >= min_age {
                        if let Ok(m) = size::measure_with(&ctx.walker(), &pip) {
                            if m.bytes_on_disk > 0 {
                                out.push(Candidate {
                                    scanner: self.id(),
                                    target: Target::Path(pip),
                                    bytes_on_disk: m.bytes_on_disk,
                                    bytes_apparent: m.bytes_apparent,
                                    last_modified: modified,
                                    risk: Risk::Safe,
                                    label: "pip wheel cache".into(),
                                    reason: format!(
                                        "not written in {age} days; re-downloaded on next install"
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }

        if crate::caps::which("uv").is_some() {
            out.push(Candidate {
                scanner: self.id(),
                target: Target::Delegated(DelegatedCmd::new("uv", &["cache", "prune"])),
                bytes_on_disk: 0,
                bytes_apparent: 0,
                last_modified: ctx.now,
                risk: Risk::Safe,
                label: "uv cache — unreferenced entries".into(),
                reason: "uv cache prune; re-fetched on next install".into(),
            });
        }

        // FR-25: __pycache__ is only searched under explicitly configured
        // project roots. There is no home-wide sweep.
        for root in &ctx.config.projects.roots {
            if root.is_dir() {
                find_pycache(ctx, root, min_age, 0, &mut out);
            }
        }

        Ok(out)
    }
}

fn find_pycache(ctx: &ScanCtx, dir: &Path, min_age: i64, depth: usize, out: &mut Vec<Candidate>) {
    if depth > ctx.config.safety.max_walk_depth {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_dir() || meta.is_symlink() {
            continue;
        }
        // Never descend into an environment, and never claim one.
        if is_virtualenv(&path) || crate::scan::node::is_node_modules(&path) {
            continue;
        }
        if ctx.excludes.is_match(&path) {
            continue;
        }

        let name = entry.file_name();
        if name == "__pycache__" {
            let Ok(m) = size::measure_with(&ctx.walker(), &path) else {
                continue;
            };
            let Some(modified) = meta.modified().ok().map(DateTime::<Local>::from) else {
                continue;
            };
            let age = ctx.age_days(modified);
            if age < min_age || m.bytes_on_disk == 0 {
                continue;
            }

            out.push(Candidate {
                scanner: "python-caches",
                target: Target::Path(path),
                bytes_on_disk: m.bytes_on_disk,
                bytes_apparent: m.bytes_apparent,
                last_modified: modified,
                risk: Risk::Safe,
                label: format!(
                    "__pycache__ — {}",
                    dir.file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default()
                ),
                reason: "compiled bytecode; regenerated on next import".into(),
            });
            continue;
        }

        if name == ".git" {
            continue;
        }
        find_pycache(ctx, &path, min_age, depth + 1, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtualenvs_are_recognised_and_never_claimed() {
        // A .venv is a project's environment, not a cache. Deleting it breaks
        // the project until someone reinstalls.
        for p in [
            "/Users/x/proj/.venv",
            "/Users/x/proj/venv/lib/python3.12",
            "/Users/x/proj/.tox/py312",
            "/Users/x/proj/.venv/lib/__pycache__",
        ] {
            assert!(is_virtualenv(Path::new(p)), "{p} should be a virtualenv");
        }
    }

    #[test]
    fn the_caches_this_scanner_claims_are_not_virtualenvs() {
        assert!(!is_virtualenv(Path::new("/Users/x/Library/Caches/pip")));
        assert!(!is_virtualenv(Path::new("/Users/x/proj/src/__pycache__")));
    }

    #[test]
    fn the_uv_command_is_the_documented_one() {
        assert_eq!(
            DelegatedCmd::new("uv", &["cache", "prune"]).display(),
            "uv cache prune"
        );
    }
}
