//! Rust scanners: S6 `target/` directories, S7 Cargo caches (spec §6).
//!
//! # The two hard denies
//!
//! `~/.cargo/bin` holds installed binaries — `cargo-nextest`, `ripgrep`,
//! whatever the user has `cargo install`ed. `~/.rustup` holds the toolchains
//! themselves. Deleting either is not a cache miss, it is an unusable Rust
//! installation and a multi-gigabyte re-download.
//!
//! Both are hard-coded denies with their own tests rather than a convention,
//! because "we just don't add those paths" is not a guarantee.

use crate::fs::size;
use crate::risk::Risk;
use crate::scan::{Candidate, DelegatedCmd, ScanCtx, Scanner, Target};
use crate::ScannerError;
use chrono::{DateTime, Local};
use std::path::{Path, PathBuf};

/// Paths under `~/.cargo` and `~/.rustup` that must never be actioned.
///
/// Checked by suffix on the *component path* so a user directory that merely
/// contains "bin" is unaffected.
const NEVER_TOUCH: &[&str] = &[".cargo/bin", ".cargo/env", ".rustup"];

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Whether a path is one of the protected Rust installation directories.
pub fn is_protected(path: &Path) -> bool {
    let s = path.to_string_lossy();
    NEVER_TOUCH.iter().any(|deny| {
        // Match `<something>/.cargo/bin` and `<something>/.cargo/bin/...`,
        // but not `~/dev/mycrate/.cargo/binaries`.
        s.contains(&format!("/{deny}/")) || s.ends_with(&format!("/{deny}"))
    })
}

fn mtime(meta: &std::fs::Metadata) -> Option<DateTime<Local>> {
    meta.modified().ok().map(DateTime::<Local>::from)
}

// ---------------------------------------------------------------------------
// S6 — rust-targets
// ---------------------------------------------------------------------------

pub struct Targets;

impl Scanner for Targets {
    fn id(&self) -> &'static str {
        "rust-targets"
    }

    fn scan(&self, ctx: &ScanCtx) -> Result<Vec<Candidate>, ScannerError> {
        // FR-25. There is deliberately no home-directory-wide fallback: with no
        // configured roots this scanner finds nothing, by design.
        if ctx.config.projects.roots.is_empty() {
            return Ok(Vec::new());
        }

        let cfg = ctx.config.scanner(self.id());
        let min_age = cfg.and_then(|c| c.min_age_days).unwrap_or(30) as i64;

        // PRD Open Question 3, resolved: prefer cargo-sweep when it is
        // installed. It solves this problem correctly and is maintained, and
        // Principle 5 says delegate to the owner tool.
        //
        // The escape hatch matters. Delegation bypasses quarantine (FR-15), so
        // a user who wants the reversible path can force the native
        // implementation with `prefer_delegation = false`.
        let prefer_delegation = cfg.and_then(|c| c.prefer_delegation).unwrap_or(true);
        if prefer_delegation && crate::caps::which("cargo-sweep").is_some() {
            return Ok(ctx
                .config
                .projects
                .roots
                .iter()
                .filter(|r| r.is_dir())
                .map(|root| Candidate {
                    scanner: self.id(),
                    target: Target::Delegated(DelegatedCmd::new(
                        "cargo-sweep",
                        &[
                            "sweep",
                            "--time",
                            &min_age.to_string(),
                            "--recursive",
                            &root.to_string_lossy(),
                        ],
                    )),
                    bytes_on_disk: 0,
                    bytes_apparent: 0,
                    last_modified: ctx.now,
                    risk: Risk::Rebuildable,
                    label: format!("target/ under {} (via cargo-sweep)", root.display()),
                    // The user must never have to guess whether their cleanup
                    // was reversible.
                    reason: format!(
                        "cargo-sweep --time {min_age} --recursive. NOT reversible: \
                         delegated commands bypass quarantine. Set \
                         `[scanners.rust-targets] prefer_delegation = false` for the \
                         native, undoable path"
                    ),
                })
                .collect());
        }

        let mut out = Vec::new();
        for root in &ctx.config.projects.roots {
            if !root.is_dir() {
                continue;
            }
            find_targets(ctx, root, min_age, 0, &mut out);
        }
        Ok(out)
    }
}

/// Depth-limited search for `target/` directories with a sibling `Cargo.toml`.
///
/// Does not descend into a matched `target/`, into `.git`, or into anything the
/// walker's guards would refuse.
fn find_targets(ctx: &ScanCtx, dir: &Path, min_age: i64, depth: usize, out: &mut Vec<Candidate>) {
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
        if is_protected(&path) || ctx.excludes.is_match(&path) {
            continue;
        }

        let name = entry.file_name();
        let name = name.to_string_lossy();

        if name == ".git" || name == "node_modules" {
            continue;
        }

        if name == "target" {
            // The defining rule (spec §6 S6): a directory named `target` whose
            // PARENT contains Cargo.toml. Without the sibling check, any
            // directory called "target" anywhere under a project root — a data
            // directory, a build output for another language — would qualify.
            if !dir.join("Cargo.toml").is_file() {
                continue;
            }

            let walker = ctx.walker();
            let Ok(result) = walker.walk(&path) else {
                continue;
            };
            let Some(newest) = result.newest_mtime().map(DateTime::<Local>::from) else {
                continue;
            };
            let age = ctx.age_days(newest);
            if age < min_age {
                continue;
            }

            let m = size::measure_result(&result);
            if m.bytes_on_disk == 0 {
                continue;
            }

            let project = dir
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| dir.display().to_string());

            out.push(Candidate {
                scanner: "rust-targets",
                target: Target::Path(path),
                bytes_on_disk: m.bytes_on_disk,
                bytes_apparent: m.bytes_apparent,
                last_modified: newest,
                risk: Risk::Rebuildable,
                label: format!("target/ — {project} (idle {age}d)"),
                reason: format!("no build artifact touched in {age} days; `cargo build` rebuilds"),
            });
            // Do not descend into a claimed target/.
            continue;
        }

        find_targets(ctx, &path, min_age, depth + 1, out);
    }
}

// ---------------------------------------------------------------------------
// S7 — cargo-cache
// ---------------------------------------------------------------------------

pub struct CargoCache;

/// Exactly the three paths spec §6 S7 names. Nothing else under `~/.cargo` is
/// ever considered.
const CARGO_CACHE_SUBPATHS: &[(&str, &str)] = &[
    (
        "registry/cache",
        "downloaded crate archives; re-fetched on demand",
    ),
    (
        "registry/src",
        "unpacked crate sources; re-extracted from cache",
    ),
    (
        "git/checkouts",
        "git dependency checkouts; re-cloned on demand",
    ),
];

impl Scanner for CargoCache {
    fn id(&self) -> &'static str {
        "cargo-cache"
    }

    fn scan(&self, ctx: &ScanCtx) -> Result<Vec<Candidate>, ScannerError> {
        let Some(home) = home() else {
            return Ok(Vec::new());
        };
        let cargo = home.join(".cargo");
        if !cargo.is_dir() {
            return Ok(Vec::new());
        }

        let cfg = ctx.config.scanner(self.id());
        let min_age = cfg.and_then(|c| c.min_age_days).unwrap_or(60) as i64;

        // Same preference, same escape hatch (PRD Open Question 3).
        let prefer_delegation = cfg.and_then(|c| c.prefer_delegation).unwrap_or(true);
        if prefer_delegation && crate::caps::which("cargo-cache").is_some() {
            return Ok(vec![Candidate {
                scanner: self.id(),
                target: Target::Delegated(DelegatedCmd::new("cargo-cache", &["--autoclean"])),
                bytes_on_disk: 0,
                bytes_apparent: 0,
                last_modified: ctx.now,
                risk: Risk::Safe,
                label: "Cargo caches (via cargo-cache)".into(),
                reason: "cargo cache --autoclean. NOT reversible: delegated commands \
                         bypass quarantine. Set `[scanners.cargo-cache] \
                         prefer_delegation = false` for the native, undoable path"
                    .into(),
            }]);
        }

        let mut out = Vec::new();
        for (sub, why) in CARGO_CACHE_SUBPATHS {
            let path = cargo.join(sub);
            if !path.is_dir() {
                continue;
            }
            // Belt and braces: these paths are hard-coded, but the deny check
            // runs anyway so a future edit to the list cannot bypass it.
            if is_protected(&path) {
                continue;
            }

            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            let Some(modified) = mtime(&meta) else {
                continue;
            };
            let age = ctx.age_days(modified);
            if age < min_age {
                continue;
            }

            let Ok(m) = size::measure_with(&ctx.walker(), &path) else {
                continue;
            };
            if m.bytes_on_disk == 0 {
                continue;
            }

            out.push(Candidate {
                scanner: "cargo-cache",
                target: Target::Path(path),
                bytes_on_disk: m.bytes_on_disk,
                bytes_apparent: m.bytes_apparent,
                last_modified: modified,
                risk: Risk::Safe,
                label: format!("Cargo {sub}"),
                reason: (*why).into(),
            });
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rust_installation_is_protected() {
        // Deleting either of these is not a cache miss, it is an unusable Rust
        // installation and a multi-gigabyte re-download.
        assert!(is_protected(Path::new("/Users/x/.cargo/bin")));
        assert!(is_protected(Path::new("/Users/x/.cargo/bin/cargo-nextest")));
        assert!(is_protected(Path::new("/Users/x/.rustup")));
        assert!(is_protected(Path::new(
            "/Users/x/.rustup/toolchains/stable"
        )));
        assert!(is_protected(Path::new("/Users/x/.cargo/env")));
    }

    #[test]
    fn the_cache_paths_are_not_protected() {
        assert!(!is_protected(Path::new("/Users/x/.cargo/registry/cache")));
        assert!(!is_protected(Path::new("/Users/x/.cargo/registry/src")));
        assert!(!is_protected(Path::new("/Users/x/.cargo/git/checkouts")));
    }

    #[test]
    fn protection_does_not_over_match_user_directories() {
        // A user's own project named `.rustup` or containing `bin` must not be
        // caught by the deny rule.
        assert!(!is_protected(Path::new(
            "/Users/x/dev/mycrate/.cargo/binaries"
        )));
        assert!(!is_protected(Path::new("/Users/x/dev/bin")));
        assert!(!is_protected(Path::new("/Users/x/rustup-notes")));
    }

    #[test]
    fn the_delegated_commands_are_the_ones_the_spec_names() {
        // spec §6 S6 and S7.
        assert_eq!(
            DelegatedCmd::new(
                "cargo-sweep",
                &["sweep", "--time", "30", "--recursive", "/x"]
            )
            .display(),
            "cargo-sweep sweep --time 30 --recursive /x"
        );
        assert_eq!(
            DelegatedCmd::new("cargo-cache", &["--autoclean"]).display(),
            "cargo-cache --autoclean"
        );
    }

    #[test]
    fn delegation_is_preferred_by_default_but_overridable() {
        // Delegation bypasses quarantine (FR-15), so a user who wants the
        // reversible path must be able to insist on it.
        let on = crate::config::Config::parse("").unwrap();
        assert_eq!(on.scanner("rust-targets").unwrap().prefer_delegation, None);

        let off =
            crate::config::Config::parse("[scanners.rust-targets]\nprefer_delegation = false\n")
                .unwrap();
        assert_eq!(
            off.scanner("rust-targets").unwrap().prefer_delegation,
            Some(false)
        );
    }

    #[test]
    fn only_the_three_spec_paths_are_considered() {
        // Principle 1: an allowlist, not a scan of ~/.cargo.
        assert_eq!(CARGO_CACHE_SUBPATHS.len(), 3);
        let names: Vec<&str> = CARGO_CACHE_SUBPATHS.iter().map(|(p, _)| *p).collect();
        assert_eq!(
            names,
            vec!["registry/cache", "registry/src", "git/checkouts"]
        );
    }

    #[test]
    fn every_cache_path_explains_what_regenerating_costs() {
        for (path, why) in CARGO_CACHE_SUBPATHS {
            assert!(!why.is_empty(), "{path} has no reason string");
        }
    }
}
