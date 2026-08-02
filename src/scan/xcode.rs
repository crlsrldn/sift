//! Xcode scanners: S2 DerivedData, S3 DeviceSupport, S4 Archives (spec §6).
//!
//! On the PRD's target persona — the developer whose SSD is full — these are
//! the largest single reclaim available, and S3 in particular is usually the
//! biggest line in the report.

pub mod version;

use crate::fs::size;
use crate::risk::Risk;
use crate::scan::{Candidate, Requirements, ScanCtx, Scanner, Target};
use crate::ScannerError;
use chrono::{DateTime, Local};
use std::path::{Path, PathBuf};
use version::OsVersion;

fn developer_dir(ctx: &ScanCtx) -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let p = PathBuf::from(home).join("Library/Developer/Xcode");
    let _ = ctx;
    p.is_dir().then_some(p)
}

fn mtime(meta: &std::fs::Metadata) -> Option<DateTime<Local>> {
    meta.modified().ok().map(DateTime::<Local>::from)
}

/// Newest mtime anywhere inside a tree.
///
/// This, not the directory's own mtime, is what FR-17's liveness guard needs: a
/// DerivedData directory's mtime does not change when a file three levels down
/// is rewritten, so trusting it would let sift quarantine a build that is
/// actively running.
fn newest_mtime_within(ctx: &ScanCtx, path: &Path) -> Option<DateTime<Local>> {
    ctx.walker()
        .newest_mtime(path)
        .ok()
        .flatten()
        .map(DateTime::<Local>::from)
}

/// Whether anything in the tree was touched inside the liveness window (FR-17).
fn is_active(ctx: &ScanCtx, path: &Path) -> bool {
    let window = chrono::Duration::minutes(ctx.config.safety.active_window_minutes as i64);
    match newest_mtime_within(ctx, path) {
        Some(t) => (ctx.now - t) < window,
        // Cannot tell, so assume active. Principle 7: refuse rather than guess.
        None => true,
    }
}

// ---------------------------------------------------------------------------
// S2 — xcode-derived
// ---------------------------------------------------------------------------

pub struct DerivedData;

/// `ModuleCache.noindex` under this size is preserved: it is shared across
/// projects and expensive to rebuild, so evicting a small one is a bad trade
/// (spec §6 S2).
const MODULE_CACHE_KEEP_UNDER: u64 = 1_000_000_000;

/// Shared caches that live in `DerivedData` but are not per-project.
///
/// Xcode 26 creates three of these on the very first build, alongside the
/// `Name-hash` project directories:
///
/// ```text
/// AlphaTool-bnrexizhpwiunkdzsgqyyprefnxf   <- a project
/// BetaTool-erwgyjswbxesebegqbdtqfjkgals    <- a project
/// CompilationCache.noindex                 <- shared
/// ModuleCache.noindex                      <- shared
/// SDKStatCaches.noindex                    <- shared
/// ```
///
/// The spec only ever named `ModuleCache`, which is what the fixtures
/// contained, so the other two fell through to the per-project branch. There
/// the project name is derived by splitting on the last `-` — and since these
/// names have no `-`, the whole directory name became the "project". A real
/// first build produced this, with the shared cache as the largest line:
///
/// ```text
/// DerivedData — SDKStatCaches.noindex (idle 0d)   14 MB
/// ```
///
/// That is a Principle 6 violation: the report named a project that does not
/// exist. They are still reclaimable — just not as projects.
const SHARED_CACHES: &[(&str, &str)] = &[
    (
        "SDKStatCaches.noindex",
        "SDK stat cache; regenerated on next build",
    ),
    (
        "CompilationCache.noindex",
        "shared compilation cache; regenerated on next build",
    ),
];

/// Whether a `DerivedData` entry is a shared cache rather than a project.
fn shared_cache_reason(name: &str) -> Option<&'static str> {
    SHARED_CACHES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, why)| *why)
}

/// The project name from a `DerivedData` directory, if it is one.
///
/// Xcode names these `<ProjectName>-<hash>`, where the hash is a long run of
/// lowercase letters (`AlphaTool-bnrexizhpwiunkdzsgqyyprefnxf`). Requiring that
/// shape — rather than just splitting on the last `-` — is what keeps a
/// non-project directory from being reported as a project.
///
/// Project names may themselves contain hyphens, so the split is from the
/// right: `My-Cool-App-bnrexizhpwiunkdzsgqyyprefnxf` yields `My-Cool-App`.
///
/// Returning `None` is not a refusal to act — the caller still claims the
/// directory. It only means the label must not assert a project name.
fn project_name(name: &str) -> Option<&str> {
    let (project, hash) = name.rsplit_once('-')?;
    if project.is_empty() {
        return None;
    }
    // Xcode's hashes are 27-28 lowercase letters. The floor is loose enough to
    // survive a change in length, tight enough that a name like
    // `SDKStatCaches.noindex` or `Foo-bar` cannot pass.
    if hash.len() >= 16 && hash.chars().all(|c| c.is_ascii_lowercase()) {
        Some(project)
    } else {
        None
    }
}

impl Scanner for DerivedData {
    fn id(&self) -> &'static str {
        "xcode-derived"
    }

    fn scan(&self, ctx: &ScanCtx) -> Result<Vec<Candidate>, ScannerError> {
        let Some(dev) = developer_dir(ctx) else {
            return Ok(Vec::new());
        };
        let root = dev.join("DerivedData");
        if !root.is_dir() {
            return Ok(Vec::new());
        }

        let cfg = ctx.config.scanner(self.id());
        let min_age = cfg.and_then(|c| c.min_age_days).unwrap_or(14) as i64;

        let entries = std::fs::read_dir(&root)
            .map_err(|e| ScannerError::new(self.id(), anyhow::Error::from(e)))?;

        let mut out = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if !meta.is_dir() || meta.is_symlink() {
                continue;
            }

            let name = entry.file_name().to_string_lossy().into_owned();

            // ModuleCache.noindex is shared, not per-project. Small ones are
            // kept; large ones are fair game.
            if name.starts_with("ModuleCache") {
                let m = match size::measure_with(&ctx.walker(), &path) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if m.bytes_on_disk < MODULE_CACHE_KEEP_UNDER {
                    continue;
                }
                if is_active(ctx, &path) {
                    continue;
                }
                out.push(Candidate {
                    scanner: self.id(),
                    target: Target::Path(path),
                    bytes_on_disk: m.bytes_on_disk,
                    bytes_apparent: m.bytes_apparent,
                    last_modified: mtime(&meta).unwrap_or(ctx.now),
                    risk: Risk::Rebuildable,
                    label: "Xcode module cache (over 1 GB)".into(),
                    reason: "shared module cache; rebuilt on next compile".into(),
                });
                continue;
            }

            let Some(modified) = newest_mtime_within(ctx, &path) else {
                continue;
            };
            let age = ctx.age_days(modified);
            if age < min_age {
                continue;
            }
            if is_active(ctx, &path) {
                continue;
            }

            let Ok(m) = size::measure_with(&ctx.walker(), &path) else {
                continue;
            };
            if m.bytes_on_disk == 0 {
                continue;
            }

            // Principle 6: name the project, not the hashed directory — and
            // never name a project that does not exist.
            let (label, reason) = match shared_cache_reason(&name) {
                Some(why) => (
                    format!("Xcode shared cache — {name}"),
                    format!("{why} (idle {age}d)"),
                ),
                None => match project_name(&name) {
                    Some(project) => (
                        format!("DerivedData — {project} (idle {age}d)"),
                        format!("no build output touched in {age} days"),
                    ),
                    // Not a recognised shared cache and not project-shaped.
                    // Still reclaimable — everything under DerivedData is — but
                    // the label says what it is rather than inventing a project.
                    None => (
                        format!("Xcode build data — {name} (idle {age}d)"),
                        format!("under DerivedData, not touched in {age} days"),
                    ),
                },
            };

            out.push(Candidate {
                scanner: self.id(),
                target: Target::Path(path),
                bytes_on_disk: m.bytes_on_disk,
                bytes_apparent: m.bytes_apparent,
                last_modified: modified,
                risk: Risk::Rebuildable,
                label,
                reason,
            });
        }

        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// S3 — xcode-devicesupport
// ---------------------------------------------------------------------------

pub struct DeviceSupport;

/// How many major versions below the newest a bundle must be (spec §6 S3).
const MAJOR_VERSIONS_BEHIND: u32 = 2;

impl Scanner for DeviceSupport {
    fn id(&self) -> &'static str {
        "xcode-devicesupport"
    }

    fn scan(&self, ctx: &ScanCtx) -> Result<Vec<Candidate>, ScannerError> {
        let Some(dev) = developer_dir(ctx) else {
            return Ok(Vec::new());
        };

        let cfg = ctx.config.scanner(self.id());
        let min_age = cfg.and_then(|c| c.min_age_days).unwrap_or(90) as i64;

        let mut out = Vec::new();

        for platform in ["iOS", "watchOS", "tvOS", "macOS"] {
            let root = dev.join(format!("{platform} DeviceSupport"));
            if !root.is_dir() {
                continue;
            }

            // Collect and parse first: eligibility is relative to the newest
            // version present, so nothing can be decided one directory at a time.
            let mut bundles: Vec<(PathBuf, OsVersion, std::fs::Metadata)> = Vec::new();
            let Ok(entries) = std::fs::read_dir(&root) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(meta) = std::fs::symlink_metadata(&path) else {
                    continue;
                };
                if !meta.is_dir() || meta.is_symlink() {
                    continue;
                }
                // Unparseable names are skipped entirely (Principle 7).
                let Some(v) = OsVersion::parse(&entry.file_name().to_string_lossy()) else {
                    continue;
                };
                bundles.push((path, v, meta));
            }

            let Some(newest) = bundles.iter().map(|(_, v, _)| v.major).max() else {
                continue;
            };

            for (path, v, meta) in bundles {
                // Guard against underflow, and against ever treating the newest
                // bundle as eligible.
                if v.major + MAJOR_VERSIONS_BEHIND > newest {
                    continue;
                }

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
                    scanner: self.id(),
                    target: Target::Path(path),
                    bytes_on_disk: m.bytes_on_disk,
                    bytes_apparent: m.bytes_apparent,
                    last_modified: modified,
                    risk: Risk::Rebuildable,
                    label: format!("{platform} {v} device support bundle"),
                    reason: format!(
                        "{} major versions behind {platform} {newest}; re-downloaded on next \
                         device connect",
                        newest - v.major
                    ),
                });
            }
        }

        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// S4 — xcode-archives (Destructive, registered but inert)
// ---------------------------------------------------------------------------

/// Shipped-build artifacts, including the dSYMs needed to symbolicate
/// production crashes.
///
/// Destructive tier. The arming framework and confirmation flow land in PR-36;
/// until then this is registered so it appears in `doctor` and `config check`,
/// but the registry's risk gate means it cannot produce candidates while
/// `max_risk` defaults to `rebuildable`.
pub struct Archives;

impl Scanner for Archives {
    fn id(&self) -> &'static str {
        "xcode-archives"
    }

    fn requirements(&self) -> Requirements {
        Requirements::default()
    }

    fn blast_radius(&self) -> Option<&'static str> {
        Some(
            "Xcode archives contain the dSYMs for builds you shipped.\n\
             Without them, crash reports from those versions cannot be\n\
             symbolicated — you will see memory addresses instead of function\n\
             names, for every user still running them. Apple does not keep a\n\
             copy you can retrieve.",
        )
    }

    fn scan(&self, ctx: &ScanCtx) -> Result<Vec<Candidate>, ScannerError> {
        let Some(dev) = developer_dir(ctx) else {
            return Ok(Vec::new());
        };
        let root = dev.join("Archives");
        if !root.is_dir() {
            return Ok(Vec::new());
        }

        let cfg = ctx.config.scanner(self.id());
        let min_age = cfg.and_then(|c| c.min_age_days).unwrap_or(180) as i64;

        let mut out = Vec::new();
        // Archives are grouped by date directory, then .xcarchive bundles.
        let Ok(date_dirs) = std::fs::read_dir(&root) else {
            return Ok(out);
        };
        for date_dir in date_dirs.flatten() {
            let Ok(entries) = std::fs::read_dir(date_dir.path()) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(meta) = std::fs::symlink_metadata(&path) else {
                    continue;
                };
                if !meta.is_dir() || meta.is_symlink() {
                    continue;
                }
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

                let name = entry.file_name().to_string_lossy().into_owned();
                out.push(Candidate {
                    scanner: self.id(),
                    target: Target::Path(path),
                    bytes_on_disk: m.bytes_on_disk,
                    bytes_apparent: m.bytes_apparent,
                    last_modified: modified,
                    risk: Risk::Destructive,
                    label: format!("Xcode archive — {name}"),
                    reason: format!(
                        "archived {age} days ago; deleting loses crash symbolication for \
                         that build"
                    ),
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
    fn module_cache_threshold_matches_the_spec() {
        assert_eq!(MODULE_CACHE_KEEP_UNDER, 1_000_000_000);
    }

    #[test]
    fn device_support_requires_two_major_versions_behind() {
        assert_eq!(MAJOR_VERSIONS_BEHIND, 2);
    }

    #[test]
    fn real_derived_data_directory_names_yield_their_project() {
        // Captured from an actual Xcode 26.6 build.
        assert_eq!(
            project_name("AlphaTool-bnrexizhpwiunkdzsgqyyprefnxf"),
            Some("AlphaTool")
        );
        assert_eq!(
            project_name("BetaTool-erwgyjswbxesebegqbdtqfjkgals"),
            Some("BetaTool")
        );
    }

    #[test]
    fn a_project_name_containing_hyphens_survives() {
        // The split is from the right, so only the hash is removed.
        assert_eq!(
            project_name("My-Cool-App-bnrexizhpwiunkdzsgqyyprefnxf"),
            Some("My-Cool-App")
        );
    }

    #[test]
    fn shared_caches_are_never_reported_as_projects() {
        // The defect this test exists for: Xcode 26 creates three shared
        // caches in DerivedData, and only ModuleCache was ever special-cased.
        // The other two fell through to the per-project branch, which split on
        // the last `-`, found none, and used the whole directory name — so a
        // real scan printed "DerivedData — SDKStatCaches.noindex" as though a
        // project by that name existed. Fixtures only ever held `Name-hash`
        // directories, so nothing caught it until a real build ran.
        for name in ["SDKStatCaches.noindex", "CompilationCache.noindex"] {
            assert!(
                project_name(name).is_none(),
                "`{name}` must not parse as a project"
            );
            assert!(
                shared_cache_reason(name).is_some(),
                "`{name}` must be recognised as a shared cache"
            );
        }
    }

    #[test]
    fn a_hash_shaped_suffix_is_required() {
        // Without the shape check, every one of these would report a project.
        for name in [
            "SDKStatCaches.noindex",
            "ModuleCache.noindex",
            "Foo-bar",                       // suffix too short
            "Foo-BNREXIZHPWIUNKDZ",          // uppercase is not Xcode's encoding
            "Foo-abc123defghijklmn",         // digits are not either
            "-bnrexizhpwiunkdzsgqyyprefnxf", // empty project name
            "NoHyphenAtAll",
        ] {
            assert!(
                project_name(name).is_none(),
                "`{name}` should not parse as a project"
            );
        }
    }

    #[test]
    fn archives_are_destructive() {
        // S4 must never be Rebuildable: dSYMs for a shipped build cannot be
        // regenerated once gone.
        let d = crate::config::defaults::scanner("xcode-archives").unwrap();
        assert_eq!(d.risk, Risk::Destructive);
        assert!(!d.enabled, "must be off by default");
    }
}
