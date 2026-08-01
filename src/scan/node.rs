//! S10 `node-caches` — npm, pnpm, yarn (spec §6).
//!
//! `node_modules` is never a candidate. It is not a cache: it is a project's
//! installed dependency tree, its removal breaks the working directory until
//! someone reinstalls, and the reinstall is not guaranteed to reproduce what
//! was there. The package-manager stores behind it are the cache, and those are
//! what this scanner claims.

use crate::fs::size;
use crate::risk::Risk;
use crate::scan::{Candidate, DelegatedCmd, ScanCtx, Scanner, Target};
use crate::ScannerError;
use chrono::{DateTime, Local};
use std::path::{Path, PathBuf};

pub struct NodeCaches;

/// Never claimed, for any reason.
pub fn is_node_modules(path: &Path) -> bool {
    path.components().any(|c| c.as_os_str() == "node_modules")
}

impl Scanner for NodeCaches {
    fn id(&self) -> &'static str {
        "node-caches"
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

        // npm's content-addressable cache. Reclaimable as a path, so it goes
        // through quarantine and stays reversible.
        let cacache = home.join(".npm/_cacache");
        if cacache.is_dir() && !is_node_modules(&cacache) {
            if let Ok(meta) = std::fs::symlink_metadata(&cacache) {
                if let Some(modified) = meta.modified().ok().map(DateTime::<Local>::from) {
                    let age = ctx.age_days(modified);
                    if age >= min_age {
                        if let Ok(m) = size::measure_with(&ctx.walker(), &cacache) {
                            if m.bytes_on_disk > 0 {
                                out.push(Candidate {
                                    scanner: self.id(),
                                    target: Target::Path(cacache),
                                    bytes_on_disk: m.bytes_on_disk,
                                    bytes_apparent: m.bytes_apparent,
                                    last_modified: modified,
                                    risk: Risk::Safe,
                                    label: "npm cache".into(),
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

        // pnpm's store is content-addressed and shared across projects, so only
        // pnpm knows what is still referenced. Delegated, and therefore not
        // reversible.
        if crate::caps::which("pnpm").is_some() {
            out.push(Candidate {
                scanner: self.id(),
                target: Target::Delegated(DelegatedCmd::new("pnpm", &["store", "prune"])),
                bytes_on_disk: 0,
                bytes_apparent: 0,
                last_modified: ctx.now,
                risk: Risk::Safe,
                label: "pnpm store — unreferenced packages".into(),
                reason: "pnpm store prune; re-fetched on next install".into(),
            });
        }

        if crate::caps::which("yarn").is_some() {
            out.push(Candidate {
                scanner: self.id(),
                target: Target::Delegated(DelegatedCmd::new("yarn", &["cache", "clean"])),
                bytes_on_disk: 0,
                bytes_apparent: 0,
                last_modified: ctx.now,
                risk: Risk::Safe,
                label: "Yarn cache".into(),
                reason: "yarn cache clean; re-fetched on next install".into(),
            });
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_modules_is_recognised_at_any_depth() {
        // Not a cache: removing it breaks the working directory, and the
        // reinstall is not guaranteed to reproduce what was there.
        assert!(is_node_modules(Path::new("/Users/x/proj/node_modules")));
        assert!(is_node_modules(Path::new(
            "/Users/x/proj/node_modules/lodash"
        )));
        assert!(is_node_modules(Path::new(
            "/Users/x/a/node_modules/b/node_modules/c"
        )));
    }

    #[test]
    fn the_caches_this_scanner_claims_are_not_node_modules() {
        assert!(!is_node_modules(Path::new("/Users/x/.npm/_cacache")));
        assert!(!is_node_modules(Path::new("/Users/x/.pnpm-store")));
    }

    #[test]
    fn delegated_store_commands_are_the_documented_ones() {
        assert_eq!(
            DelegatedCmd::new("pnpm", &["store", "prune"]).display(),
            "pnpm store prune"
        );
        assert_eq!(
            DelegatedCmd::new("yarn", &["cache", "clean"]).display(),
            "yarn cache clean"
        );
    }

    #[test]
    fn the_scanner_requires_no_tool_because_npm_cache_is_a_plain_path() {
        // npm's cache is reclaimable without npm installed; pnpm and yarn are
        // added only when present.
        assert_eq!(NodeCaches.requirements().tool, None);
    }
}
