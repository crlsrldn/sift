//! S14 `app-caches` — a curated allowlist over `~/Library/Caches` (spec §6).
//!
//! # The mitigation
//!
//! The PRD rates blanket `~/Library/Caches` deletion as a **High** severity
//! risk: some applications keep state there that they cannot regenerate, and a
//! wildcard delete eventually breaks one of them.
//!
//! This scanner is the mitigation, and it works exactly one way: an entry must
//! appear in `resources/app_cache_allowlist.toml` by bundle ID and named
//! subpath. **An unlisted bundle ID is never touched, regardless of size**
//! (Principle 1). There is no wildcard mode and adding one would be a spec
//! violation.

use crate::fs::size;
use crate::risk::Risk;
use crate::scan::{Candidate, ScanCtx, Scanner, Target};
use crate::ScannerError;
use chrono::{DateTime, Local};
use serde::Deserialize;
use std::path::PathBuf;

/// Embedded at compile time so the binary stays self-contained (G5) and the
/// allowlist cannot be edited out from under a running install.
const ALLOWLIST_TOML: &str = include_str!("../../resources/app_cache_allowlist.toml");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Allowlist {
    entry: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub bundle_id: String,
    pub subpaths: Vec<String>,
    pub min_age_days: u32,
    /// What regenerating actually costs. Required — if nobody can explain what
    /// is lost, the entry does not belong in the allowlist.
    pub note: String,
}

/// Parse the embedded allowlist.
///
/// Panics on a malformed allowlist. That is deliberate: the file is compiled
/// in, so a parse failure is a build-time authoring error rather than anything
/// a user can cause at runtime, and a test exercises it on every build.
pub fn allowlist() -> Vec<Entry> {
    let parsed: Allowlist =
        toml::from_str(ALLOWLIST_TOML).expect("embedded app_cache_allowlist.toml must be valid");
    parsed.entry
}

pub struct AppCaches;

impl Scanner for AppCaches {
    fn id(&self) -> &'static str {
        "app-caches"
    }

    fn scan(&self, ctx: &ScanCtx) -> Result<Vec<Candidate>, ScannerError> {
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
            return Ok(Vec::new());
        };
        let caches = home.join("Library/Caches");
        if !caches.is_dir() {
            return Ok(Vec::new());
        }

        // A config-level min_age raises the floor for every entry but never
        // lowers an entry's own floor: per-entry values exist because some
        // caches are more expensive to lose than others.
        let cfg_min = ctx
            .config
            .scanner(self.id())
            .and_then(|c| c.min_age_days)
            .unwrap_or(30);

        let mut out = Vec::new();
        for entry in allowlist() {
            let base = caches.join(&entry.bundle_id);
            if !base.is_dir() {
                continue;
            }
            let min_age = entry.min_age_days.max(cfg_min) as i64;

            for sub in &entry.subpaths {
                let path = if sub == "." {
                    base.clone()
                } else {
                    base.join(sub)
                };
                if !path.is_dir() {
                    continue;
                }

                let Ok(meta) = std::fs::symlink_metadata(&path) else {
                    continue;
                };
                if meta.is_symlink() {
                    continue;
                }
                let Some(modified) = meta.modified().ok().map(DateTime::<Local>::from) else {
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

                let what = if sub == "." {
                    entry.bundle_id.clone()
                } else {
                    format!("{} — {sub}", entry.bundle_id)
                };

                out.push(Candidate {
                    scanner: "app-caches",
                    target: Target::Path(path),
                    bytes_on_disk: m.bytes_on_disk,
                    bytes_apparent: m.bytes_apparent,
                    last_modified: modified,
                    risk: Risk::Safe,
                    label: format!("Cache — {what}"),
                    reason: entry.note.clone(),
                });
            }
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn the_embedded_allowlist_parses() {
        // The file is compiled in, so a malformed entry is a build-time
        // authoring error. This test is what turns it into one.
        let list = allowlist();
        assert!(
            list.len() >= 15,
            "expected a meaningful allowlist, got {}",
            list.len()
        );
    }

    #[test]
    fn every_entry_explains_what_regenerating_costs() {
        // If nobody can explain what is lost, the entry does not belong here.
        for e in allowlist() {
            assert!(!e.note.trim().is_empty(), "`{}` has no note", e.bundle_id);
            assert!(
                e.note.len() > 20,
                "`{}` has a uselessly short note: {:?}",
                e.bundle_id,
                e.note
            );
        }
    }

    #[test]
    fn every_entry_has_subpaths_and_an_age_floor() {
        for e in allowlist() {
            assert!(!e.subpaths.is_empty(), "`{}` has no subpaths", e.bundle_id);
            assert!(e.min_age_days > 0, "`{}` has no age floor", e.bundle_id);
        }
    }

    #[test]
    fn bundle_ids_are_unique() {
        let list = allowlist();
        let ids: HashSet<&str> = list.iter().map(|e| e.bundle_id.as_str()).collect();
        assert_eq!(ids.len(), list.len(), "duplicate bundle_id in allowlist");
    }

    #[test]
    fn no_entry_uses_a_wildcard() {
        // Principle 1. A glob here would reintroduce exactly the blanket
        // deletion this scanner exists to prevent.
        for e in allowlist() {
            assert!(
                !e.bundle_id.contains('*'),
                "wildcard bundle_id: {}",
                e.bundle_id
            );
            for s in &e.subpaths {
                assert!(!s.contains('*'), "wildcard subpath in {}: {s}", e.bundle_id);
            }
        }
    }

    #[test]
    fn browser_entries_never_claim_profile_state() {
        // Cookies, Local Storage, and IndexedDB are user state, not cache.
        // Claiming them would log the user out of everything.
        for e in allowlist() {
            for s in &e.subpaths {
                let lower = s.to_ascii_lowercase();
                for forbidden in ["cookie", "local storage", "indexeddb", "login", "profile"] {
                    assert!(
                        !lower.contains(forbidden),
                        "`{}` claims profile state: {s}",
                        e.bundle_id
                    );
                }
            }
        }
    }
}
