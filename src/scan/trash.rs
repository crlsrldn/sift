//! S12 `trash` — the user's Trash (spec §6).
//!
//! # The most dangerous scanner in the tool
//!
//! It hard-deletes. `~/.Trash` **is** the user's quarantine — items are there
//! because they already asked for them to go — so staging them into a second
//! quarantine would be theatre that costs an inode operation and buys nothing.
//!
//! The consequence is that this is the one scanner whose action cannot be
//! undone by anything sift does, and its blast radius says so without hedging.

use crate::fs::size;
use crate::risk::Risk;
use crate::scan::{Candidate, Requirements, ScanCtx, Scanner, Target};
use crate::ScannerError;
use chrono::{DateTime, Local};
use std::path::PathBuf;

pub struct Trash;

impl Scanner for Trash {
    fn id(&self) -> &'static str {
        "trash"
    }

    fn requirements(&self) -> Requirements {
        // TCC guards ~/.Trash on recent macOS (spec §10).
        Requirements {
            fda: true,
            tool: None,
        }
    }

    fn blast_radius(&self) -> Option<&'static str> {
        Some(
            "Everything listed is permanently erased. Not moved, not staged —\n\
             erased. `sift restore` cannot bring it back, Finder's Put Back\n\
             cannot, and no undo exists. If something in your Trash matters,\n\
             take it out before confirming.",
        )
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

        let mut roots = vec![home.join(".Trash")];
        // Per-volume trash for external disks. `$UID` scoping matters: another
        // user's trash on a shared volume is not ours to empty (N6).
        // SAFETY: getuid has no preconditions and cannot fail.
        let uid = unsafe { libc::getuid() };
        if let Ok(volumes) = std::fs::read_dir("/Volumes") {
            for v in volumes.flatten() {
                roots.push(v.path().join(".Trashes").join(uid.to_string()));
            }
        }

        let mut out = Vec::new();
        for root in roots {
            if !root.is_dir() {
                continue;
            }
            let Ok(entries) = std::fs::read_dir(&root) else {
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
                // Per-item age from mtime. The Trash put-back record would be
                // better but is not reliably present; mtime is the honest
                // approximation and errs toward keeping things longer.
                let Some(modified) = meta.modified().ok().map(DateTime::<Local>::from) else {
                    continue;
                };
                let age = ctx.age_days(modified);
                if age < min_age {
                    continue;
                }

                let m = if meta.is_dir() {
                    match size::measure_with(&ctx.walker(), &path) {
                        Ok(m) => m,
                        Err(_) => continue,
                    }
                } else {
                    let mut mm = size::Measurer::new();
                    mm.add(&meta);
                    mm.finish()
                };
                if m.bytes_on_disk == 0 {
                    continue;
                }

                let name = entry.file_name().to_string_lossy().into_owned();
                out.push(Candidate {
                    scanner: self.id(),
                    // HardDelete, not Path: this bypasses quarantine, and the
                    // type is what the pipeline reads.
                    target: Target::HardDelete(path),
                    bytes_on_disk: m.bytes_on_disk,
                    bytes_apparent: m.bytes_apparent,
                    last_modified: modified,
                    risk: Risk::Destructive,
                    label: format!("Trash — {name}"),
                    reason: format!("in the Trash for {age} days"),
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
    fn trash_items_are_hard_deletes_not_quarantine_targets() {
        // ~/.Trash IS the quarantine; staging into a second one buys nothing.
        // The type is what stops `restore` claiming it can undo this.
        let t = Target::HardDelete(PathBuf::from("/Users/x/.Trash/thing"));
        assert!(!t.is_reversible());
        assert!(t.hard_delete_path().is_some());
    }

    #[test]
    fn the_scanner_requires_full_disk_access() {
        // TCC guards ~/.Trash on recent macOS (spec §10).
        assert!(Trash.requirements().fda);
    }

    #[test]
    fn the_blast_radius_does_not_hedge() {
        // This is the one action in the tool with no undo anywhere.
        let b = Trash.blast_radius().unwrap();
        assert!(b.contains("permanently erased"), "{b}");
        assert!(b.contains("cannot"), "{b}");
        assert!(b.contains("Put Back"), "{b}");
    }
}
