//! S13 `downloads` — stale installers in `~/Downloads` (spec §6).
//!
//! # An exhaustive extension allowlist
//!
//! Only `.dmg`, `.pkg`, `.iso`, `.zip`. Nothing else, ever, regardless of age
//! or size — `~/Downloads` is where people keep work they have not filed yet,
//! and a two-year-old `.psd` or `.pdf` there is a document, not an artifact.
//!
//! Unlike `trash`, these go through quarantine, so despite the Destructive tier
//! they are recoverable for the TTL window. The blast radius says so, because
//! overstating the danger is its own kind of dishonesty.

use crate::fs::size;
use crate::risk::Risk;
use crate::scan::{Candidate, ScanCtx, Scanner, Target};
use crate::ScannerError;
use chrono::{DateTime, Local};
use std::path::PathBuf;

pub struct Downloads;

/// The complete list. Adding to it is a deliberate act, not a convenience.
pub const RECLAIMABLE_EXTENSIONS: &[&str] = &["dmg", "pkg", "iso", "zip"];

pub fn is_reclaimable_extension(path: &std::path::Path) -> bool {
    path.extension()
        .map(|e| {
            let e = e.to_string_lossy().to_ascii_lowercase();
            RECLAIMABLE_EXTENSIONS.contains(&e.as_str())
        })
        .unwrap_or(false)
}

impl Scanner for Downloads {
    fn id(&self) -> &'static str {
        "downloads"
    }

    fn blast_radius(&self) -> Option<&'static str> {
        Some(
            "Installers and archives you would have to download again. Only\n\
             .dmg, .pkg, .iso, and .zip are ever touched — documents, images,\n\
             and everything else in Downloads are not eligible at any age.\n\
             These are staged to quarantine first, so `sift restore` can undo\n\
             this until the TTL expires.",
        )
    }

    fn scan(&self, ctx: &ScanCtx) -> Result<Vec<Candidate>, ScannerError> {
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
            return Ok(Vec::new());
        };
        let dir = home.join("Downloads");
        if !dir.is_dir() {
            return Ok(Vec::new());
        }

        let min_age = ctx
            .config
            .scanner(self.id())
            .and_then(|c| c.min_age_days)
            .unwrap_or(90) as i64;

        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Ok(Vec::new());
        };

        let mut out = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            // Files only. A directory named `foo.zip` is not an archive.
            if !meta.is_file() || meta.is_symlink() {
                continue;
            }
            if !is_reclaimable_extension(&path) {
                continue;
            }

            let Some(modified) = meta.modified().ok().map(DateTime::<Local>::from) else {
                continue;
            };
            let age = ctx.age_days(modified);
            if age < min_age {
                continue;
            }

            let mut mm = size::Measurer::new();
            mm.add(&meta);
            let m = mm.finish();
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
                label: format!("Downloads — {name}"),
                reason: format!("downloaded {age} days ago; re-downloadable"),
            });
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn only_the_four_installer_extensions_are_eligible() {
        for good in ["a.dmg", "b.pkg", "c.iso", "d.zip", "E.DMG", "f.Zip"] {
            assert!(is_reclaimable_extension(Path::new(good)), "{good}");
        }
    }

    #[test]
    fn documents_and_media_are_never_eligible_at_any_age() {
        // ~/Downloads is where people keep work they have not filed yet.
        for bad in [
            "thesis.pdf",
            "artwork.psd",
            "recording.mov",
            "spreadsheet.xlsx",
            "archive.tar.gz",
            "notes.txt",
            "photo.jpg",
            "noextension",
        ] {
            assert!(!is_reclaimable_extension(Path::new(bad)), "{bad}");
        }
    }

    #[test]
    fn the_extension_list_is_exactly_the_spec_set() {
        assert_eq!(RECLAIMABLE_EXTENSIONS, &["dmg", "pkg", "iso", "zip"]);
    }

    #[test]
    fn the_blast_radius_is_honest_that_this_one_is_recoverable() {
        // Overstating the danger is its own kind of dishonesty, and trains
        // people to ignore the warnings that matter.
        let b = Downloads.blast_radius().unwrap();
        assert!(b.contains("sift restore"), "{b}");
        assert!(b.contains("not eligible at any age"), "{b}");
    }
}
