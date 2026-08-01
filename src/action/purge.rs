//! Purge: the hard delete (FR-13, spec §7).
//!
//! **This is the only code in `sift` that destroys data irrecoverably.**
//! Everything else stages, reports, or moves. When this function returns, the
//! bytes are gone and no `restore` will bring them back.
//!
//! # The containment rail
//!
//! Every path is canonicalised and re-checked against the quarantine root
//! **immediately before** `remove_dir_all`, not merely trusted from the
//! manifest that produced it. The manifest is a file on disk: it can be
//! corrupted, hand-edited, or written by an older buggy version. A manifest
//! claiming an item lives at `/Users/me/Documents` must produce an error and
//! zero deletions, not a deletion.
//!
//! That check is redundant with correct upstream behaviour, and that is exactly
//! why it is there. The cost is one `canonicalize` per item; the alternative is
//! trusting a file to be honest about what may be destroyed.

use crate::action::manifest::Manifest;
use crate::action::quarantine;
use crate::paths;
use crate::{Result, SiftError};
use chrono::{DateTime, Local};
use std::path::{Path, PathBuf};

/// What a purge did, or refused to do.
#[derive(Debug, Default)]
pub struct PurgeOutcome {
    pub runs_purged: Vec<String>,
    pub runs_retained: Vec<(String, DateTime<Local>)>,
    pub bytes_purged: u64,
    /// Refusals. A non-empty list means something was wrong enough that
    /// deletion was declined — always worth surfacing.
    pub refused: Vec<(PathBuf, String)>,
}

impl PurgeOutcome {
    pub fn anything_purged(&self) -> bool {
        !self.runs_purged.is_empty()
    }
}

/// Verify a path may be destroyed: it must canonicalise to somewhere strictly
/// inside `root`.
///
/// Returns the canonical path on success, so the caller deletes the resolved
/// path rather than the one it was handed — closing the window between check
/// and use.
fn verify_within(root: &Path, path: &Path) -> Result<PathBuf> {
    let canonical_root = root.canonicalize().map_err(|e| {
        SiftError::Io(std::io::Error::new(
            e.kind(),
            format!("quarantine root {}: {e}", root.display()),
        ))
    })?;

    let canonical = path.canonicalize().map_err(|e| {
        SiftError::Io(std::io::Error::new(
            e.kind(),
            format!("{}: {e}", path.display()),
        ))
    })?;

    if !canonical.starts_with(&canonical_root) {
        // Deliberately a hard error rather than a skip. A manifest pointing
        // outside quarantine means something is badly wrong — corruption,
        // tampering, or a bug — and continuing to delete other items on that
        // manifest's say-so would be indefensible.
        return Err(SiftError::Config(format!(
            "refusing to purge {}: it resolves to {}, which is outside the \
             quarantine root {}. Nothing has been deleted.",
            path.display(),
            canonical.display(),
            canonical_root.display()
        )));
    }

    if canonical == canonical_root {
        return Err(SiftError::Config(
            "refusing to purge the quarantine root itself".into(),
        ));
    }

    Ok(canonical)
}

/// Permanently delete one quarantine run directory.
fn purge_run_dir(root: &Path, run_dir: &Path) -> Result<()> {
    let verified = verify_within(root, run_dir)?;

    // A symlink where the run directory should be would make remove_dir_all
    // follow it out of the quarantine tree. canonicalize() above resolves it,
    // and this catches the case where the resolved path is itself a link.
    let meta = std::fs::symlink_metadata(&verified)?;
    if meta.is_symlink() {
        return Err(SiftError::Config(format!(
            "refusing to purge {}: it is a symlink",
            verified.display()
        )));
    }
    if !meta.is_dir() {
        return Err(SiftError::Config(format!(
            "refusing to purge {}: not a directory",
            verified.display()
        )));
    }

    std::fs::remove_dir_all(&verified)?;
    Ok(())
}

/// Purge runs whose TTL has elapsed (FR-13).
pub fn purge_expired(now: DateTime<Local>) -> Result<PurgeOutcome> {
    purge_matching(now, |m| m.is_expired(now))
}

/// Purge every run regardless of TTL (`sift purge --now`).
pub fn purge_all() -> Result<PurgeOutcome> {
    purge_matching(Local::now(), |_| true)
}

/// Purge a single run by id.
pub fn purge_run(run_id: &str) -> Result<PurgeOutcome> {
    let target = run_id.to_string();
    purge_matching(Local::now(), move |m| m.run_id == target)
}

fn purge_matching<F>(now: DateTime<Local>, should_purge: F) -> Result<PurgeOutcome>
where
    F: Fn(&Manifest) -> bool,
{
    let root = paths::quarantine_dir()?;
    let mut outcome = PurgeOutcome::default();

    if !root.exists() {
        return Ok(outcome);
    }

    for manifest in quarantine::runs()? {
        let run_dir = root.join(&manifest.run_id);

        if !should_purge(&manifest) {
            outcome
                .runs_retained
                .push((manifest.run_id.clone(), manifest.expires_at()));
            continue;
        }

        // Sum before deleting; afterwards there is nothing to measure.
        let bytes = manifest.total_bytes();

        match purge_run_dir(&root, &run_dir) {
            Ok(()) => {
                outcome.runs_purged.push(manifest.run_id.clone());
                outcome.bytes_purged += bytes;
            }
            Err(e) => {
                // A containment failure is not survivable: it means a manifest
                // claimed something outside quarantine. Stop, rather than
                // proceeding to the next run on the same evidence.
                if matches!(e, SiftError::Config(_)) {
                    return Err(e);
                }
                outcome.refused.push((run_dir, e.to_string()));
            }
        }
    }

    let _ = now;
    Ok(outcome)
}

/// Render the outcome.
pub fn render(outcome: &PurgeOutcome) -> String {
    use crate::report::human::size;
    use std::fmt::Write;

    let mut o = String::new();

    if outcome.runs_purged.is_empty() {
        let _ = writeln!(o, "sift — nothing to purge.");
    } else {
        let _ = writeln!(
            o,
            "sift — purged {} run(s), {} permanently deleted.",
            outcome.runs_purged.len(),
            size(outcome.bytes_purged)
        );
    }

    if !outcome.runs_retained.is_empty() {
        let _ = writeln!(o);
        let _ = writeln!(
            o,
            "  {} run(s) still within their TTL and retained:",
            outcome.runs_retained.len()
        );
        for (id, expires) in &outcome.runs_retained {
            let _ = writeln!(
                o,
                "    {}  purgeable after {}",
                &id[..id.len().min(8)],
                expires.format("%Y-%m-%d %H:%M")
            );
        }
    }

    if !outcome.refused.is_empty() {
        let _ = writeln!(o);
        for (path, why) in &outcome.refused {
            let _ = writeln!(o, "  Refused: {} — {why}", path.display());
        }
    }

    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_outside_the_root_is_refused() {
        // The rail that matters. A manifest is a file on disk; it can be
        // corrupted, hand-edited, or written by an older buggy version.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("quarantine");
        let outside = dir.path().join("precious");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        let err = verify_within(&root, &outside).unwrap_err();
        assert_eq!(err.exit_code(), crate::ExitCode::Config);
        assert!(
            err.to_string().contains("Nothing has been deleted"),
            "{err}"
        );
        assert!(outside.exists(), "the outside path must be untouched");
    }

    #[test]
    fn a_symlink_out_of_the_root_is_refused() {
        // Otherwise remove_dir_all would follow it and delete the target.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("quarantine");
        let outside = dir.path().join("precious");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("data.txt"), b"important").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();

        assert!(verify_within(&root, &root.join("escape")).is_err());
        assert!(purge_run_dir(&root, &root.join("escape")).is_err());
        assert!(
            outside.join("data.txt").exists(),
            "the symlink target must survive"
        );
    }

    #[test]
    fn the_quarantine_root_itself_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("quarantine");
        std::fs::create_dir_all(&root).unwrap();

        assert!(verify_within(&root, &root).is_err());
        assert!(root.exists());
    }

    #[test]
    fn a_path_inside_the_root_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("quarantine");
        let run = root.join("run1");
        std::fs::create_dir_all(&run).unwrap();

        let verified = verify_within(&root, &run).unwrap();
        assert!(verified.starts_with(root.canonicalize().unwrap()));
    }

    #[test]
    fn verification_returns_the_canonical_path_so_the_delete_uses_it() {
        // Deleting the path we were handed rather than the one we verified
        // would reopen the window between check and use.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("quarantine");
        let run = root.join("run1");
        std::fs::create_dir_all(&run).unwrap();

        let verified = verify_within(&root, &root.join("./run1")).unwrap();
        assert_eq!(verified, run.canonicalize().unwrap());
    }

    #[test]
    fn purging_a_real_run_directory_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("quarantine");
        let run = root.join("run1");
        std::fs::create_dir_all(run.join("nested/deep")).unwrap();
        std::fs::write(run.join("nested/deep/f.bin"), vec![0u8; 4096]).unwrap();

        purge_run_dir(&root, &run).unwrap();
        assert!(!run.exists());
        assert!(root.exists(), "the root must survive");
    }
}
