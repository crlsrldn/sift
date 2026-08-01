//! Restore: undoing a quarantine run (FR-14, spec §7.3).
//!
//! # Refuse, never overwrite
//!
//! If the original location is occupied again — the user rebuilt the project,
//! or a tool recreated the cache — restore **refuses that item and reports it**
//! rather than replacing what is there now.
//!
//! The reasoning: the thing currently at that path is newer and was created
//! deliberately. Overwriting it to reinstate something the user asked to delete
//! days ago would turn an undo into a second, unrequested deletion. A partial
//! restore with a clear conflict list is the correct outcome, and spec §7.3
//! names it as such.
//!
//! # Partial restore is success
//!
//! `restore` exits 0 with a conflict list rather than failing. The manifest is
//! updated so a second `restore` retries only what remains, which means the
//! user can resolve a conflict by hand and run it again without the tool
//! re-attempting what already worked.

use crate::action::manifest::Manifest;
use crate::action::quarantine;
use crate::paths;
use crate::{Result, SiftError};
use std::path::PathBuf;

/// What happened to one item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemOutcome {
    Restored,
    /// The original path is occupied. Nothing was touched.
    Conflict,
    /// Not in quarantine — it never moved, or a previous restore took it.
    Missing,
    /// Went to macOS Trash (FR-12); `sift` cannot rename it back.
    InTrash,
    Failed(String),
}

#[derive(Debug, Default)]
pub struct RestoreOutcome {
    pub run_id: String,
    pub restored: Vec<PathBuf>,
    pub conflicts: Vec<PathBuf>,
    pub in_trash: Vec<PathBuf>,
    pub missing: Vec<PathBuf>,
    pub failed: Vec<(PathBuf, String)>,
    pub bytes_restored: u64,
}

impl RestoreOutcome {
    /// Whether anything still needs the user's attention.
    pub fn fully_restored(&self) -> bool {
        self.conflicts.is_empty() && self.failed.is_empty() && self.in_trash.is_empty()
    }
}

/// Restore a run, identified by id or unique prefix.
pub fn restore(run_prefix: &str) -> Result<RestoreOutcome> {
    let manifest = quarantine::resolve_run(run_prefix)?;
    let root = paths::quarantine_dir()?;
    let run_dir = root.join(&manifest.run_id);

    let mut updated = manifest.clone();
    let mut outcome = RestoreOutcome {
        run_id: manifest.run_id.clone(),
        ..Default::default()
    };

    // Reverse order (spec §7.3). Items were staged parent-before-child within a
    // run; unwinding in reverse means a nested item is put back before anything
    // that could contain it, so no restore depends on an earlier one.
    for idx in (0..manifest.items.len()).rev() {
        let item = &manifest.items[idx];
        let staged = run_dir.join(&item.quarantine_path);

        let result = restore_one(item, &staged);

        match &result {
            ItemOutcome::Restored => {
                outcome.restored.push(item.original_path.clone());
                outcome.bytes_restored += item.bytes_on_disk;
                // Mark as no longer in quarantine so a second restore does not
                // retry it.
                updated.items[idx].moved = false;
            }
            ItemOutcome::Conflict => outcome.conflicts.push(item.original_path.clone()),
            ItemOutcome::InTrash => outcome.in_trash.push(item.original_path.clone()),
            ItemOutcome::Missing => {
                outcome.missing.push(item.original_path.clone());
                updated.items[idx].moved = false;
            }
            ItemOutcome::Failed(why) => outcome
                .failed
                .push((item.original_path.clone(), why.clone())),
        }
    }

    // Persist what remains, so a retry only attempts the unresolved items.
    updated.save(&run_dir)?;

    // A run with nothing left in it is removed, so `sift report` and `purge`
    // do not keep listing an empty shell.
    if updated.items.iter().all(|i| !i.moved) && outcome.fully_restored() {
        let _ = std::fs::remove_dir_all(&run_dir);
    }

    Ok(outcome)
}

fn restore_one(item: &crate::action::manifest::Item, staged: &std::path::Path) -> ItemOutcome {
    if item.via_trash {
        // FR-12. Saying "restored" here would be a lie; the item is in Trash
        // and only the user can put it back.
        return ItemOutcome::InTrash;
    }
    if !item.moved || !staged.exists() {
        return ItemOutcome::Missing;
    }

    // Refuse rather than overwrite. Checked before attempting the rename so the
    // reported reason is precise, and enforced again by RENAME_EXCL below so
    // there is no check-then-act race.
    if item.original_path.exists() {
        return ItemOutcome::Conflict;
    }

    if let Some(parent) = item.original_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return ItemOutcome::Failed(format!("cannot recreate {}: {e}", parent.display()));
        }
    }

    match rename_back(staged, &item.original_path) {
        Ok(()) => ItemOutcome::Restored,
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => ItemOutcome::Conflict,
        Err(e) => ItemOutcome::Failed(e.to_string()),
    }
}

/// The same no-clobber rename quarantine uses, in the other direction.
fn rename_back(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let from_c = std::ffi::CString::new(from.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("source path contains a NUL byte"))?;
    let to_c = std::ffi::CString::new(to.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("destination path contains a NUL byte"))?;

    // SAFETY: both are valid NUL-terminated C strings alive for the call.
    // RENAME_EXCL makes this fail rather than replace an existing destination —
    // the same guarantee as staging, which is what makes restore non-destructive.
    let rc = unsafe { libc::renamex_np(from_c.as_ptr(), to_c.as_ptr(), libc::RENAME_EXCL) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

pub fn render(outcome: &RestoreOutcome) -> String {
    use crate::report::human::size;
    use std::fmt::Write;

    let mut o = String::new();
    let short = &outcome.run_id[..outcome.run_id.len().min(8)];

    let _ = writeln!(
        o,
        "sift — restored {} item(s) from run {short}, {}.",
        outcome.restored.len(),
        size(outcome.bytes_restored)
    );

    if !outcome.conflicts.is_empty() {
        let _ = writeln!(o);
        let _ = writeln!(
            o,
            "  {} item(s) NOT restored: something already occupies the original",
            outcome.conflicts.len()
        );
        let _ = writeln!(
            o,
            "  location. Nothing there was touched. They remain in quarantine."
        );
        let _ = writeln!(o);
        for p in &outcome.conflicts {
            let _ = writeln!(o, "    {}", p.display());
        }
        let _ = writeln!(o);
        let _ = writeln!(
            o,
            "  Move or remove what is there, then run `sift restore {short}` again."
        );
    }

    if !outcome.in_trash.is_empty() {
        let _ = writeln!(o);
        let _ = writeln!(
            o,
            "  {} item(s) were moved to the Trash rather than quarantine, because",
            outcome.in_trash.len()
        );
        let _ = writeln!(
            o,
            "  they were on another volume. sift cannot restore those — recover"
        );
        let _ = writeln!(o, "  them from the Trash yourself:");
        let _ = writeln!(o);
        for p in &outcome.in_trash {
            let _ = writeln!(o, "    {}", p.display());
        }
    }

    if !outcome.failed.is_empty() {
        let _ = writeln!(o);
        for (p, why) in &outcome.failed {
            let _ = writeln!(o, "  Failed:  {} — {why}", p.display());
        }
    }

    o
}

/// Resolve a prefix without restoring, for `clean` to name the undo command.
pub fn find(prefix: &str) -> Result<Manifest> {
    quarantine::resolve_run(prefix).map_err(|e| match e {
        SiftError::Usage(m) => SiftError::Usage(m),
        other => other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rename_back_refuses_an_occupied_destination() {
        // The property that makes restore non-destructive: it cannot replace
        // whatever the user has since put at that path.
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("staged");
        let original = dir.path().join("original");
        std::fs::write(&staged, b"quarantined").unwrap();
        std::fs::write(&original, b"NEWER, MUST SURVIVE").unwrap();

        let err = rename_back(&staged, &original).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EEXIST));
        assert_eq!(std::fs::read(&original).unwrap(), b"NEWER, MUST SURVIVE");
        assert!(staged.exists(), "the quarantined copy must remain");
    }

    #[test]
    fn an_outcome_with_conflicts_is_not_fully_restored() {
        let mut o = RestoreOutcome::default();
        assert!(o.fully_restored());
        o.conflicts.push("/tmp/x".into());
        assert!(!o.fully_restored());
    }

    #[test]
    fn a_trashed_item_is_reported_as_such_not_restored() {
        let item = crate::action::manifest::Item {
            original_path: "/tmp/x".into(),
            quarantine_path: "tmp/x".into(),
            bytes_on_disk: 1,
            scanner: "logs".into(),
            risk: crate::risk::Risk::Safe,
            via_trash: true,
            moved: true,
        };
        assert_eq!(
            restore_one(&item, std::path::Path::new("/nonexistent")),
            ItemOutcome::InTrash
        );
    }

    #[test]
    fn the_conflict_message_says_nothing_was_touched() {
        // The user's first fear on seeing "not restored" is that sift damaged
        // whatever is there now.
        let mut o = RestoreOutcome {
            run_id: "0192abcd-ef".into(),
            ..Default::default()
        };
        o.conflicts.push("/Users/x/dev/proj/target".into());

        let text = render(&o);
        assert!(text.contains("Nothing there was touched"), "{text}");
        assert!(text.contains("remain in quarantine"), "{text}");
        assert!(text.contains("sift restore 0192abcd"), "{text}");
    }

    #[test]
    fn the_trash_message_does_not_claim_sift_can_restore_them() {
        let mut o = RestoreOutcome {
            run_id: "abc".into(),
            ..Default::default()
        };
        o.in_trash.push("/Volumes/Ext/thing".into());

        let text = render(&o);
        assert!(text.contains("cannot restore"), "{text}");
        assert!(text.contains("Trash"), "{text}");
    }
}
