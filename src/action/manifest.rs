//! The quarantine manifest (spec §7.2).
//!
//! # Why this is written before anything moves
//!
//! The manifest is the *only* record of where a quarantined item came from.
//! Without it, a directory sitting in `quarantine/<uuid>/` is unrecoverable
//! rubble — nobody knows where it belongs.
//!
//! So the ordering is: **write and fsync the manifest describing what is about
//! to move, then move things.** If the process dies mid-run, the manifest
//! describes a superset of what actually moved, and `restore` handles the
//! difference by simply skipping items that are not there. The reverse ordering
//! — move first, record after — has a window in which a crash produces
//! orphaned quarantine with no restore path, which is precisely the
//! unrecoverable-data-loss outcome G2 forbids.

use crate::risk::Risk;
use crate::{Result, SiftError};
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const MANIFEST_FILENAME: &str = "manifest.json";

/// One quarantined item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    /// Where it came from, absolute.
    pub original_path: PathBuf,
    /// Where it went, relative to the run directory. Relative so the whole
    /// quarantine tree can be moved or inspected without invalidating it.
    pub quarantine_path: PathBuf,
    pub bytes_on_disk: u64,
    pub scanner: String,
    pub risk: Risk,
    /// True when the item went to macOS Trash instead, because it was on a
    /// different volume and a rename was impossible (FR-12). Restore cannot
    /// undo these, and the report says so rather than implying otherwise.
    #[serde(default)]
    pub via_trash: bool,
    /// Set once the move actually succeeded. An item written to the manifest
    /// but never moved — because the process died, or the rename failed —
    /// stays `false`, and restore skips it.
    #[serde(default)]
    pub moved: bool,
}

/// One `sift clean` run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub run_id: String,
    pub created_at: DateTime<Local>,
    pub ttl_days: u32,
    pub items: Vec<Item>,
}

impl Manifest {
    pub fn new(run_id: String, ttl_days: u32) -> Self {
        Self {
            run_id,
            created_at: Local::now(),
            ttl_days,
            items: Vec::new(),
        }
    }

    /// Whether the TTL has elapsed and this run may be purged (FR-13).
    pub fn is_expired(&self, now: DateTime<Local>) -> bool {
        now >= self.expires_at()
    }

    pub fn expires_at(&self) -> DateTime<Local> {
        self.created_at + chrono::Duration::days(self.ttl_days as i64)
    }

    /// Items that actually moved and can be restored.
    pub fn restorable(&self) -> impl Iterator<Item = &Item> {
        self.items.iter().filter(|i| i.moved && !i.via_trash)
    }

    pub fn total_bytes(&self) -> u64 {
        self.items
            .iter()
            .filter(|i| i.moved)
            .map(|i| i.bytes_on_disk)
            .sum()
    }

    /// Write atomically and fsync, so the record survives a crash.
    ///
    /// Written to a temporary file and renamed, so a reader never sees a
    /// half-written manifest — and the directory itself is fsynced, because on
    /// APFS a rename is not durable until the parent directory is.
    pub fn save(&self, run_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(run_dir)?;

        let final_path = run_dir.join(MANIFEST_FILENAME);
        let tmp_path = run_dir.join(".manifest.json.tmp");

        let json = serde_json::to_string_pretty(self)?;
        {
            let mut f = std::fs::File::create(&tmp_path)?;
            f.write_all(json.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp_path, &final_path)?;

        // Durability of the rename itself.
        if let Ok(dir) = std::fs::File::open(run_dir) {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    pub fn load(run_dir: &Path) -> Result<Self> {
        let path = run_dir.join(MANIFEST_FILENAME);
        let text = std::fs::read_to_string(&path).map_err(|e| {
            SiftError::Io(std::io::Error::new(
                e.kind(),
                format!("{}: {e}", path.display()),
            ))
        })?;
        serde_json::from_str(&text).map_err(|e| {
            SiftError::Config(format!("{} is not a valid manifest: {e}", path.display()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Manifest {
        let mut m = Manifest::new("test-run".into(), 7);
        m.items.push(Item {
            original_path: "/Users/x/Library/Developer/Xcode/DerivedData/App-abc".into(),
            quarantine_path: "Users/x/Library/Developer/Xcode/DerivedData/App-abc".into(),
            bytes_on_disk: 1000,
            scanner: "xcode-derived".into(),
            risk: Risk::Rebuildable,
            via_trash: false,
            moved: true,
        });
        m
    }

    #[test]
    fn a_manifest_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let m = manifest();
        m.save(dir.path()).unwrap();

        let back = Manifest::load(dir.path()).unwrap();
        assert_eq!(back.run_id, "test-run");
        assert_eq!(back.items.len(), 1);
        assert_eq!(back.items[0].scanner, "xcode-derived");
        assert_eq!(back.items[0].risk, Risk::Rebuildable);
    }

    #[test]
    fn the_schema_matches_spec_7_2() {
        let json = serde_json::to_string(&manifest()).unwrap();
        for field in [
            "run_id",
            "created_at",
            "ttl_days",
            "items",
            "original_path",
            "quarantine_path",
            "bytes_on_disk",
            "scanner",
            "risk",
            "via_trash",
        ] {
            assert!(json.contains(field), "manifest is missing `{field}`");
        }
    }

    #[test]
    fn saving_leaves_no_temporary_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        manifest().save(dir.path()).unwrap();

        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec![MANIFEST_FILENAME.to_string()]);
    }

    #[test]
    fn a_reader_never_sees_a_partial_manifest() {
        // The write goes to a temp file and is renamed into place, so the final
        // path either does not exist or is complete.
        let dir = tempfile::tempdir().unwrap();
        let mut m = Manifest::new("big".into(), 7);
        for i in 0..500 {
            m.items.push(Item {
                original_path: format!("/tmp/item{i}").into(),
                quarantine_path: format!("tmp/item{i}").into(),
                bytes_on_disk: i,
                scanner: "logs".into(),
                risk: Risk::Safe,
                via_trash: false,
                moved: true,
            });
        }
        m.save(dir.path()).unwrap();
        assert_eq!(Manifest::load(dir.path()).unwrap().items.len(), 500);
    }

    #[test]
    fn ttl_expiry_is_computed_from_creation() {
        let m = Manifest::new("x".into(), 7);
        assert!(!m.is_expired(m.created_at + chrono::Duration::days(6)));
        assert!(!m.is_expired(m.created_at + chrono::Duration::hours(167)));
        assert!(m.is_expired(m.created_at + chrono::Duration::days(7)));
        assert!(m.is_expired(m.created_at + chrono::Duration::days(30)));
    }

    #[test]
    fn an_item_that_never_moved_is_not_restorable() {
        // The crash-safety property: the manifest is written before anything
        // moves, so it lists a superset of what actually did.
        let mut m = manifest();
        m.items[0].moved = false;
        assert_eq!(m.restorable().count(), 0);
        assert_eq!(m.total_bytes(), 0);
    }

    #[test]
    fn a_trashed_item_is_not_restorable_by_sift() {
        // FR-12: cross-volume items go to Trash and sift cannot rename them
        // back. Claiming otherwise would be a lie the user discovers too late.
        let mut m = manifest();
        m.items[0].via_trash = true;
        assert_eq!(m.restorable().count(), 0);
    }

    #[test]
    fn a_corrupt_manifest_is_a_config_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(MANIFEST_FILENAME), b"{ not json").unwrap();

        let err = Manifest::load(dir.path()).unwrap_err();
        assert_eq!(err.exit_code(), crate::ExitCode::Config);
    }

    #[test]
    fn a_missing_manifest_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Manifest::load(dir.path()).is_err());
    }
}
