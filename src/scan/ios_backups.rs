//! S15 `ios-backups` — device backups under MobileSync (spec §6).
//!
//! # Naming the device, not the directory
//!
//! A backup directory is a 40-character hex string. "iPhone 13 backup from
//! 2023-04-11, 8.2 GB" is a decision someone can make; a hex string is not
//! (Principle 6). The name and date come from the backup's own `Info.plist`,
//! and a backup whose plist cannot be read is **skipped rather than guessed
//! at** — offering to delete "some device backup" is worse than offering
//! nothing.

use crate::fs::size;
use crate::risk::Risk;
use crate::scan::{Candidate, Requirements, ScanCtx, Scanner, Target};
use crate::ScannerError;
use chrono::{DateTime, Local};
use std::path::{Path, PathBuf};

pub struct IosBackups;

/// What a backup's `Info.plist` tells us about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupInfo {
    pub device_name: String,
    pub product_name: Option<String>,
    pub last_backup: Option<String>,
}

impl BackupInfo {
    /// The user-facing label.
    pub fn label(&self) -> String {
        let device = match &self.product_name {
            // "Carlos's iPhone (iPhone 13)" is more useful than either alone.
            Some(p) if p != &self.device_name => format!("{} ({p})", self.device_name),
            _ => self.device_name.clone(),
        };
        match &self.last_backup {
            Some(d) => format!("{device} backup from {d}"),
            None => format!("{device} backup"),
        }
    }
}

/// Read a backup's identity from its `Info.plist`.
///
/// Returns `None` on anything unreadable or unrecognised (Principle 7).
pub fn read_info(backup_dir: &Path) -> Option<BackupInfo> {
    let plist_path = backup_dir.join("Info.plist");
    let value = plist::Value::from_file(&plist_path).ok()?;
    let d = value.as_dictionary()?;

    let device_name = d
        .get("Device Name")
        .and_then(|v| v.as_string())?
        .to_string();
    if device_name.trim().is_empty() {
        return None;
    }

    Some(BackupInfo {
        product_name: d
            .get("Product Name")
            .and_then(|v| v.as_string())
            .map(str::to_string),
        last_backup: d
            .get("Last Backup Date")
            .and_then(|v| v.as_date())
            .map(|date| {
                DateTime::<Local>::from(std::time::SystemTime::from(date))
                    .format("%Y-%m-%d")
                    .to_string()
            }),
        device_name,
    })
}

impl Scanner for IosBackups {
    fn id(&self) -> &'static str {
        "ios-backups"
    }

    fn requirements(&self) -> Requirements {
        Requirements {
            fda: true,
            tool: None,
        }
    }

    fn blast_radius(&self) -> Option<&'static str> {
        Some(
            "A device backup is the only copy of everything that was not in\n\
             iCloud: app data, Health records, Messages attachments, and the\n\
             device's settings at that moment. If you restore this phone later\n\
             and the backup is gone, that data is gone with it. Deleting a\n\
             backup does not affect the device itself.",
        )
    }

    fn scan(&self, ctx: &ScanCtx) -> Result<Vec<Candidate>, ScannerError> {
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
            return Ok(Vec::new());
        };
        let root = home.join("Library/Application Support/MobileSync/Backup");
        if !root.is_dir() {
            return Ok(Vec::new());
        }

        let min_age = ctx
            .config
            .scanner(self.id())
            .and_then(|c| c.min_age_days)
            .unwrap_or(365) as i64;

        let Ok(entries) = std::fs::read_dir(&root) else {
            return Ok(Vec::new());
        };

        let mut out = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if !meta.is_dir() || meta.is_symlink() {
                continue;
            }

            // Skipped, not guessed at: offering to delete "some device backup"
            // is worse than offering nothing.
            let Some(info) = read_info(&path) else {
                continue;
            };

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

            out.push(Candidate {
                scanner: self.id(),
                target: Target::Path(path),
                bytes_on_disk: m.bytes_on_disk,
                bytes_apparent: m.bytes_apparent,
                last_modified: modified,
                risk: Risk::Destructive,
                label: info.label(),
                reason: format!("last written {age} days ago"),
            });
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_info(dir: &Path, keys: &[(&str, &str)]) {
        std::fs::create_dir_all(dir).unwrap();
        let mut d = plist::Dictionary::new();
        for (k, v) in keys {
            d.insert((*k).into(), plist::Value::String((*v).into()));
        }
        plist::Value::Dictionary(d)
            .to_file_xml(dir.join("Info.plist"))
            .unwrap();
    }

    #[test]
    fn a_backup_is_named_by_its_device_not_its_hex_directory() {
        // Principle 6. "iPhone 13 backup" is a decision someone can make; a
        // 40-character hex string is not.
        let dir = tempfile::tempdir().unwrap();
        let b = dir.path().join("a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4");
        write_info(
            &b,
            &[
                ("Device Name", "Carlos's iPhone"),
                ("Product Name", "iPhone 13"),
            ],
        );

        let info = read_info(&b).expect("should have read the plist");
        let label = info.label();
        assert!(label.contains("Carlos's iPhone"), "{label}");
        assert!(label.contains("iPhone 13"), "{label}");
        assert!(!label.contains("a1b2c3"), "{label}");
    }

    #[test]
    fn a_device_whose_name_matches_its_model_is_not_repeated() {
        let dir = tempfile::tempdir().unwrap();
        let b = dir.path().join("x");
        write_info(&b, &[("Device Name", "iPad"), ("Product Name", "iPad")]);
        assert_eq!(read_info(&b).unwrap().label(), "iPad backup");
    }

    #[test]
    fn an_unreadable_backup_is_skipped_rather_than_guessed_at() {
        // Offering to delete "some device backup" is worse than offering
        // nothing (Principle 7).
        let dir = tempfile::tempdir().unwrap();

        let missing = dir.path().join("no-plist");
        std::fs::create_dir_all(&missing).unwrap();
        assert_eq!(read_info(&missing), None);

        let corrupt = dir.path().join("corrupt");
        std::fs::create_dir_all(&corrupt).unwrap();
        std::fs::write(corrupt.join("Info.plist"), b"not a plist").unwrap();
        assert_eq!(read_info(&corrupt), None);

        let nameless = dir.path().join("nameless");
        write_info(&nameless, &[("Product Name", "iPhone 13")]);
        assert_eq!(read_info(&nameless), None);

        let blank = dir.path().join("blank");
        write_info(&blank, &[("Device Name", "   ")]);
        assert_eq!(read_info(&blank), None);
    }

    #[test]
    fn the_scanner_requires_full_disk_access() {
        assert!(IosBackups.requirements().fda);
    }

    #[test]
    fn the_blast_radius_names_the_data_not_the_directory() {
        let b = IosBackups.blast_radius().unwrap();
        assert!(b.contains("Health"), "{b}");
        assert!(b.contains("Messages"), "{b}");
        // And reassures about the thing people fear most.
        assert!(b.contains("does not affect the device"), "{b}");
    }
}
