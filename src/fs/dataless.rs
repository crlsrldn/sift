//! iCloud dataless-file detection.
//!
//! # Why this matters
//!
//! A file evicted to iCloud still has a directory entry and a plausible
//! `st_size`, but no local blocks. **Reading it triggers a download.** For a
//! tool that walks large trees, touching these would mean silently pulling
//! gigabytes over the network — which is both a bandwidth surprise and a direct
//! violation of G4's "no network access". PRD non-goal N7 excludes them
//! outright, and the PRD risk table rates a mass download as High severity.
//!
//! Detection is the `SF_DATALESS` flag in `st_flags`. Crucially, *checking* the
//! flag is free: it comes from `lstat`, which does not materialise the file.
//! Only opening or reading does.
//!
//! # Correction C3
//!
//! The technical spec §5.2 says to check `st_flags & SF_DATALESS`, but the
//! `libc` crate does not export `SF_DATALESS`. The constant is defined here
//! from the system header.

// `st_flags` is macOS-specific; the Unix MetadataExt does not have it.
use std::os::macos::fs::MetadataExt;

/// `SF_DATALESS` from `<sys/stat.h>`:
///
/// ```c
/// #define SF_DATALESS  0x40000000  /* file is dataless object */
/// ```
///
/// Defined locally because `libc` does not export it (correction C3).
pub const SF_DATALESS: u32 = 0x4000_0000;

/// Whether this file is an iCloud-evicted placeholder.
///
/// Takes already-fetched metadata rather than a path, so callers cannot
/// accidentally pay for a second `stat` — and so this can never be the thing
/// that opens the file.
pub fn is_dataless(meta: &std::fs::Metadata) -> bool {
    meta.st_flags() & SF_DATALESS != 0
}

/// Whether the file at `path` is dataless.
///
/// Uses `symlink_metadata`, so a symlink pointing at a dataless file is
/// reported on its own terms rather than its target's.
pub fn path_is_dataless(path: &std::path::Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| is_dataless(&m))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_matches_the_system_header() {
        // If this ever changes, every dataless check silently becomes a no-op
        // and sift starts downloading people's iCloud libraries.
        assert_eq!(SF_DATALESS, 0x4000_0000);
        assert_eq!(SF_DATALESS, 1_073_741_824);
    }

    #[test]
    fn does_not_collide_with_other_st_flags() {
        // Guards against a typo'd constant that happens to alias a common flag.
        const UF_NODUMP: u32 = 0x0000_0001;
        const UF_IMMUTABLE: u32 = 0x0000_0002;
        const UF_APPEND: u32 = 0x0000_0004;
        const UF_OPAQUE: u32 = 0x0000_0008;
        const UF_COMPRESSED: u32 = 0x0000_0020;
        const UF_HIDDEN: u32 = 0x0000_8000;
        const SF_ARCHIVED: u32 = 0x0001_0000;
        const SF_IMMUTABLE: u32 = 0x0002_0000;
        const SF_APPEND: u32 = 0x0004_0000;

        for other in [
            UF_NODUMP,
            UF_IMMUTABLE,
            UF_APPEND,
            UF_OPAQUE,
            UF_COMPRESSED,
            UF_HIDDEN,
            SF_ARCHIVED,
            SF_IMMUTABLE,
            SF_APPEND,
        ] {
            assert_eq!(
                SF_DATALESS & other,
                0,
                "SF_DATALESS overlaps another st_flags bit"
            );
        }
    }

    #[test]
    fn ordinary_files_are_not_dataless() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("plain.txt");
        std::fs::write(&f, b"local content").unwrap();

        let meta = std::fs::symlink_metadata(&f).unwrap();
        assert!(!is_dataless(&meta));
        assert!(!path_is_dataless(&f));
    }

    #[test]
    fn missing_paths_report_false_rather_than_erroring() {
        // A path that vanished mid-walk is not dataless; it is gone. Returning
        // false here keeps the caller on the "skip it" path either way.
        assert!(!path_is_dataless(std::path::Path::new("/no/such/file")));
    }

    #[test]
    fn detection_reads_only_metadata() {
        // The whole safety property: checking the flag must not materialise the
        // file. This asserts the API shape that makes that true — is_dataless
        // takes Metadata, so it has nothing to open.
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("x");
        std::fs::write(&f, b"data").unwrap();
        let meta = std::fs::symlink_metadata(&f).unwrap();

        let before = std::fs::symlink_metadata(&f).unwrap().accessed().ok();
        let _ = is_dataless(&meta);
        let after = std::fs::symlink_metadata(&f).unwrap().accessed().ok();
        assert_eq!(before, after, "checking the flag touched the file");
    }
}
