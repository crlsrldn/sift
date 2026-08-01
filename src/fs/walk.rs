//! Guarded directory traversal (FR-7, spec §5.2).
//!
//! This is the component that can hang, recurse forever, or wander outside the
//! tree it was asked about. Every guard here exists because of a specific,
//! documented way a naive walk of a macOS filesystem goes wrong.
//!
//! # Guards, applied in this order on every entry
//!
//! 1. **Device check** — `st_dev` must equal the root volume's. Stops descent
//!    into mounted volumes, disk images, and network shares.
//! 2. **Firmlink guard** — explicit deny on `/System/Volumes/Data`. macOS
//!    firmlinks the Data volume into `/`, so a naive walk of `/` traverses the
//!    same content twice under two different paths.
//! 3. **No symlink following** — `follow_links(false)`, all metadata via
//!    `symlink_metadata`. This is what makes cycles impossible rather than
//!    merely bounded.
//! 4. **Dataless check** — `st_flags & SF_DATALESS`. An iCloud-evicted file
//!    materialises on read; these are counted separately and never touched.
//! 5. **Exclude globs** — the user's `safety.exclude` veto, applied last so it
//!    can override anything the scanners would otherwise claim (FR-24).
//!
//! Depth is capped (default 24) as a backstop. With symlink following disabled
//! a true cycle is not reachable, but a pathological tree still is.
//!
//! # Streaming, and why
//!
//! [`Walker::visit`] hands each accepted entry to a closure and keeps nothing.
//! [`Walker::walk`] collects everything into a `Vec` and is for tests that need
//! to assert on the exact entry set.
//!
//! The distinction is not stylistic. Each collected `Entry` costs ~543 bytes —
//! a `PathBuf`, a full `Metadata`, and a depth — measured at 140 MB peak RSS
//! for a 258 K-file walk of `~/Library`. Extrapolated to PRD M5's 2 M-file
//! target that is ~1.1 GB against a 100 MB budget. Nothing in the scanner path
//! ever needs every entry at once: sizes are folded into a sum and mtimes into
//! a maximum, both of which stream.

use crate::config::defaults;
use crate::fs::dataless;
use crate::{Result, SiftError};
use globset::GlobSet;
use std::path::{Path, PathBuf};

/// Why an entry was not descended into or counted.
///
/// Skips are recorded rather than silently dropped: PRD §7 requires that
/// skipped and blocked items appear in the report instead of quietly vanishing,
/// and a scanner that finds nothing should be able to say why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SkipReason {
    /// Different `st_dev` — a mount point, disk image, or network share.
    OtherVolume,
    /// `/System/Volumes/Data`, which is firmlinked into `/`.
    Firmlink,
    /// A symlink. Never followed, never counted as its target.
    Symlink,
    /// iCloud-evicted. Reading it would trigger a download.
    Dataless,
    /// Vetoed by a user exclude pattern.
    Excluded,
    /// Depth cap reached.
    TooDeep,
    /// Could not be read (permissions, or it vanished mid-walk).
    Unreadable,
}

impl SkipReason {
    pub fn as_str(self) -> &'static str {
        match self {
            SkipReason::OtherVolume => "on another volume",
            SkipReason::Firmlink => "firmlink to the Data volume",
            SkipReason::Symlink => "symlink",
            SkipReason::Dataless => "iCloud-evicted (would download if read)",
            SkipReason::Excluded => "excluded by config",
            SkipReason::TooDeep => "deeper than the depth cap",
            SkipReason::Unreadable => "unreadable",
        }
    }
}

/// A file the walk accepted.
#[derive(Debug, Clone)]
pub struct Entry {
    pub path: PathBuf,
    pub metadata: std::fs::Metadata,
    pub depth: usize,
}

/// An entry the walk rejected, and why.
#[derive(Debug, Clone)]
pub struct Skipped {
    pub path: PathBuf,
    pub reason: SkipReason,
}

/// A streaming walk's outcome: counts and bounded samples, no entry list.
///
/// Skips are counted rather than accumulated for the same reason entries are
/// not collected — a tree with a million excluded paths would otherwise trade
/// one unbounded `Vec` for another. A few examples are kept so the report can
/// show what was skipped rather than only how much.
#[derive(Debug, Default)]
pub struct WalkSummary {
    pub files: u64,
    pub newest_mtime: Option<std::time::SystemTime>,
    skipped_counts: std::collections::BTreeMap<SkipReason, u64>,
    skipped_samples: Vec<Skipped>,
}

/// How many skipped paths to keep as examples.
const SKIP_SAMPLE_LIMIT: usize = 32;

impl WalkSummary {
    fn record_skip(&mut self, path: PathBuf, reason: SkipReason) {
        *self.skipped_counts.entry(reason).or_insert(0) += 1;
        if self.skipped_samples.len() < SKIP_SAMPLE_LIMIT {
            self.skipped_samples.push(Skipped { path, reason });
        }
    }

    pub fn count_skipped(&self, reason: SkipReason) -> u64 {
        self.skipped_counts.get(&reason).copied().unwrap_or(0)
    }

    pub fn total_skipped(&self) -> u64 {
        self.skipped_counts.values().sum()
    }

    /// Up to [`SKIP_SAMPLE_LIMIT`] examples, for the report.
    pub fn skipped_samples(&self) -> &[Skipped] {
        &self.skipped_samples
    }
}

/// Everything a walk produced, with every entry retained.
///
/// Memory grows linearly with file count, so this is for tests and for callers
/// that genuinely need the exact set. Scanners use [`Walker::visit`].
#[derive(Debug, Default)]
pub struct WalkResult {
    pub entries: Vec<Entry>,
    pub skipped: Vec<Skipped>,
}

impl WalkResult {
    pub fn skipped_for(&self, reason: SkipReason) -> impl Iterator<Item = &Skipped> {
        self.skipped.iter().filter(move |s| s.reason == reason)
    }

    pub fn count_skipped(&self, reason: SkipReason) -> usize {
        self.skipped_for(reason).count()
    }

    /// Newest mtime among accepted entries. Drives the FR-17 liveness guard:
    /// a tree touched in the last hour is not a candidate.
    pub fn newest_mtime(&self) -> Option<std::time::SystemTime> {
        self.entries
            .iter()
            .filter_map(|e| e.metadata.modified().ok())
            .max()
    }
}

/// Paths that are never descended into, regardless of configuration.
///
/// `/System/Volumes/Data` is the firmlink guard from spec §5.2. The rest are
/// system trees where a walk is pointless (SIP makes them unactionable) and
/// slow.
const ALWAYS_DENY: &[&str] = &[
    "/System/Volumes/Data",
    "/System",
    "/private/var/vm", // swap; huge, and deleting it is a kernel panic
    "/dev",
    "/net",
    "/Network",
];

/// A configured walker.
pub struct Walker {
    root_device: u64,
    max_depth: usize,
    excludes: Option<GlobSet>,
    skip_dataless: bool,
}

impl Walker {
    /// Build a walker pinned to the device of `root`.
    ///
    /// The device is captured once, from the walk root, and every entry is
    /// compared against it. Re-deriving it per directory would defeat the guard:
    /// descending into a mount would simply adopt the mount's device as the new
    /// baseline.
    pub fn new(root: &Path) -> Result<Self> {
        Ok(Self {
            root_device: crate::fs::volume::device_of(root)?,
            max_depth: defaults::MAX_WALK_DEPTH,
            excludes: None,
            skip_dataless: true,
        })
    }

    pub fn with_device(device: u64) -> Self {
        Self {
            root_device: device,
            max_depth: defaults::MAX_WALK_DEPTH,
            excludes: None,
            skip_dataless: true,
        }
    }

    pub fn max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    pub fn excludes(mut self, set: GlobSet) -> Self {
        self.excludes = Some(set);
        self
    }

    /// Decide whether a path is admissible, without reading it.
    ///
    /// Split out from the walk so the guards are testable in isolation and so
    /// scanners can ask the same question about a single candidate root.
    pub fn check(&self, path: &Path, meta: &std::fs::Metadata, depth: usize) -> Option<SkipReason> {
        use std::os::unix::fs::MetadataExt;

        if depth > self.max_depth {
            return Some(SkipReason::TooDeep);
        }
        if is_always_denied(path) {
            return Some(SkipReason::Firmlink);
        }
        if meta.is_symlink() {
            return Some(SkipReason::Symlink);
        }
        if meta.dev() != self.root_device {
            return Some(SkipReason::OtherVolume);
        }
        if self.skip_dataless && dataless::is_dataless(meta) {
            return Some(SkipReason::Dataless);
        }
        // Excludes last, so a user veto beats every other decision (FR-24).
        if let Some(set) = &self.excludes {
            if set.is_match(path) {
                return Some(SkipReason::Excluded);
            }
        }
        None
    }

    /// Walk `root`, handing each accepted file to `visit` and keeping nothing.
    ///
    /// This is what scanners use. Peak memory is independent of file count.
    pub fn visit<F>(&self, root: &Path, mut visit: F) -> Result<WalkSummary>
    where
        F: FnMut(&Path, &std::fs::Metadata, usize),
    {
        let meta = std::fs::symlink_metadata(root).map_err(|e| {
            SiftError::Io(std::io::Error::new(
                e.kind(),
                format!("{}: {e}", root.display()),
            ))
        })?;

        let mut summary = WalkSummary::default();

        if let Some(reason) = self.check(root, &meta, 0) {
            summary.record_skip(root.to_path_buf(), reason);
            return Ok(summary);
        }

        if meta.is_file() {
            summary.files += 1;
            summary.newest_mtime = meta.modified().ok();
            visit(root, &meta, 0);
            return Ok(summary);
        }

        let mut stack = vec![(root.to_path_buf(), 0usize)];

        while let Some((dir, depth)) = stack.pop() {
            let iter = match std::fs::read_dir(&dir) {
                Ok(i) => i,
                Err(_) => {
                    summary.record_skip(dir, SkipReason::Unreadable);
                    continue;
                }
            };

            for entry in iter {
                let Ok(entry) = entry else { continue };
                let path = entry.path();

                let Ok(meta) = std::fs::symlink_metadata(&path) else {
                    summary.record_skip(path, SkipReason::Unreadable);
                    continue;
                };

                if let Some(reason) = self.check(&path, &meta, depth + 1) {
                    summary.record_skip(path, reason);
                    continue;
                }

                if meta.is_dir() {
                    stack.push((path, depth + 1));
                } else {
                    summary.files += 1;
                    if let Ok(m) = meta.modified() {
                        summary.newest_mtime =
                            Some(summary.newest_mtime.map_or(m, |cur| cur.max(m)));
                    }
                    visit(&path, &meta, depth + 1);
                }
            }
        }

        Ok(summary)
    }

    /// Newest mtime anywhere in the tree, without retaining anything.
    pub fn newest_mtime(&self, root: &Path) -> Result<Option<std::time::SystemTime>> {
        Ok(self.visit(root, |_, _, _| {})?.newest_mtime)
    }

    /// Walk `root`, collecting accepted files and recording every skip.
    ///
    /// Retains every entry, so memory grows with file count. Prefer
    /// [`Walker::visit`] outside tests.
    pub fn walk(&self, root: &Path) -> Result<WalkResult> {
        let meta = std::fs::symlink_metadata(root).map_err(|e| {
            SiftError::Io(std::io::Error::new(
                e.kind(),
                format!("{}: {e}", root.display()),
            ))
        })?;

        let mut result = WalkResult::default();

        if let Some(reason) = self.check(root, &meta, 0) {
            result.skipped.push(Skipped {
                path: root.to_path_buf(),
                reason,
            });
            return Ok(result);
        }

        if meta.is_file() {
            result.entries.push(Entry {
                path: root.to_path_buf(),
                metadata: meta,
                depth: 0,
            });
            return Ok(result);
        }

        // Explicit stack rather than recursion: a deep tree must not blow the
        // thread stack, and jwalk's parallelism is not wanted here because the
        // device guard has to be applied before descending, not after.
        let mut stack = vec![(root.to_path_buf(), 0usize)];

        while let Some((dir, depth)) = stack.pop() {
            let iter = match std::fs::read_dir(&dir) {
                Ok(i) => i,
                Err(_) => {
                    result.skipped.push(Skipped {
                        path: dir,
                        reason: SkipReason::Unreadable,
                    });
                    continue;
                }
            };

            for entry in iter {
                let Ok(entry) = entry else {
                    continue;
                };
                let path = entry.path();

                // symlink_metadata, never metadata: following here would
                // reintroduce exactly the cycle risk guard 3 exists to remove.
                let Ok(meta) = std::fs::symlink_metadata(&path) else {
                    result.skipped.push(Skipped {
                        path,
                        reason: SkipReason::Unreadable,
                    });
                    continue;
                };

                if let Some(reason) = self.check(&path, &meta, depth + 1) {
                    result.skipped.push(Skipped { path, reason });
                    continue;
                }

                if meta.is_dir() {
                    stack.push((path, depth + 1));
                } else {
                    result.entries.push(Entry {
                        path,
                        metadata: meta,
                        depth: depth + 1,
                    });
                }
            }
        }

        Ok(result)
    }
}

/// Whether a path is on the hard-coded deny list.
///
/// Compares component-wise rather than by string prefix, so `/Systemic` is not
/// mistaken for a path under `/System`.
fn is_always_denied(path: &Path) -> bool {
    ALWAYS_DENY.iter().any(|deny| {
        let deny = Path::new(deny);
        path == deny || path.starts_with(deny)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firmlink_path_is_always_denied() {
        // Spec §5.2 guard 2. This is the one that causes double-counting on a
        // naive walk of /.
        assert!(is_always_denied(Path::new("/System/Volumes/Data")));
        assert!(is_always_denied(Path::new("/System/Volumes/Data/Users/x")));
        assert!(is_always_denied(Path::new("/System")));
        assert!(is_always_denied(Path::new("/System/Library")));
    }

    #[test]
    fn deny_list_matches_components_not_string_prefixes() {
        // `/Systemic` must not be caught by the `/System` rule.
        assert!(!is_always_denied(Path::new("/Systemic")));
        assert!(!is_always_denied(Path::new("/Users/x/System")));
        assert!(!is_always_denied(Path::new("/devious")));
    }

    #[test]
    fn root_and_home_are_not_denied() {
        assert!(!is_always_denied(Path::new("/")));
        assert!(!is_always_denied(Path::new("/Users")));
        assert!(!is_always_denied(Path::new("/opt/homebrew")));
    }
}
