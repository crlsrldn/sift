//! On-disk size accounting (FR-6, spec §5.3).
//!
//! ```text
//! bytes_on_disk = Σ (st_blocks × 512)   over unique (st_dev, st_ino)
//! ```
//!
//! # Why not `st_size`
//!
//! Apparent size lies in both directions. A sparse file reports terabytes and
//! occupies kilobytes; a small file occupies a full block. Reclaim is about
//! blocks returned to the free list, so blocks are what we count. Apparent size
//! is captured too, but only ever shown as context.
//!
//! # Hard links
//!
//! Counted once per `(st_dev, st_ino)`. Without dedup, a Homebrew Cellar or a
//! `node_modules` tree full of links reports many multiples of its real size,
//! and the circuit breaker (FR-16) would trip on numbers that do not exist.
//!
//! The dedup set is **per measurement**, not global. Two candidates that share
//! a hard link each report it, because each one, deleted alone, is what the
//! user would get back. A global set would attribute the bytes to whichever
//! candidate happened to be measured first.
//!
//! # Known limitation: APFS clones
//!
//! `cp -c`, Finder copies, and Xcode create clones that share blocks but each
//! report full `st_blocks`. A tree containing clones **overcounts**, and there
//! is no cheap way to detect it. Per spec §5.3 this is not corrected in v1;
//! sizes are labelled estimates and the free-space delta across a purge is the
//! ground truth (spec §5.1).

use crate::fs::dataless;
use crate::fs::walk::{SkipReason, WalkResult, Walker};
use crate::Result;
use std::collections::HashSet;
use std::path::Path;

/// Bytes per `st_blocks` unit. Fixed at 512 by POSIX regardless of the
/// filesystem's actual block size — `st_blocks` is defined in 512-byte units.
const BLOCK_SIZE: u64 = 512;

/// The result of measuring a tree.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Measurement {
    /// Allocated blocks, hard-link deduped. This is the reclaim estimate.
    pub bytes_on_disk: u64,
    /// Sum of `st_size`. Context only; never used for decisions.
    pub bytes_apparent: u64,
    /// Files counted.
    pub files: u64,
    /// Hard links seen more than once and therefore not double-counted.
    pub hardlinks_deduped: u64,
    /// Files skipped because they are iCloud-evicted.
    ///
    /// Reported separately so the gap between `sift` and `du` is explainable
    /// rather than mysterious — `du` will happily count these.
    pub dataless_files: u64,
    /// Apparent bytes of those dataless files. Not reclaimable: the blocks are
    /// already not here.
    pub dataless_bytes_apparent: u64,
    /// True if any clone-prone condition was seen. Currently always true for
    /// non-empty trees, because clones are undetectable cheaply — see module
    /// docs. Kept explicit so the report can say "estimate" honestly.
    pub is_estimate: bool,
}

impl Measurement {
    /// Ratio of allocated to apparent size. Useful for spotting sparse files.
    pub fn allocation_ratio(&self) -> f64 {
        if self.bytes_apparent == 0 {
            return 0.0;
        }
        self.bytes_on_disk as f64 / self.bytes_apparent as f64
    }
}

/// Accumulates a measurement, deduplicating hard links as it goes.
///
/// Exposed so scanners can measure several roots into one figure while keeping
/// a single dedup scope — for example one DerivedData project directory made of
/// several subtrees.
#[derive(Debug, Default)]
pub struct Measurer {
    seen: HashSet<(u64, u64)>,
    m: Measurement,
}

impl Measurer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one file's metadata to the running total.
    pub fn add(&mut self, meta: &std::fs::Metadata) {
        use std::os::unix::fs::MetadataExt;

        if dataless::is_dataless(meta) {
            // Never counted as reclaimable: the blocks are already gone, and
            // st_blocks reflects that. Recorded so the report can explain the
            // difference from `du`.
            self.m.dataless_files += 1;
            self.m.dataless_bytes_apparent += meta.size();
            return;
        }

        let key = (meta.dev(), meta.ino());
        if meta.nlink() > 1 && !self.seen.insert(key) {
            self.m.hardlinks_deduped += 1;
            return;
        }

        self.m.files += 1;
        self.m.bytes_on_disk += meta.blocks() * BLOCK_SIZE;
        self.m.bytes_apparent += meta.size();
    }

    pub fn finish(mut self) -> Measurement {
        self.m.is_estimate = self.m.files > 0;
        self.m
    }
}

/// Measure an already-collected walk. For tests; prefer [`measure_with`].
pub fn measure_result(result: &WalkResult) -> Measurement {
    let mut m = Measurer::new();
    for entry in &result.entries {
        m.add(&entry.metadata);
    }
    let mut out = m.finish();
    out.dataless_files += result.count_skipped(SkipReason::Dataless) as u64;
    out
}

/// Walk and measure a tree in one step.
pub fn measure(path: &Path) -> Result<Measurement> {
    let walker = Walker::new(path)?;
    measure_with(&walker, path)
}

/// Measure using a caller-supplied walker, so scanner excludes and depth caps
/// apply to the measurement as well as the search.
///
/// Streams: peak memory is independent of file count. The dedup set is the only
/// thing that grows, and only for files with more than one link, which is a
/// small minority on any real tree.
pub fn measure_with(walker: &Walker, path: &Path) -> Result<Measurement> {
    let mut m = Measurer::new();
    let summary = walker.visit(path, |_, meta, _| m.add(meta))?;
    let mut out = m.finish();
    // The walker refuses dataless entries before the visitor sees them, so pick
    // up its count too. Otherwise the two paths disagree about how many were
    // seen depending on which layer noticed first.
    out.dataless_files += summary.count_skipped(SkipReason::Dataless);
    Ok(out)
}

/// Measure and report the newest mtime in one traversal.
///
/// Scanners need both — the size to report and the newest write for the
/// liveness guard — and walking twice doubles the cost of the most expensive
/// thing sift does.
pub fn measure_and_newest(
    walker: &Walker,
    path: &Path,
) -> Result<(Measurement, Option<std::time::SystemTime>)> {
    let mut m = Measurer::new();
    let summary = walker.visit(path, |_, meta, _| m.add(meta))?;
    let mut out = m.finish();
    out.dataless_files += summary.count_skipped(SkipReason::Dataless);
    Ok((out, summary.newest_mtime))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn meta(p: &Path) -> std::fs::Metadata {
        fs::symlink_metadata(p).unwrap()
    }

    #[test]
    fn block_size_is_the_posix_constant() {
        // st_blocks is defined in 512-byte units regardless of the filesystem's
        // block size. Using the FS block size here would inflate every figure.
        assert_eq!(BLOCK_SIZE, 512);
    }

    #[test]
    fn a_hard_linked_file_is_counted_once() {
        // FR-6. Without this, a Cellar or node_modules tree reports multiples of
        // its real size and the circuit breaker trips on numbers that do not
        // exist.
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        fs::write(&a, vec![0u8; 8192]).unwrap();
        fs::hard_link(&a, dir.path().join("b")).unwrap();
        fs::hard_link(&a, dir.path().join("c")).unwrap();

        let m = measure(dir.path()).unwrap();
        assert_eq!(m.files, 1, "three links to one inode is one file");
        assert_eq!(m.hardlinks_deduped, 2);

        let single = measure_single(&a);
        assert_eq!(m.bytes_on_disk, single.bytes_on_disk);
    }

    fn measure_single(p: &Path) -> Measurement {
        let mut m = Measurer::new();
        m.add(&meta(p));
        m.finish()
    }

    #[test]
    fn distinct_files_of_equal_size_are_both_counted() {
        // Guards against a dedup key that ignores the inode and collapses
        // same-sized files.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a"), vec![0u8; 4096]).unwrap();
        fs::write(dir.path().join("b"), vec![0u8; 4096]).unwrap();

        let m = measure(dir.path()).unwrap();
        assert_eq!(m.files, 2);
        assert_eq!(m.hardlinks_deduped, 0);
    }

    #[test]
    fn a_sparse_file_reports_allocated_not_apparent_size() {
        // spec §5.3. A 64 MB sparse file occupies almost nothing; counting
        // st_size would report reclaim that does not exist.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sparse.bin");

        let f = fs::File::create(&p).unwrap();
        f.set_len(64 * 1024 * 1024).unwrap();
        drop(f);

        let m = measure(dir.path()).unwrap();
        assert_eq!(m.bytes_apparent, 64 * 1024 * 1024);
        assert!(
            m.bytes_on_disk < 1024 * 1024,
            "sparse file reported {} on-disk bytes; should be near zero",
            m.bytes_on_disk
        );
        assert!(m.allocation_ratio() < 0.05);
    }

    #[test]
    fn a_dense_file_allocates_at_least_its_apparent_size() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("dense.bin"), vec![7u8; 100_000]).unwrap();

        let m = measure(dir.path()).unwrap();
        assert!(m.bytes_on_disk >= m.bytes_apparent);
    }

    #[test]
    fn symlinks_are_not_followed_into_the_measurement() {
        // The link's target must not be counted through it — otherwise a tree
        // of links to one large file reports that file many times.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.bin");
        fs::write(&target, vec![0u8; 16384]).unwrap();
        for i in 0..4 {
            std::os::unix::fs::symlink(&target, dir.path().join(format!("l{i}"))).unwrap();
        }

        let m = measure(dir.path()).unwrap();
        assert_eq!(m.files, 1, "only the real file");
    }

    #[test]
    fn an_empty_tree_measures_zero_and_is_not_an_estimate() {
        let dir = tempfile::tempdir().unwrap();
        let m = measure(dir.path()).unwrap();
        assert_eq!(m, Measurement::default());
        assert!(!m.is_estimate);
    }

    #[test]
    fn a_non_empty_tree_is_flagged_as_an_estimate() {
        // spec §5.3: APFS clones make block accounting overcount and cannot be
        // cheaply detected, so any real figure is an estimate and must say so.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("f"), b"x").unwrap();
        assert!(measure(dir.path()).unwrap().is_estimate);
    }

    #[test]
    fn dedup_scope_is_per_measurement_not_global() {
        // Two candidates sharing a hard link should each report it: deleting
        // either one alone is what the user gets back. A global dedup set would
        // give the bytes to whichever was measured first.
        let dir = tempfile::tempdir().unwrap();
        let a_dir = dir.path().join("a");
        let b_dir = dir.path().join("b");
        fs::create_dir(&a_dir).unwrap();
        fs::create_dir(&b_dir).unwrap();

        let f = a_dir.join("shared.bin");
        fs::write(&f, vec![0u8; 8192]).unwrap();
        fs::hard_link(&f, b_dir.join("shared.bin")).unwrap();

        let ma = measure(&a_dir).unwrap();
        let mb = measure(&b_dir).unwrap();

        assert_eq!(ma.bytes_on_disk, mb.bytes_on_disk);
        assert!(ma.bytes_on_disk > 0);
        assert_eq!(ma.files, 1);
        assert_eq!(mb.files, 1);
    }

    #[test]
    fn nested_directories_are_summed() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("x/y/z")).unwrap();
        for p in ["a", "x/b", "x/y/c", "x/y/z/d"] {
            fs::write(dir.path().join(p), vec![0u8; 4096]).unwrap();
        }

        let m = measure(dir.path()).unwrap();
        assert_eq!(m.files, 4);
        assert!(m.bytes_on_disk >= 4 * 4096);
    }

    #[test]
    fn measuring_a_single_file_works() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("one");
        fs::write(&f, vec![0u8; 2048]).unwrap();

        let m = measure(&f).unwrap();
        assert_eq!(m.files, 1);
        assert!(m.bytes_on_disk >= 2048);
    }

    #[test]
    fn excludes_reduce_the_measurement() {
        // FR-24: a vetoed subtree must not contribute bytes, or `clean` would
        // promise reclaim it will not deliver.
        let dir = tempfile::tempdir().unwrap();
        let skip = dir.path().join("skip");
        fs::create_dir(&skip).unwrap();
        fs::write(dir.path().join("keep.bin"), vec![0u8; 4096]).unwrap();
        fs::write(skip.join("big.bin"), vec![0u8; 65536]).unwrap();

        let full = measure(dir.path()).unwrap();

        let mut b = globset::GlobSetBuilder::new();
        b.add(globset::Glob::new(&skip.display().to_string()).unwrap());
        let walker = Walker::new(dir.path())
            .unwrap()
            .excludes(b.build().unwrap());
        let filtered = measure_with(&walker, dir.path()).unwrap();

        assert_eq!(filtered.files, 1);
        assert!(filtered.bytes_on_disk < full.bytes_on_disk);
    }
}
