//! Run history (FR-8, spec §11).
//!
//! One JSON object per run, appended to `~/.local/state/sift/history.jsonl`,
//! rotated at 10 MB.
//!
//! # Why append-only JSONL and not a database
//!
//! Two processes can run at once — an interactive `sift scan` while the
//! launchd agent fires at 03:00 — and the failure mode of a corrupted history
//! file is that the user loses the record of what was deleted. A single
//! `write(2)` of one line to an `O_APPEND` file is atomic on macOS for
//! reasonably sized writes, so concurrent writers interleave whole records
//! rather than shredding each other's. Anything involving read-modify-write
//! would not have that property.
//!
//! A corrupt line is skipped on read rather than aborting, for the same reason:
//! partial history is far better than none.

use crate::paths;
use crate::scan::{ScanCtx, ScanReport};
use crate::{Result, SiftError};
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Rotate once the file passes this size (spec §11).
pub const ROTATE_AT_BYTES: u64 = 10 * 1024 * 1024;

/// Per-scanner outcome within one run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScannerRecord {
    pub identified: u64,
    #[serde(default)]
    pub quarantined: u64,
    #[serde(default)]
    pub errors: u32,
}

/// One run. Field names follow spec §11.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRecord {
    pub run_id: String,
    pub started_at: DateTime<Local>,
    pub duration_ms: u64,
    /// Important-usage capacity before the run (spec §5.1).
    pub free_before: u64,
    /// Important-usage capacity after. Equal to `free_before` for a scan.
    pub free_after: u64,
    /// Raw available capacity, recorded alongside so the gap against `df` stays
    /// explainable after the fact.
    #[serde(default)]
    pub free_before_raw: u64,
    pub per_scanner: BTreeMap<String, ScannerRecord>,
    #[serde(default)]
    pub purged_bytes: u64,
    #[serde(default)]
    pub gated_reason: Option<String>,
    /// What produced this record: `scan`, `clean`, `purge`.
    pub command: String,
}

impl RunRecord {
    /// Build a record from a completed scan.
    pub fn from_scan(report: &ScanReport, ctx: &ScanCtx, command: &str) -> Self {
        let mut per_scanner: BTreeMap<String, ScannerRecord> = BTreeMap::new();

        for (id, bytes) in report.bytes_by_scanner() {
            per_scanner.entry(id.to_string()).or_default().identified = bytes;
        }
        for (id, _) in &report.errors {
            per_scanner.entry(id.to_string()).or_default().errors += 1;
        }

        Self {
            run_id: uuid::Uuid::now_v7().to_string(),
            started_at: ctx.now,
            duration_ms: report.duration.as_millis() as u64,
            free_before: ctx.root_volume.available_important,
            free_after: ctx.root_volume.available_important,
            free_before_raw: ctx.root_volume.available_raw,
            per_scanner,
            purged_bytes: 0,
            gated_reason: None,
            command: command.to_string(),
        }
    }

    pub fn total_identified(&self) -> u64 {
        self.per_scanner.values().map(|s| s.identified).sum()
    }

    /// Bytes this run actually staged to quarantine.
    ///
    /// Distinct from [`total_identified`](Self::total_identified), and the
    /// distinction is the whole of Principle 2: `sift scan` identifies and can
    /// never act, so a run with a large `identified` and a zero here did
    /// nothing at all.
    pub fn total_quarantined(&self) -> u64 {
        self.per_scanner.values().map(|s| s.quarantined).sum()
    }

    /// Whether this run changed anything on disk.
    ///
    /// Staging or purging counts; identifying does not. Using `identified` for
    /// this made every `sift scan` look like a run that acted — and since
    /// scans are far more frequent than cleans, the report then named a scan
    /// as "the last run that acted" while the real one scrolled out of view.
    pub fn acted(&self) -> bool {
        self.total_quarantined() > 0 || self.purged_bytes > 0
    }

    pub fn total_errors(&self) -> u32 {
        self.per_scanner.values().map(|s| s.errors).sum()
    }

    /// Ground-truth reclaim: the delta in important-usage capacity (spec §5.1).
    /// Per-candidate byte counts are estimates; this is what actually happened.
    pub fn actual_reclaimed(&self) -> u64 {
        self.free_after.saturating_sub(self.free_before)
    }
}

/// Append a record, rotating first if needed.
pub fn append(record: &RunRecord) -> Result<()> {
    append_to(&paths::history_file()?, record)
}

pub fn append_to(path: &Path, record: &RunRecord) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    rotate_if_needed(path)?;

    let mut line = serde_json::to_string(record)?;
    line.push('\n');

    // O_APPEND plus a single write. Two concurrent sift processes interleave
    // whole records rather than corrupting each other's.
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(line.as_bytes())?;
    f.flush()?;
    Ok(())
}

fn rotate_if_needed(path: &Path) -> Result<()> {
    let Ok(meta) = std::fs::metadata(path) else {
        return Ok(());
    };
    if meta.len() < ROTATE_AT_BYTES {
        return Ok(());
    }
    let rotated = path.with_extension("jsonl.1");
    // Rename, not copy: the record that triggered rotation is written to the
    // fresh file immediately after, so nothing is lost.
    std::fs::rename(path, rotated)?;
    Ok(())
}

/// Read all records, newest last.
///
/// A malformed line is skipped rather than aborting the read: partial history
/// beats none, and a truncated final line is the expected result of a process
/// killed mid-write.
pub fn read_all() -> Result<Vec<RunRecord>> {
    read_from(&paths::history_file()?)
}

pub fn read_from(path: &Path) -> Result<Vec<RunRecord>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(SiftError::Io(e)),
    };

    let mut out = Vec::new();
    let mut skipped = 0usize;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<RunRecord>(line) {
            Ok(r) => out.push(r),
            Err(_) => skipped += 1,
        }
    }
    if skipped > 0 {
        tracing::warn!(skipped, "skipped malformed history lines");
    }
    Ok(out)
}

/// Records within the last `days`, plus the rotated file if it exists.
pub fn recent(days: u32) -> Result<Vec<RunRecord>> {
    let path = paths::history_file()?;
    let mut all = read_from(&path.with_extension("jsonl.1")).unwrap_or_default();
    all.extend(read_from(&path)?);

    let cutoff = Local::now() - chrono::Duration::days(days as i64);
    all.retain(|r| r.started_at >= cutoff);
    all.sort_by_key(|r| r.started_at);
    Ok(all)
}

/// Path of the rotated file, for `uninstall` to name (FR-21).
pub fn rotated_path() -> Result<PathBuf> {
    Ok(paths::history_file()?.with_extension("jsonl.1"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str) -> RunRecord {
        RunRecord {
            run_id: id.into(),
            started_at: Local::now(),
            duration_ms: 100,
            free_before: 1000,
            free_after: 1000,
            free_before_raw: 900,
            per_scanner: BTreeMap::new(),
            purged_bytes: 0,
            gated_reason: None,
            command: "scan".into(),
        }
    }

    #[test]
    fn a_record_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("history.jsonl");

        append_to(&p, &record("a")).unwrap();
        let back = read_from(&p).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].run_id, "a");
    }

    #[test]
    fn concurrent_appends_produce_whole_records() {
        // Two sift processes can run at once — an interactive scan while the
        // agent fires. Interleaved partial writes would destroy the record of
        // what was deleted.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("history.jsonl");

        std::thread::scope(|s| {
            for t in 0..8 {
                let p = p.clone();
                s.spawn(move || {
                    for i in 0..25 {
                        append_to(&p, &record(&format!("t{t}-{i}"))).unwrap();
                    }
                });
            }
        });

        let text = std::fs::read_to_string(&p).unwrap();
        let lines = text.lines().filter(|l| !l.trim().is_empty()).count();
        assert_eq!(lines, 200, "expected 200 whole lines");

        let parsed = read_from(&p).unwrap();
        assert_eq!(parsed.len(), 200, "every line must parse");
    }

    #[test]
    fn a_corrupt_line_does_not_prevent_reading_the_rest() {
        // A truncated final line is the expected result of a process killed
        // mid-write. Partial history beats none.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("history.jsonl");

        append_to(&p, &record("first")).unwrap();
        {
            let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
            f.write_all(b"{ this is not json\n").unwrap();
        }
        append_to(&p, &record("third")).unwrap();

        let back = read_from(&p).unwrap();
        assert_eq!(back.len(), 2, "the two valid records must survive");
        assert_eq!(back[0].run_id, "first");
        assert_eq!(back[1].run_id, "third");
    }

    #[test]
    fn rotation_at_the_threshold_keeps_the_triggering_record() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("history.jsonl");

        // Fill past the threshold.
        let filler = "x".repeat(1024);
        {
            let mut f = std::fs::File::create(&p).unwrap();
            for _ in 0..(ROTATE_AT_BYTES / 1024 + 1) {
                writeln!(f, "{filler}").unwrap();
            }
        }
        assert!(std::fs::metadata(&p).unwrap().len() >= ROTATE_AT_BYTES);

        append_to(&p, &record("after-rotation")).unwrap();

        assert!(p.with_extension("jsonl.1").exists(), "rotated file missing");
        let back = read_from(&p).unwrap();
        assert_eq!(
            back.len(),
            1,
            "the triggering record must be in the new file"
        );
        assert_eq!(back[0].run_id, "after-rotation");
    }

    #[test]
    fn a_missing_history_file_reads_as_empty_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let back = read_from(&dir.path().join("nope.jsonl")).unwrap();
        assert!(back.is_empty());
    }

    #[test]
    fn both_capacity_figures_are_recorded() {
        // spec §5.1: the gap between important-usage and raw must stay
        // explainable after the fact, not only at scan time.
        let r = record("x");
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("free_before"));
        assert!(json.contains("free_before_raw"));
    }

    #[test]
    fn actual_reclaimed_uses_the_capacity_delta() {
        // Per-candidate bytes are estimates (APFS clones); the free-space delta
        // is the ground truth.
        let mut r = record("x");
        r.free_before = 1_000;
        r.free_after = 5_000;
        assert_eq!(r.actual_reclaimed(), 4_000);

        // A run where free space went down (something else wrote) must not
        // report negative reclaim.
        r.free_after = 500;
        assert_eq!(r.actual_reclaimed(), 0);
    }
}
