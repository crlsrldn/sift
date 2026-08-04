//! `sift report` — last run plus a trend over recent history (FR-9).

use crate::report::history::RunRecord;
use crate::report::human::size;
use std::collections::BTreeMap;
use std::fmt::Write;

/// Aggregate over a window of runs.
#[derive(Debug, Default)]
pub struct Trend {
    pub runs: usize,
    pub gated_runs: usize,
    pub error_runs: usize,
    pub total_identified: u64,
    pub total_purged: u64,
    pub by_scanner: BTreeMap<String, u64>,
    /// Free space at each run, oldest first, for the sparkline.
    pub free_series: Vec<u64>,
}

impl Trend {
    pub fn from(records: &[RunRecord]) -> Self {
        let mut t = Trend {
            runs: records.len(),
            ..Default::default()
        };
        for r in records {
            if r.gated_reason.is_some() {
                t.gated_runs += 1;
            }
            if r.total_errors() > 0 {
                t.error_runs += 1;
            }
            t.total_identified += r.total_identified();
            t.total_purged += r.purged_bytes;
            for (id, rec) in &r.per_scanner {
                *t.by_scanner.entry(id.clone()).or_insert(0) += rec.identified;
            }
            t.free_series.push(r.free_after);
        }
        t
    }

    /// Fraction of runs that declined to do work because a gate fired (FR-20).
    pub fn gate_rate(&self) -> f64 {
        if self.runs == 0 {
            return 0.0;
        }
        self.gated_runs as f64 / self.runs as f64
    }
}

/// A unicode sparkline. Returns an empty string for fewer than two points,
/// since a single point has no trend to show.
pub fn sparkline(values: &[u64]) -> String {
    const BLOCKS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    if values.len() < 2 {
        return String::new();
    }
    let min = *values.iter().min().unwrap();
    let max = *values.iter().max().unwrap();
    if max == min {
        return BLOCKS[0].to_string().repeat(values.len());
    }
    values
        .iter()
        .map(|v| {
            let scaled = (v - min) as f64 / (max - min) as f64;
            let idx = ((scaled * (BLOCKS.len() - 1) as f64).round() as usize).min(BLOCKS.len() - 1);
            BLOCKS[idx]
        })
        .collect()
}

/// What is currently staged and when it will be purged.
fn quarantine_summary() -> Option<(usize, u64, String)> {
    let runs = crate::action::quarantine::runs().ok()?;
    if runs.is_empty() {
        return None;
    }
    let bytes: u64 = runs.iter().map(|m| m.total_bytes()).sum();
    let soonest = runs.iter().map(|m| m.expires_at()).min()?;
    Some((runs.len(), bytes, soonest.format("%Y-%m-%d").to_string()))
}

pub fn render(records: &[RunRecord], days: u32) -> String {
    let mut o = String::new();

    if records.is_empty() {
        // An empty frame reads like a bug. Say what to do instead.
        let _ = writeln!(o, "sift — no run history yet");
        let _ = writeln!(o);
        let _ = writeln!(o, "  Nothing has been recorded in the last {days} days.");
        let _ = writeln!(
            o,
            "  Run `sift scan` to produce a report, or `sift install`"
        );
        let _ = writeln!(o, "  to have it run on a schedule.");
        return o;
    }

    let last = records.last().unwrap();
    let t = Trend::from(records);

    // The last run that actually did something, which is rarely the last run.
    // Five `sift scan` invocations should not bury the `clean` the user cares
    // about. Compared by run_id rather than pointer, which is what the earlier
    // std::ptr::eq attempt got wrong.
    //
    // The predicate used to be `total_identified() > 0`, which meant a scan
    // qualified — and a scan cannot act, by construction (Principle 2). On a
    // real history that had staged 1.7 GB once and then run a dozen scans, the
    // report named a 20 MB *scan* as the last run that acted and hid the clean
    // holding the quarantine.
    let last_effective = records.iter().rev().find(|r| r.acted());

    let _ = writeln!(
        o,
        "sift — last run {}",
        last.started_at.format("%Y-%m-%d %H:%M")
    );
    let _ = writeln!(o);
    let _ = writeln!(o, "  command            {}", last.command);
    let _ = writeln!(o, "  identified         {}", size(last.total_identified()));
    if last.purged_bytes > 0 {
        let _ = writeln!(o, "  purged             {}", size(last.purged_bytes));
    }
    if last.actual_reclaimed() > 0 {
        // spec §5.1: the capacity delta is ground truth; per-candidate counts
        // are estimates.
        let _ = writeln!(
            o,
            "  actually reclaimed {}   (free-space delta — ground truth)",
            size(last.actual_reclaimed())
        );
    }
    let _ = writeln!(o, "  free space         {}", size(last.free_after));
    if let Some(reason) = &last.gated_reason {
        let _ = writeln!(o, "  gated              {reason}");
    }
    if last.total_errors() > 0 {
        let _ = writeln!(o, "  errors             {}", last.total_errors());
    }

    // Only when there is something to list. An empty "by scanner" heading reads
    // like a bug.
    let mut rows: Vec<(&String, u64)> = last
        .per_scanner
        .iter()
        .filter(|(_, r)| r.identified > 0)
        .map(|(id, r)| (id, r.identified))
        .collect();
    if !rows.is_empty() {
        rows.sort_by_key(|(_, b)| std::cmp::Reverse(*b));
        let _ = writeln!(o);
        let _ = writeln!(o, "  by scanner");
        for (id, bytes) in rows {
            let _ = writeln!(o, "    {id:<24}{}", size(bytes));
        }
    }

    // The last run that did something, when that is not the last run at all.
    if let Some(eff) = last_effective {
        if eff.run_id != last.run_id {
            let _ = writeln!(o);
            let _ = writeln!(
                o,
                "  last run that acted   {}  ({}, {})",
                eff.started_at.format("%Y-%m-%d %H:%M"),
                eff.command,
                // What it staged, not what it noticed.
                size(eff.total_quarantined())
            );
        }
    }

    // What is staged right now, and when it goes. This is the most actionable
    // thing the report can say, and it was missing entirely.
    if let Some((runs, bytes, expires)) = quarantine_summary() {
        let _ = writeln!(o);
        let _ = writeln!(
            o,
            "  in quarantine      {} across {} run(s)",
            size(bytes),
            runs
        );
        let _ = writeln!(
            o,
            "                     purged automatically from {expires}"
        );
        let _ = writeln!(o, "                     `sift restore <run-id>` to undo");
    }

    let _ = writeln!(o);
    let _ = writeln!(o, "sift — {days}-day trend ({} run(s))", t.runs);
    let _ = writeln!(o);
    let _ = writeln!(o, "  total identified   {}", size(t.total_identified));
    if t.total_purged > 0 {
        let _ = writeln!(o, "  total purged       {}", size(t.total_purged));
    }
    if t.gated_runs > 0 {
        let _ = writeln!(
            o,
            "  gated runs         {} of {} ({:.0}%)",
            t.gated_runs,
            t.runs,
            t.gate_rate() * 100.0
        );
    }
    if t.error_runs > 0 {
        let _ = writeln!(o, "  runs with errors   {} of {}", t.error_runs, t.runs);
    }

    let spark = sparkline(&t.free_series);
    if !spark.is_empty() {
        let first = *t.free_series.first().unwrap();
        let lastf = *t.free_series.last().unwrap();
        let _ = writeln!(o);
        let _ = writeln!(o, "  free space         {spark}");
        let _ = writeln!(o, "                     {} → {}", size(first), size(lastf));
        // Free space moves for every reason on the machine, and sift is usually
        // a small one. Without this the chart reads as sift losing ground when
        // the user simply filled the disk.
        if lastf < first {
            let _ = writeln!(
                o,
                "                     down {} overall — that is everything on this",
                size(first - lastf)
            );
            let _ = writeln!(
                o,
                "                     machine, not sift. sift identified {} in",
                size(t.total_identified)
            );
            let _ = writeln!(o, "                     the same window.");
        }
    }

    o
}

pub fn to_json(records: &[RunRecord], days: u32) -> serde_json::Value {
    let t = Trend::from(records);
    serde_json::json!({
        "schema_version": 1,
        "window_days": days,
        "runs": t.runs,
        "gated_runs": t.gated_runs,
        "gate_rate": t.gate_rate(),
        "error_runs": t.error_runs,
        "total_identified_bytes": t.total_identified,
        "total_purged_bytes": t.total_purged,
        "by_scanner": t.by_scanner,
        "last_run": records.last(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Local;

    fn rec(free: u64, identified: u64) -> RunRecord {
        let mut per = BTreeMap::new();
        per.insert(
            "logs".to_string(),
            crate::report::history::ScannerRecord {
                identified,
                quarantined: 0,
                errors: 0,
            },
        );
        RunRecord {
            run_id: "x".into(),
            started_at: Local::now(),
            duration_ms: 10,
            free_before: free,
            free_after: free,
            free_before_raw: free,
            per_scanner: per,
            purged_bytes: 0,
            gated_reason: None,
            command: "scan".into(),
        }
    }

    /// A `clean` that actually staged bytes.
    fn cleaned(run_id: &str, quarantined: u64) -> RunRecord {
        let mut r = rec(1_000, quarantined);
        r.run_id = run_id.into();
        r.command = "clean".into();
        r.per_scanner.get_mut("logs").unwrap().quarantined = quarantined;
        r
    }

    /// A `scan` that identified bytes and, being a scan, staged none.
    fn scanned(run_id: &str, identified: u64) -> RunRecord {
        let mut r = rec(1_000, identified);
        r.run_id = run_id.into();
        r
    }

    #[test]
    fn a_scan_is_never_the_last_run_that_acted() {
        // Taken from a real history: one clean staged 1.7 GB, then a dozen
        // scans identified smaller amounts. The predicate was
        // `total_identified() > 0`, so the most recent 20 MB *scan* was named
        // as the run that acted and the clean holding the quarantine vanished
        // from the report.
        //
        // A scan cannot act. That is Principle 2, and it is enforced
        // structurally — so a report claiming otherwise is stating something
        // the architecture makes impossible.
        let records = vec![
            cleaned("the-clean", 1_683_558_400),
            scanned("scan-1", 18_710_528),
            scanned("scan-2", 403_431_424),
            scanned("scan-3", 20_140_032),
        ];

        let out = render(&records, 90);
        let line = out
            .lines()
            .find(|l| l.contains("last run that acted"))
            .unwrap_or_else(|| panic!("{out}"));

        assert!(line.contains("clean"), "named a scan as acting: {line}");
        assert!(!line.contains("scan"), "named a scan as acting: {line}");
        // And the figure is what it staged, not what some scan noticed.
        assert!(line.contains(&size(1_683_558_400)), "{line}");
        assert!(!line.contains(&size(20_140_032)), "{line}");
    }

    #[test]
    fn a_history_of_scans_alone_names_no_acting_run() {
        // Nothing has acted, so the line must be absent rather than pointing
        // at whichever scan happened to identify the most.
        let records = vec![scanned("a", 5_000), scanned("b", 9_000)];
        let out = render(&records, 90);
        assert!(
            !out.contains("last run that acted"),
            "claimed a run acted when none did:\n{out}"
        );
    }

    #[test]
    fn a_purge_counts_as_acting_even_with_nothing_staged() {
        // A run that staged nothing but expired a quarantine did change the
        // disk, and is the run a user asking "what happened to my space?"
        // needs to find.
        let mut purger = scanned("purger", 0);
        purger.command = "clean".into();
        purger.purged_bytes = 900_000_000;

        let records = vec![purger, scanned("later-scan", 40_000_000)];
        let out = render(&records, 90);
        let line = out
            .lines()
            .find(|l| l.contains("last run that acted"))
            .unwrap_or_else(|| panic!("{out}"));
        assert!(line.contains("clean"), "{line}");
    }

    #[test]
    fn acted_distinguishes_identifying_from_staging() {
        assert!(!scanned("s", 5_000_000).acted(), "a scan never acts");
        assert!(cleaned("c", 5_000_000).acted());

        let mut staged_nothing = scanned("c2", 5_000_000);
        staged_nothing.command = "clean".into();
        assert!(
            !staged_nothing.acted(),
            "a clean that staged nothing did not act"
        );
    }

    #[test]
    fn empty_history_renders_guidance_not_an_empty_frame() {
        let out = render(&[], 90);
        assert!(out.contains("no run history"), "{out}");
        assert!(out.contains("sift scan"), "{out}");
    }

    #[test]
    fn trend_totals_match_hand_computed_values() {
        let records = vec![rec(100, 1_000), rec(200, 2_000), rec(300, 3_000)];
        let t = Trend::from(&records);
        assert_eq!(t.runs, 3);
        assert_eq!(t.total_identified, 6_000);
        assert_eq!(t.by_scanner.get("logs"), Some(&6_000));
    }

    #[test]
    fn sparkline_needs_at_least_two_points() {
        assert_eq!(sparkline(&[]), "");
        assert_eq!(sparkline(&[5]), "");
        assert_eq!(sparkline(&[1, 2]).chars().count(), 2);
    }

    #[test]
    fn sparkline_rises_with_the_data() {
        let s = sparkline(&[1, 50, 100]);
        let chars: Vec<char> = s.chars().collect();
        assert_eq!(chars[0], '▁');
        assert_eq!(chars[2], '█');
    }

    #[test]
    fn a_flat_series_does_not_divide_by_zero() {
        let s = sparkline(&[7, 7, 7]);
        assert_eq!(s.chars().count(), 3);
    }

    #[test]
    fn gate_rate_is_reported() {
        let mut a = rec(100, 0);
        a.gated_reason = Some("free space above floor".into());
        let records = vec![a, rec(100, 500)];

        let t = Trend::from(&records);
        assert_eq!(t.gated_runs, 1);
        assert!((t.gate_rate() - 0.5).abs() < f64::EPSILON);

        let out = render(&records, 90);
        assert!(out.contains("gated runs"), "{out}");
    }

    #[test]
    fn the_ground_truth_reclaim_is_labelled_as_such() {
        let mut r = rec(100, 5_000);
        r.free_before = 1_000_000;
        r.free_after = 3_000_000;
        let out = render(&[r], 90);
        assert!(out.contains("actually reclaimed"), "{out}");
        assert!(out.contains("ground truth"), "{out}");
    }
}
