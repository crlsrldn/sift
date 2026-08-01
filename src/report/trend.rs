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

    if !last.per_scanner.is_empty() {
        let _ = writeln!(o);
        let _ = writeln!(o, "  by scanner");
        let mut rows: Vec<(&String, u64)> = last
            .per_scanner
            .iter()
            .filter(|(_, r)| r.identified > 0)
            .map(|(id, r)| (id, r.identified))
            .collect();
        rows.sort_by_key(|(_, b)| std::cmp::Reverse(*b));
        for (id, bytes) in rows {
            let _ = writeln!(o, "    {id:<24}{}", size(bytes));
        }
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
        let _ = writeln!(o);
        let _ = writeln!(o, "  free space         {spark}");
        let _ = writeln!(
            o,
            "                     {} → {}",
            size(*t.free_series.first().unwrap()),
            size(*t.free_series.last().unwrap())
        );
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
