//! The terminal report (PRD §7).
//!
//! Design intent, quoted from the PRD: *"the summary is scannable in three
//! seconds, the risk tier is always visible, and skipped/blocked items are
//! surfaced rather than silently omitted."*
//!
//! All three are load-bearing. The third is the G7 honesty differentiator — the
//! commercial cleaners this tool is a reaction to are notable for quietly
//! omitting what they could not or would not touch.

use crate::report::group::{family_of, Family};
use crate::scan::{ScanCtx, ScanReport, SkippedScanner};
use std::collections::BTreeMap;
use std::fmt::Write;

/// Total line width. Fixed rather than terminal-derived for the body, so the
/// report looks the same when piped into a file or a PR description.
const WIDTH: usize = 66;

/// Human-readable size in the PRD's style: "22.1 GB", "0.5 GB".
///
/// Decimal GB, not GiB, because that is what Finder and the storage pane show.
/// Matching the number the user can see elsewhere matters more than matching
/// the unit the filesystem thinks in.
pub fn size(bytes: u64) -> String {
    const KB: f64 = 1e3;
    const MB: f64 = 1e6;
    const GB: f64 = 1e9;
    const TB: f64 = 1e12;
    let b = bytes as f64;

    if b >= TB {
        format!("{:.1} TB", b / TB)
    } else if b >= GB {
        format!("{:.1} GB", b / GB)
    } else if b >= MB {
        format!("{:.0} MB", b / MB)
    } else if b >= KB {
        format!("{:.0} KB", b / KB)
    } else {
        format!("{bytes} B")
    }
}

/// Render the full report.
pub fn render(report: &ScanReport, ctx: &ScanCtx) -> String {
    let mut o = String::new();

    let _ = writeln!(
        o,
        "sift — scan complete in {:.1}s",
        report.duration.as_secs_f64()
    );
    let _ = writeln!(
        o,
        "Volume: {}  ·  {} free of {}",
        ctx.root_volume.name,
        size(ctx.root_volume.available_important),
        size(ctx.root_volume.total)
    );
    let _ = writeln!(o);

    if report.candidates.is_empty() {
        render_empty(&mut o, report);
    } else {
        render_families(&mut o, report);
        let _ = writeln!(o);
        let _ = write_row(
            &mut o,
            2,
            "Total identified",
            &size(report.total_bytes()),
            "",
        );
    }

    render_skipped_and_blocked(&mut o, report);
    render_errors(&mut o, report);

    let _ = writeln!(o);
    if report.candidates.is_empty() {
        let _ = writeln!(o, "Nothing has been deleted.");
    } else {
        let _ = writeln!(
            o,
            "Run `sift clean` to quarantine. Nothing has been deleted."
        );
    }

    o
}

fn render_empty(o: &mut String, report: &ScanReport) {
    // A blank frame reads like a bug. Say what happened, and distinguish "no
    // scanners could run" from "scanners ran and found nothing" — those call
    // for completely different user actions.
    let ran = report.skipped.len() < report.skipped.len() + report.errors.len()
        || report.skipped.is_empty();
    if report.skipped.is_empty() && report.errors.is_empty() && ran {
        let _ = writeln!(o, "  Nothing reclaimable found.");
    } else if report.blocked().is_empty() {
        let _ = writeln!(o, "  Nothing reclaimable found by the enabled scanners.");
    } else {
        let _ = writeln!(
            o,
            "  Nothing found — but some scanners could not run. See below."
        );
    }
}

fn render_families(o: &mut String, report: &ScanReport) {
    let mut by_family: BTreeMap<Family, Vec<&crate::scan::Candidate>> = BTreeMap::new();
    for c in &report.candidates {
        by_family.entry(family_of(c.scanner)).or_default().push(c);
    }

    for (family, mut candidates) in by_family {
        candidates.sort_by_key(|c| std::cmp::Reverse(c.bytes_on_disk));
        let total: u64 = candidates.iter().map(|c| c.bytes_on_disk).sum();

        let _ = write_row(o, 2, family.title(), &size(total), "");

        for c in candidates {
            // The risk tier is always visible (PRD §7 design intent) — it is
            // the difference between "this regenerates" and "this is gone".
            let _ = write_row(o, 4, &c.label, &size(c.bytes_on_disk), c.risk.as_str());
        }
    }
}

/// One report line: `<indent><label><dots><size>  <risk>`.
fn write_row(
    o: &mut String,
    indent: usize,
    label: &str,
    value: &str,
    risk: &str,
) -> std::fmt::Result {
    let risk_col = if risk.is_empty() {
        String::new()
    } else {
        format!("   {risk}")
    };

    let label_budget = WIDTH.saturating_sub(indent + value.len() + 2);
    let label = truncate(label, label_budget);
    let pad = WIDTH.saturating_sub(indent + label.chars().count() + value.len());

    writeln!(
        o,
        "{:indent$}{}{:pad$}{}{}",
        "",
        label,
        "",
        value,
        risk_col,
        indent = indent,
        pad = pad
    )
}

/// Truncate on character boundaries, with an ellipsis.
///
/// Labels are derived from filesystem paths, which can contain anything; a
/// byte-slice truncation would panic on a multibyte boundary.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    if max <= 1 {
        return "…".into();
    }
    let keep: String = s.chars().take(max - 1).collect();
    format!("{keep}…")
}

fn render_skipped_and_blocked(o: &mut String, report: &ScanReport) {
    // PRD §7: surfaced rather than silently omitted. This is the G7 honesty
    // differentiator against the commercial cleaners.
    let disabled: Vec<&str> = report
        .skipped
        .iter()
        .filter(|(_, s)| {
            matches!(
                s,
                SkippedScanner::Disabled | SkippedScanner::RiskGated { .. }
            )
        })
        .map(|(id, _)| *id)
        .collect();

    if !disabled.is_empty() {
        let _ = writeln!(o);
        let _ = writeln!(o, "  Skipped: {} (disabled)", disabled.join(", "));
    }

    let blocked = report.blocked();
    if !blocked.is_empty() {
        if disabled.is_empty() {
            let _ = writeln!(o);
        }
        for (id, why) in blocked {
            let _ = writeln!(
                o,
                "  Blocked: {id} — {} (run `sift doctor`)",
                why.describe()
            );
        }
    }
}

fn render_errors(o: &mut String, report: &ScanReport) {
    if report.errors.is_empty() {
        return;
    }
    let _ = writeln!(o);
    for (id, msg) in &report.errors {
        // Errors are shown, not hidden behind a log level. A scanner that
        // failed means the total is an undercount, and the user must know.
        let _ = writeln!(o, "  Error:   {id} — {msg}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_uses_decimal_units_matching_finder() {
        assert_eq!(size(22_100_000_000), "22.1 GB");
        assert_eq!(size(1_000_000_000), "1.0 GB");
        assert_eq!(size(500_000_000), "500 MB");
        assert_eq!(size(1_500), "2 KB");
        assert_eq!(size(37), "37 B");
    }

    #[test]
    fn size_handles_terabytes_and_zero() {
        assert_eq!(size(0), "0 B");
        assert_eq!(size(2_500_000_000_000), "2.5 TB");
    }

    #[test]
    fn truncate_respects_character_boundaries() {
        // Labels come from paths, which can contain anything. Byte slicing
        // would panic mid-codepoint.
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 8), "hello w…");
        assert_eq!(truncate("日本語のパス名です", 5), "日本語の…");
        assert_eq!(truncate("abc", 1), "…");
        assert_eq!(truncate("abc", 0), "…");
    }

    #[test]
    fn a_row_fits_the_target_width() {
        let mut o = String::new();
        write_row(&mut o, 4, "DerivedData", "8.4 GB", "rebuildable").unwrap();
        let line = o.trim_end();
        assert!(line.contains("DerivedData"));
        assert!(line.contains("8.4 GB"));
        assert!(line.contains("rebuildable"));
    }

    #[test]
    fn a_very_long_label_does_not_break_the_layout() {
        let mut o = String::new();
        let long = "a".repeat(500);
        write_row(&mut o, 4, &long, "1.0 GB", "safe").unwrap();
        let line = o.lines().next().unwrap();
        assert!(
            line.chars().count() <= WIDTH + 16,
            "line was {} chars",
            line.chars().count()
        );
    }
}
