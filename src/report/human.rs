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

        // The total sums measured bytes, so every unknown delegated line is
        // missing from it. Saying so is the difference between an undercount
        // and a wrong number (G7).
        let unknown = report
            .candidates
            .iter()
            .filter(|c| {
                c.bytes_on_disk == 0 && matches!(c.target, crate::scan::Target::Delegated(_))
            })
            .count();
        if unknown > 0 {
            let _ = writeln!(o);
            let _ = writeln!(
                o,
                "  {unknown} line(s) show `unknown` and are not in that total."
            );
            let _ = write_unknown_explanation(&mut o, report, ctx);
        }
    }

    render_disabled(&mut o, report);
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
            let _ = write_row(o, 4, &c.label, &candidate_size(c), c.risk.as_str());
        }
    }
}

/// Why the `unknown` lines are unknown.
///
/// There are three different answers and they call for different actions, so
/// collapsing them misleads:
///
///   * **nobody asked** — `--estimate-delegated` was off. Re-running helps.
///   * **asked, no answer** — the tool supports being asked and returned
///     nothing useful this time. Re-running will not help; something is wrong
///     with the tool.
///   * **cannot be asked** — `uv cache prune`, `pnpm store prune`,
///     `yarn cache clean` and `cargo-sweep` have no dry-run and no reporting
///     mode. Re-running will *never* help, and saying otherwise sends the user
///     after a flag that cannot fix it.
///
/// The third case was previously reported as the second, which is how a `uv`
/// line came to claim it had been asked when nothing had asked it.
fn write_unknown_explanation(
    o: &mut String,
    report: &ScanReport,
    ctx: &ScanCtx,
) -> std::fmt::Result {
    // Split by whether the tool can be asked at all, naming the *tool* rather
    // than the scanner — `uv` is what the user recognises and can go check,
    // `python-caches` is sift's internal id for the rule.
    let mut unaskable: Vec<&str> = Vec::new();
    let mut askable = false;

    for c in &report.candidates {
        let crate::scan::Target::Delegated(cmd) = &c.target else {
            continue;
        };
        if c.bytes_on_disk != 0 {
            continue;
        }
        if crate::scan::scanner_estimates_size(c.scanner) {
            askable = true;
        } else {
            unaskable.push(&cmd.program);
        }
    }
    unaskable.sort_unstable();
    unaskable.dedup();

    if !unaskable.is_empty() {
        let (subject, verb) = if unaskable.len() == 1 {
            (unaskable[0].to_string(), "provides")
        } else {
            (unaskable.join(", "), "provide")
        };
        writeln!(
            o,
            "  `{subject}` {verb} no way to ask what would be freed — that \
             figure\n  is not obtainable, with or without --estimate-delegated."
        )?;
    }

    if askable {
        // Only mention the flag for lines it could actually change. Suggesting
        // it for a tool that has no reporting mode sends the user after a fix
        // that cannot work.
        writeln!(
            o,
            "  {}",
            if ctx.estimate_delegated {
                "The rest were asked, and did not report one."
            } else {
                "Re-run with --estimate-delegated to ask the rest for a figure."
            }
        )?;
    }

    Ok(())
}

/// The size column for one candidate.
///
/// A delegated candidate carries 0 bytes when nobody asked the other tool how
/// much it would free (`--estimate-delegated` is off by default, because
/// asking costs subprocesses that `scan` is not allowed to spawn). Printing
/// that as "0 B" states the opposite of what is true: it reads as "nothing to
/// reclaim here" when the honest answer is "we did not ask". On the machine
/// this was found on, a bare "0 B" was standing in for 403 MB.
///
/// A path candidate measuring 0 is a different thing — that is a real,
/// measured zero — but such candidates are dropped before they reach here.
fn candidate_size(c: &crate::scan::Candidate) -> String {
    if c.bytes_on_disk == 0 && matches!(c.target, crate::scan::Target::Delegated(_)) {
        return "unknown".to_string();
    }
    size(c.bytes_on_disk)
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

/// What the disabled scanners hold — shown only under `--include-disabled`.
///
/// Set apart from the main body, with its own total, and never folded into
/// "Total identified": `clean` will not touch any of it, and a reader who
/// added the two figures together would be told the wrong number.
fn render_disabled(o: &mut String, report: &ScanReport) {
    if report.disabled_candidates.is_empty() {
        return;
    }

    let _ = writeln!(o);
    let _ = writeln!(o, "  Disabled in config — not counted above, and `clean`");
    let _ = writeln!(o, "  will not touch these:");
    let _ = writeln!(o);

    for c in &report.disabled_candidates {
        let _ = write_row(o, 4, &c.label, &candidate_size(c), c.risk.as_str());
    }

    let _ = writeln!(o);
    let _ = write_row(
        o,
        4,
        "Held by disabled scanners",
        &size(report.disabled_bytes()),
        "",
    );
    let _ = writeln!(o);
    let _ = writeln!(
        o,
        "  Enable in {}: {}",
        crate::paths::config_file()
            .map(|p| tildify(&p))
            .unwrap_or_else(|_| "your config".into()),
        report.disabled_scanners().join(", ")
    );
}

/// `/Users/you/x` -> `~/x`, so a path fits the report width.
fn tildify(p: &std::path::Path) -> String {
    let s = p.display().to_string();
    match std::env::var("HOME") {
        Ok(h) if !h.is_empty() && s.starts_with(&h) => s.replacen(&h, "~", 1),
        _ => s,
    }
}

fn render_skipped_and_blocked(o: &mut String, report: &ScanReport) {
    // PRD §7: surfaced rather than silently omitted. This is the G7 honesty
    // differentiator against the commercial cleaners.
    // Disabled and risk-gated are different problems with different fixes, and
    // collapsing them sent users to the wrong config key: a scanner the user
    // had explicitly set `enabled = true` was still reported as "(disabled)",
    // when what actually held it back was the `max_risk` ceiling.
    let disabled: Vec<&str> = report
        .skipped
        .iter()
        .filter(|(_, s)| matches!(s, SkippedScanner::Disabled))
        .map(|(id, _)| *id)
        .collect();

    let risk_gated: Vec<(&str, &str)> = report
        .skipped
        .iter()
        .filter_map(|(id, s)| match s {
            SkippedScanner::RiskGated { risk, .. } => Some((*id, risk.as_str())),
            _ => None,
        })
        .collect();

    let any_skipped = !disabled.is_empty() || !risk_gated.is_empty();

    if !disabled.is_empty() {
        let _ = writeln!(o);
        let _ = writeln!(o, "  Skipped: {} (disabled)", disabled.join(", "));
    }

    if !risk_gated.is_empty() {
        if disabled.is_empty() {
            let _ = writeln!(o);
        }
        let names: Vec<&str> = risk_gated.iter().map(|(id, _)| *id).collect();
        // Every risk-gated scanner in a single run is held back by the same
        // ceiling, so the tier is named once.
        let tier = risk_gated[0].1;
        let _ = writeln!(
            o,
            "  Skipped: {} — {tier}, above max_risk (enabled, but the tier is not armed)",
            names.join(", ")
        );
    }

    let blocked = report.blocked();
    if !blocked.is_empty() {
        if !any_skipped {
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
