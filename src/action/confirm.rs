//! Confirmation for irreversible actions (PRD §6.1, PR plan PR-36).
//!
//! # Why `y` is not enough
//!
//! `[y/N]` is a reflex. People answer it while reading the next thing. For a
//! Rebuildable quarantine that is fine — the action is undoable and the prompt
//! is a courtesy.
//!
//! For a Destructive scanner it is not fine, so confirmation requires **typing
//! the scanner's name**. That is not friction for its own sake: it forces the
//! user to have read which scanner they are arming, and it makes an accidental
//! Return keystroke incapable of destroying anything.
//!
//! # Why `--yes` does not cover it
//!
//! `--yes` means "do not ask me about the routine parts". Someone who scripts
//! `sift clean --yes` in a cron job has not thereby consented to permanently
//! deleting their Trash. Destructive scanners need config-level arming — two
//! independent switches — and that arming is what authorises the unattended
//! run. The prompt authorises the interactive one.

use crate::report::human::size;
use crate::risk::Risk;
use crate::scan::Candidate;
use std::collections::BTreeMap;
use std::io::Write;

/// Destructive candidates, grouped by scanner.
pub fn destructive_by_scanner(candidates: &[Candidate]) -> BTreeMap<&'static str, Vec<&Candidate>> {
    let mut m: BTreeMap<&'static str, Vec<&Candidate>> = BTreeMap::new();
    for c in candidates.iter().filter(|c| c.risk == Risk::Destructive) {
        m.entry(c.scanner).or_default().push(c);
    }
    m
}

/// The text shown before a Destructive scanner acts.
pub fn render_blast_radius(
    scanner: &str,
    blast_radius: &str,
    candidates: &[&Candidate],
    reversible: bool,
) -> String {
    use std::fmt::Write as _;
    let mut o = String::new();
    let total: u64 = candidates.iter().map(|c| c.bytes_on_disk).sum();

    let _ = writeln!(o);
    let _ = writeln!(
        o,
        "  {scanner} — {} across {} item(s)",
        size(total),
        candidates.len()
    );
    let _ = writeln!(o);
    for c in candidates.iter().take(10) {
        let _ = writeln!(o, "    {:>10}  {}", size(c.bytes_on_disk), c.label);
    }
    if candidates.len() > 10 {
        let _ = writeln!(o, "    … and {} more", candidates.len() - 10);
    }
    let _ = writeln!(o);
    // The blast radius, stated before the ask rather than after it.
    for line in blast_radius.lines() {
        let _ = writeln!(o, "  {line}");
    }
    let _ = writeln!(o);
    if reversible {
        let _ = writeln!(
            o,
            "  These go to quarantine first, so `sift restore` can undo them"
        );
        let _ = writeln!(o, "  until the TTL expires.");
    } else {
        let _ = writeln!(
            o,
            "  This bypasses quarantine. `sift restore` CANNOT undo it."
        );
    }
    o
}

/// Ask for confirmation by requiring the scanner's name.
///
/// `reader` is injected so the interaction is testable without a terminal.
pub fn confirm_destructive<R: std::io::BufRead>(
    scanner: &str,
    blast_radius: &str,
    candidates: &[&Candidate],
    reversible: bool,
    reader: &mut R,
    out: &mut impl Write,
) -> std::io::Result<bool> {
    write!(
        out,
        "{}",
        render_blast_radius(scanner, blast_radius, candidates, reversible)
    )?;
    write!(
        out,
        "\n  Type `{scanner}` to confirm, anything else to skip: "
    )?;
    out.flush()?;

    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        // EOF. No terminal, no answer, no consent.
        writeln!(out)?;
        return Ok(false);
    }

    // Exact match after trimming. Not case-insensitive, not a prefix: the point
    // is that the user typed the thing they read.
    Ok(line.trim() == scanner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::Target;
    use chrono::Local;

    fn candidate(scanner: &'static str, bytes: u64, label: &str) -> Candidate {
        Candidate {
            scanner,
            target: Target::Path("/tmp/x".into()),
            bytes_on_disk: bytes,
            bytes_apparent: bytes,
            last_modified: Local::now(),
            risk: Risk::Destructive,
            label: label.into(),
            reason: "test".into(),
        }
    }

    fn ask(scanner: &str, input: &str) -> bool {
        let c = candidate("trash", 1000, "x");
        let cs = vec![&c];
        let mut reader = std::io::Cursor::new(input.as_bytes().to_vec());
        let mut out = Vec::new();
        confirm_destructive(
            scanner,
            "everything is lost",
            &cs,
            false,
            &mut reader,
            &mut out,
        )
        .unwrap()
    }

    #[test]
    fn typing_the_scanner_name_confirms() {
        assert!(ask("trash", "trash\n"));
        assert!(ask("trash", "  trash  \n"));
    }

    #[test]
    fn y_does_not_confirm_a_destructive_scanner() {
        // The whole point. `[y/N]` is a reflex people answer while reading the
        // next thing; a Return keystroke must not be able to destroy anything.
        for reflex in ["y\n", "Y\n", "yes\n", "\n", "Enter\n"] {
            assert!(!ask("trash", reflex), "`{reflex:?}` should not confirm");
        }
    }

    #[test]
    fn a_near_miss_does_not_confirm() {
        // Not case-insensitive, not a prefix: the user must have typed the
        // thing they read.
        for near in ["Trash\n", "TRASH\n", "tras\n", "trashh\n", "trash extra\n"] {
            assert!(!ask("trash", near), "`{near:?}` should not confirm");
        }
    }

    #[test]
    fn eof_does_not_confirm() {
        // No terminal, no answer, no consent.
        assert!(!ask("trash", ""));
    }

    #[test]
    fn confirming_one_scanner_does_not_confirm_another() {
        assert!(!ask("downloads", "trash\n"));
    }

    #[test]
    fn the_prompt_states_the_blast_radius_before_asking() {
        let c = candidate("trash", 5_000_000_000, "Trash contents");
        let out = render_blast_radius(
            "trash",
            "Everything in your Trash is permanently gone. This cannot be undone.",
            &[&c],
            false,
        );

        assert!(out.contains("permanently gone"), "{out}");
        assert!(out.contains("CANNOT undo"), "{out}");
        assert!(out.contains("5.0 GB"), "{out}");
    }

    #[test]
    fn a_reversible_destructive_scanner_says_so() {
        // downloads is Destructive but goes through quarantine, so the honest
        // statement is different from trash's.
        let c = candidate("downloads", 1_000_000_000, "old.dmg");
        let out = render_blast_radius("downloads", "Installers are gone.", &[&c], true);

        assert!(out.contains("sift restore"), "{out}");
        assert!(!out.contains("CANNOT undo"), "{out}");
    }

    #[test]
    fn a_long_list_is_truncated_rather_than_flooding_the_terminal() {
        let cs: Vec<Candidate> = (0..50)
            .map(|i| candidate("trash", 1000, &format!("item{i}")))
            .collect();
        let refs: Vec<&Candidate> = cs.iter().collect();
        let out = render_blast_radius("trash", "gone", &refs, false);

        assert!(out.contains("and 40 more"), "{out}");
        assert!(out.lines().count() < 25, "the prompt flooded the terminal");
    }

    #[test]
    fn grouping_splits_by_scanner_and_ignores_non_destructive() {
        let mut safe = candidate("logs", 100, "log");
        safe.risk = Risk::Safe;
        let cs = vec![
            candidate("trash", 100, "a"),
            candidate("downloads", 200, "b"),
            candidate("trash", 300, "c"),
            safe,
        ];

        let grouped = destructive_by_scanner(&cs);
        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped["trash"].len(), 2);
        assert!(!grouped.contains_key("logs"));
    }
}
