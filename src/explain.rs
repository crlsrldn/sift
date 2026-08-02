//! `sift explain <path>` — what is this, and what happens if I delete it?
//!
//! Resolves PRD Open Question 5.
//!
//! # Why this is in a disk-cleaning tool
//!
//! The PRD's problem statement is that macOS reports a large opaque "System
//! Data" bucket with no drill-down and no remedy, and that the user cannot find
//! out what is in it. Every other command here answers "what can I safely
//! delete". This one answers "what *is* this", which is the question people
//! actually have when they go looking.
//!
//! It deletes nothing and has no flag that could. That is what lets it explain
//! paths sift would never touch — the honest answer for `~/Library/Mobile
//! Documents` is "38 GB of iCloud Drive, and sift will never go near it", which
//! no scanner could tell you because no scanner claims it.

use crate::config::Config;
use crate::risk::Risk;
use crate::scan::ScanCtx;
use std::path::{Path, PathBuf};

/// A curated explanation for a well-known path.
pub struct Known {
    /// Matched against the path with `$HOME` expanded.
    pub suffix: &'static str,
    pub what: &'static str,
    /// What it costs to lose it.
    pub cost: &'static str,
    /// Whether sift can ever claim it, and why or why not.
    pub sift_policy: &'static str,
}

/// Paths people find and wonder about.
///
/// Longest suffix wins, so a specific entry beats a general one.
pub const KNOWN: &[Known] = &[
    Known {
        suffix: "Library/Mobile Documents",
        what: "iCloud Drive. Everything in your iCloud Drive and any app that \
               syncs through it — Desktop and Documents too, if you enabled that.",
        cost: "Deleting from here deletes it from iCloud, and therefore from \
               every device signed into your account.",
        sift_policy: "Never touched. PRD non-goal N7 excludes iCloud content \
                      outright, and files evicted to iCloud are skipped even \
                      during a size walk because reading one downloads it.",
    },
    Known {
        suffix: "Library/Developer/Xcode/DerivedData",
        what: "Xcode's build output: compiled objects, indexes, and module caches, \
               one directory per project.",
        cost: "A full rebuild of that project. Minutes, not data.",
        sift_policy: "Claimed by `xcode-derived` when idle for 14 days and \
                      nothing inside was touched in the last hour. Quarantined, \
                      so it is undoable.",
    },
    Known {
        suffix: "Library/Developer/Xcode/iOS DeviceSupport",
        what: "Symbol files Xcode downloads the first time you attach a device \
               running a given iOS version. Usually the single largest thing on \
               a developer's machine.",
        cost: "Re-downloaded automatically the next time you attach a device on \
               that version. Bandwidth and a few minutes.",
        sift_policy: "Claimed by `xcode-devicesupport` for versions at least two \
                      major releases behind the newest present, older than 90 \
                      days. The newest bundle is never touched.",
    },
    Known {
        suffix: "Library/Developer/Xcode/Archives",
        what: "Builds you distributed, including the dSYMs that turn crash \
               addresses back into function names.",
        cost: "Crash reports from those released builds become unreadable, \
               permanently. Apple keeps no copy.",
        sift_policy: "Destructive tier, off by default. Requires two config \
                      switches and typing `xcode-archives` at a prompt.",
    },
    Known {
        suffix: "Library/Developer/CoreSimulator/Devices",
        what: "Your simulator devices and everything installed in them.",
        cost: "The simulators and their state.",
        sift_policy: "Never touched directly. `simctl` maintains an index \
                      alongside this directory and deleting by hand corrupts \
                      it; only `simctl delete unavailable` is ever used.",
    },
    Known {
        suffix: ".cargo/registry/src",
        what: "Unpacked sources of every crate you have built against.",
        cost: "Re-extracted from `registry/cache` on the next build. Seconds.",
        sift_policy: "Claimed by `cargo-cache` after 60 days. Quarantined.",
    },
    Known {
        suffix: ".cargo/bin",
        what: "Binaries you installed with `cargo install`.",
        cost: "Reinstalling each one, which means recompiling each one.",
        sift_policy: "Hard-coded deny. Never claimed by any scanner at any \
                      setting, with a test asserting it.",
    },
    Known {
        suffix: ".rustup",
        what: "Your Rust toolchains — the compilers themselves.",
        cost: "A multi-gigabyte re-download, and an unusable Rust install until \
               it finishes.",
        sift_policy: "Hard-coded deny. Never claimed by any scanner at any \
                      setting, with a test asserting it.",
    },
    Known {
        suffix: "node_modules",
        what: "A project's installed dependency tree.",
        cost: "A reinstall, which without a lockfile may not reproduce what was \
               there.",
        sift_policy: "Never claimed. It is not a cache — the package-manager \
                      stores behind it are, and those are what sift touches.",
    },
    Known {
        suffix: ".Trash",
        what: "Files you have already asked macOS to delete.",
        cost: "They are gone. This is the one thing sift can do that nothing \
               undoes.",
        sift_policy: "Destructive tier, off by default, requires Full Disk \
                      Access. Hard-deletes rather than quarantining, because \
                      the Trash already is a quarantine.",
    },
    Known {
        suffix: "Library/Application Support/MobileSync/Backup",
        what: "iPhone and iPad backups: app data, Health records, Messages \
               attachments, device settings.",
        cost: "The only copy of anything not in iCloud. Restoring a device later \
               will not bring it back.",
        sift_policy: "Destructive tier, off by default, requires Full Disk \
                      Access and a 365-day floor.",
    },
    Known {
        suffix: "Library/Caches",
        what: "Per-application caches, keyed by bundle identifier.",
        cost: "Varies by app, from nothing to a slow first launch.",
        sift_policy: "Only bundle IDs on a curated allowlist are ever \
                      considered, and only their named subdirectories. An \
                      unlisted app is never touched regardless of size.",
    },
    Known {
        suffix: "Library/Messages",
        what: "Your iMessage history and its attachments, including photos and \
               videos people sent you that exist nowhere else.",
        cost: "Every conversation on this Mac. If Messages in iCloud is off, \
               this is the only copy and it is not in any backup you have not \
               made yourself.",
        sift_policy: "Never claimed by any scanner.",
    },
    Known {
        suffix: ".ssh",
        what: "Your SSH private keys, public keys, known-hosts, and client \
               configuration.",
        cost: "Access to every server and git remote those keys authenticate to.",
        sift_policy: "Never claimed. Part of the never-touch corpus that every \
                      scanner is tested against at maximum aggression.",
    },
];

/// What `explain` found.
pub struct Explanation {
    pub path: PathBuf,
    pub exists: bool,
    pub bytes_on_disk: Option<u64>,
    pub known: Option<&'static Known>,
    /// Scanners that would claim this path under *some* configuration, with the
    /// tier each would claim it at.
    pub claimed_by: Vec<(&'static str, Risk)>,
    /// Whether the user's current configuration would claim it.
    pub claimed_now: bool,
}

/// Longest matching known-path entry.
fn lookup(path: &Path) -> Option<&'static Known> {
    let s = path.to_string_lossy();
    KNOWN
        .iter()
        .filter(|k| s.contains(k.suffix))
        .max_by_key(|k| k.suffix.len())
}

pub fn explain(ctx: &ScanCtx, raw: &Path) -> crate::Result<Explanation> {
    let path = crate::paths::expand(raw)?;
    let exists = path.exists();

    let bytes_on_disk = if exists {
        crate::fs::size::measure_with(&ctx.walker(), &path)
            .ok()
            .map(|m| m.bytes_on_disk)
    } else {
        None
    };

    // Ask every scanner, under a configuration that admits everything, whether
    // it would claim this path. That is the honest answer to "could sift ever
    // touch this", as distinct from "will it today".
    let mut claimed_by = Vec::new();
    let permissive = permissive_ctx(ctx)?;
    for scanner in crate::scan::registry().ids() {
        let Some(d) = crate::config::defaults::scanner(scanner) else {
            continue;
        };
        if scanner_would_claim(&permissive, scanner, &path) {
            claimed_by.push((scanner, d.risk));
        }
    }

    let claimed_now = claimed_by.iter().any(|(id, _)| {
        ctx.config
            .scanner(id)
            .map(|s| s.enabled && s.risk <= ctx.config.general.max_risk)
            .unwrap_or(false)
    });

    Ok(Explanation {
        path,
        exists,
        bytes_on_disk,
        known: lookup(raw).or_else(|| lookup(&crate::paths::expand(raw).unwrap_or_default())),
        claimed_by,
        claimed_now,
    })
}

/// A context in which every scanner could claim anything it is capable of
/// claiming — every scanner enabled, every tier admitted, **and every age floor
/// at zero**.
///
/// The age floors matter and were initially missed. `~/.cargo/registry/src` is
/// claimable by `cargo-cache`, but with a 60-day floor a freshly recreated one
/// produced no candidate, and `explain` reported "no scanner claims this under
/// any configuration" — which was false, because the floor *is* configuration.
/// The question this command answers is "could sift ever touch this", not
/// "would it today".
fn permissive_ctx(ctx: &ScanCtx) -> crate::Result<ScanCtx> {
    let mut toml = String::from(
        "[general]\nmax_risk = \"destructive\"\n\n[safety]\nactive_window_minutes = 0\n\n",
    );
    for id in crate::config::defaults::scanner_ids() {
        toml.push_str(&format!(
            "[scanners.{id}]\nenabled = true\nmin_age_days = 0\n\n"
        ));
    }
    // S6 and S11 only look under configured project roots, so without one they
    // can never claim anything and `explain` would understate them.
    if let Some(home) = crate::paths::home().ok().map(|h| h.display().to_string()) {
        toml.push_str(&format!("[projects]\nroots = [\"{home}\"]\n\n"));
    }
    let cfg = Config::parse(&toml)?;
    ScanCtx::new(
        std::sync::Arc::new(cfg),
        ctx.root_volume.clone(),
        ctx.caps.clone(),
    )
}

/// Whether a scanner's candidate set includes this path, or an ancestor of it.
fn scanner_would_claim(ctx: &ScanCtx, scanner: &str, path: &Path) -> bool {
    let Ok(filter) = crate::scan::only_filter(scanner) else {
        return false;
    };
    let report = crate::scan::registry().run(ctx, Some(&filter));

    report.candidates.iter().any(|c| match &c.target {
        crate::scan::Target::Path(p) | crate::scan::Target::HardDelete(p) => {
            path.starts_with(p) || p.starts_with(path)
        }
        _ => false,
    })
}

pub fn render(e: &Explanation) -> String {
    use crate::report::human::size;
    use std::fmt::Write;
    let mut o = String::new();

    let _ = writeln!(o, "{}", e.path.display());
    let _ = writeln!(o);

    if !e.exists {
        let _ = writeln!(o, "  Does not exist on this machine.");
        let _ = writeln!(o);
    } else if let Some(b) = e.bytes_on_disk {
        let _ = writeln!(o, "  size        {}", size(b));
    }

    if let Some(k) = e.known {
        let _ = writeln!(o, "  what        {}", wrap(k.what, 14));
        let _ = writeln!(o);
        let _ = writeln!(o, "  if deleted  {}", wrap(k.cost, 14));
        let _ = writeln!(o);
        let _ = writeln!(o, "  sift        {}", wrap(k.sift_policy, 14));
    } else {
        let _ = writeln!(o, "  what        Not a path sift knows about specifically.");
    }

    let _ = writeln!(o);
    if e.claimed_by.is_empty() {
        // The honest answer, and often the useful one.
        let _ = writeln!(
            o,
            "  VERDICT     No scanner claims this, under any configuration."
        );
        let _ = writeln!(
            o,
            "              sift will never delete it. If it is large and you"
        );
        let _ = writeln!(
            o,
            "              want it gone, that is a decision only you can make."
        );
    } else {
        let names: Vec<String> = e
            .claimed_by
            .iter()
            .map(|(id, risk)| format!("{id} ({risk})"))
            .collect();
        let _ = writeln!(o, "  VERDICT     Claimable by: {}", names.join(", "));
        if e.claimed_now {
            let _ = writeln!(
                o,
                "              Your CURRENT config would claim it on the next"
            );
            let _ = writeln!(o, "              `sift clean`.");
        } else {
            let _ = writeln!(
                o,
                "              Your current config would NOT claim it — the"
            );
            let _ = writeln!(o, "              scanner is disabled or gated by max_risk.");
        }
    }

    o
}

/// Wrap prose to fit under a label, continuing at `indent`.
fn wrap(text: &str, indent: usize) -> String {
    const WIDTH: usize = 62;
    let mut out = String::new();
    let mut col = 0;
    for word in text.split_whitespace() {
        if col + word.len() + 1 > WIDTH {
            out.push('\n');
            out.push_str(&" ".repeat(indent));
            col = 0;
        } else if col > 0 {
            out.push(' ');
            col += 1;
        }
        out.push_str(word);
        col += word.len();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_known_entry_answers_all_three_questions() {
        // An entry that cannot say what it is, what it costs, and what sift does
        // is not an explanation.
        for k in KNOWN {
            assert!(!k.suffix.is_empty());
            assert!(k.what.len() > 30, "`{}` has a thin `what`", k.suffix);
            assert!(k.cost.len() > 20, "`{}` has a thin `cost`", k.suffix);
            assert!(k.sift_policy.len() > 25, "`{}` has a thin policy", k.suffix);
        }
    }

    #[test]
    fn the_longest_matching_suffix_wins() {
        // `Library/Developer/Xcode/Archives` must beat nothing, and
        // `.cargo/registry/src` must not be shadowed by a shorter entry.
        let k = lookup(Path::new("/Users/x/.cargo/registry/src")).unwrap();
        assert_eq!(k.suffix, ".cargo/registry/src");

        let k = lookup(Path::new("/Users/x/Library/Developer/Xcode/Archives")).unwrap();
        assert_eq!(k.suffix, "Library/Developer/Xcode/Archives");
    }

    #[test]
    fn the_things_sift_never_touches_are_explained_too() {
        // This is the point of the command: the useful answer for iCloud Drive
        // is "38 GB, and sift will never go near it", which no scanner could
        // give because no scanner claims it.
        for p in [
            "/Users/x/Library/Mobile Documents",
            "/Users/x/.ssh",
            "/Users/x/.rustup",
            "/Users/x/Library/Messages",
        ] {
            let k = lookup(Path::new(p)).unwrap_or_else(|| panic!("no entry for {p}"));
            assert!(
                k.sift_policy.contains("Never") || k.sift_policy.contains("never"),
                "`{p}` should be explained as never-touched: {}",
                k.sift_policy
            );
        }
    }

    #[test]
    fn an_unknown_path_is_not_pretended_to_be_understood() {
        assert!(lookup(Path::new("/Users/x/some/random/thing")).is_none());
    }

    #[test]
    fn wrapping_keeps_lines_readable() {
        let long = "word ".repeat(60);
        for line in wrap(&long, 14).lines() {
            assert!(line.chars().count() <= 80, "line too long: {line}");
        }
    }
}
