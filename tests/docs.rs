//! Documentation that cannot drift from the code.
//!
//! Docs rot silently: a scanner is added, nobody remembers the reference, and
//! six months later the docs describe a tool that no longer exists. These
//! cross-reference the prose against the registry so drift is a failing build.

use sift::config::defaults;

fn read(rel: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

#[test]
fn every_scanner_has_its_own_section_in_the_reference() {
    // The PR-42 exit criterion. A scanner nobody documented is one nobody can
    // decide whether to enable.
    let doc = read("docs/scanners.md");
    for id in defaults::scanner_ids() {
        assert!(
            doc.contains(&format!("## `{id}`")),
            "`{id}` has no section in docs/scanners.md"
        );
    }
}

#[test]
fn the_reference_documents_no_scanner_that_does_not_exist() {
    // The other direction: a section for a scanner that was renamed or removed
    // is worse than no section, because it reads as current.
    let doc = read("docs/scanners.md");
    let ids = defaults::scanner_ids();

    for line in doc.lines() {
        let Some(rest) = line.strip_prefix("## `") else {
            continue;
        };
        let name = rest.trim_end_matches('`');
        assert!(
            ids.contains(&name),
            "docs/scanners.md documents `{name}`, which is not a registered scanner"
        );
    }
}

#[test]
fn every_scanner_section_states_what_you_lose() {
    // "What it targets" without "what you lose" is a feature list, not a
    // reference someone can make a decision from.
    let doc = read("docs/scanners.md");
    for section in doc.split("\n## ").skip(1) {
        let id = section.lines().next().unwrap_or("").trim_matches('`');
        assert!(
            section.contains("**What you lose.**"),
            "the `{id}` section does not say what is lost"
        );
        assert!(
            section.contains("**How it decides.**"),
            "the `{id}` section does not say how it decides"
        );
    }
}

#[test]
fn every_destructive_scanner_is_marked_as_off_by_default() {
    // A reader skimming the table must not mistake a destructive scanner for
    // something already running.
    let doc = read("docs/scanners.md");
    for d in defaults::SCANNERS {
        if d.risk != sift::risk::Risk::Destructive {
            continue;
        }
        let section = doc
            .split("\n## ")
            .find(|s| s.starts_with(&format!("`{}`", d.id)))
            .unwrap_or_else(|| panic!("no section for `{}`", d.id));
        assert!(
            section.contains("**off** by default"),
            "the `{}` section does not mark it off by default",
            d.id
        );
    }
}

#[test]
fn the_documented_exit_codes_match_the_implementation() {
    // The exit table is a public contract; a man page that disagrees with the
    // binary is worse than one that omits it.
    let man = read("man/sift.1");
    for code in sift::ExitCode::ALL {
        assert!(
            man.contains(&format!(".B {}\n", code.as_i32())),
            "man page does not document exit code {}",
            code.as_i32()
        );
    }
}

#[test]
fn every_command_appears_in_the_man_page() {
    use clap::CommandFactory;
    let man = read("man/sift.1");
    for cmd in sift::cli::Cli::command().get_subcommands() {
        let name = cmd.get_name();
        // `.B` for a bare command, `.BI` for one taking an argument — both are
        // correct roff, and an earlier version of this test only accepted the
        // first, failing on `restore RUN_ID` when the man page was right.
        let documented = [".B ", ".BI "].iter().any(|macro_| {
            man.contains(&format!("{macro_}{name}\n")) || man.contains(&format!("{macro_}{name} "))
        });
        assert!(documented, "man page does not document `{name}`");
    }
}

#[test]
fn the_readme_does_not_promise_a_release_that_does_not_exist() {
    // Until PR-44/45 land there is no signed binary and no tap. A README that
    // says `brew install` would be lying on arrival.
    let readme = read("README.md");
    assert!(
        readme.contains("pre-release"),
        "the README must say this is not released yet"
    );
    assert!(
        !readme.contains("brew install cindral"),
        "the README advertises a Homebrew tap that does not exist yet"
    );
}

#[test]
fn documented_config_paths_match_the_code() {
    let doc = read("docs/config.md");
    for p in [
        "~/.config/sift/config.toml",
        "~/.local/state/sift/quarantine/",
        "~/.local/state/sift/history.jsonl",
        "~/Library/LaunchAgents/com.cindral.sift.plist",
    ] {
        assert!(doc.contains(p), "docs/config.md does not mention `{p}`");
    }
}

#[test]
fn the_safety_doc_covers_every_guard_the_walker_implements() {
    // If a guard exists and is undocumented, the safety story is incomplete in
    // exactly the place people go looking.
    let doc = read("docs/safety.md").to_ascii_lowercase();
    for guard in [
        "minimum age",
        "liveness",
        "circuit breaker",
        "device check",
        "firmlink",
        "symlink",
        "dataless",
        "exclude",
    ] {
        assert!(
            doc.contains(guard),
            "docs/safety.md does not cover `{guard}`"
        );
    }
}
