//! `sift explain` (PRD Open Question 5).
//!
//! The verdict is the load-bearing part. "No scanner claims this under any
//! configuration" is a promise, and a wrong one either scares a user off
//! something harmless or reassures them about something sift will take.

use std::path::PathBuf;
use std::process::{Command, Output};

fn bin() -> PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("sift")
}

fn explain(home: &std::path::Path, path: &str) -> Output {
    Command::new(bin())
        .args(["explain", path])
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_STATE_HOME", home.join(".state"))
        .output()
        .unwrap()
}

fn json(home: &std::path::Path, path: &str) -> serde_json::Value {
    let out = Command::new(bin())
        .args(["explain", path, "--json"])
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_STATE_HOME", home.join(".state"))
        .output()
        .unwrap();
    serde_json::from_slice(&out.stdout).expect("explain --json was not valid JSON")
}

/// A fixture home with something in every interesting category.
fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let h = dir.path();

    for (rel, bytes) in [
        (".ssh/id_ed25519", 4096usize),
        (".rustup/toolchains/stable/bin/rustc", 8192),
        (".cargo/bin/cargo-nextest", 8192),
        (".cargo/registry/src/crate-1.0.0/lib.rs", 8192),
        ("Library/Mobile Documents/doc.txt", 4096),
        ("Documents/thesis.pdf", 4096),
        ("Library/Logs/MyApp/app.log", 4096),
    ] {
        let p = h.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, vec![0u8; bytes]).unwrap();
    }
    dir
}

#[test]
fn explain_deletes_nothing() {
    // It has no flag that could, and this asserts the whole fixture survives.
    let dir = fixture();
    let before: Vec<PathBuf> = walkdir(dir.path());

    for p in [
        "~/.ssh",
        "~/.cargo/registry/src",
        "~/Documents",
        "~/nonexistent",
    ] {
        assert_eq!(explain(dir.path(), p).status.code(), Some(0));
    }

    assert_eq!(
        before,
        walkdir(dir.path()),
        "explain modified the filesystem"
    );
}

fn walkdir(root: &std::path::Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    fn go(d: &std::path::Path, out: &mut Vec<PathBuf>) {
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                out.push(e.path());
                if e.path().is_dir() {
                    go(&e.path(), out);
                }
            }
        }
    }
    go(root, &mut out);
    out.sort();
    out
}

#[test]
fn the_never_touched_paths_are_reported_as_never_touched() {
    // A wrong verdict here reassures someone about something sift will take.
    let dir = fixture();
    for p in ["~/.ssh", "~/.rustup", "~/.cargo/bin", "~/Documents"] {
        let v = json(dir.path(), p);
        assert!(
            v["claimable_by"].as_array().unwrap().is_empty(),
            "`{p}` was reported as claimable: {v}"
        );
        assert_eq!(v["claimed_by_current_config"], false, "{p}");
    }
}

#[test]
fn a_claimable_path_is_reported_as_claimable_even_when_too_young() {
    // The bug this test exists for: `~/.cargo/registry/src` is claimable by
    // `cargo-cache`, but a freshly created one is under the 60-day floor. The
    // first version reported "no scanner claims this under any configuration",
    // which was false — the floor IS configuration.
    let dir = fixture();
    let v = json(dir.path(), "~/.cargo/registry/src");

    let claimable: Vec<String> = v["claimable_by"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["scanner"].as_str().unwrap().to_string())
        .collect();

    assert!(
        claimable.contains(&"cargo-cache".to_string()),
        "a claimable path was reported as never-claimed: {v}"
    );
}

#[test]
fn claimable_and_claimed_now_are_distinguished() {
    // "sift could take this" and "sift will take this on the next run" are
    // different answers, and conflating them makes the command useless for
    // deciding whether to act.
    let dir = fixture();
    std::fs::create_dir_all(dir.path().join(".config/sift")).unwrap();
    std::fs::write(
        dir.path().join(".config/sift/config.toml"),
        "[scanners.cargo-cache]\nenabled = false\n",
    )
    .unwrap();

    let v = json(dir.path(), "~/.cargo/registry/src");
    assert!(!v["claimable_by"].as_array().unwrap().is_empty());
    assert_eq!(
        v["claimed_by_current_config"], false,
        "a disabled scanner was reported as claiming it now"
    );
}

#[test]
fn icloud_is_explained_as_the_thing_sift_will_never_go_near() {
    // The PRD's problem statement. The useful answer for a large iCloud Drive
    // is not "nothing to clean here" but "this is iCloud, and here is why sift
    // will not touch it".
    let dir = fixture();
    let out = explain(dir.path(), "~/Library/Mobile Documents");
    let text = String::from_utf8_lossy(&out.stdout);

    assert!(text.contains("iCloud"), "{text}");
    assert!(text.contains("every device"), "{text}");
    assert!(text.contains("No scanner claims this"), "{text}");
}

#[test]
fn an_unknown_path_is_not_pretended_to_be_understood() {
    let dir = fixture();
    let out = explain(dir.path(), "~/some-random-directory");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("Not a path sift knows about"), "{text}");
}

#[test]
fn a_nonexistent_path_says_so_rather_than_erroring() {
    let dir = fixture();
    let out = explain(dir.path(), "~/definitely-not-here");
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("Does not exist"));
}
