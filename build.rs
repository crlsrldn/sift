//! Stamps the binary with the commit it came from.
//!
//! # Why this exists
//!
//! `sift --version` reported `0.1.0` and always would: the number comes from
//! `Cargo.toml` and does not move between commits. For a tool whose install
//! path is "clone and `cargo build --release`", that means a binary cannot
//! answer "am I running the current code?" — the only way to tell was to hash
//! it against a fresh build, which needs the repo and the same toolchain.
//!
//! # Deliberately no dependencies
//!
//! CI fails the build if an HTTP or TLS crate reaches the binary, and a build
//! script is the easiest place for one to arrive unnoticed. Everything here is
//! `std` plus two `git` invocations, so the dependency audit has nothing new to
//! inspect. That is also why the date arithmetic is written out rather than
//! pulled from `chrono`.
//!
//! # Why no `rerun-if-changed`
//!
//! A build script that emits none is re-run by cargo whenever any file in the
//! package changes. That is exactly what the `-dirty` marker needs: narrowing
//! it to `.git/HEAD` would leave the marker stale after an uncommitted edit,
//! and a version string that says "clean" about a modified tree is worse than
//! no marker at all. The cost is two `git` calls on builds that were going to
//! recompile anyway.

use std::process::Command;

// Shared with the library so `cargo test` can reach it — a build script is not
// compiled into any test target, so the date arithmetic would otherwise be the
// one piece of logic here that nothing exercises.
include!("src/civil.rs");

fn main() {
    let version = env!("CARGO_PKG_VERSION");
    let detail = match git_describe() {
        Some(sha) => format!("{version} ({sha}, built {})", build_date()),
        // A source tarball, or git not installed. Say less rather than
        // guessing — an invented commit is worse than an absent one.
        None => format!("{version} (built {})", build_date()),
    };
    println!("cargo:rustc-env=SIFT_VERSION={detail}");
}

/// Short commit hash, with `-dirty` when the tree has uncommitted changes.
fn git_describe() -> Option<String> {
    let sha = git(&["rev-parse", "--short=7", "HEAD"])?;
    // An empty `status --porcelain` means a clean tree. If the command fails
    // outright the tree state is unknown, and the marker is left off rather
    // than asserted either way.
    let dirty = match git(&["status", "--porcelain"]) {
        Some(s) if !s.is_empty() => "-dirty",
        _ => "",
    };
    Some(format!("{sha}{dirty}"))
}

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8(out.stdout).ok()?.trim().to_string())
}

/// Build date as `YYYY-MM-DD`.
///
/// Honours `SOURCE_DATE_EPOCH`, the standard for reproducible builds: with it
/// set, two builds of the same source produce byte-identical binaries, which
/// is the only way to verify that a distributed binary matches its source.
fn build_date() -> String {
    let secs = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0)
        });

    // Euclidean division, so a pre-epoch timestamp floors to the right day
    // instead of truncating toward zero into the following one.
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}
