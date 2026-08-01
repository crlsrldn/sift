//! The never-touch corpus (G2, spec §12).
//!
//! A fixture home containing the things whose loss would be unrecoverable, or
//! catastrophic, or both. **Every scanner, fully enabled, at
//! `max_risk = "destructive"`, must produce zero candidates from any of it.**
//!
//! This is the test that has to pass before any of the others matter. It runs
//! on every PR, and it is deliberately paranoid: it asserts on the whole
//! candidate set rather than checking a list of known-bad paths, so a scanner
//! added later that reaches somewhere new fails here without anyone having to
//! remember to extend it.
//!
//! # Two corrections, made when the destructive scanners landed
//!
//! **The corpus grants FDA.** Overriding `$HOME` made the FDA probe return
//! `Unknown`, so `trash`, `snapshots`, and `ios-backups` were skipped and never
//! ran against the corpus at all — the three most dangerous scanners in the
//! tool were passing this gate vacuously. The fixture now creates a readable
//! TCC directory so they actually execute, and asserts they are not skipped.
//!
//! **Trash and backups are not in the corpus.** They were, and that was wrong:
//! if a user arms `trash`, claiming Trash contents is the scanner working, not
//! failing. The corpus is for things no scanner may claim *however it is
//! configured*. What belongs here instead is a document in `~/Downloads` — the
//! directory S13 does operate on, where only four extensions are ever
//! eligible.

use sift::caps::Capabilities;
use sift::config::Config;
use sift::scan::ScanCtx;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

static HOME_LOCK: Mutex<()> = Mutex::new(());

struct Corpus {
    _dir: tempfile::TempDir,
    home: PathBuf,
    prev_home: Option<std::ffi::OsString>,
    _guard: std::sync::MutexGuard<'static, ()>,
}

/// Everything here is either irreplaceable, or its loss breaks the machine.
///
/// Each entry is (relative path, why it must never be touched).
const NEVER_TOUCH: &[(&str, &str)] = &[
    // Credentials and keys. Unrecoverable, and losing them locks the user out
    // of remote systems.
    (".ssh/id_ed25519", "private SSH key"),
    (".ssh/id_ed25519.pub", "SSH public key"),
    (".ssh/known_hosts", "SSH known hosts"),
    (".ssh/config", "SSH client config"),
    (".gnupg/pubring.kbx", "GPG keyring"),
    (".gnupg/private-keys-v1.d/key.key", "GPG private key"),
    ("Library/Keychains/login.keychain-db", "macOS keychain"),
    (".aws/credentials", "AWS credentials"),
    (".config/gh/hosts.yml", "GitHub CLI token"),
    (".netrc", "netrc credentials"),
    // The user's own documents. The whole reason G2 exists.
    ("Documents/thesis.pdf", "user document"),
    ("Documents/taxes-2025.numbers", "user document"),
    ("Desktop/notes.txt", "user document"),
    ("Pictures/wedding.jpg", "user photo"),
    ("Movies/recital.mov", "user video"),
    // Source code, including things that merely look like build output.
    ("dev/myproject/src/main.rs", "source code"),
    ("dev/myproject/Cargo.toml", "project manifest"),
    ("dev/myproject/.git/HEAD", "git metadata"),
    ("dev/myproject/.env", "local secrets"),
    // Toolchains. Not caches: deleting these is a multi-gigabyte re-download
    // and an unusable install.
    (".rustup/toolchains/stable/bin/rustc", "Rust toolchain"),
    (".cargo/bin/cargo-nextest", "cargo-installed binary"),
    (".cargo/env", "cargo environment script"),
    // Documents sitting in Downloads. S13 operates on this directory, and only
    // four installer extensions are ever eligible — everything else here must
    // survive at any age.
    ("Downloads/thesis-final.pdf", "document in Downloads"),
    ("Downloads/contract-signed.docx", "document in Downloads"),
    ("Downloads/family-photos.heic", "photo in Downloads"),
    ("Downloads/recording.mov", "video in Downloads"),
    ("Downloads/dataset.csv", "data file in Downloads"),
    // Application state that looks like cache but is not.
    (
        "Library/Caches/com.google.Chrome/Default/Cookies",
        "browser cookies — user state, not cache",
    ),
    (
        "Library/Caches/com.google.Chrome/Default/Local Storage/leveldb/000003.log",
        "browser local storage — user state",
    ),
    (
        "Library/Caches/com.someapp.NotOnTheAllowlist/huge.bin",
        "unlisted bundle — Principle 1",
    ),
    // Mail and messages.
    ("Library/Mail/V10/mbox.mbox", "mail store"),
    ("Library/Messages/chat.db", "iMessage history"),
];

impl Corpus {
    fn new() -> Self {
        let guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("HOME", &home);

        // Grant FDA to the probe. Without this the fixture's own $HOME override
        // makes `probe_fda` see ENOENT -> Unknown, and every FDA-requiring
        // scanner is skipped before it ever looks at the corpus.
        fs::create_dir_all(home.join("Library/Application Support/com.apple.TCC")).unwrap();

        for (rel, _) in NEVER_TOUCH {
            let p = home.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            // Large and ancient: if size or age were the deciding factor rather
            // than allowlist membership, these would be the first things taken.
            fs::write(&p, vec![0u8; 256 * 1024]).unwrap();
            age(&p, 2000);
        }
        // Age the enclosing directories too.
        for (rel, _) in NEVER_TOUCH {
            let mut p = home.join(rel);
            while p.pop() && p.starts_with(&home) {
                age(&p, 2000);
            }
        }

        Self {
            _dir: dir,
            home,
            prev_home,
            _guard: guard,
        }
    }

    /// The most permissive configuration the tool allows: every scanner on,
    /// every risk tier admitted, project roots pointed at the whole home.
    fn maximally_dangerous_config(&self) -> Config {
        let mut toml = String::from(
            "[general]\nmax_risk = \"destructive\"\nmax_bytes_per_run = \"1000GiB\"\n\n",
        );
        toml.push_str(&format!(
            "[projects]\nroots = [\"{}\"]\n\n",
            self.home.display()
        ));
        // Also drop the liveness window to zero, so nothing is spared merely
        // for having been touched recently.
        toml.push_str("[safety]\nactive_window_minutes = 0\n\n");
        for id in sift::config::defaults::scanner_ids() {
            toml.push_str(&format!("[scanners.{id}]\nenabled = true\n\n"));
        }
        Config::parse(&toml).expect("the maximally dangerous config must be valid")
    }

    fn ctx(&self, cfg: Config) -> ScanCtx {
        ScanCtx::new(
            Arc::new(cfg),
            sift::fs::volume::root().unwrap(),
            Capabilities::probe(),
        )
        .unwrap()
    }
}

impl Drop for Corpus {
    fn drop(&mut self) {
        match &self.prev_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
    }
}

fn age(path: &Path, days: i64) {
    let when = chrono::Local::now() - chrono::Duration::days(days);
    let _ = filetime::set_file_mtime(
        path,
        filetime::FileTime::from_unix_time(when.timestamp(), 0),
    );
}

/// Assert no candidate claims anything in the corpus, or any ancestor of it.
///
/// Checks ancestors too: claiming `~/Documents` is exactly as destructive as
/// claiming `~/Documents/thesis.pdf`, and a scanner that took the parent
/// directory would otherwise slip through a leaf-only check.
fn assert_corpus_untouched(home: &Path, candidates: &[sift::scan::Candidate]) {
    for c in candidates {
        // EVERY path-bearing target, not just Path.
        //
        // This originally matched `Target::Path` alone, which silently excused
        // every `HardDelete` candidate — the one target kind that cannot be
        // undone. `trash` was invisible to this gate. Verified by sabotage:
        // pointing trash at ~/Documents did not fail the corpus until this was
        // fixed.
        let claimed = match &c.target {
            sift::scan::Target::Path(p) => p,
            sift::scan::Target::HardDelete(p) => p,
            sift::scan::Target::Delegated(_) | sift::scan::Target::Snapshot(_) => continue,
        };
        for (rel, why) in NEVER_TOUCH {
            let protected = home.join(rel);
            assert!(
                !protected.starts_with(claimed) && !claimed.starts_with(&protected),
                "scanner `{}` claimed {} which covers {} ({why})\n  label: {}",
                c.scanner,
                claimed.display(),
                protected.display(),
                c.label
            );
        }
    }
}

#[test]
fn no_scanner_claims_anything_in_the_never_touch_corpus() {
    // THE test. Every scanner enabled, every risk tier admitted, liveness
    // window at zero, project roots covering the entire home.
    let corpus = Corpus::new();
    let ctx = corpus.ctx(corpus.maximally_dangerous_config());

    let report = sift::scan::registry().run(&ctx, None);
    assert_corpus_untouched(&corpus.home, &report.candidates);
}

#[test]
fn the_destructive_scanners_actually_run_against_the_corpus() {
    // Guards the hole this test had until the destructive scanners landed: the
    // $HOME override made the FDA probe return Unknown, so trash, snapshots,
    // and ios-backups were SKIPPED and the corpus never exercised them. The
    // gate was green and proving nothing about the three scanners that can do
    // the most damage.
    let corpus = Corpus::new();
    let ctx = corpus.ctx(corpus.maximally_dangerous_config());
    let report = sift::scan::registry().run(&ctx, None);

    for id in [
        "trash",
        "snapshots",
        "ios-backups",
        "downloads",
        "xcode-archives",
    ] {
        let skipped_for_capability = report.skipped.iter().any(|(s, why)| {
            *s == id
                && matches!(
                    why,
                    sift::scan::SkippedScanner::NeedsFda
                        | sift::scan::SkippedScanner::NeedsTool(_)
                        | sift::scan::SkippedScanner::Disabled
                        | sift::scan::SkippedScanner::RiskGated { .. }
                )
        });
        assert!(
            !skipped_for_capability,
            "`{id}` never ran against the corpus, so its assertions prove nothing:\n{:?}",
            report.skipped
        );
    }
}

#[test]
fn the_full_action_pipeline_would_touch_nothing_in_the_corpus() {
    // The scanners are one gate; the filter chain is another. This asserts the
    // composed result, which is what `clean` would actually stage.
    let corpus = Corpus::new();
    let ctx = corpus.ctx(corpus.maximally_dangerous_config());

    let report = sift::scan::registry().run(&ctx, None);
    let filtered = sift::action::filter::apply(&ctx, report.candidates, |c| {
        sift::action::liveness::check(&ctx, c)
    });

    assert_corpus_untouched(&corpus.home, &filtered.accepted);
}

#[test]
fn the_corpus_is_actually_present_so_this_test_is_not_vacuous() {
    // A corpus that failed to materialise would make every assertion above
    // trivially true. Guard against the green-but-meaningless failure mode.
    let corpus = Corpus::new();
    assert!(
        NEVER_TOUCH.len() >= 25,
        "the corpus is too small to be meaningful"
    );

    for (rel, _) in NEVER_TOUCH {
        let p = corpus.home.join(rel);
        assert!(p.exists(), "corpus entry missing: {rel}");
        assert!(
            p.metadata().unwrap().len() > 0,
            "corpus entry is empty: {rel}"
        );
    }
}

#[test]
fn the_scanners_do_find_things_in_this_config_so_the_gate_is_real() {
    // If the maximally dangerous config somehow produced no candidates at all,
    // the corpus assertions would pass without proving anything. Seed something
    // legitimately claimable and confirm it IS claimed.
    let corpus = Corpus::new();

    let claimable = corpus.home.join(".cargo/registry/src");
    fs::create_dir_all(&claimable).unwrap();
    fs::write(claimable.join("old.crate"), vec![0u8; 128 * 1024]).unwrap();
    age(&claimable.join("old.crate"), 500);
    age(&claimable, 500);

    let ctx = corpus.ctx(corpus.maximally_dangerous_config());
    let report = sift::scan::registry().run(&ctx, None);

    assert!(
        !report.candidates.is_empty(),
        "no candidates at all — the corpus assertions would be vacuous"
    );
    // And the corpus is still untouched even though scanners are finding things.
    assert_corpus_untouched(&corpus.home, &report.candidates);
}

#[test]
fn an_unlisted_cache_bundle_is_never_claimed_however_large() {
    // Principle 1, isolated. Size and age are irrelevant; only allowlist
    // membership decides.
    let corpus = Corpus::new();
    let huge = corpus
        .home
        .join("Library/Caches/com.enormous.Unlisted/blob.bin");
    fs::create_dir_all(huge.parent().unwrap()).unwrap();
    fs::write(&huge, vec![0u8; 4 * 1024 * 1024]).unwrap();
    age(&huge, 3000);
    age(huge.parent().unwrap(), 3000);

    let ctx = corpus.ctx(corpus.maximally_dangerous_config());
    let report = sift::scan::registry().run(&ctx, None);

    for c in &report.candidates {
        assert!(
            !c.target.display().contains("com.enormous.Unlisted"),
            "an unlisted bundle was claimed: {}",
            c.target.display()
        );
    }
}

#[test]
fn a_target_directory_without_a_cargo_toml_is_never_claimed_even_at_max_risk() {
    // The S6 sibling rule, under the most permissive config available.
    let corpus = Corpus::new();
    let fake = corpus.home.join("Documents/design-assets/target");
    fs::create_dir_all(&fake).unwrap();
    fs::write(fake.join("final-artwork.psd"), vec![0u8; 512 * 1024]).unwrap();
    age(&fake.join("final-artwork.psd"), 1000);
    age(&fake, 1000);

    let ctx = corpus.ctx(corpus.maximally_dangerous_config());
    let report = sift::scan::registry().run(&ctx, None);

    for c in &report.candidates {
        assert!(
            !c.target.display().contains("design-assets"),
            "a `target` directory with no sibling Cargo.toml was claimed: {}",
            c.target.display()
        );
    }
}
