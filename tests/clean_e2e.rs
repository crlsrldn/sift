//! `sift clean` end to end, driving the real binary (PRD §7, FR-11).
//!
//! These run the actual process rather than calling library functions, because
//! the properties under test — that `--dry-run` mutates nothing, that declining
//! the prompt mutates nothing — are properties of a complete invocation.
//!
//! The dry-run assertion uses a **filesystem snapshot taken before and after**,
//! not a reading of the output. A command that printed "nothing was deleted"
//! while deleting something would pass an output check and fail this one.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn bin() -> PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("sift")
}

/// An isolated home, state directory, and project tree.
struct Sandbox {
    dir: tempfile::TempDir,
}

impl Sandbox {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("home")).unwrap();
        std::fs::create_dir_all(dir.path().join("state")).unwrap();
        std::fs::create_dir_all(dir.path().join("config")).unwrap();
        Self { dir }
    }

    fn home(&self) -> PathBuf {
        self.dir.path().join("home")
    }

    /// A `~/.cargo/registry/src` old enough for the cargo-cache scanner to
    /// claim, so `clean` has something real to act on.
    fn seed_cargo_cache(&self, bytes: usize) -> PathBuf {
        let p = self.home().join(".cargo/registry/src");
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("crate-1.0.0.crate"), vec![0u8; bytes]).unwrap();

        let old = chrono::Local::now() - chrono::Duration::days(400);
        let ft = filetime::FileTime::from_unix_time(old.timestamp(), 0);
        filetime::set_file_mtime(p.join("crate-1.0.0.crate"), ft).unwrap();
        filetime::set_file_mtime(&p, ft).unwrap();
        p
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(bin());
        c.args(args)
            .env("HOME", self.home())
            .env("XDG_STATE_HOME", self.dir.path().join("state"))
            .env("XDG_CONFIG_HOME", self.dir.path().join("config"))
            .env_remove("SIFT_CONFIG")
            .env_remove("SIFT_LOG");
        c
    }

    fn run(&self, args: &[&str]) -> Output {
        self.cmd(args).output().expect("failed to run sift")
    }

    /// Run with something piped to stdin, for the confirmation prompt.
    fn run_with_input(&self, args: &[&str], input: &str) -> Output {
        let mut child = self
            .cmd(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }
}

/// Every path under `root`, with size and mtime.
///
/// This is the spy: comparing two of these detects any creation, deletion,
/// move, or modification, regardless of what the command claimed it did.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, (u64, std::time::SystemTime)> {
    let mut out = BTreeMap::new();
    fn walk(dir: &Path, out: &mut BTreeMap<PathBuf, (u64, std::time::SystemTime)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            let Ok(m) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            out.insert(
                p.clone(),
                (m.len(), m.modified().unwrap_or(std::time::UNIX_EPOCH)),
            );
            if m.is_dir() && !m.is_symlink() {
                walk(&p, out);
            }
        }
    }
    walk(root, &mut out);
    out
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

// ---------------------------------------------------------------------------
// The two properties that must never be lost
// ---------------------------------------------------------------------------

#[test]
fn dry_run_mutates_absolutely_nothing() {
    // Verified by filesystem snapshot, not by reading the output. A command
    // that printed "nothing was deleted" while deleting something would pass an
    // output check and fail this one.
    let sb = Sandbox::new();
    let cache = sb.seed_cargo_cache(64 * 1024);

    let before = snapshot(sb.dir.path());
    let out = sb.run(&["clean", "--dry-run"]);
    let after = snapshot(sb.dir.path());

    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    assert!(cache.exists(), "the source was moved by a dry run");
    assert_eq!(
        before,
        after,
        "--dry-run modified the filesystem:\n  before: {} entries\n  after:  {} entries",
        before.len(),
        after.len()
    );
    assert!(
        stdout(&out).contains("nothing was moved"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn declining_the_prompt_mutates_nothing() {
    let sb = Sandbox::new();
    let cache = sb.seed_cargo_cache(64 * 1024);

    let before = snapshot(sb.dir.path());
    let out = sb.run_with_input(&["clean"], "n\n");
    let after = snapshot(sb.dir.path());

    assert_eq!(out.status.code(), Some(0), "declining must not be an error");
    assert!(cache.exists());
    assert_eq!(before, after, "declining the prompt still changed the disk");
    assert!(stdout(&out).contains("Aborted"), "{}", stdout(&out));
}

#[test]
fn an_unreadable_stdin_is_treated_as_declining() {
    // A `clean` in a pipeline with no terminal must not proceed on the grounds
    // that nobody said no.
    let sb = Sandbox::new();
    let cache = sb.seed_cargo_cache(64 * 1024);

    let out = sb.run_with_input(&["clean"], "");
    assert_eq!(out.status.code(), Some(0));
    assert!(cache.exists(), "proceeded without an affirmative answer");
}

// ---------------------------------------------------------------------------
// The happy path, and the undo
// ---------------------------------------------------------------------------

#[test]
fn clean_stages_and_always_prints_the_undo_command() {
    // A reversibility guarantee the user cannot find is not a guarantee.
    let sb = Sandbox::new();
    let cache = sb.seed_cargo_cache(64 * 1024);

    let out = sb.run(&["clean", "--yes"]);
    let text = stdout(&out);

    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(!cache.exists(), "the source was not staged: {text}");
    assert!(text.contains("Quarantined"), "{text}");
    assert!(text.contains("sift restore "), "no undo command:\n{text}");
    assert!(
        text.contains("Nothing has been permanently deleted yet"),
        "{text}"
    );
}

#[test]
fn the_printed_undo_command_actually_works() {
    // The undo instruction must be correct, not merely present.
    let sb = Sandbox::new();
    let cache = sb.seed_cargo_cache(64 * 1024);

    let clean = sb.run(&["clean", "--yes"]);
    let text = stdout(&clean);
    assert!(!cache.exists());

    let run_id = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("Undo:    sift restore "))
        .expect("no undo line in output")
        .trim()
        .to_string();

    let restore = sb.run(&["restore", &run_id]);
    assert_eq!(restore.status.code(), Some(0), "{}", stdout(&restore));
    assert!(
        cache.join("crate-1.0.0.crate").exists(),
        "the undo command did not restore the content"
    );
}

#[test]
fn clean_records_a_history_entry_with_the_clean_command() {
    let sb = Sandbox::new();
    sb.seed_cargo_cache(64 * 1024);
    sb.run(&["clean", "--yes"]);

    let history = sb.dir.path().join("state/sift/history.jsonl");
    let text = std::fs::read_to_string(&history).unwrap();
    assert!(text.contains(r#""command":"clean""#), "{text}");
}

#[test]
fn clean_json_reports_the_run_id_and_restore_command() {
    let sb = Sandbox::new();
    sb.seed_cargo_cache(64 * 1024);

    let out = sb.run(&["clean", "--yes", "--json"]);
    let v: serde_json::Value =
        serde_json::from_str(&stdout(&out)).expect("clean --json was not valid JSON");

    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["quarantined"], 1);
    assert!(v["restore_command"]
        .as_str()
        .unwrap()
        .starts_with("sift restore "));
}

// ---------------------------------------------------------------------------
// Guards
// ---------------------------------------------------------------------------

#[test]
fn the_circuit_breaker_aborts_clean_before_staging_anything() {
    // FR-16 through the real command: exit 4, and the source untouched.
    let sb = Sandbox::new();
    let cache = sb.seed_cargo_cache(256 * 1024);
    std::fs::write(
        sb.dir.path().join("config/sift/config.toml"),
        "[general]\nmax_bytes_per_run = \"1KB\"\n",
    )
    .ok();
    std::fs::create_dir_all(sb.dir.path().join("config/sift")).unwrap();
    std::fs::write(
        sb.dir.path().join("config/sift/config.toml"),
        "[general]\nmax_bytes_per_run = \"1KB\"\n",
    )
    .unwrap();

    let before = snapshot(sb.dir.path());
    let out = sb.run(&["clean", "--yes"]);
    let after = snapshot(sb.dir.path());

    assert_eq!(out.status.code(), Some(4), "expected exit 4");
    assert!(
        cache.exists(),
        "the breaker tripped but something still moved"
    );
    assert_eq!(before, after, "the breaker tripped but the disk changed");

    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("NOTHING HAS BEEN ACTIONED"), "{err}");
}

#[test]
fn clean_with_nothing_eligible_is_a_clean_no_op() {
    let sb = Sandbox::new();
    let before = snapshot(sb.dir.path());
    let out = sb.run(&["clean", "--yes"]);
    let after = snapshot(sb.dir.path());

    assert_eq!(out.status.code(), Some(0));
    assert!(
        stdout(&out).contains("nothing to clean"),
        "{}",
        stdout(&out)
    );
    assert_eq!(before, after);
}

#[test]
fn only_restricts_clean_to_the_named_scanners() {
    let sb = Sandbox::new();
    let cache = sb.seed_cargo_cache(64 * 1024);

    // A glob matching nothing that has candidates.
    let out = sb.run(&["clean", "--yes", "--only", "xcode-*"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(cache.exists(), "--only did not restrict the scanner set");
}

#[test]
fn scan_remains_read_only_after_clean_exists() {
    // Principle 2. Adding a deletion command must not have given `scan` a path
    // to deletion.
    let sb = Sandbox::new();
    let cache = sb.seed_cargo_cache(64 * 1024);

    let before = snapshot(sb.dir.path());
    let out = sb.run(&["scan"]);
    let after = snapshot(sb.dir.path());

    assert_eq!(out.status.code(), Some(0));
    assert!(cache.exists());

    // `scan` appends a history record, which is the only permitted mutation.
    let changed: Vec<_> = after
        .keys()
        .filter(|k| !before.contains_key(*k))
        .filter(|k| !k.to_string_lossy().contains("state/sift"))
        .collect();
    assert!(
        changed.is_empty(),
        "scan touched more than history: {changed:?}"
    );
}
