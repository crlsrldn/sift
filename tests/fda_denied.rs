//! The Full Disk Access denied path (FR-26, FR-27, spec §10).
//!
//! # What this reproduces, and what it does not
//!
//! `Capabilities::probe` decides FDA by `read_dir` on the TCC directory and
//! maps `PermissionDenied` to `FdaStatus::Denied`. These tests produce that
//! errno genuinely, by making the directory mode 000 — the same `EACCES` a real
//! TCC denial delivers to the same call.
//!
//! What they do **not** prove is that macOS TCC actually denies that path with
//! that errno on every OS version. Only revoking Full Disk Access for real
//! proves that, and it cannot be done from a test. Until someone does it by
//! hand, treat "TCC denies read_dir with EACCES" as the assumption this rests
//! on — everything downstream of it is covered here.
//!
//! This exists because the denied path *is* the first-run experience for every
//! user who installs sift, and it was previously exercised only by pointing
//! `$HOME` at an empty directory — which produces `Unknown`, not `Denied`, and
//! therefore never reached the remediation rendering at all.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

fn bin() -> PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("sift")
}

/// A home whose TCC directory cannot be read.
struct DeniedHome {
    dir: tempfile::TempDir,
}

impl DeniedHome {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let tcc = dir
            .path()
            .join("home/Library/Application Support/com.apple.TCC");
        fs::create_dir_all(&tcc).unwrap();
        fs::create_dir_all(dir.path().join("config/sift")).unwrap();
        fs::set_permissions(&tcc, fs::Permissions::from_mode(0o000)).unwrap();

        // Assert the premise. If the directory turned out readable — running as
        // root, say — every assertion below would pass while proving nothing.
        assert!(
            fs::read_dir(&tcc).is_err(),
            "the fixture is readable, so it does not reproduce a denial"
        );

        Self { dir }
    }

    fn home(&self) -> PathBuf {
        self.dir.path().join("home")
    }

    fn write_config(&self, toml: &str) {
        fs::write(self.dir.path().join("config/sift/config.toml"), toml).unwrap();
    }

    fn doctor(&self) -> String {
        let out = Command::new(bin())
            .arg("doctor")
            .env("HOME", self.home())
            .env("XDG_CONFIG_HOME", self.dir.path().join("config"))
            .env("XDG_STATE_HOME", self.dir.path().join("state"))
            .output()
            .expect("failed to run sift doctor");
        assert_eq!(
            out.status.code(),
            Some(0),
            "doctor must exit 0 even when capabilities are missing"
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

impl Drop for DeniedHome {
    fn drop(&mut self) {
        // Restore the mode so the TempDir can clean itself up.
        let tcc = self
            .dir
            .path()
            .join("home/Library/Application Support/com.apple.TCC");
        let _ = fs::set_permissions(&tcc, fs::Permissions::from_mode(0o755));
    }
}

#[test]
fn a_denied_probe_is_reported_as_denied_not_unknown() {
    // The distinction matters: `Unknown` means "could not determine" and gives
    // no remediation, `Denied` means "go grant it" and does.
    let h = DeniedHome::new();
    let out = h.doctor();

    assert!(out.contains("DENIED"), "{out}");
    assert!(
        !out.contains("could not determine"),
        "a genuine denial was reported as indeterminate:\n{out}"
    );
}

#[test]
fn every_fda_requiring_scanner_that_is_enabled_is_reported_blocked() {
    // spec §10's permissions matrix: snapshots, trash, ios-backups, and
    // mail-downloads all need FDA.
    let h = DeniedHome::new();
    h.write_config(
        "[general]\nmax_risk = \"destructive\"\n\n\
         [scanners.snapshots]\nenabled = true\n\n\
         [scanners.trash]\nenabled = true\n\n\
         [scanners.ios-backups]\nenabled = true\n",
    );
    let out = h.doctor();

    for id in ["snapshots", "trash", "ios-backups", "mail-downloads"] {
        let line = out
            .lines()
            .find(|l| l.contains(id) && l.trim_start().starts_with("BLOCKED"))
            .unwrap_or_else(|| panic!("`{id}` was not reported as BLOCKED:\n{out}"));
        assert!(line.contains("Full Disk Access"), "{line}");
    }

    // Asserted on the FDA line, not the total blocked count. The total also
    // includes scanners blocked by a MISSING TOOL, which varies by host — the
    // CI runner has no Docker, so it reports 5 where this machine reports 4.
    // A count assertion would be testing the host, not the code.
    let fda_line = out
        .lines()
        .find(|l| l.contains("Full Disk Access — blocks:"))
        .unwrap_or_else(|| panic!("no grouped FDA remediation line:\n{out}"));
    for id in ["snapshots", "trash", "ios-backups", "mail-downloads"] {
        assert!(fda_line.contains(id), "`{id}` missing from: {fda_line}");
    }
}

#[test]
fn a_disabled_scanner_is_reported_disabled_rather_than_blocked() {
    // Precedence matters. A scanner the user turned off does not need FDA, and
    // telling them to grant it would be noise that buries the real problems.
    let h = DeniedHome::new();
    let out = h.doctor();

    for id in ["snapshots", "trash", "ios-backups"] {
        let line = out
            .lines()
            .find(|l| l.contains(id) && !l.contains("blocks:"))
            .unwrap_or_else(|| panic!("`{id}` missing from output:\n{out}"));
        assert!(
            line.contains("disabled"),
            "an off scanner was reported as blocked: {line}"
        );
    }

    // Only mail-downloads is on by default and needs FDA. Asserted on the FDA
    // line rather than the total, which also counts missing-tool blocks and so
    // varies by host.
    let fda_line = out
        .lines()
        .find(|l| l.contains("Full Disk Access — blocks:"))
        .unwrap_or_else(|| panic!("no grouped FDA remediation line:\n{out}"));
    assert!(fda_line.contains("mail-downloads"), "{fda_line}");
    for id in ["snapshots", "trash", "ios-backups"] {
        assert!(
            !fda_line.contains(id),
            "a disabled scanner appeared in the FDA remediation: {fda_line}"
        );
    }
}

#[test]
fn the_remediation_names_the_binary_and_warns_about_terminal() {
    // FR-26 and spec §10's "critical first-run detail". Granting FDA to
    // Terminal covers interactive runs and silently does nothing for the
    // scheduled agent — a failure invisible until runs stop finding anything.
    let h = DeniedHome::new();
    let out = h.doctor();

    assert!(out.contains("System Settings"), "{out}");
    assert!(out.contains("Privacy & Security"), "{out}");
    assert!(out.contains("NOT to Terminal"), "{out}");
    assert!(out.contains("launchd"), "{out}");

    // The exact path, not a placeholder — this is the string the user pastes.
    let path = bin().display().to_string();
    assert!(
        out.contains(&path),
        "the remediation must name the actual binary path `{path}`:\n{out}"
    );
}

#[test]
fn the_denied_state_does_not_stop_the_other_scanners_working() {
    // FR-27: a missing capability skips its scanners, it does not disable the
    // tool. A user without FDA should still reclaim everything else.
    let h = DeniedHome::new();
    let out = h.doctor();

    let ready = out
        .lines()
        .filter(|l| l.trim_start().starts_with("ready"))
        .count();
    assert!(
        ready >= 8,
        "FDA denial should not have blocked unrelated scanners; only {ready} ready:\n{out}"
    );
}

#[test]
fn doctor_json_reports_the_denial_machine_readably() {
    let h = DeniedHome::new();
    let out = Command::new(bin())
        .args(["doctor", "--json"])
        .env("HOME", h.home())
        .env("XDG_CONFIG_HOME", h.dir.path().join("config"))
        .env("XDG_STATE_HOME", h.dir.path().join("state"))
        .output()
        .unwrap();

    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("not valid JSON");

    assert_eq!(v["full_disk_access"], "denied");
    assert!(v["blocked_count"].as_u64().unwrap() >= 1);
}

/// The granted-state caveat, checked only when this machine actually has FDA.
#[test]
fn granted_fda_warns_that_the_scheduled_agent_may_not_have_it() {
    let out = Command::new(bin())
        .arg("doctor")
        .env("XDG_CONFIG_HOME", "/nonexistent-sift-fda-test")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);

    // Match the status line specifically. A bare `contains("granted")` also
    // matches the remediation prose — "FDA granted to Terminal covers
    // interactive runs" — which appears in the DENIED state, so the loose
    // version fired on exactly the case it was meant to skip.
    let granted = text
        .lines()
        .any(|l| l.trim_start().starts_with("full disk") && l.contains("granted"));

    if granted {
        assert!(text.contains("current process"), "{text}");
        assert!(text.contains("scheduled agent"), "{text}");
    }
}

/// Sanity: the fixture technique itself works.
#[test]
fn the_mode_000_technique_actually_denies() {
    let dir = tempfile::tempdir().unwrap();
    let locked = dir.path().join("locked");
    fs::create_dir(&locked).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();

    let err = fs::read_dir(&locked).unwrap_err();
    let kind = err.kind();
    let _ = fs::set_permissions(&locked, fs::Permissions::from_mode(0o755));

    assert_eq!(
        kind,
        std::io::ErrorKind::PermissionDenied,
        "mode 000 did not produce PermissionDenied, so these tests reproduce nothing"
    );
}
