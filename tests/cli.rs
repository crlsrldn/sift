//! CLI surface and dispatch (PRD §7, FR-23).
//!
//! These drive the real binary rather than the library, because exit codes and
//! stream separation are properties of the process, not of a function.

use std::path::PathBuf;
use std::process::{Command, Output};

fn bin() -> PathBuf {
    // Cargo puts integration-test binaries in target/<profile>/deps; the binary
    // under test is two levels up.
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("sift")
}

fn sift(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        // Isolate from the developer's real config so these tests are
        // deterministic on any machine.
        .env("XDG_CONFIG_HOME", "/nonexistent-sift-test-config")
        .env("XDG_STATE_HOME", "/nonexistent-sift-test-state")
        .env_remove("SIFT_CONFIG")
        .env_remove("SIFT_LOG")
        .output()
        .expect("failed to run sift")
}

fn code(o: &Output) -> i32 {
    o.status.code().expect("process terminated by signal")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

// ---------------------------------------------------------------------------
// Exit codes (spec §11)
// ---------------------------------------------------------------------------

#[test]
fn version_and_help_exit_zero() {
    assert_eq!(code(&sift(&["--version"])), 0);
    assert_eq!(code(&sift(&["--help"])), 0);
}

#[test]
fn usage_errors_exit_64_not_claps_default_2() {
    // clap exits 2 on parse failure by default, which collides with the spec's
    // "invalid configuration" code. Parse errors are re-coded to 64.
    assert_eq!(code(&sift(&["--bogus"])), 64);
    assert_eq!(code(&sift(&["nonsense"])), 64);
    assert_eq!(code(&sift(&["restore"])), 64); // missing required run-id
}

#[test]
fn invalid_config_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.toml");
    std::fs::write(&path, "[general]\nmax_risk_levl = \"safe\"\n").unwrap();

    let out = sift(&["config", "check", "--config", path.to_str().unwrap()]);
    assert_eq!(code(&out), 2);
    assert!(stderr(&out).contains("max_risk_levl"), "{}", stderr(&out));
}

#[test]
fn a_named_config_file_that_does_not_exist_is_an_error() {
    // Distinct from the default path being absent, which means "all defaults"
    // (FR-22). If the user named a file, silently substituting defaults would
    // be dishonest.
    let out = sift(&["config", "check", "--config", "/no/such/file.toml"]);
    assert_eq!(code(&out), 2);
}

#[test]
fn config_is_validated_even_for_unimplemented_commands() {
    // An invalid config should fail immediately, not later when whichever
    // command happens to read that key finally lands.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.toml");
    std::fs::write(&path, "garbage = true\n").unwrap();

    let out = sift(&["scan", "--config", path.to_str().unwrap()]);
    assert_eq!(code(&out), 2, "config error must win over not-implemented");
}

// ---------------------------------------------------------------------------
// Command surface (PRD §7)
// ---------------------------------------------------------------------------

#[test]
fn commands_not_yet_implemented_say_so_rather_than_exiting_zero() {
    // What must not happen is a command silently exiting 0 having done nothing:
    // indistinguishable from having run and found nothing.
    //
    // `doctor` is absent from this list because PR-08 implemented it. Each PR
    // that lands a command removes it here, so the list is a live inventory of
    // what remains rather than a stale copy of the plan.
    for cmd in [
        "scan",
        "clean",
        "purge",
        "restore",
        "report",
        "install",
        "uninstall",
    ] {
        let args: Vec<&str> = if cmd == "restore" {
            vec![cmd, "0192abc"]
        } else {
            vec![cmd]
        };
        let out = sift(&args);
        assert_ne!(code(&out), 0, "`{cmd}` exited 0 without being implemented");
        assert!(
            stderr(&out).contains("not implemented"),
            "`{cmd}` should say it is unimplemented, got: {}",
            stderr(&out)
        );
    }
}

#[test]
fn no_arguments_behaves_as_scan() {
    // Principle 2: dry-run is the default.
    let bare = sift(&[]);
    let scan = sift(&["scan"]);
    assert_eq!(code(&bare), code(&scan));
    assert_eq!(stderr(&bare), stderr(&scan));
}

#[test]
fn help_documents_exit_codes_and_the_default_safe_behaviour() {
    let out = sift(&["--help"]);
    let text = stdout(&out);
    assert!(text.contains("EXIT CODES"));
    assert!(text.contains("Nothing is deleted"));
}

// ---------------------------------------------------------------------------
// FR-23 — config check
// ---------------------------------------------------------------------------

#[test]
fn config_check_reports_defaults_when_no_file_exists() {
    let out = sift(&["config", "check"]);
    assert_eq!(code(&out), 0);
    let text = stdout(&out);
    assert!(text.contains("built-in defaults"), "{text}");
    assert!(text.contains("general.max_risk"), "{text}");
}

#[test]
fn config_check_marks_user_set_values_and_leaves_defaults_unmarked() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("c.toml");
    std::fs::write(&path, "[general]\nquarantine_ttl_days = 3\n").unwrap();

    let out = sift(&["config", "check", "--config", path.to_str().unwrap()]);
    assert_eq!(code(&out), 0);

    let text = stdout(&out);
    let ttl_line = text
        .lines()
        .find(|l| l.contains("quarantine_ttl_days"))
        .expect("ttl line missing");
    assert!(ttl_line.contains("[set in file]"), "{ttl_line}");

    let risk_line = text
        .lines()
        .find(|l| l.contains("general.max_risk"))
        .expect("max_risk line missing");
    assert!(!risk_line.contains("[set in file]"), "{risk_line}");
}

#[test]
fn config_check_surfaces_scanners_that_are_enabled_but_gated() {
    // A user who enabled a Destructive scanner without raising max_risk has a
    // config that looks armed and is not. Saying so beats letting them discover
    // it by the scanner doing nothing.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("c.toml");
    std::fs::write(&path, "[scanners.trash]\nenabled = true\n").unwrap();

    let out = sift(&["config", "check", "--config", path.to_str().unwrap()]);
    let text = stdout(&out);
    assert!(text.contains("enabled but inactive"), "{text}");
    assert!(text.contains("trash"), "{text}");
}

// ---------------------------------------------------------------------------
// FR-10 — --json stream discipline
// ---------------------------------------------------------------------------

#[test]
fn json_output_is_parseable_and_versioned() {
    let out = sift(&["config", "check", "--json"]);
    assert_eq!(code(&out), 0);

    let v: serde_json::Value =
        serde_json::from_str(&stdout(&out)).expect("stdout was not valid JSON");
    assert_eq!(v["schema_version"], 1);
    assert!(v["values"].as_array().unwrap().len() > 10);
}

#[test]
fn stdout_stays_pure_json_even_with_debug_logging() {
    // FR-10's promise is that `sift ... --json | jq` works. A stray log line on
    // stdout would break it, so logging must never touch stdout.
    let out = Command::new(bin())
        .args(["config", "check", "--json", "--verbose"])
        .env("SIFT_LOG", "debug")
        .env("XDG_CONFIG_HOME", "/nonexistent-sift-test-config")
        .output()
        .unwrap();

    serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(&out.stdout))
        .expect("stdout was polluted by log output");
}

// ---------------------------------------------------------------------------
// FR-26 / FR-27 — doctor
// ---------------------------------------------------------------------------

#[test]
fn doctor_runs_and_exits_zero() {
    // A machine missing an optional tool is not in an error state. doctor is a
    // diagnostic; a non-zero exit would make it useless in a health check that
    // only cares whether sift itself is broken.
    let out = sift(&["doctor"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let text = stdout(&out);
    for section in ["config", "volume", "full disk", "tools", "scanners"] {
        assert!(
            text.contains(section),
            "missing `{section}` section:\n{text}"
        );
    }
}

#[test]
fn doctor_reports_every_scanner() {
    let out = sift(&["doctor"]);
    let text = stdout(&out);
    for id in sift_lib_scanner_ids() {
        assert!(
            text.contains(id),
            "scanner `{id}` missing from doctor output"
        );
    }
}

fn sift_lib_scanner_ids() -> Vec<&'static str> {
    sift::config::defaults::scanner_ids()
}

#[test]
fn doctor_json_is_structurally_complete() {
    let out = sift(&["doctor", "--json"]);
    assert_eq!(code(&out), 0);

    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("not valid JSON");
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["scanners"].as_array().unwrap().len(), 17);
    assert!(v["volume"]["is_apfs"].is_boolean());
    assert!(v["full_disk_access"].is_string());
}

#[test]
fn doctor_names_the_binary_in_fda_instructions_when_something_is_blocked() {
    // FR-26's whole point: the remediation must name the sift binary, because
    // granting FDA to Terminal silently does nothing for the scheduled agent.
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(bin())
        .args(["doctor"])
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", "/nonexistent-sift-test-config")
        .output()
        .unwrap();

    let text = String::from_utf8_lossy(&out.stdout);
    if text.contains("blocked") {
        assert!(text.contains("Full Disk Access"), "{text}");
        assert!(text.contains("NOT to Terminal"), "{text}");
        assert!(text.contains("sift"), "{text}");
    }
}
