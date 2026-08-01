//! LaunchAgent plist and scheduling gates (FR-18, FR-19, FR-20, spec §9).

use sift::agent::plist;
use sift::config::Config;
use std::path::Path;
use std::process::Command;

#[test]
fn the_generated_plist_passes_apples_own_parser() {
    // `plutil -lint` is the authority. A plist that Rust can serialise but
    // launchd rejects is a job that never runs and never says why.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("com.cindral.sift.plist");

    let v = plist::build(&Config::default(), Path::new("/opt/homebrew/bin/sift")).unwrap();
    v.to_file_xml(&path).unwrap();

    let out = Command::new("plutil")
        .arg("-lint")
        .arg(&path)
        .output()
        .expect("plutil should exist on macOS");

    assert!(
        out.status.success(),
        "plutil rejected the plist: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn plutil_can_read_back_every_key_we_wrote() {
    // Round-trips through Apple's parser rather than our own, so a key that
    // serialises to something launchd misreads is caught.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.plist");
    plist::build(&Config::default(), Path::new("/opt/homebrew/bin/sift"))
        .unwrap()
        .to_file_xml(&path)
        .unwrap();

    let read = |key: &str| -> String {
        let out = Command::new("plutil")
            .args(["-extract", key, "raw", "-o", "-"])
            .arg(&path)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };

    assert_eq!(read("Label"), "com.cindral.sift");
    assert_eq!(read("RunAtLoad"), "false");
    assert_eq!(read("ProcessType"), "Background");
    assert_eq!(read("LowPriorityIO"), "true");
    assert_eq!(read("Nice"), "10");
    assert_eq!(read("ThrottleInterval"), "3600");
    assert_eq!(read("StartCalendarInterval.Hour"), "3");
    assert_eq!(read("ProgramArguments.0"), "/opt/homebrew/bin/sift");
    assert_eq!(read("ProgramArguments.3"), "--scheduled");
    assert!(read("EnvironmentVariables.PATH").contains("/opt/homebrew/bin"));
}

#[test]
fn the_label_and_service_target_agree() {
    // `launchctl bootout gui/$UID/<label>` must name the same label the plist
    // declares, or uninstall silently does nothing.
    assert!(plist::service_target().ends_with(plist::LABEL));
    assert!(plist::plist_path()
        .unwrap()
        .to_string_lossy()
        .contains(plist::LABEL));
}

#[test]
fn the_plist_lands_in_the_per_user_launchagents_directory() {
    // A user agent, never /Library/LaunchDaemons (Principle 8: no root).
    let p = plist::plist_path().unwrap();
    let s = p.to_string_lossy();
    assert!(s.contains("Library/LaunchAgents"), "{s}");
    assert!(!s.starts_with("/Library/"), "{s}");
    assert!(!s.contains("LaunchDaemons"), "{s}");
}

// ---------------------------------------------------------------------------
// install --dry-run
// ---------------------------------------------------------------------------

fn bin() -> std::path::PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("sift")
}

/// Whether the agent is loaded in this user's real launchd session.
fn agent_loaded() -> bool {
    let uid = unsafe { libc::getuid() };
    Command::new("launchctl")
        .args(["print", &format!("gui/{uid}/{}", plist::LABEL)])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn install_dry_run_writes_nothing_and_loads_nothing() {
    // `launchctl bootstrap gui/$UID` targets the caller's real login session
    // and is unaffected by $HOME, so there is no way to rehearse an install by
    // pointing the environment somewhere harmless. --dry-run is that rehearsal,
    // and this test is what keeps it honest.
    //
    // Skipped if the agent is already installed for real, because then the
    // "still not loaded" assertion would be meaningless.
    if agent_loaded() {
        eprintln!("skipping: the agent is genuinely installed on this machine");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(bin())
        .args(["install", "--dry-run"])
        .env("HOME", dir.path())
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);

    assert!(
        text.contains("Nothing has been written or loaded"),
        "{text}"
    );
    assert!(text.contains("would write"), "{text}");
    assert!(text.contains("launchctl bootstrap"), "{text}");
    // The consequence, stated before the user commits to it.
    assert!(text.contains("persist across reboots"), "{text}");

    assert!(
        !dir.path()
            .join("Library/LaunchAgents/com.cindral.sift.plist")
            .exists(),
        "--dry-run wrote the plist"
    );
    assert!(!agent_loaded(), "--dry-run loaded a real LaunchAgent");
}

#[test]
fn install_dry_run_json_carries_the_whole_plist() {
    if agent_loaded() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(bin())
        .args(["install", "--dry-run", "--json"])
        .env("HOME", dir.path())
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .output()
        .unwrap();

    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("not valid JSON");

    assert_eq!(v["dry_run"], true);
    assert!(v["would_run"].as_str().unwrap().contains("bootstrap"));
    assert!(v["plist"].as_str().unwrap().contains("com.cindral.sift"));
    assert!(!agent_loaded());
}

#[test]
fn uninstall_is_idempotent_when_nothing_is_installed() {
    if agent_loaded() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(bin())
        .arg("uninstall")
        .env("HOME", dir.path())
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("nothing was installed"));
}

// ---------------------------------------------------------------------------
// Refusing to install a build artifact
// ---------------------------------------------------------------------------

#[test]
fn build_artifact_paths_are_recognised() {
    use sift::agent::install::is_build_artifact;
    use std::path::Path;

    for p in [
        "/Users/x/proj/target/release/sift",
        "/Users/x/proj/target/debug/sift",
        "/Users/x/proj/target/aarch64-apple-darwin/release/sift",
    ] {
        assert!(is_build_artifact(Path::new(p)), "{p} should be an artifact");
    }
}

#[test]
fn installed_paths_are_not_mistaken_for_artifacts() {
    // A false positive here would make sift refuse to install for real users.
    use sift::agent::install::is_build_artifact;
    use std::path::Path;

    for p in [
        "/opt/homebrew/bin/sift",
        "/usr/local/bin/sift",
        "/Users/x/.local/bin/sift",
        "/Users/x/target-practice/sift",
        "/Users/x/release/sift",
    ] {
        assert!(!is_build_artifact(Path::new(p)), "{p} is not an artifact");
    }
}

#[test]
fn installing_from_a_build_directory_is_refused_with_the_fix() {
    // Principle 7: refuse rather than quietly set up a job that will break the
    // next time someone runs `cargo clean`.
    if agent_loaded() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(bin())
        .arg("install")
        .env("HOME", dir.path())
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .output()
        .unwrap();

    // The test binary lives under target/, so this is the artifact path.
    assert_eq!(out.status.code(), Some(2), "expected a config error");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("Cargo build artifact"), "{err}");
    // Refusing without saying what to do instead would be useless.
    assert!(err.contains("cp "), "the fix must be given: {err}");
    assert!(err.contains("SYMLINK will not help"), "{err}");

    assert!(!agent_loaded(), "a refused install still loaded an agent");
}

#[test]
fn a_binary_outside_a_build_directory_is_accepted() {
    // The other half: the refusal must not block a legitimate install.
    if agent_loaded() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let stable = dir.path().join("bin");
    std::fs::create_dir_all(&stable).unwrap();
    let copied = stable.join("sift");
    std::fs::copy(bin(), &copied).unwrap();

    let out = Command::new(&copied)
        .args(["install", "--dry-run"])
        .env("HOME", dir.path())
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !text.contains("Cargo build artifact"),
        "a copy outside target/ was wrongly flagged:\n{text}"
    );
    assert!(!agent_loaded());
}
