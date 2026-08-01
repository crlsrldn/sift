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
