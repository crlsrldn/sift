//! LaunchAgent property list generation (FR-18, FR-19, spec §9).

use crate::config::Config;
use crate::{paths, Result, SiftError};
use plist::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// launchd label. Also the plist filename and the `launchctl` service target.
pub const LABEL: &str = "com.cindral.sift";

/// Minimum seconds between runs, however often launchd is provoked.
///
/// Guards against a `RunAtLoad` plus rapid login/logout cycle turning into a
/// disk scan every few seconds.
const THROTTLE_SECONDS: i64 = 3600;

/// `Nice` value (FR-19). Positive is lower priority.
const NICE: i64 = 10;

pub fn plist_path() -> Result<PathBuf> {
    let home = paths::home()?;
    Ok(home
        .join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist")))
}

pub fn stdout_log() -> Result<PathBuf> {
    Ok(paths::state_dir()?.join("agent.out.log"))
}

pub fn stderr_log() -> Result<PathBuf> {
    Ok(paths::state_dir()?.join("agent.err.log"))
}

/// Build the plist for this machine.
///
/// # Why `current_exe()` and not the spec's literal
///
/// Spec §9 hardcodes `/usr/local/bin/sift`. That is the Intel Homebrew prefix;
/// on Apple Silicon it is `/opt/homebrew/bin`, and during development it is
/// `target/release/sift`. A plist pointing at a path that does not exist
/// produces a launchd job that fails silently forever, which is precisely the
/// failure mode this tool is least able to afford. The running binary's own
/// path is the only value that is always right.
pub fn build(cfg: &Config, exe: &Path) -> Result<Value> {
    if !exe.is_absolute() {
        return Err(SiftError::Config(format!(
            "the LaunchAgent needs an absolute path to sift, got {}",
            exe.display()
        )));
    }

    let mut calendar = plist::Dictionary::new();
    calendar.insert(
        "Hour".into(),
        Value::Integer((cfg.schedule.hour as i64).into()),
    );
    calendar.insert(
        "Minute".into(),
        Value::Integer((cfg.schedule.minute as i64).into()),
    );

    let mut env = plist::Dictionary::new();
    // launchd provides a minimal environment. Without this, brew, docker, and
    // cargo are simply not found, and the scheduled run quietly reclaims
    // nothing while the interactive one works fine.
    env.insert(
        "PATH".into(),
        Value::String(crate::action::delegate::DELEGATE_PATH.into()),
    );

    let args: Vec<Value> = vec![
        Value::String(exe.display().to_string()),
        Value::String("clean".into()),
        Value::String("--yes".into()),
        Value::String("--scheduled".into()),
    ];

    let mut d = plist::Dictionary::new();
    d.insert("Label".into(), Value::String(LABEL.into()));
    d.insert("ProgramArguments".into(), Value::Array(args));
    d.insert("StartCalendarInterval".into(), Value::Dictionary(calendar));
    // A login-time disk operation is exactly the wrong time for one (spec §9).
    d.insert("RunAtLoad".into(), Value::Boolean(false));
    d.insert(
        "ThrottleInterval".into(),
        Value::Integer(THROTTLE_SECONDS.into()),
    );
    // FR-19: a scheduled run must never be perceptible.
    d.insert("ProcessType".into(), Value::String("Background".into()));
    d.insert("LowPriorityIO".into(), Value::Boolean(true));
    d.insert("Nice".into(), Value::Integer(NICE.into()));
    d.insert(
        "StandardOutPath".into(),
        Value::String(stdout_log()?.display().to_string()),
    );
    d.insert(
        "StandardErrorPath".into(),
        Value::String(stderr_log()?.display().to_string()),
    );
    d.insert("EnvironmentVariables".into(), Value::Dictionary(env));

    Ok(Value::Dictionary(d))
}

/// Write the plist, creating `~/Library/LaunchAgents` if needed.
pub fn write(cfg: &Config, exe: &Path) -> Result<PathBuf> {
    let path = plist_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // The log directory must exist before launchd starts the job, or it refuses
    // to open StandardOutPath and the job never runs.
    std::fs::create_dir_all(paths::state_dir()?)?;

    let value = build(cfg, exe)?;
    value
        .to_file_xml(&path)
        .map_err(|e| SiftError::Config(format!("cannot write {}: {e}", path.display())))?;
    Ok(path)
}

/// The `launchctl` service target for this user session.
pub fn service_target() -> String {
    // SAFETY: getuid cannot fail and has no preconditions.
    let uid = unsafe { libc::getuid() };
    format!("gui/{uid}/{LABEL}")
}

pub fn domain_target() -> String {
    let uid = unsafe { libc::getuid() };
    format!("gui/{uid}")
}

/// Flatten a plist into `key -> string` for assertions and diffing.
pub fn as_map(v: &Value) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(d) = v.as_dictionary() {
        for (k, val) in d {
            out.insert(k.clone(), format!("{val:?}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config::default()
    }

    #[test]
    fn the_plist_carries_every_key_spec_9_names() {
        let v = build(&cfg(), Path::new("/opt/homebrew/bin/sift")).unwrap();
        let d = v.as_dictionary().unwrap();

        for key in [
            "Label",
            "ProgramArguments",
            "StartCalendarInterval",
            "RunAtLoad",
            "ThrottleInterval",
            "ProcessType",
            "LowPriorityIO",
            "Nice",
            "StandardOutPath",
            "StandardErrorPath",
            "EnvironmentVariables",
        ] {
            assert!(d.contains_key(key), "plist is missing `{key}`");
        }
    }

    #[test]
    fn the_program_path_comes_from_the_running_binary_not_a_literal() {
        // Spec §9 hardcodes /usr/local/bin/sift, which is the Intel Homebrew
        // prefix. A plist pointing at a nonexistent path is a launchd job that
        // fails silently forever.
        let v = build(&cfg(), Path::new("/opt/homebrew/bin/sift")).unwrap();
        let args = v.as_dictionary().unwrap()["ProgramArguments"]
            .as_array()
            .unwrap();

        assert_eq!(args[0].as_string().unwrap(), "/opt/homebrew/bin/sift");
        assert_ne!(args[0].as_string().unwrap(), "/usr/local/bin/sift");
    }

    #[test]
    fn a_relative_program_path_is_refused() {
        // launchd resolves nothing; a relative path is a job that never runs.
        assert!(build(&cfg(), Path::new("target/release/sift")).is_err());
    }

    #[test]
    fn the_agent_runs_clean_scheduled_and_unattended() {
        let v = build(&cfg(), Path::new("/opt/homebrew/bin/sift")).unwrap();
        let args: Vec<&str> = v.as_dictionary().unwrap()["ProgramArguments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_string().unwrap())
            .collect();

        assert_eq!(&args[1..], &["clean", "--yes", "--scheduled"]);
    }

    #[test]
    fn run_at_load_is_false() {
        // spec §9: a login-time disk operation is exactly the wrong time.
        let v = build(&cfg(), Path::new("/opt/homebrew/bin/sift")).unwrap();
        assert!(!v.as_dictionary().unwrap()["RunAtLoad"]
            .as_boolean()
            .unwrap());
    }

    #[test]
    fn the_run_is_low_priority_so_it_is_never_perceptible() {
        // FR-19.
        let v = build(&cfg(), Path::new("/opt/homebrew/bin/sift")).unwrap();
        let d = v.as_dictionary().unwrap();

        assert_eq!(d["ProcessType"].as_string().unwrap(), "Background");
        assert!(d["LowPriorityIO"].as_boolean().unwrap());
        assert_eq!(d["Nice"].as_signed_integer().unwrap(), 10);
    }

    #[test]
    fn the_path_matches_what_delegated_commands_use() {
        // If these drift, a tool found interactively vanishes under launchd and
        // the agent silently reclaims nothing.
        let v = build(&cfg(), Path::new("/opt/homebrew/bin/sift")).unwrap();
        let env = v.as_dictionary().unwrap()["EnvironmentVariables"]
            .as_dictionary()
            .unwrap();
        let path = env["PATH"].as_string().unwrap();

        assert_eq!(path, crate::action::delegate::DELEGATE_PATH);
        assert!(path.contains("/opt/homebrew/bin"));
    }

    #[test]
    fn the_schedule_comes_from_config() {
        let c = Config::parse("[schedule]\nhour = 5\nminute = 30\n").unwrap();
        let v = build(&c, Path::new("/opt/homebrew/bin/sift")).unwrap();
        let cal = v.as_dictionary().unwrap()["StartCalendarInterval"]
            .as_dictionary()
            .unwrap();

        assert_eq!(cal["Hour"].as_signed_integer().unwrap(), 5);
        assert_eq!(cal["Minute"].as_signed_integer().unwrap(), 30);
    }

    #[test]
    fn the_service_target_is_a_gui_domain_for_this_uid() {
        // A user agent, never a system daemon (Principle 8: no root).
        let t = service_target();
        assert!(t.starts_with("gui/"), "{t}");
        assert!(t.ends_with(LABEL), "{t}");
        assert!(!t.contains("system/"), "{t}");
    }

    #[test]
    fn throttle_prevents_a_login_loop_becoming_a_scan_loop() {
        let v = build(&cfg(), Path::new("/opt/homebrew/bin/sift")).unwrap();
        assert_eq!(
            v.as_dictionary().unwrap()["ThrottleInterval"]
                .as_signed_integer()
                .unwrap(),
            3600
        );
    }
}
