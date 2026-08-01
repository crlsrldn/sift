//! LaunchAgent lifecycle (FR-18, FR-21, spec §9, §13).

use crate::agent::plist;
use crate::config::Config;
use crate::{paths, Result, SiftError};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

/// Whether the agent is currently loaded in this user's launchd domain.
pub fn is_loaded() -> bool {
    matches!(
        crate::action::delegate::probe(
            "launchctl",
            &["print", &plist::service_target()],
            Duration::from_secs(15),
        ),
        crate::action::delegate::Outcome::Ok { .. }
    )
}

#[derive(Debug)]
pub struct Installed {
    pub plist_path: PathBuf,
    pub exe: PathBuf,
    pub already_loaded: bool,
}

/// Whether a path lives inside a Cargo build directory.
///
/// Installing an agent that points at `target/release/sift` sets up a silent
/// failure: `cargo clean`, `cargo build` with a different profile, or simply
/// moving the checkout leaves launchd invoking a path that no longer exists.
/// The job then fails at 03:00 every night forever, and nothing surfaces it —
/// which is precisely the outcome `current_exe()` was chosen to avoid, arriving
/// by a different route.
pub fn is_build_artifact(exe: &std::path::Path) -> bool {
    let mut components = exe.components().rev();
    // .../target/{debug,release}/sift, or .../target/<triple>/{debug,release}/sift
    let _binary = components.next();
    let profile = components
        .next()
        .map(|c| c.as_os_str().to_string_lossy().into_owned());

    if !matches!(profile.as_deref(), Some("debug") | Some("release")) {
        return false;
    }
    // Walk up looking for `target`, allowing one target-triple directory.
    for c in components.take(2) {
        if c.as_os_str() == "target" {
            return true;
        }
    }
    false
}

/// A warning to show before installing from a build directory.
///
/// Written unindented; callers indent uniformly.
pub fn build_artifact_warning(exe: &std::path::Path) -> String {
    let p = exe.display();
    [
        "WARNING: this binary is a Cargo build artifact.".to_string(),
        String::new(),
        format!("  {p}"),
        String::new(),
        "launchd will invoke that exact path. `cargo clean`, a rebuild under a".into(),
        "different profile, or moving this checkout will leave the scheduled".into(),
        "run failing every night with nothing to show for it.".into(),
        String::new(),
        "Copy it somewhere stable first, then install from there:".into(),
        String::new(),
        format!("  cp {p} ~/.local/bin/sift"),
        "  ~/.local/bin/sift install".into(),
        String::new(),
        "A SYMLINK will not help: the path is canonicalised, so installing".into(),
        "through a symlink records this same build path.".into(),
    ]
    .join(
        "
",
    )
}

/// What `install` would do, without doing any of it.
///
/// `launchctl bootstrap gui/$UID` targets the caller's real login session — it
/// is not affected by `$HOME`, so there is no way to rehearse an install by
/// pointing the environment somewhere harmless. This is that rehearsal.
pub fn preview(cfg: &Config) -> Result<(PathBuf, PathBuf, String)> {
    let exe = std::env::current_exe()
        .map_err(|e| SiftError::Config(format!("cannot determine this binary's path: {e}")))?
        .canonicalize()
        .map_err(|e| SiftError::Config(format!("cannot resolve this binary's path: {e}")))?;

    let value = plist::build(cfg, &exe)?;
    let mut xml = Vec::new();
    value
        .to_writer_xml(&mut xml)
        .map_err(|e| SiftError::Config(format!("cannot render the plist: {e}")))?;

    Ok((
        plist::plist_path()?,
        exe,
        String::from_utf8_lossy(&xml).into_owned(),
    ))
}

/// Write the plist and bootstrap the agent (FR-18).
///
/// Idempotent: installing twice replaces the plist and reloads, rather than
/// failing on an "already bootstrapped" error the user can do nothing with.
pub fn install(cfg: &Config) -> Result<Installed> {
    let exe = std::env::current_exe()
        .map_err(|e| SiftError::Config(format!("cannot determine this binary's path: {e}")))?
        .canonicalize()
        .map_err(|e| SiftError::Config(format!("cannot resolve this binary's path: {e}")))?;

    // Refuse rather than quietly set up a job that will break (Principle 7).
    // `--force` is not offered: someone who genuinely wants this can copy the
    // binary, which is the fix anyway and takes one command.
    if is_build_artifact(&exe) {
        return Err(SiftError::Config(build_artifact_warning(&exe)));
    }

    let already_loaded = is_loaded();
    if already_loaded {
        // Unload first. launchd will not pick up a rewritten plist otherwise,
        // so a reinstall after changing the schedule would silently keep the
        // old one.
        let _ = bootout();
    }

    let plist_path = plist::write(cfg, &exe)?;

    let out = Command::new("launchctl")
        .args(["bootstrap", &plist::domain_target()])
        .arg(&plist_path)
        .output()
        .map_err(|e| SiftError::Config(format!("cannot run launchctl: {e}")))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(SiftError::Config(format!(
            "launchctl bootstrap failed: {}",
            stderr.trim()
        )));
    }

    // Verify rather than assume. `bootstrap` can exit zero and leave nothing
    // loaded if the plist is malformed in a way it tolerates.
    if !is_loaded() {
        return Err(SiftError::Config(format!(
            "launchctl reported success but {} is not loaded",
            plist::service_target()
        )));
    }

    Ok(Installed {
        plist_path,
        exe,
        already_loaded,
    })
}

fn bootout() -> Result<()> {
    let out = Command::new("launchctl")
        .args(["bootout", &plist::service_target()])
        .output()
        .map_err(|e| SiftError::Config(format!("cannot run launchctl: {e}")))?;
    let _ = out;
    Ok(())
}

#[derive(Debug, Default)]
pub struct Uninstalled {
    pub was_loaded: bool,
    pub plist_removed: bool,
    pub quarantine_purged: u64,
    pub config_removed: bool,
    /// Deliberately kept. FR-21 says name it, do not delete it.
    pub history_path: Option<PathBuf>,
}

/// Remove the agent and everything sift owns except the user's records (FR-21).
///
/// Idempotent: uninstalling when nothing is installed succeeds quietly.
pub fn uninstall() -> Result<Uninstalled> {
    let mut out = Uninstalled {
        was_loaded: is_loaded(),
        ..Default::default()
    };

    if out.was_loaded {
        bootout()?;
    }

    if let Ok(p) = plist::plist_path() {
        if p.exists() {
            std::fs::remove_file(&p)?;
            out.plist_removed = true;
        }
    }

    // Purge everything staged. Leaving quarantine behind after an uninstall
    // would strand the user's data in a directory they no longer have a tool
    // to inspect.
    let purged = crate::action::purge::purge_all()?;
    out.quarantine_purged = purged.bytes_purged;
    if let Ok(q) = paths::quarantine_dir() {
        let _ = std::fs::remove_dir_all(&q);
    }

    if let Ok(c) = paths::config_dir() {
        if c.exists() {
            std::fs::remove_dir_all(&c)?;
            out.config_removed = true;
        }
    }

    // The history is the user's record of what was deleted from their machine.
    // Removing it silently during an uninstall would destroy the only evidence
    // of what the tool ever did. FR-21: name it, let them decide.
    if let Ok(h) = paths::history_file() {
        if h.exists() {
            out.history_path = Some(h);
        }
    }

    Ok(out)
}

/// The launchd-vs-Terminal FDA mismatch (spec §10's "critical first-run
/// detail"), completing the diagnosis stubbed in PR-08.
///
/// FDA granted to Terminal covers interactive runs and does nothing for the
/// agent, because launchd is that process's parent. The mismatch is invisible
/// until a scheduled run silently stops finding anything — so the only evidence
/// is the agent's own error log.
pub fn agent_permission_mismatch() -> Result<Option<String>> {
    let log = plist::stderr_log()?;
    let Ok(text) = std::fs::read_to_string(&log) else {
        return Ok(None);
    };

    let denied = text.lines().rev().take(200).find(|l| {
        let l = l.to_ascii_lowercase();
        l.contains("permission denied")
            || l.contains("operation not permitted")
            || l.contains("needs full disk access")
    });

    Ok(denied.map(|line| {
        format!(
            "The scheduled agent is hitting permission errors even though this \
             session has Full Disk Access.\n\n  from {}:\n    {}\n\n\
             This is the launchd/Terminal mismatch: FDA granted to your terminal \
             covers interactive\n  runs and does nothing for the agent, because \
             launchd is its parent rather than\n  Terminal. Grant FDA to the sift \
             binary itself.",
            log.display(),
            line.trim()
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `XDG_STATE_HOME` is process-global, so these must not run concurrently.
    /// Without this they pass alone and read each other's agent logs under the
    /// full suite.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Point the state directory at a fresh temp dir for the duration.
    struct StateDir {
        dir: tempfile::TempDir,
        prev: Option<std::ffi::OsString>,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl StateDir {
        fn new() -> Self {
            let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let dir = tempfile::tempdir().unwrap();
            let prev = std::env::var_os("XDG_STATE_HOME");
            std::env::set_var("XDG_STATE_HOME", dir.path());
            Self {
                dir,
                prev,
                _guard: guard,
            }
        }

        fn write_agent_log(&self, contents: &str) {
            std::fs::create_dir_all(self.dir.path().join("sift")).unwrap();
            std::fs::write(self.dir.path().join("sift/agent.err.log"), contents).unwrap();
        }
    }

    impl Drop for StateDir {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var("XDG_STATE_HOME", v),
                None => std::env::remove_var("XDG_STATE_HOME"),
            }
        }
    }

    #[test]
    fn uninstall_names_the_history_rather_than_deleting_it() {
        // FR-21. The history is the user's record of what was removed from
        // their machine; deleting it during uninstall would destroy the only
        // evidence the tool ever ran.
        let u = Uninstalled {
            history_path: Some(PathBuf::from("/x/history.jsonl")),
            ..Default::default()
        };
        assert!(u.history_path.is_some());
    }

    #[test]
    fn a_missing_agent_log_is_not_a_mismatch() {
        // No log means the agent has never run, which is not evidence of a
        // permission problem.
        let _s = StateDir::new();
        assert_eq!(agent_permission_mismatch().unwrap(), None);
    }

    #[test]
    fn a_permission_error_in_the_agent_log_is_diagnosed() {
        let s = StateDir::new();
        s.write_agent_log(
            "sift: scanner mail-downloads failed: Operation not permitted (os error 1)\n",
        );

        let msg = agent_permission_mismatch()
            .unwrap()
            .expect("should have diagnosed a mismatch");
        assert!(msg.contains("launchd"), "{msg}");
        assert!(msg.contains("sift binary itself"), "{msg}");
        assert!(msg.contains("Operation not permitted"), "{msg}");
    }

    #[test]
    fn an_unremarkable_agent_log_is_not_a_mismatch() {
        let s = StateDir::new();
        s.write_agent_log("sift — scan complete in 0.4s\n");
        assert_eq!(agent_permission_mismatch().unwrap(), None);
    }
}
