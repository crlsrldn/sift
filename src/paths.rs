//! Filesystem locations `sift` owns.
//!
//! # Correction C2
//!
//! The technical spec §2 lists `directories = "5"` as a dependency, but §8 and
//! §11 mandate `~/.config/sift` and `~/.local/state/sift`. Those are
//! incompatible: on macOS the `directories` crate resolves config to
//! `~/Library/Application Support`, which is the platform-native answer but not
//! the one the spec asks for.
//!
//! The spec's XDG-style choice is the right one for this tool — it is a CLI
//! that developers will want to keep in dotfiles, not a GUI app — so path
//! resolution is hand-rolled here and `directories` is not a dependency.
//! `XDG_CONFIG_HOME` and `XDG_STATE_HOME` are honoured when set.

use crate::{Result, SiftError};
use std::path::{Path, PathBuf};

/// The user's home directory, from `$HOME`.
///
/// launchd sets `HOME` for user agents, so this works for the scheduled run as
/// well as interactive use. If it is genuinely unset we fail loudly rather than
/// guessing — a disk reclamation tool that has to guess where "home" is should
/// not be deleting anything.
pub fn home() -> Result<PathBuf> {
    match std::env::var_os("HOME") {
        Some(h) if !h.is_empty() => Ok(PathBuf::from(h)),
        _ => Err(SiftError::Config(
            "$HOME is not set; sift cannot determine the user's home directory".into(),
        )),
    }
}

/// Honour an XDG override if it is set to a non-empty absolute path, else fall
/// back to `home()/default_rel`.
///
/// The absolute-path requirement matches the XDG spec: a relative value is
/// invalid and must be ignored rather than resolved against the cwd, which for
/// a launchd agent is `/`.
fn xdg_dir(var: &str, default_rel: &str) -> Result<PathBuf> {
    if let Some(v) = std::env::var_os(var) {
        let p = PathBuf::from(&v);
        if !v.is_empty() && p.is_absolute() {
            return Ok(p.join("sift"));
        }
    }
    Ok(home()?.join(default_rel).join("sift"))
}

/// `~/.config/sift`, or `$XDG_CONFIG_HOME/sift`.
pub fn config_dir() -> Result<PathBuf> {
    xdg_dir("XDG_CONFIG_HOME", ".config")
}

/// `~/.local/state/sift`, or `$XDG_STATE_HOME/sift`.
pub fn state_dir() -> Result<PathBuf> {
    xdg_dir("XDG_STATE_HOME", ".local/state")
}

/// `~/.config/sift/config.toml` (FR-22).
pub fn config_file() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.toml"))
}

/// `~/.local/state/sift/quarantine` (spec §7.1).
pub fn quarantine_dir() -> Result<PathBuf> {
    Ok(state_dir()?.join("quarantine"))
}

/// `~/.local/state/sift/history.jsonl` (FR-8).
pub fn history_file() -> Result<PathBuf> {
    Ok(state_dir()?.join("history.jsonl"))
}

/// Expand a leading `~` or `$HOME` to the user's home directory.
///
/// Only a *leading* tilde is expanded, and only when followed by a separator or
/// end-of-string. `~foo` (another user's home) is deliberately not supported:
/// sift is single-user per `$UID` (N6), and silently resolving another user's
/// home would be a scope escape.
pub fn expand(path: impl AsRef<Path>) -> Result<PathBuf> {
    let p = path.as_ref();
    let s = p.to_string_lossy();

    let rest = if s == "~" {
        return home();
    } else if let Some(r) = s.strip_prefix("~/") {
        r
    } else if s == "$HOME" {
        return home();
    } else if let Some(r) = s.strip_prefix("$HOME/") {
        r
    } else {
        return Ok(p.to_path_buf());
    };

    Ok(home()?.join(rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These tests mutate process-global environment variables, so they must not
    /// run concurrently with each other. Rust runs tests in one process across
    /// many threads, so a mutex is required — without it these pass alone and
    /// fail at random under the full suite.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvGuard {
        key: &'static str,
        prev: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: Option<&str>) -> Self {
            let prev = std::env::var_os(key);
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
            Self { key, prev }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    #[test]
    fn config_dir_defaults_to_xdg_style_not_application_support() {
        // Correction C2: this is the assertion that would fail if someone
        // reintroduced the `directories` crate.
        let _lock = ENV_LOCK.lock().unwrap();
        let _h = EnvGuard::set("HOME", Some("/Users/test"));
        let _x = EnvGuard::set("XDG_CONFIG_HOME", None);

        assert_eq!(
            config_dir().unwrap(),
            PathBuf::from("/Users/test/.config/sift")
        );
        assert!(!config_dir()
            .unwrap()
            .to_string_lossy()
            .contains("Application Support"));
    }

    #[test]
    fn state_dir_defaults_to_local_state() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _h = EnvGuard::set("HOME", Some("/Users/test"));
        let _x = EnvGuard::set("XDG_STATE_HOME", None);

        assert_eq!(
            state_dir().unwrap(),
            PathBuf::from("/Users/test/.local/state/sift")
        );
    }

    #[test]
    fn xdg_overrides_are_honoured() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _h = EnvGuard::set("HOME", Some("/Users/test"));
        let _x = EnvGuard::set("XDG_CONFIG_HOME", Some("/custom/cfg"));

        assert_eq!(config_dir().unwrap(), PathBuf::from("/custom/cfg/sift"));
    }

    #[test]
    fn relative_xdg_override_is_ignored() {
        // A relative XDG value is invalid per the XDG spec. Resolving it against
        // the cwd would be actively dangerous for a launchd agent, whose cwd is /.
        let _lock = ENV_LOCK.lock().unwrap();
        let _h = EnvGuard::set("HOME", Some("/Users/test"));
        let _x = EnvGuard::set("XDG_CONFIG_HOME", Some("relative/path"));

        assert_eq!(
            config_dir().unwrap(),
            PathBuf::from("/Users/test/.config/sift")
        );
    }

    #[test]
    fn empty_xdg_override_is_ignored() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _h = EnvGuard::set("HOME", Some("/Users/test"));
        let _x = EnvGuard::set("XDG_CONFIG_HOME", Some(""));

        assert_eq!(
            config_dir().unwrap(),
            PathBuf::from("/Users/test/.config/sift")
        );
    }

    #[test]
    fn missing_home_is_a_config_error_not_a_guess() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _h = EnvGuard::set("HOME", None);

        let err = home().unwrap_err();
        assert_eq!(err.exit_code(), crate::ExitCode::Config);
    }

    #[test]
    fn expand_handles_tilde_and_home_var() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _h = EnvGuard::set("HOME", Some("/Users/test"));

        assert_eq!(expand("~").unwrap(), PathBuf::from("/Users/test"));
        assert_eq!(expand("~/dev").unwrap(), PathBuf::from("/Users/test/dev"));
        assert_eq!(expand("$HOME").unwrap(), PathBuf::from("/Users/test"));
        assert_eq!(
            expand("$HOME/dev").unwrap(),
            PathBuf::from("/Users/test/dev")
        );
        assert_eq!(expand("/abs/path").unwrap(), PathBuf::from("/abs/path"));
        assert_eq!(expand("relative").unwrap(), PathBuf::from("relative"));
    }

    #[test]
    fn expand_does_not_resolve_another_users_home() {
        // `~otheruser` must stay literal. sift is single-user per $UID (N6);
        // silently resolving another user's home would be a scope escape.
        let _lock = ENV_LOCK.lock().unwrap();
        let _h = EnvGuard::set("HOME", Some("/Users/test"));

        assert_eq!(
            expand("~root/secrets").unwrap(),
            PathBuf::from("~root/secrets")
        );
        assert_eq!(expand("~admin").unwrap(), PathBuf::from("~admin"));
    }
}
