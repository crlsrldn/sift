//! Capability detection: Full Disk Access and external tool availability
//! (FR-26, FR-27, spec §10).
//!
//! Everything here is a *probe*, never an assumption. A scanner that requires a
//! capability asks this module and is skipped with a reason if it is absent
//! (FR-27) — skipped, not failed, because a missing optional tool is a normal
//! state, not an error.

use std::collections::BTreeMap;
use std::path::PathBuf;

/// External tools scanners may delegate to (Principle 5).
///
/// Each entry is `(key, binary, what it is for)`. The key is what scanners and
/// config refer to; the binary is what is looked up on `PATH`.
pub const TOOLS: &[(&str, &str, &str)] = &[
    ("brew", "brew", "Homebrew cleanup (S8)"),
    (
        "docker",
        "docker",
        "container image and build cache pruning (S9)",
    ),
    ("xcrun", "xcrun", "simulator management (S5)"),
    ("tmutil", "tmutil", "APFS local snapshot thinning (S1)"),
    (
        "pmset",
        "pmset",
        "battery state for the scheduling gate (FR-20)",
    ),
    (
        "cargo-sweep",
        "cargo-sweep",
        "Rust target pruning (S6, preferred)",
    ),
    (
        "cargo-cache",
        "cargo-cache",
        "Cargo registry cleanup (S7, preferred)",
    ),
    ("pnpm", "pnpm", "pnpm store pruning (S10)"),
    ("yarn", "yarn", "Yarn cache cleaning (S10)"),
    ("uv", "uv", "uv cache pruning (S11)"),
    ("npm", "npm", "npm cache (S10)"),
];

/// Whether Full Disk Access has been granted to this binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdaStatus {
    Granted,
    Denied,
    /// The probe itself failed for a reason other than permission — treated as
    /// denied for safety, but reported differently so `doctor` does not give
    /// misleading remediation advice.
    Unknown,
}

impl FdaStatus {
    pub fn is_granted(self) -> bool {
        matches!(self, FdaStatus::Granted)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            FdaStatus::Granted => "granted",
            FdaStatus::Denied => "denied",
            FdaStatus::Unknown => "unknown",
        }
    }
}

/// What this process can currently do.
#[derive(Debug, Clone)]
pub struct Capabilities {
    pub fda: FdaStatus,
    /// Tool key to resolved path, for tools present on `PATH`.
    pub tools: BTreeMap<&'static str, PathBuf>,
    /// Path of the running binary, which is what FDA must be granted to.
    pub exe: Option<PathBuf>,
}

impl Capabilities {
    /// Probe the current process.
    pub fn probe() -> Self {
        Self {
            fda: probe_fda(),
            tools: probe_tools(),
            exe: std::env::current_exe().ok(),
        }
    }

    pub fn has_tool(&self, key: &str) -> bool {
        self.tools.contains_key(key)
    }

    pub fn tool_path(&self, key: &str) -> Option<&PathBuf> {
        self.tools.get(key)
    }

    /// Tools that are absent. Not an error — a machine without Docker simply
    /// has no containers to prune.
    pub fn missing_tools(&self) -> Vec<&'static str> {
        TOOLS
            .iter()
            .map(|(k, _, _)| *k)
            .filter(|k| !self.tools.contains_key(k))
            .collect()
    }
}

/// Probe for Full Disk Access.
///
/// Method from spec §10: attempt `read_dir` on the TCC directory. `EPERM`
/// means FDA is absent. This is the standard detection because TCC guards that
/// directory specifically and reading it has no side effects.
///
/// `NotFound` is treated as `Unknown` rather than `Granted`: if the directory
/// is missing, the probe proves nothing, and claiming FDA we might not have
/// would send scanners into failures instead of clean skips.
fn probe_fda() -> FdaStatus {
    let Some(home) = std::env::var_os("HOME") else {
        return FdaStatus::Unknown;
    };
    let tcc = PathBuf::from(home).join("Library/Application Support/com.apple.TCC");

    match std::fs::read_dir(&tcc) {
        Ok(_) => FdaStatus::Granted,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => FdaStatus::Denied,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => FdaStatus::Unknown,
        Err(_) => FdaStatus::Unknown,
    }
}

fn probe_tools() -> BTreeMap<&'static str, PathBuf> {
    let mut found = BTreeMap::new();
    for (key, binary, _) in TOOLS {
        if let Some(path) = which(binary) {
            found.insert(*key, path);
        }
    }
    found
}

/// Locate a binary on `PATH`.
///
/// Hand-rolled rather than shelling out to `which`, because a launchd-spawned
/// run has a minimal environment and spawning a process per tool to discover
/// that none of them exist is wasteful. Also avoids depending on the shell.
pub fn which(binary: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(binary);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn is_executable(p: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_does_not_panic_and_reports_something() {
        let caps = Capabilities::probe();
        assert!(matches!(
            caps.fda,
            FdaStatus::Granted | FdaStatus::Denied | FdaStatus::Unknown
        ));
    }

    #[test]
    fn which_finds_a_binary_that_certainly_exists() {
        let sh = which("sh").expect("/bin/sh should be on PATH");
        assert!(sh.exists());
    }

    #[test]
    fn which_returns_none_for_a_binary_that_does_not_exist() {
        assert!(which("definitely-not-a-real-binary-xyzzy").is_none());
    }

    #[test]
    fn which_rejects_non_executable_files() {
        // A file named like a tool but without +x must not be reported as the
        // tool, or delegation would fail confusingly at run time.
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("faketool");
        std::fs::write(&fake, b"not executable").unwrap();

        let old = std::env::var_os("PATH");
        std::env::set_var("PATH", dir.path());
        let found = which("faketool");
        match old {
            Some(p) => std::env::set_var("PATH", p),
            None => std::env::remove_var("PATH"),
        }

        assert!(
            found.is_none(),
            "a non-executable file was reported as a tool"
        );
    }

    #[test]
    fn every_tool_entry_has_a_purpose() {
        // A tool nobody can explain the need for should not be probed for.
        for (key, binary, purpose) in TOOLS {
            assert!(!key.is_empty());
            assert!(!binary.is_empty());
            assert!(!purpose.is_empty(), "tool `{key}` has no stated purpose");
        }
    }

    #[test]
    fn missing_tools_and_found_tools_partition_the_list() {
        let caps = Capabilities::probe();
        assert_eq!(caps.tools.len() + caps.missing_tools().len(), TOOLS.len());
    }

    #[test]
    fn fda_probe_treats_a_missing_tcc_directory_as_unknown_not_granted() {
        // Claiming FDA we might not have would send scanners into hard failures
        // instead of the clean skips FR-27 requires.
        let dir = tempfile::tempdir().unwrap();
        let old = std::env::var_os("HOME");
        std::env::set_var("HOME", dir.path());
        let status = probe_fda();
        match old {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
        assert_eq!(status, FdaStatus::Unknown);
    }
}
