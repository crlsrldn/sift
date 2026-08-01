//! Running another tool's cleanup command (FR-4, FR-15, Principle 5).
//!
//! # Why delegate at all
//!
//! `brew cleanup`, `docker prune`, and `simctl delete unavailable` know their
//! own invariants. Homebrew knows which bottles are still referenced; Docker
//! knows which layers a running container needs. Reimplementing that knowledge
//! means reimplementing it wrong, eventually, on someone's machine.
//!
//! # What delegation costs
//!
//! **Delegated commands bypass quarantine entirely** (FR-15). There is no
//! rename to undo — the other tool deleted the bytes. That is why a delegated
//! scanner is only permitted at Safe tier or behind an explicit opt-in, and why
//! `Target::is_reversible()` answers `false` for them at the type level.
//!
//! # Absence is not failure
//!
//! A machine without Docker has no containers to prune. FR-4 requires that be a
//! silent skip, not an error — otherwise every non-developer's `sift doctor`
//! would be a wall of red about tools they have no reason to install.

use crate::caps::Capabilities;
use crate::scan::DelegatedCmd;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Default per-command timeout.
///
/// `docker system prune` on a large daemon genuinely takes minutes, so this is
/// generous. The point is not speed — it is that a scheduled 03:00 run must not
/// hang forever on a wedged daemon and still be holding the machine at 09:00.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

/// `PATH` for delegated commands.
///
/// Set explicitly rather than inherited, and identical to the LaunchAgent's
/// (spec §9). launchd provides a minimal environment, so a tool that resolves
/// interactively would otherwise vanish under the scheduled run — a failure
/// that shows up as "the agent reclaims nothing" weeks later.
pub const DELEGATE_PATH: &str = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";

/// What running a command produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Ran and exited zero.
    Ok { stdout: String, stderr: String },
    /// The tool is not installed. Not an error (FR-4).
    ToolMissing(String),
    /// Ran and exited non-zero. Recorded as a scanner error; the run continues.
    Failed { code: Option<i32>, stderr: String },
    /// Exceeded the timeout and was killed.
    TimedOut(Duration),
    /// Could not be spawned at all.
    SpawnFailed(String),
    /// `--dry-run`: the command line was reported and nothing was executed.
    NotRun(String),
}

impl Outcome {
    pub fn succeeded(&self) -> bool {
        matches!(self, Outcome::Ok { .. })
    }

    /// Whether this should be recorded as a scanner error (FR-2).
    ///
    /// A missing tool is not; a tool that ran and failed is. The distinction is
    /// the whole of FR-4.
    pub fn is_error(&self) -> bool {
        matches!(
            self,
            Outcome::Failed { .. } | Outcome::TimedOut(_) | Outcome::SpawnFailed(_)
        )
    }

    pub fn describe(&self) -> String {
        match self {
            Outcome::Ok { .. } => "completed".into(),
            Outcome::ToolMissing(t) => format!("`{t}` is not installed"),
            Outcome::Failed { code, stderr } => {
                let first = stderr.lines().next().unwrap_or("").trim();
                match code {
                    Some(c) if !first.is_empty() => format!("exited {c}: {first}"),
                    Some(c) => format!("exited {c}"),
                    None => "terminated by signal".into(),
                }
            }
            Outcome::TimedOut(d) => format!("timed out after {}s", d.as_secs()),
            Outcome::SpawnFailed(e) => format!("could not start: {e}"),
            Outcome::NotRun(cmd) => format!("would run: {cmd}"),
        }
    }
}

/// How to run a delegated command.
pub struct Runner {
    timeout: Duration,
    dry_run: bool,
}

impl Default for Runner {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            dry_run: false,
        }
    }
}

impl Runner {
    pub fn new() -> Self {
        Self::default()
    }

    /// A runner that reports command lines and executes nothing.
    pub fn dry_run() -> Self {
        Self {
            dry_run: true,
            ..Self::default()
        }
    }

    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = d;
        self
    }

    /// Run a command, having first confirmed its tool exists.
    pub fn run(&self, caps: &Capabilities, cmd: &DelegatedCmd) -> Outcome {
        // FR-4, checked before anything else. A machine without the tool is a
        // normal machine.
        if crate::caps::which(&cmd.program).is_none() {
            return Outcome::ToolMissing(cmd.program.clone());
        }
        let _ = caps;

        if self.dry_run {
            return Outcome::NotRun(cmd.display());
        }

        self.execute(cmd)
    }

    fn execute(&self, cmd: &DelegatedCmd) -> Outcome {
        let child = Command::new(&cmd.program)
            .args(&cmd.args)
            .env("PATH", DELEGATE_PATH)
            // A delegated tool must never wait for input. Without this, a
            // command that decides to prompt would hang a scheduled run
            // indefinitely rather than failing.
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();

        let mut child = match child {
            Ok(c) => c,
            Err(e) => return Outcome::SpawnFailed(e.to_string()),
        };

        // Poll rather than block, so the timeout is enforceable. `wait_timeout`
        // would be neater but is another dependency for a loop this small.
        let start = std::time::Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let out = child.wait_with_output().ok();
                    let stdout = out
                        .as_ref()
                        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                        .unwrap_or_default();
                    let stderr = out
                        .as_ref()
                        .map(|o| String::from_utf8_lossy(&o.stderr).into_owned())
                        .unwrap_or_default();

                    return if status.success() {
                        Outcome::Ok { stdout, stderr }
                    } else {
                        Outcome::Failed {
                            code: status.code(),
                            stderr,
                        }
                    };
                }
                Ok(None) => {
                    if start.elapsed() > self.timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Outcome::TimedOut(self.timeout);
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => return Outcome::SpawnFailed(e.to_string()),
            }
        }
    }
}

/// Run a command purely to read its output, e.g. a `--dry-run` size estimate.
///
/// Separate from [`Runner::run`] so a probe cannot be mistaken for an action:
/// this is what scanners call during `scan`, which FR-1 requires be free of
/// side effects.
pub fn probe(program: &str, args: &[&str], timeout: Duration) -> Outcome {
    if crate::caps::which(program).is_none() {
        return Outcome::ToolMissing(program.to_string());
    }
    Runner::new()
        .timeout(timeout)
        .execute(&DelegatedCmd::new(program, args))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps() -> Capabilities {
        Capabilities::probe()
    }

    #[test]
    fn a_missing_tool_is_a_skip_not_an_error() {
        // FR-4. Every non-developer's machine is missing most of these tools.
        let cmd = DelegatedCmd::new("definitely-not-a-real-binary-xyzzy", &["--version"]);
        let outcome = Runner::new().run(&caps(), &cmd);

        assert!(matches!(outcome, Outcome::ToolMissing(_)));
        assert!(!outcome.is_error(), "a missing tool must not be an error");
        assert!(outcome.describe().contains("not installed"));
    }

    #[test]
    fn a_successful_command_reports_its_output() {
        let outcome = Runner::new().run(&caps(), &DelegatedCmd::new("echo", &["hello"]));
        match outcome {
            Outcome::Ok { stdout, .. } => assert_eq!(stdout.trim(), "hello"),
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn a_non_zero_exit_is_an_error_and_keeps_the_message() {
        // FR-2: recorded, and the run continues. The first stderr line is kept
        // because "exited 1" alone tells the user nothing.
        let outcome = Runner::new().run(
            &caps(),
            &DelegatedCmd::new("sh", &["-c", "echo boom >&2; exit 3"]),
        );

        match &outcome {
            Outcome::Failed { code, stderr } => {
                assert_eq!(*code, Some(3));
                assert!(stderr.contains("boom"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        assert!(outcome.is_error());
        assert!(
            outcome.describe().contains("boom"),
            "{}",
            outcome.describe()
        );
    }

    #[test]
    fn a_hanging_command_is_killed_at_the_timeout() {
        // A wedged daemon must not leave a 03:00 run still holding the machine
        // at 09:00.
        let outcome = Runner::new()
            .timeout(Duration::from_millis(300))
            .run(&caps(), &DelegatedCmd::new("sleep", &["30"]));

        assert!(matches!(outcome, Outcome::TimedOut(_)), "{outcome:?}");
        assert!(outcome.is_error());
    }

    #[test]
    fn dry_run_reports_the_command_line_and_executes_nothing() {
        // Verified by effect: the command would create a file, and does not.
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("SHOULD_NOT_EXIST");
        let cmd = DelegatedCmd::new("touch", &[marker.to_str().unwrap()]);

        let outcome = Runner::dry_run().run(&caps(), &cmd);

        assert!(!marker.exists(), "--dry-run executed the command");
        match outcome {
            Outcome::NotRun(line) => {
                assert!(line.starts_with("touch "), "{line}");
                assert!(line.contains("SHOULD_NOT_EXIST"), "{line}");
            }
            other => panic!("expected NotRun, got {other:?}"),
        }
    }

    #[test]
    fn dry_run_still_reports_a_missing_tool_rather_than_a_command_line() {
        // Printing "would run: nonexistent-tool ..." would be misleading — it
        // would not run even without --dry-run.
        let cmd = DelegatedCmd::new("definitely-not-a-real-binary-xyzzy", &[]);
        assert!(matches!(
            Runner::dry_run().run(&caps(), &cmd),
            Outcome::ToolMissing(_)
        ));
    }

    #[test]
    fn stdin_is_closed_so_a_prompting_tool_cannot_hang_the_run() {
        // `read` on a null stdin returns EOF immediately rather than blocking.
        let outcome = Runner::new().timeout(Duration::from_secs(5)).run(
            &caps(),
            &DelegatedCmd::new("sh", &["-c", "read x; echo done"]),
        );

        assert!(
            !matches!(outcome, Outcome::TimedOut(_)),
            "a tool reading stdin hung the run: {outcome:?}"
        );
    }

    #[test]
    fn the_delegate_path_matches_the_launchagent_environment() {
        // spec §9. If these drift, a tool found interactively vanishes under
        // launchd, and the agent silently reclaims nothing.
        assert!(DELEGATE_PATH.contains("/opt/homebrew/bin"));
        assert!(DELEGATE_PATH.contains("/usr/local/bin"));
        assert!(DELEGATE_PATH.contains("/usr/bin"));
        assert!(DELEGATE_PATH.contains("/bin"));
    }

    #[test]
    fn probe_is_available_for_side_effect_free_size_estimates() {
        // FR-1: `scan` must not mutate anything, so a size estimate needs a
        // path that is visibly not an action.
        match probe("echo", &["42"], Duration::from_secs(5)) {
            Outcome::Ok { stdout, .. } => assert_eq!(stdout.trim(), "42"),
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn a_command_line_renders_readably_for_the_report() {
        let cmd = DelegatedCmd::new("brew", &["cleanup", "--prune=all", "-q"]);
        assert_eq!(cmd.display(), "brew cleanup --prune=all -q");
        assert_eq!(DelegatedCmd::new("brew", &[]).display(), "brew");
    }
}
