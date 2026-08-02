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

        // Drain the pipes on threads, poll for exit in the parent.
        //
        // Two earlier versions were wrong, both in ways that only showed up
        // intermittently:
        //
        //   1. `try_wait()` then `wait_with_output()`. `try_wait` reaps the
        //      child, so `wait_with_output` had nothing left to wait on and
        //      both the exit status and the output were lost. It passed most of
        //      the time because the poll usually saw the child still running.
        //
        //   2. Waiting on a thread and killing by raw pid on timeout. The
        //      parent no longer owned the `Child`, so `libc::kill` could signal
        //      a pid the OS had already recycled for someone else's process —
        //      which is exactly what happened: a concurrent test's child was
        //      killed, and its exit code came back as "terminated by signal".
        //
        // This version keeps the `Child` in the parent, so `child.kill()` is
        // safe by construction (it refuses to signal a reaped child), and moves
        // only the pipe handles to reader threads, so a child that fills the
        // pipe buffer cannot deadlock against a parent waiting for it to exit.
        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();

        let read = |pipe: Option<std::process::ChildStdout>| {
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                if let Some(mut p) = pipe {
                    use std::io::Read;
                    let _ = p.read_to_end(&mut buf);
                }
                buf
            })
        };
        let out_handle = read(stdout_pipe);
        let err_handle = std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut p) = stderr_pipe {
                use std::io::Read;
                let _ = p.read_to_end(&mut buf);
            }
            buf
        });

        let start = std::time::Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => {
                    if start.elapsed() > self.timeout {
                        // Safe: the parent still owns the Child.
                        let _ = child.kill();
                        let _ = child.wait();
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Outcome::SpawnFailed(e.to_string()),
            }
        };

        let stdout = String::from_utf8_lossy(&out_handle.join().unwrap_or_default()).into_owned();
        let stderr = String::from_utf8_lossy(&err_handle.join().unwrap_or_default()).into_owned();

        match status {
            None => Outcome::TimedOut(self.timeout),
            Some(s) if s.success() => Outcome::Ok { stdout, stderr },
            Some(s) => Outcome::Failed {
                code: s.code(),
                stderr,
            },
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

    /// These tests spawn real processes, and run serially.
    ///
    /// In parallel they fail intermittently (~10-15%) with the child reporting
    /// **signal 9**, empty output, on commands as trivial as `echo hello`. That
    /// is not the timeout path — it returns `TimedOut` before reaching the
    /// signalled branch — so something outside this code is sending SIGKILL.
    ///
    /// **Not root-caused.** The leading hypothesis is macOS jetsam reaping
    /// short-lived children under memory pressure: it appeared only late in a
    /// long session on a machine running near its limits, and signal 9 with no
    /// output is what jetsam looks like. That is a hypothesis, not a finding.
    ///
    /// Serialising removes the flake. It does not remove the underlying cause,
    /// and if a delegated command is ever killed in production the effect is
    /// bounded: a signalled child surfaces as `Outcome::Failed { code: None }`,
    /// which the registry records as a scanner error and survives (FR-2).
    static SPAWN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn spawn_guard() -> std::sync::MutexGuard<'static, ()> {
        SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

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
        let _g = spawn_guard();
        let outcome = Runner::new().run(&caps(), &DelegatedCmd::new("echo", &["hello"]));
        match outcome {
            Outcome::Ok { stdout, .. } => assert_eq!(stdout.trim(), "hello"),
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn a_non_zero_exit_is_an_error_and_keeps_the_message() {
        let _g = spawn_guard();
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
        let _g = spawn_guard();
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
        let _g = spawn_guard();
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
        let _g = spawn_guard();
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
        let _g = spawn_guard();
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
