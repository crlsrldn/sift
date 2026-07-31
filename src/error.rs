//! Error taxonomy and process exit codes.
//!
//! Implements technical spec §11. The exit-code table is a public contract —
//! `sift` is designed to run under launchd and to be piped into scripts, so
//! these numbers are as much a part of the interface as the CLI flags.

use std::path::PathBuf;

/// Process exit codes, per spec §11.
///
/// `GatedNoOp` deliberately maps to the same value as success: a scheduled run
/// that declines to do anything because the battery is low or the disk is
/// comfortable (FR-20) is a *correct* outcome, not a failure, and launchd must
/// not treat it as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// Success, including a gated no-op run.
    Success = 0,
    /// Unhandled runtime error.
    Runtime = 1,
    /// Invalid configuration.
    Config = 2,
    /// Required permission unavailable and no scanners could run.
    Permission = 3,
    /// Circuit breaker tripped; nothing was actioned.
    CircuitBreaker = 4,
    /// Completed with one or more scanner errors.
    ScannerErrors = 5,
    /// CLI usage error.
    Usage = 64,
}

impl ExitCode {
    pub fn as_i32(self) -> i32 {
        self as i32
    }

    /// Human-readable meaning, used by `--help` epilogues and documentation.
    pub fn meaning(self) -> &'static str {
        match self {
            ExitCode::Success => "success (including a gated no-op run)",
            ExitCode::Runtime => "unhandled runtime error",
            ExitCode::Config => "invalid configuration",
            ExitCode::Permission => "required permission unavailable and no scanners could run",
            ExitCode::CircuitBreaker => "circuit breaker tripped; nothing was actioned",
            ExitCode::ScannerErrors => "completed with one or more scanner errors",
            ExitCode::Usage => "CLI usage error",
        }
    }

    /// Every variant, for exhaustive testing and documentation generation.
    pub const ALL: [ExitCode; 7] = [
        ExitCode::Success,
        ExitCode::Runtime,
        ExitCode::Config,
        ExitCode::Permission,
        ExitCode::CircuitBreaker,
        ExitCode::ScannerErrors,
        ExitCode::Usage,
    ];
}

/// Fatal errors. A `SiftError` terminates the run.
///
/// Scanner failures are deliberately *not* in this enum's fatal path — see
/// [`ScannerError`], which is recorded and survived (FR-2).
#[derive(Debug, thiserror::Error)]
pub enum SiftError {
    #[error("invalid configuration: {0}")]
    Config(String),

    #[error("permission denied: {}", .0.display())]
    Permission(PathBuf),

    #[error(
        "circuit breaker tripped: {bytes} bytes identified exceeds the {limit} byte limit; \
         nothing was actioned"
    )]
    CircuitBreaker { bytes: u64, limit: u64 },

    #[error("completed with {count} scanner error(s)")]
    ScannerErrors { count: usize },

    #[error("usage: {0}")]
    Usage(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl SiftError {
    /// Map an error to its process exit code (spec §11).
    pub fn exit_code(&self) -> ExitCode {
        match self {
            SiftError::Config(_) => ExitCode::Config,
            SiftError::Permission(_) => ExitCode::Permission,
            SiftError::CircuitBreaker { .. } => ExitCode::CircuitBreaker,
            SiftError::ScannerErrors { .. } => ExitCode::ScannerErrors,
            SiftError::Usage(_) => ExitCode::Usage,
            SiftError::Io(_) => ExitCode::Runtime,
        }
    }
}

/// A single scanner's failure.
///
/// This is non-fatal by construction (FR-2): the registry records it and the
/// run continues. It is a separate type from [`SiftError`] specifically so that
/// a scanner cannot accidentally return something the run treats as fatal — the
/// type system enforces the invariant rather than a code review catching it.
#[derive(Debug, thiserror::Error)]
#[error("scanner `{id}` failed: {source}")]
pub struct ScannerError {
    pub id: &'static str,
    #[source]
    pub source: anyhow::Error,
}

impl ScannerError {
    pub fn new(id: &'static str, source: impl Into<anyhow::Error>) -> Self {
        Self {
            id,
            source: source.into(),
        }
    }
}

pub type Result<T> = std::result::Result<T, SiftError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_values_match_spec_table() {
        // Spec §11. These are a public contract; changing one is a breaking change.
        assert_eq!(ExitCode::Success.as_i32(), 0);
        assert_eq!(ExitCode::Runtime.as_i32(), 1);
        assert_eq!(ExitCode::Config.as_i32(), 2);
        assert_eq!(ExitCode::Permission.as_i32(), 3);
        assert_eq!(ExitCode::CircuitBreaker.as_i32(), 4);
        assert_eq!(ExitCode::ScannerErrors.as_i32(), 5);
        assert_eq!(ExitCode::Usage.as_i32(), 64);
    }

    #[test]
    fn every_exit_code_is_reachable_from_an_error() {
        // Success is not reachable from an error by construction; every other
        // code must be produced by some SiftError variant. If a variant is added
        // without a mapping, this test fails.
        let produced: Vec<ExitCode> = vec![
            SiftError::Config("x".into()).exit_code(),
            SiftError::Permission(PathBuf::from("/x")).exit_code(),
            SiftError::CircuitBreaker { bytes: 2, limit: 1 }.exit_code(),
            SiftError::ScannerErrors { count: 1 }.exit_code(),
            SiftError::Usage("x".into()).exit_code(),
            SiftError::Io(std::io::Error::other("x")).exit_code(),
        ];

        for code in ExitCode::ALL {
            if code == ExitCode::Success {
                continue;
            }
            assert!(
                produced.contains(&code),
                "exit code {} ({}) is not produced by any SiftError variant",
                code.as_i32(),
                code.meaning()
            );
        }
    }

    #[test]
    fn gated_no_op_shares_the_success_code() {
        // FR-20: a gated scheduled run must not look like a failure to launchd.
        assert_eq!(ExitCode::Success.as_i32(), 0);
        assert!(ExitCode::Success.meaning().contains("gated"));
    }

    #[test]
    fn io_errors_convert_and_map_to_runtime() {
        let e: SiftError = std::io::Error::other("boom").into();
        assert_eq!(e.exit_code(), ExitCode::Runtime);
    }

    #[test]
    fn circuit_breaker_message_states_nothing_was_actioned() {
        // FR-16: the user must be told the run was aborted *before* any action.
        let msg = SiftError::CircuitBreaker {
            bytes: 200,
            limit: 100,
        }
        .to_string();
        assert!(msg.contains("nothing was actioned"), "got: {msg}");
    }

    #[test]
    fn scanner_error_is_not_a_sift_error() {
        // FR-2 is enforced by the type system: there is no From<ScannerError>
        // for SiftError, so a scanner cannot return a run-fatal error by accident.
        let e = ScannerError::new("test-scanner", anyhow::anyhow!("nope"));
        assert_eq!(e.id, "test-scanner");
        assert!(e.to_string().contains("test-scanner"));
    }
}
