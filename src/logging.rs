//! Logging setup (spec §11).
//!
//! Two output shapes:
//!   - interactive: human-readable, to **stderr**
//!   - `--scheduled`: JSON, to stderr, for launchd's StandardErrorPath
//!
//! Everything goes to stderr, never stdout. That is not a style preference:
//! `--json` (FR-10) promises that stdout contains *only* the JSON document, so
//! any log line on stdout would corrupt a pipe into `jq`. Keeping the streams
//! separated here is what makes that guarantee cheap to hold in PR-11.

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Environment variable controlling log level, per spec §11.
pub const LOG_ENV: &str = "SIFT_LOG";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable, for interactive use.
    Human,
    /// Structured JSON, for scheduled runs read out of the agent log.
    Json,
}

impl LogFormat {
    /// `--scheduled` implies JSON; interactive implies human.
    pub fn for_run(scheduled: bool) -> Self {
        if scheduled {
            LogFormat::Json
        } else {
            LogFormat::Human
        }
    }
}

/// Build the level filter: `SIFT_LOG` if set, otherwise `warn` by default,
/// bumped to `debug` by `--verbose`.
///
/// The default is deliberately quiet. `sift scan` on a healthy machine should
/// print a report and nothing else; a tool that chatters at INFO trains users
/// to ignore its output, which is the opposite of what a safety-critical
/// deletion tool wants.
fn filter(verbose: bool) -> EnvFilter {
    match std::env::var(LOG_ENV) {
        Ok(v) if !v.trim().is_empty() => {
            EnvFilter::try_new(&v).unwrap_or_else(|_| EnvFilter::new(default_level(verbose)))
        }
        _ => EnvFilter::new(default_level(verbose)),
    }
}

fn default_level(verbose: bool) -> &'static str {
    if verbose {
        "sift=debug"
    } else {
        "sift=warn"
    }
}

/// Initialize the global subscriber. Idempotent: a second call is a no-op
/// rather than a panic, so tests and nested invocations are safe.
pub fn init(format: LogFormat, verbose: bool) {
    let filter = filter(verbose);

    let result = match format {
        LogFormat::Human => tracing_subscriber::registry()
            .with(filter)
            .with(
                fmt::layer()
                    .with_writer(std::io::stderr)
                    .with_target(false)
                    .without_time(),
            )
            .try_init(),
        LogFormat::Json => tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json().with_writer(std::io::stderr))
            .try_init(),
    };

    // A failed init means a subscriber is already installed. That is fine.
    let _ = result;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduled_runs_log_json() {
        assert_eq!(LogFormat::for_run(true), LogFormat::Json);
        assert_eq!(LogFormat::for_run(false), LogFormat::Human);
    }

    #[test]
    fn default_level_is_quiet_until_verbose() {
        assert_eq!(default_level(false), "sift=warn");
        assert_eq!(default_level(true), "sift=debug");
    }

    #[test]
    fn init_is_idempotent() {
        init(LogFormat::Human, false);
        init(LogFormat::Json, true);
    }
}
