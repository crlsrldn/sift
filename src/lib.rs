//! `sift` — an automated, safety-first disk reclamation agent for macOS.
//!
//! The crate is split into a library and a thin binary so that integration
//! tests in `tests/` can exercise real internals. The safety guarantees this
//! tool makes (allowlist containment, walker termination, quarantine
//! round-tripping) are only credible if they are tested against the actual
//! implementation rather than a reimplementation, and that requires a library
//! target.

pub mod action;
pub mod agent;
pub mod caps;
/// Days-since-epoch to a calendar date, for the `--version` build stamp.
///
/// Shared with `build.rs` through `include!` so that `cargo test` can reach
/// it: a build script is not compiled into any test target, and date
/// arithmetic nothing exercises is exactly the code that is wrong at a leap
/// year and right every other day of the decade.
///
/// `chrono` would do this in one call, but `build.rs` is kept dependency-free
/// — CI fails the build if an HTTP or TLS crate reaches the binary, and a
/// build script is the easiest place for one to arrive unnoticed.
pub mod civil;
pub mod cli;
pub mod commands;
pub mod config;
pub mod doctor;
pub mod error;
pub mod explain;
pub mod fs;
pub mod logging;
pub mod paths;
pub mod report;
pub mod risk;
pub mod scan;

pub use config::Config;
pub use error::{ExitCode, Result, ScannerError, SiftError};
pub use risk::Risk;
