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
