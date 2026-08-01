//! Command implementations.
//!
//! Every PRD §7 command is dispatchable from PR-04 onward. Commands whose
//! implementing PR has not landed return [`not_implemented`], which is an
//! explicit, honest failure rather than a silent success — a `clean` that
//! printed nothing and exited 0 would be indistinguishable from a `clean` that
//! found nothing to do.

pub mod config_check;
pub mod doctor;

use crate::{Result, SiftError};

/// Placeholder for a command whose implementing PR has not landed.
pub fn not_implemented(command: &str, pr: &str) -> Result<()> {
    Err(SiftError::Usage(format!(
        "`sift {command}` is not implemented yet (lands in {pr})"
    )))
}
