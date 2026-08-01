//! Command implementations.
//!
//! Every command in PRD §7 is implemented. The `not_implemented` placeholder
//! that stood in for the unfinished ones is gone, having run out of callers.

pub mod clean;
pub mod config_check;
pub mod doctor;
pub mod install;
pub mod purge;
pub mod report;
pub mod restore;
pub mod scan;
