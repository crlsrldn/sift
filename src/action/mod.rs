//! The action pipeline: deciding what may be actioned, and doing it.
//!
//! Split so the *deciding* (filter, breaker, liveness) is pure and reviewable
//! without a filesystem, and the *doing* (quarantine, purge, restore) is
//! isolated behind it.

pub mod breaker;
pub mod filter;
pub mod liveness;
pub mod manifest;
pub mod quarantine;
