//! Regression fixtures — one file per bug (spec §12).
//!
//! > "Every safety bug found gets a fixture before it gets a fix."
//!
//! That ordering is the point. A fix written first is a fix nobody can prove
//! works, and nobody can prove stays working. Writing the fixture first forces
//! the bug to be understood well enough to reproduce, which is usually where
//! the real cause turns up.
//!
//! # Adding one
//!
//! 1. Copy `TEMPLATE.rs` to `NNN_short_description.rs`.
//! 2. Make it fail against the current code. **If it passes, it is not yet a
//!    reproduction** — do not proceed.
//! 3. Fix the bug.
//! 4. Add the module below.
//!
//! Nothing is ever deleted from here. A regression that has not recurred in two
//! years is a regression that has not recurred *because this file exists*.

// Regressions are registered here as they are added.
