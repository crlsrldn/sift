//! Filesystem primitives: volume identity, capacity, guarded walking, dataless
//! detection, and size accounting.

pub mod dataless;
pub mod volume;
pub mod walk;

pub use volume::VolumeInfo;
pub use walk::{SkipReason, Walker};
