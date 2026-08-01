//! Filesystem primitives: volume identity, capacity, guarded walking, dataless
//! detection, and size accounting.

pub mod dataless;
pub mod size;
pub mod volume;
pub mod walk;

pub use size::{measure, Measurement, Measurer};
pub use volume::VolumeInfo;
pub use walk::{SkipReason, Walker};
