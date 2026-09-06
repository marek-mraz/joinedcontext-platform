//! Declarative reconciler, migration engine, and configuration loader for joinedcontext (API/03, CC-08).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod commands;
pub mod diff;
pub mod loader;
pub mod platform;
pub mod waves;

pub use diff::{diff, FieldDiff};
pub use loader::{LoadError, LoadedResource, RawManifest, RawMetadata, Repository, ResourceId};
pub use waves::{
    plan, wave_of, Plan, WAVE_ACCESS, WAVE_EXPOSURE, WAVE_FEDERATION, WAVE_ROOTS, WAVE_RUNTIME,
    WAVE_SPACES,
};
