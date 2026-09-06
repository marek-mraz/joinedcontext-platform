//! Declarative reconciler, migration engine, and configuration loader for joinedcontext (API/03, CC-08).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod loader;
pub mod waves;

pub use loader::{LoadError, LoadedResource, RawManifest, RawMetadata, Repository, ResourceId};
pub use waves::{
    plan, wave_of, Plan, WAVE_ACCESS, WAVE_EXPOSURE, WAVE_FEDERATION, WAVE_ROOTS, WAVE_RUNTIME,
    WAVE_SPACES,
};
