//! Declarative reconciler, migration engine, and configuration loader for joinedcontext (API/03, CC-08).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod apisix;
pub mod commands;
pub mod diff;
pub mod lanes;
pub mod loader;
pub mod pipelines;
pub mod platform;
pub mod service_accounts;
pub mod waves;

pub use diff::{diff, FieldDiff};
pub use lanes::{change_envelope, lane_of, lane_of_changeset, Lane, LaneVerdict};
pub use loader::{LoadError, LoadedResource, RawManifest, RawMetadata, Repository, ResourceId};
pub use waves::{
    plan, wave_of, Plan, WAVE_ACCESS, WAVE_EXPOSURE, WAVE_FEDERATION, WAVE_ROOTS, WAVE_RUNTIME,
    WAVE_SPACES,
};
