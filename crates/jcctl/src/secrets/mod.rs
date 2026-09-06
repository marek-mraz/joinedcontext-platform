//! Secret resolution for the reconciler (CC-06, OPS-37, ADR-N-012).
//!
//! Manifests carry named references only. The values live outside them: today in
//! SOPS-encrypted files in the repository, later in OpenBao for larger installations.

pub mod sops;

pub use sops::{identities_from_file, SecretStore, SecretValue, SopsError};
