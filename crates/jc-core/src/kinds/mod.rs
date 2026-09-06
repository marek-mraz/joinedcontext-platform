//! The manifest kinds of `apiVersion: joinedcontext.com/v1alpha1` (MF-01, Architecture/06).

pub mod organization;
pub mod space;

pub use organization::{Contact, ContactRole, OrganizationSpec};
pub use space::{ContextSpaceSpec, ProjectSpec, Quotas};

/// `kind: Organization` as a whole manifest.
pub type Organization = crate::envelope::ResourceEnvelope<OrganizationSpec>;
/// `kind: Project` as a whole manifest.
pub type Project = crate::envelope::ResourceEnvelope<ProjectSpec>;
/// `kind: ContextSpace` as a whole manifest.
pub type ContextSpace = crate::envelope::ResourceEnvelope<ContextSpaceSpec>;
