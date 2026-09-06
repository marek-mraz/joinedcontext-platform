//! Shared domain and configuration-as-code models for the joinedcontext platform.
//!
//! This crate defines the deterministic URN scheme (PF-10, PF-42), Kubernetes-style
//! manifest envelope and metadata types (MF-01..MF-10), multi-language localization
//! mapping (PF-24..PF-28), typed reference schemas, and validation rules used across
//! the Context Gateway, reconciler (`jcctl`), and Portal backend.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod envelope;
pub mod error;
pub mod i18n;
pub mod kinds;
pub mod names;
pub mod urn;

pub use envelope::{
    annotations, de_api_version, de_kind, validate_locales, Condition, Kind, ObjectMeta, Phase,
    Ref, ResourceEnvelope, Scope, SecretRef, Status, TypedRef, API_VERSION,
};
pub use error::{Error, Result, UrnError};
pub use i18n::MultiLanguageMap;
pub use kinds::{
    Audience, Caching, Contact, ContactRole, ContextSpace, ContextSpaceSpec, Endpoint,
    EndpointSlug, EndpointSpec, EntitySelector, Operation, OperationGroup, OperationRef,
    Organization, OrganizationSpec, Policy, PolicySpec, Principal, PrincipalKind, Project,
    ProjectSpec, Quotas, RateLimits, RegistrationInfo, Representation, ScopeDefinition,
    ScopeDefinitionSpec, SharedSpaceReference, SharedSpaceReferenceSpec, Validity,
};
pub use urn::Urn;
