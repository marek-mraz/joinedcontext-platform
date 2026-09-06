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
pub mod registry;
pub mod urn;

pub use envelope::{
    annotations, de_api_version, de_kind, validate_locales, Condition, Kind, ObjectMeta, Phase,
    Ref, ResourceEnvelope, Scope, SecretRef, Status, TypedRef, API_VERSION,
};
pub use error::{Error, ProblemDetails, Result, UrnError, PROBLEM_JSON, PROBLEM_TYPE_BASE};
pub use i18n::MultiLanguageMap;
pub use kinds::{
    App, AppClass, AppLifecycle, AppLimits, AppSource, AppSpec, AppVisibility, Audience, Caching,
    Compute, ComputeKind, Contact, ContactRole, ContextSpace, ContextSpaceSpec, Credential,
    CredentialKind, DataModel, DataModelLifecycle, DataModelRef, DataModelSource, DataModelSpec,
    DataNeed, Endpoint, EndpointSlug, EndpointSpec, EntitySelector, GeneratedArtifacts,
    KubernetesBinding, Mapping, MappingSpec, MappingTest, NativeBlock, NativeLanguage, Operation,
    OperationGroup, OperationRef, Organization, OrganizationSpec, Output, OutputMode, Owner,
    Pipeline, PipelineClass, PipelineQuotas, PipelineSource, PipelineSpec, Policy, PolicySpec,
    Principal, PrincipalKind, Project, ProjectSpec, Quotas, RateLimits, RegistrationInfo,
    Representation, RoleBinding, RoleScope, ScopeDefinition, ScopeDefinitionSpec, SemVer,
    ServiceAccount, ServiceAccountLimits, ServiceAccountSpec, SharedSpaceReference,
    SharedSpaceReferenceSpec, SourceQuery, SubscriptionTrigger, TemporalWindow, Trigger, Validity,
    Workload,
};
pub use registry::{by_kind, by_plural, KindInfo, KINDS};
pub use urn::Urn;
