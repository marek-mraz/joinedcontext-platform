//! The manifest kinds of `apiVersion: joinedcontext.com/v1alpha1` (MF-01, Architecture/06).

pub mod endpoint;
pub mod organization;
pub mod pipeline;
pub mod policy;
pub mod service_account;
pub mod space;

pub use endpoint::{
    Audience, Caching, EndpointSlug, EndpointSpec, RateLimits, Representation,
    SharedSpaceReferenceSpec,
};
pub use organization::{Contact, ContactRole, OrganizationSpec};
pub use pipeline::{
    Compute, ComputeKind, Output, OutputMode, PipelineClass, PipelineQuotas, PipelineSource,
    PipelineSpec, SourceQuery, SubscriptionTrigger, TemporalWindow, Trigger,
};
pub use policy::{
    EntitySelector, Operation, OperationGroup, OperationRef, PolicySpec, Principal, PrincipalKind,
    RegistrationInfo, ScopeDefinitionSpec, Validity,
};
pub use service_account::{
    Credential, CredentialKind, KubernetesBinding, Owner, RoleBinding, RoleScope,
    ServiceAccountLimits, ServiceAccountSpec, Workload,
};
pub use space::{ContextSpaceSpec, ProjectSpec, Quotas};

/// `kind: Organization` as a whole manifest.
pub type Organization = crate::envelope::ResourceEnvelope<OrganizationSpec>;
/// `kind: Project` as a whole manifest.
pub type Project = crate::envelope::ResourceEnvelope<ProjectSpec>;
/// `kind: ContextSpace` as a whole manifest.
pub type ContextSpace = crate::envelope::ResourceEnvelope<ContextSpaceSpec>;
/// `kind: Endpoint` as a whole manifest.
pub type Endpoint = crate::envelope::ResourceEnvelope<EndpointSpec>;
/// `kind: SharedSpaceReference` as a whole manifest.
pub type SharedSpaceReference = crate::envelope::ResourceEnvelope<SharedSpaceReferenceSpec>;
/// `kind: Policy` as a whole manifest.
pub type Policy = crate::envelope::ResourceEnvelope<PolicySpec>;
/// `kind: ScopeDefinition` as a whole manifest.
pub type ScopeDefinition = crate::envelope::ResourceEnvelope<ScopeDefinitionSpec>;
/// `kind: ServiceAccount` as a whole manifest.
pub type ServiceAccount = crate::envelope::ResourceEnvelope<ServiceAccountSpec>;
/// `kind: Pipeline` as a whole manifest.
pub type Pipeline = crate::envelope::ResourceEnvelope<PipelineSpec>;
