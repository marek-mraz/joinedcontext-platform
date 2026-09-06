//! The manifest kinds of `apiVersion: joinedcontext.com/v1alpha1` (MF-01, Architecture/06).

pub mod app;
pub mod data_model;
pub mod dataspace;
pub mod endpoint;
pub mod mapping;
pub mod organization;
pub mod pipeline;
pub mod policy;
pub mod service_account;
pub mod space;
pub mod sync;

pub use app::{
    AppBuild, AppClass, AppLifecycle, AppLimits, AppSource, AppSpec, AppVisibility,
    ContentSecurityPolicy, DataNeed, GeoConstraint, GeoWithin, GitSource, TemporalConstraint,
};
pub use data_model::{
    DataModelLifecycle, DataModelSource, DataModelSpec, GeneratedArtifacts, RemoteSource, SemVer,
};
pub use dataspace::{
    AgreementConstraints, AgreementRole, AgreementState, ConnectorEngine, DataAgreementSpec,
    DataOfferSpec, DataSpaceParticipantSpec, Did,
};
pub use endpoint::{
    Audience, Caching, EndpointSlug, EndpointSpec, RateLimits, Representation,
    SharedSpaceReferenceSpec,
};
pub use mapping::{
    DataModelRef, MappingSpec, MappingTest, NativeBlock, NativeLanguage, VocabularyAlignment,
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
pub use sync::{
    BundleItem, BundleOrigin, BundleSpec, ConflictPolicy, GitOrigin, PlatformApiOrigin, Schedule,
    SyncMode, SyncOrigin, SyncSourceSpec,
};

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
/// `kind: DataModel` as a whole manifest.
pub type DataModel = crate::envelope::ResourceEnvelope<DataModelSpec>;
/// `kind: Mapping` as a whole manifest.
pub type Mapping = crate::envelope::ResourceEnvelope<MappingSpec>;
/// `kind: App` as a whole manifest.
pub type App = crate::envelope::ResourceEnvelope<AppSpec>;
/// `kind: SyncSource` as a whole manifest.
pub type SyncSource = crate::envelope::ResourceEnvelope<SyncSourceSpec>;
/// `kind: Bundle` as a whole manifest.
pub type Bundle = crate::envelope::ResourceEnvelope<BundleSpec>;
/// `kind: DataSpaceParticipant` as a whole manifest.
pub type DataSpaceParticipant = crate::envelope::ResourceEnvelope<DataSpaceParticipantSpec>;
/// `kind: DataOffer` as a whole manifest.
pub type DataOffer = crate::envelope::ResourceEnvelope<DataOfferSpec>;
/// `kind: DataAgreement` as a whole manifest.
pub type DataAgreement = crate::envelope::ResourceEnvelope<DataAgreementSpec>;
