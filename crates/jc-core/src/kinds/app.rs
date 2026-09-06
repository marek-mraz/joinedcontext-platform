//! Manifest kinds for Apps on Demand (T-0119, AP-01..AP-33, Architecture/16).

use crate::envelope::{Kind, ObjectMeta, Scope};
use crate::error::{Error, Result};
use crate::kinds::policy::{OperationGroup, OperationRef};
use crate::names;
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::LazyLock;

static IMAGE_DIGEST_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^.+@sha256:[a-fA-F0-9]{64}$").expect("valid image digest regex"));

/// Execution class of an application (AP-01, AP-25).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum AppClass {
    /// Static single-page application served by portal static host (AP-01, AP-14).
    Static,
    /// Containerized backend service running as a deployment (AP-01, AP-15).
    Service,
    /// Single container containing Axum backend and embedded React frontend (AP-01, AP-25).
    Fullstack,
}

impl AppClass {
    /// Returns the kebab-case wire name for this app class.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Service => "service",
            Self::Fullstack => "fullstack",
        }
    }
}

impl fmt::Display for AppClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Target visibility and audience access scope for an application (AP-01).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum AppVisibility {
    /// Restricted to the application author.
    Private,
    /// Accessible to members of the owning project.
    Project,
    /// Accessible to authenticated members of the organization.
    Organization,
    /// Accessible publicly without authentication under the synthetic public role grant (GW22).
    Public,
}

impl AppVisibility {
    /// Returns the kebab-case wire name for this visibility scope.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Project => "project",
            Self::Organization => "organization",
            Self::Public => "public",
        }
    }
}

impl fmt::Display for AppVisibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Lifecycle state of an application (AP-18).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum AppLifecycle {
    /// Initial authoring and iterative draft state (AP-18).
    Draft,
    /// Ephemeral preview running against a sandbox space (AP-18, AP-19).
    Preview,
    /// Live production deployment bound to real spaces and routes (AP-18, AP-20).
    Published,
    /// Decommissioned application with route and endpoint removed (AP-18, AP-21).
    Retired,
}

impl AppLifecycle {
    /// Returns the kebab-case wire name for this lifecycle state.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Preview => "preview",
            Self::Published => "published",
            Self::Retired => "retired",
        }
    }

    /// Checks whether transitioning from `self` to `next` is permitted (AP-18).
    ///
    /// Lifecycle follows the forward pipeline `draft -> preview -> published -> retired`.
    /// Each state may transition to itself. `retired` is terminal.
    pub fn allows_transition_to(&self, next: AppLifecycle) -> bool {
        let rank = |l: AppLifecycle| match l {
            AppLifecycle::Draft => 0,
            AppLifecycle::Preview => 1,
            AppLifecycle::Published => 2,
            AppLifecycle::Retired => 3,
        };
        rank(next) >= rank(*self)
    }
}

impl fmt::Display for AppLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Source code location or container image for an application (AP-01, AP-02, AP-13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AppSource {
    /// Git repository URL or identifier within the organization forge (AP-02).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    /// Path relative to the repository root for app source files (AP-01, AP-02).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Container image pinned by digest (`...@sha256:<64 hex>`) (AP-13).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

impl AppSource {
    /// Validates source fields and image digest pinning (AP-02, AP-13).
    pub fn validate(&self) -> Result<()> {
        if self.repository.is_none() && self.path.is_none() && self.image.is_none() {
            return Err(Error::Name {
                field: "spec.source",
                value: String::new(),
                reason: "at least one of repository, path, or image must be specified in source",
            });
        }

        if let Some(ref r) = self.repository {
            if r.trim().is_empty() {
                return Err(Error::Name {
                    field: "spec.source.repository",
                    value: r.clone(),
                    reason: "repository must not be empty",
                });
            }
        }

        if let Some(ref p) = self.path {
            if p.trim().is_empty() {
                return Err(Error::Name {
                    field: "spec.source.path",
                    value: p.clone(),
                    reason: "path must not be empty",
                });
            }
        }

        if let Some(ref img) = self.image {
            if !IMAGE_DIGEST_RE.is_match(img) {
                return Err(Error::Name {
                    field: "spec.source.image",
                    value: img.clone(),
                    reason: "image must be pinned by sha256 digest (`...@sha256:<64 hex>`) (AP-13)",
                });
            }
        }

        Ok(())
    }
}

/// Resource quotas and replica limits for an application (AP-01, AP-15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AppLimits {
    /// CPU limit or request (e.g. `500m`, `1`) (AP-15).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<String>,
    /// Memory limit or request (e.g. `256Mi`, `1Gi`) (AP-15).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
    /// Number of pod replicas to deploy (must be >= 1 if present).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<u32>,
}

impl AppLimits {
    /// Validates CPU, memory, and replica limits.
    pub fn validate(&self) -> Result<()> {
        if let Some(ref cpu) = self.cpu {
            if cpu.trim().is_empty() {
                return Err(Error::Name {
                    field: "spec.limits.cpu",
                    value: cpu.clone(),
                    reason: "cpu limit must not be empty",
                });
            }
        }
        if let Some(ref mem) = self.memory {
            if mem.trim().is_empty() {
                return Err(Error::Name {
                    field: "spec.limits.memory",
                    value: mem.clone(),
                    reason: "memory limit must not be empty",
                });
            }
        }
        if let Some(replicas) = self.replicas {
            if replicas == 0 {
                return Err(Error::Name {
                    field: "spec.limits.replicas",
                    value: "0".to_string(),
                    reason: "replicas must be >= 1",
                });
            }
        }
        Ok(())
    }
}

/// Least-privilege data access requirement declared by an application (AP-04, AP-05).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DataNeed {
    /// Target Context Space name (DNS-1123 label) (AP-05).
    pub context_space_ref: String,
    /// Entity types required by the application (AP-05).
    pub entity_types: Vec<String>,
    /// Whitelist of readable or writable attribute names (empty means all readable attributes) (AP-05).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<String>,
    /// CIM 009 clause 4.20 operations or operation groups requested (AP-05).
    pub operations: Vec<OperationRef>,
    /// Residual NGSI-LD query filter string (AP-05).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,
    /// Residual scope query filter string (AP-05).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_q: Option<String>,
    /// Residual geographic query filter string (AP-05).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geo_q: Option<String>,
}

impl DataNeed {
    /// Validates context space reference, entity types, attributes, and operations.
    pub fn validate(&self) -> Result<()> {
        names::validate_dns1123_label(&self.context_space_ref).map_err(|e| match e {
            Error::Name { reason, .. } => Error::Name {
                field: "dataNeeds.contextSpaceRef",
                value: self.context_space_ref.clone(),
                reason,
            },
            other => other,
        })?;

        if self.entity_types.is_empty() {
            return Err(Error::Name {
                field: "dataNeeds.entityTypes",
                value: String::new(),
                reason: "entityTypes must not be empty",
            });
        }

        let mut seen_types = std::collections::BTreeSet::new();
        for t in &self.entity_types {
            names::validate_entity_type(t)?;
            if !seen_types.insert(t.as_str()) {
                return Err(Error::Name {
                    field: "dataNeeds.entityTypes",
                    value: t.clone(),
                    reason: "duplicate entity type in entityTypes list",
                });
            }
        }

        let mut seen_attrs = std::collections::BTreeSet::new();
        for attr in &self.attributes {
            if attr.trim().is_empty() {
                return Err(Error::Name {
                    field: "dataNeeds.attributes",
                    value: attr.clone(),
                    reason: "attribute name must not be empty",
                });
            }
            if !seen_attrs.insert(attr.as_str()) {
                return Err(Error::Name {
                    field: "dataNeeds.attributes",
                    value: attr.clone(),
                    reason: "duplicate attribute name in attributes list",
                });
            }
        }

        if self.operations.is_empty() {
            return Err(Error::Name {
                field: "dataNeeds.operations",
                value: String::new(),
                reason: "operations must not be empty",
            });
        }

        let mut seen_ops = std::collections::BTreeSet::new();
        for op in &self.operations {
            let wire = op.as_str();
            if !seen_ops.insert(wire) {
                return Err(Error::Name {
                    field: "dataNeeds.operations",
                    value: wire.to_string(),
                    reason: "duplicate operation in operations list",
                });
            }
        }

        Ok(())
    }

    /// Returns `true` if any requested operation or group modifies context state (AP-09).
    pub fn has_write(&self) -> bool {
        self.operations.iter().any(|op| match op {
            OperationRef::Single(s) => s.is_write(),
            OperationRef::Group(g) => {
                matches!(g, OperationGroup::UpdateOps | OperationGroup::FederationOps)
            }
        })
    }
}

/// Desired specification of an [`App`][crate::kinds::App] resource (AP-01..AP-33).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AppSpec {
    /// Operational execution class (`static`, `service`, `fullstack`) (AP-01, AP-25).
    #[serde(rename = "kind")]
    pub class: AppClass,
    /// Target visibility and audience access scope (AP-01).
    pub visibility: AppVisibility,
    /// Lifecycle state (`draft`, `preview`, `published`, `retired`) (AP-18).
    pub lifecycle: AppLifecycle,
    /// Source code location or container image (AP-01, AP-02, AP-13).
    pub source: AppSource,
    /// Data needs and permissions requested by the application (AP-01, AP-05).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub data_needs: Vec<DataNeed>,
    /// Optional resource quotas and replica limits (AP-01, AP-15).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<AppLimits>,
    /// Public URL path route prefixes (e.g. `/apps/air-quality/`) (AP-14, AP-26).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<String>,
}

impl Kind for AppSpec {
    const KIND: &'static str = "App";
    const PLURAL: &'static str = "apps";
    const SCOPE: Scope = Scope::Project;
    const PATH_TEMPLATE: &'static str = "projects/{project}/apps/{name}/app.yaml";

    fn validate_spec(&self, meta: &ObjectMeta) -> Result<()> {
        names::validate_dns1123_label(&meta.name)?;
        self.validate()
    }
}

impl AppSpec {
    /// Validates application class, data needs, source, limits, routes, and lifecycle constraints.
    pub fn validate(&self) -> Result<()> {
        self.source.validate()?;

        if let Some(ref limits) = self.limits {
            limits.validate()?;
        }

        for route in &self.routes {
            if !route.starts_with('/') {
                return Err(Error::Name {
                    field: "spec.routes",
                    value: route.clone(),
                    reason: "route must start with `/`",
                });
            }
        }

        if self.class != AppClass::Static && self.data_needs.is_empty() {
            return Err(Error::Name {
                field: "spec.dataNeeds",
                value: String::new(),
                reason: "dataNeeds must not be empty for service and fullstack apps (AP-05)",
            });
        }

        for need in &self.data_needs {
            need.validate()?;
        }

        if self.lifecycle == AppLifecycle::Published {
            if self.visibility == AppVisibility::Private {
                return Err(Error::Name {
                    field: "spec.visibility",
                    value: self.visibility.as_str().to_string(),
                    reason: "published app cannot have private visibility (AP-18)",
                });
            }
            if matches!(self.class, AppClass::Static | AppClass::Fullstack)
                && self.routes.is_empty()
            {
                return Err(Error::Name {
                    field: "spec.routes",
                    value: String::new(),
                    reason:
                        "published static or fullstack app must declare at least one route (AP-14)",
                });
            }
        }

        Ok(())
    }

    /// Returns `true` if any declared data need includes a write operation (AP-09).
    pub fn write_operations(&self) -> bool {
        self.data_needs.iter().any(|need| need.has_write())
    }

    /// Checks whether transitioning to `next` lifecycle state is permitted from current state (AP-18).
    pub fn allows_transition_to(&self, next: AppLifecycle) -> bool {
        self.lifecycle.allows_transition_to(next)
    }
}
