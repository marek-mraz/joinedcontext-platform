//! Manifest kinds for projects and context spaces (T-0112, PF-05, PF-06, PF-07, PF-09, PF-17, PF-19).

use crate::envelope::{Kind, ObjectMeta, Ref, Scope};
use crate::error::{Error, Result};
use crate::names;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Desired specification of a [`Project`][crate::kinds::Project] resource (PF-05, PF-17).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProjectSpec {
    /// Reference to the parent Organization.
    pub organization_ref: Ref,
    /// Optional resource quotas for this Project (PF-17).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quotas: Option<Quotas>,
}

impl Kind for ProjectSpec {
    const KIND: &'static str = "Project";
    const PLURAL: &'static str = "projects";
    const SCOPE: Scope = Scope::Organization;

    fn validate_spec(&self, _meta: &ObjectMeta) -> Result<()> {
        self.validate()
    }

    fn repo_path(&self, meta: &ObjectMeta) -> String {
        format!("projects/{}/project.yaml", meta.name)
    }
}

impl ProjectSpec {
    /// Validates the organization reference and optional quotas.
    pub fn validate(&self) -> Result<()> {
        let org_name = self.organization_ref.name();
        names::validate_dns1123_label(org_name)?;
        if let Some(kind) = self.organization_ref.kind() {
            if kind != "Organization" {
                return Err(Error::Kind {
                    expected: "Organization",
                    got: kind.to_string(),
                });
            }
        }
        if let Some(ref q) = self.quotas {
            q.validate()?;
        }
        Ok(())
    }
}

/// Structural resource quotas per project (PF-17).
///
/// An absent field indicates unlimited quota for that resource.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Quotas {
    /// Maximum number of active Context Spaces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_spaces: Option<u32>,
    /// Maximum number of resident streaming pipelines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resident_pipelines: Option<u32>,
    /// Maximum number of public endpoints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_endpoints: Option<u32>,
    /// Maximum ingestion rate in events per second.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingest_events_per_second: Option<u32>,
}

impl Quotas {
    /// Validates that all defined quotas are positive integers (>= 1).
    pub fn validate(&self) -> Result<()> {
        if let Some(val) = self.context_spaces {
            if val == 0 {
                return Err(Error::Name {
                    field: "quotas.contextSpaces",
                    value: "0".to_string(),
                    reason: "quota must be >= 1",
                });
            }
        }
        if let Some(val) = self.resident_pipelines {
            if val == 0 {
                return Err(Error::Name {
                    field: "quotas.residentPipelines",
                    value: "0".to_string(),
                    reason: "quota must be >= 1",
                });
            }
        }
        if let Some(val) = self.public_endpoints {
            if val == 0 {
                return Err(Error::Name {
                    field: "quotas.publicEndpoints",
                    value: "0".to_string(),
                    reason: "quota must be >= 1",
                });
            }
        }
        if let Some(val) = self.ingest_events_per_second {
            if val == 0 {
                return Err(Error::Name {
                    field: "quotas.ingestEventsPerSecond",
                    value: "0".to_string(),
                    reason: "quota must be >= 1",
                });
            }
        }
        Ok(())
    }
}

/// Desired specification of a [`ContextSpace`][crate::kinds::ContextSpace] resource (PF-06, PF-09, PF-19).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ContextSpaceSpec {
    /// Whether this context space is an ephemeral sandbox (CC-67, PF-19).
    #[serde(default)]
    pub is_sandbox: bool,
    /// Default locale for entities and metadata within this space (PF-25).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_locale: Option<String>,
    /// Reference to the primary LinkML Data Model for this space (Architecture/03).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_model_ref: Option<Ref>,
    /// Enforced time-to-live in days for ephemeral sandboxes (1..=14, PF-19).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_days: Option<u32>,
}

impl Kind for ContextSpaceSpec {
    const KIND: &'static str = "ContextSpace";
    const PLURAL: &'static str = "contextspaces";
    const SCOPE: Scope = Scope::Project;

    fn validate_spec(&self, meta: &ObjectMeta) -> Result<()> {
        self.validate_with_meta(meta)
    }

    fn repo_path(&self, meta: &ObjectMeta) -> String {
        let ns = meta.namespace.as_deref().unwrap_or_default();
        format!("projects/{ns}/spaces/{}/space.yaml", meta.name)
    }
}

impl ContextSpaceSpec {
    /// Validates locale and sandbox TTL rules without metadata.
    pub fn validate(&self) -> Result<()> {
        if let Some(ref loc) = self.default_locale {
            names::validate_locale(loc)?;
        }

        if let Some(ref dm) = self.data_model_ref {
            names::validate_dns1123_label(dm.name())?;
            if let Some(kind) = dm.kind() {
                if kind != "DataModel" {
                    return Err(Error::Kind {
                        expected: "DataModel",
                        got: kind.to_string(),
                    });
                }
            }
        }

        if let Some(ttl) = self.ttl_days {
            if !self.is_sandbox {
                return Err(Error::Name {
                    field: "spec.ttlDays",
                    value: ttl.to_string(),
                    reason: "ttlDays is only allowed on sandbox context spaces (PF-19)",
                });
            }
            if !(1..=14).contains(&ttl) {
                return Err(Error::Name {
                    field: "spec.ttlDays",
                    value: ttl.to_string(),
                    reason: "sandbox ttlDays must be between 1 and 14 calendar days (PF-19)",
                });
            }
        }

        Ok(())
    }

    /// Validates the context space against PF-09, PF-19 and locale rules.
    pub fn validate_with_meta(&self, meta: &ObjectMeta) -> Result<()> {
        names::validate_space_name(&meta.name)?;
        self.validate()?;
        Ok(())
    }
}
