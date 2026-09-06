//! Kubernetes-style resource envelope, metadata, and status types (MF-01..MF-08).

use crate::error::{Error, Result};
use crate::i18n::MultiLanguageMap;
use crate::names;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The canonical API version for joinedcontext resources (MF-01).
pub const API_VERSION: &str = "joinedcontext.com/v1alpha1";

/// Trait implemented by every manifest spec kind.
pub trait Kind:
    Serialize + serde::de::DeserializeOwned + JsonSchema + Clone + std::fmt::Debug + PartialEq
{
    /// Manifest kind name (e.g. "ContextSpace").
    const KIND: &'static str;
    /// Plural resource name for URL routing (e.g. "contextspaces").
    const PLURAL: &'static str;
    /// Target scope (Organization or Project).
    const SCOPE: Scope;

    /// Kind-specific validation of the spec against its own metadata.
    ///
    /// The default checks nothing; every kind that has invariants of its own implements it,
    /// so [`ResourceEnvelope::validate`] is the single entry point for `jcctl`, the Portal
    /// API and CI.
    fn validate_spec(&self, _meta: &ObjectMeta) -> Result<()> {
        Ok(())
    }

    /// Path of this resource inside the organization repository (MF-06, Architecture/06 section 1).
    ///
    /// The default is `projects/{namespace}/{plural}/{name}.yaml` for project-scoped kinds
    /// and `{plural}/{name}.yaml` for organization-scoped ones; kinds whose directory nests
    /// deeper (ContextSpace, Endpoint, Policy) override it.
    fn repo_path(&self, meta: &ObjectMeta) -> String {
        let name = &meta.name;
        let plural = Self::PLURAL;
        match Self::SCOPE {
            Scope::Organization => format!("{plural}/{name}.yaml"),
            Scope::Project => {
                let ns = meta.namespace.as_deref().unwrap_or_default();
                format!("projects/{ns}/{plural}/{name}.yaml")
            }
        }
    }
}

/// Target scope hierarchy of a manifest kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum Scope {
    /// Organization-level resource (namespace must be "org").
    Organization,
    /// Project-level resource (namespace must be a project slug).
    Project,
}

/// Kubernetes-style resource envelope (MF-01..MF-04).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    deny_unknown_fields,
    rename_all = "camelCase",
    bound(serialize = "S: Kind", deserialize = "S: Kind")
)]
pub struct ResourceEnvelope<S: Kind> {
    /// API version (must match [`API_VERSION`]).
    #[serde(deserialize_with = "de_api_version")]
    pub api_version: String,
    /// Resource kind name (must match [`Kind::KIND`]).
    #[serde(deserialize_with = "de_kind::<S, _>")]
    pub kind: String,
    /// Metadata identifying and labeling the resource.
    pub metadata: ObjectMeta,
    /// Desired spec state.
    pub spec: S,
    /// Server-computed status. Stripped during export and serialization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
}

/// Deserializes and validates that `apiVersion` matches [`API_VERSION`].
pub fn de_api_version<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s != API_VERSION {
        return Err(serde::de::Error::custom(Error::ApiVersion(s)));
    }
    Ok(s)
}

/// Deserializes and validates that `kind` matches [`Kind::KIND`].
pub fn de_kind<'de, S: Kind, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<String, D::Error> {
    let s = String::deserialize(deserializer)?;
    if s != S::KIND {
        return Err(serde::de::Error::custom(Error::Kind {
            expected: S::KIND,
            got: s,
        }));
    }
    Ok(s)
}

/// Validates a list of ISO 639-1 locales and the fallback that must be among them (PF-25).
pub fn validate_locales(locales: &[String], default_locale: &str) -> Result<()> {
    if locales.is_empty() {
        return Err(Error::Name {
            field: "locales",
            value: String::new(),
            reason: "locales list must not be empty",
        });
    }
    names::validate_locale(default_locale)?;
    let mut seen = std::collections::BTreeSet::new();
    for loc in locales {
        names::validate_locale(loc)?;
        if !seen.insert(loc.as_str()) {
            return Err(Error::Name {
                field: "locales",
                value: loc.clone(),
                reason: "duplicate locale in locales list",
            });
        }
    }
    if !seen.contains(default_locale) {
        return Err(Error::MissingFallbackLocale(default_locale.to_string()));
    }
    Ok(())
}

impl<S: Kind> ResourceEnvelope<S> {
    /// Creates a new resource envelope with default [`API_VERSION`] and [`Kind::KIND`].
    pub fn new(metadata: ObjectMeta, spec: S) -> Self {
        Self {
            api_version: API_VERSION.to_string(),
            kind: S::KIND.to_string(),
            metadata,
            spec,
            status: None,
        }
    }

    /// Validates envelope metadata and scope agreement (MF-02).
    pub fn validate(&self) -> Result<()> {
        self.metadata.validate()?;
        let ns = match &self.metadata.namespace {
            Some(ns) => ns.as_str(),
            None => {
                return Err(Error::Name {
                    field: "metadata.namespace",
                    value: String::new(),
                    reason: "namespace is required",
                });
            }
        };

        match S::SCOPE {
            Scope::Organization => {
                if ns != "org" {
                    return Err(Error::Name {
                        field: "metadata.namespace",
                        value: ns.to_string(),
                        reason: "organization-scoped resources must have namespace `org`",
                    });
                }
            }
            Scope::Project => {
                if ns == "org" {
                    return Err(Error::Name {
                        field: "metadata.namespace",
                        value: ns.to_string(),
                        reason: "project-scoped resources must not have namespace `org`",
                    });
                }
            }
        }

        self.spec.validate_spec(&self.metadata)
    }

    /// Strips status in-place (MF-04).
    pub fn strip_status(&mut self) {
        self.status = None;
    }

    /// Returns a copy of the envelope without status (MF-04).
    pub fn without_status(mut self) -> Self {
        self.status = None;
        self
    }

    /// Derives the canonical repository file path for this resource (MF-06).
    pub fn resource_path(&self) -> Result<String> {
        self.validate()?;
        Ok(self.spec.repo_path(&self.metadata))
    }

    /// Serializes envelope to YAML, unconditionally stripping server status (MF-04).
    pub fn to_yaml(&self) -> std::result::Result<String, serde_norway::Error> {
        let mut stripped = self.clone();
        stripped.strip_status();
        serde_norway::to_string(&stripped)
    }

    /// Deserializes envelope from YAML.
    pub fn from_yaml(s: &str) -> std::result::Result<Self, serde_norway::Error> {
        serde_norway::from_str(s)
    }

    /// Serializes envelope to pretty JSON, unconditionally stripping server status (MF-04).
    pub fn to_json(&self) -> std::result::Result<String, serde_json::Error> {
        let mut stripped = self.clone();
        stripped.strip_status();
        serde_json::to_string_pretty(&stripped)
    }

    /// Deserializes envelope from JSON.
    pub fn from_json(s: &str) -> std::result::Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

/// Metadata envelope attached to every platform resource (MF-02).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObjectMeta {
    /// Resource name (DNS-1123 label).
    pub name: String,
    /// Resource namespace ("org" or project slug).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Key-value labels for filtering (MF-10).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Key-value annotations for provenance and ownership (MF-08).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
    /// Human-readable multilingual title (PF-24).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<MultiLanguageMap>,
    /// Human-readable multilingual description (PF-24).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<MultiLanguageMap>,
}

impl ObjectMeta {
    /// Creates an [`ObjectMeta`] with name and namespace.
    pub fn new(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            namespace: Some(namespace.into()),
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
            title: None,
            description: None,
        }
    }

    /// Validates DNS-1123 name and optional namespace.
    pub fn validate(&self) -> Result<()> {
        names::validate_dns1123_label(&self.name)?;
        if let Some(ref ns) = self.namespace {
            names::validate_namespace(ns)?;
        }
        Ok(())
    }
}

/// Well-known platform annotations (MF-08, CC-69).
pub mod annotations {
    /// Managed attributes annotation for server-side attribute ownership (MF-08, CC-69).
    pub const MANAGED_ATTRIBUTES: &str = "joinedcontext.com/managed-attributes";
    /// Provenance tracking annotation for imported bundles (MF-08, MF-20).
    pub const IMPORTED_FROM: &str = "joinedcontext.com/imported-from";
    /// Provenance tracking annotation for SyncSource instances (MF-08, MF-27).
    pub const SYNC_SOURCE: &str = "joinedcontext.com/sync-source";
    /// Provenance tracking annotation for blueprint instantiations (MF-08).
    pub const BLUEPRINT: &str = "joinedcontext.com/blueprint";
    /// Provenance tracking annotation for generator tools (MF-08).
    pub const GENERATED_BY: &str = "joinedcontext.com/generated-by";
    /// Digest of the prompt that created the resource (MF-08).
    pub const PROMPT_DIGEST: &str = "joinedcontext.com/prompt-digest";
}

/// Reference to another resource, either bare name or typed reference (MF-07).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Ref {
    /// Bare string resource name.
    Name(String),
    /// Typed reference with kind, name, and optional namespace.
    Typed(TypedRef),
}

impl Ref {
    /// Returns the referenced resource name.
    pub fn name(&self) -> &str {
        match self {
            Ref::Name(name) => name.as_str(),
            Ref::Typed(typed) => typed.name.as_str(),
        }
    }

    /// Returns the referenced resource kind if typed.
    pub fn kind(&self) -> Option<&str> {
        match self {
            Ref::Name(_) => None,
            Ref::Typed(typed) => Some(typed.kind.as_str()),
        }
    }

    /// Returns the referenced resource namespace if specified.
    pub fn namespace(&self) -> Option<&str> {
        match self {
            Ref::Name(_) => None,
            Ref::Typed(typed) => typed.namespace.as_deref(),
        }
    }
}

/// Structured typed resource reference (MF-07).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TypedRef {
    /// Target resource kind.
    pub kind: String,
    /// Target resource name.
    pub name: String,
    /// Target resource namespace (defaults to caller namespace if omitted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// Reference to a credential stored in SOPS or OpenBao (PF-36).
///
/// `deny_unknown_fields` is a security control: it rejects inline `value:` or `password:`
/// fields at parse time, enforcing that secrets never appear in Git or manifest files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SecretRef {
    /// Secret name in secret store.
    pub name: String,
    /// Optional key within secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Optional environment variable name for injection into runners.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_var: Option<String>,
}

/// Server-computed lifecycle and reconciliation status (MF-04). Never stored in Git.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Status {
    /// Current lifecycle phase.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<Phase>,
    /// Git commit revision observed during reconciliation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_revision: Option<String>,
    /// Reconciler condition transitions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

/// Lifecycle phase enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub enum Phase {
    /// Resource manifest is in draft state.
    Draft,
    /// Resource is pending review or approval.
    Pending,
    /// Resource deployment is in progress.
    Deploying,
    /// Resource is live and active in cluster.
    Live,
    /// Reconciliation error.
    Error,
}

/// Status condition entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Condition {
    /// Type of condition (e.g. Reconciled, Ready).
    pub r#type: String,
    /// Status value ("True", "False", "Unknown").
    pub status: String,
    /// Machine-readable reason code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Human-readable message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Last transition timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_transition_time: Option<chrono::DateTime<chrono::Utc>>,
}
