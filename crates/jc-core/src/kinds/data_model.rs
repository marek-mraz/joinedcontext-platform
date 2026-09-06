//! Manifest kind for LinkML Data Models and generated schema artifacts (T-0117, DM-01..DM-53).

use crate::envelope::{Kind, ObjectMeta, Scope, TypedRef};
use crate::error::{Error, Result};
use crate::names;
use chrono::{DateTime, Utc};
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use std::sync::LazyLock;

static SEMVER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
        .expect("valid regex for SemVer")
});

/// Semantic version string conforming to `major.minor.patch` (DM-22).
///
/// Pre-release identifiers and build metadata are not used by the platform and are rejected.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SemVer(String);

impl SemVer {
    /// Creates a validated [`SemVer`] instance (DM-22).
    pub fn new(s: &str) -> Result<Self> {
        let caps = SEMVER_RE.captures(s).ok_or_else(|| Error::Name {
            field: "version",
            value: s.to_string(),
            reason: "version must follow semantic version format `major.minor.patch` with non-negative integers and no leading zeros (DM-22)",
        })?;

        // Ensure major, minor, and patch values fit within u32.
        caps[1].parse::<u32>().map_err(|_| Error::Name {
            field: "version",
            value: s.to_string(),
            reason: "major version exceeds maximum u32",
        })?;
        caps[2].parse::<u32>().map_err(|_| Error::Name {
            field: "version",
            value: s.to_string(),
            reason: "minor version exceeds maximum u32",
        })?;
        caps[3].parse::<u32>().map_err(|_| Error::Name {
            field: "version",
            value: s.to_string(),
            reason: "patch version exceeds maximum u32",
        })?;

        Ok(Self(s.to_string()))
    }

    /// Returns a string slice of the semantic version.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the major version number (DM-22).
    pub fn major(&self) -> u32 {
        let mut parts = self.0.split('.');
        parts.next().and_then(|p| p.parse().ok()).unwrap_or(0)
    }

    /// Returns the minor version number (DM-22).
    pub fn minor(&self) -> u32 {
        let mut parts = self.0.split('.');
        parts.next();
        parts.next().and_then(|p| p.parse().ok()).unwrap_or(0)
    }

    /// Returns the patch version number (DM-22).
    pub fn patch(&self) -> u32 {
        let mut parts = self.0.split('.');
        parts.next();
        parts.next();
        parts.next().and_then(|p| p.parse().ok()).unwrap_or(0)
    }
}

impl AsRef<str> for SemVer {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SemVer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for SemVer {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

impl Serialize for SemVer {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SemVer {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        SemVer::new(&s).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for SemVer {
    fn schema_name() -> String {
        "SemVer".to_string()
    }

    fn json_schema(_gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        let schema = schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::String.into()),
            string: Some(Box::new(schemars::schema::StringValidation {
                pattern: Some(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$".to_string()),
                ..Default::default()
            })),
            metadata: Some(Box::new(schemars::schema::Metadata {
                description: Some(
                    "Semantic version string conforming to major.minor.patch (DM-22)".to_string(),
                ),
                ..Default::default()
            })),
            ..Default::default()
        };
        schemars::schema::Schema::Object(schema)
    }
}

/// Lifecycle state of a DataModel version (DM-26, DM-48).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum DataModelLifecycle {
    /// Draft data model under active development (DM-26).
    Draft,
    /// Published immutable data model version (DM-22, DM-26).
    Published,
    /// Deprecated data model version superseded by a newer release (DM-26).
    Deprecated,
    /// Retired data model version accepting no new references (DM-26).
    Retired,
    /// Read-only mirror of a foreign data model (DM-48, DM-49).
    Mirrored,
}

impl DataModelLifecycle {
    /// Returns the kebab-case wire name for this lifecycle state.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Published => "published",
            Self::Deprecated => "deprecated",
            Self::Retired => "retired",
            Self::Mirrored => "mirrored",
        }
    }

    /// Returns `true` if transitioning from `self` to `next` is allowed by the DM-26 state machine.
    pub fn allows_transition_to(&self, next: Self) -> bool {
        if *self == next {
            return true;
        }
        matches!(
            (*self, next),
            (Self::Draft, Self::Published)
                | (Self::Published, Self::Deprecated)
                | (Self::Deprecated, Self::Retired)
        )
    }
}

impl fmt::Display for DataModelLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Source provenance and authoring origin of a LinkML data model (DM-01, DM-08, DM-48).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum DataModelSource {
    /// Locally authored LinkML data model (DM-01).
    Authored {},
    /// Imported data model from upstream repository (DM-08).
    Imported {
        /// Git repository URL of upstream data model.
        repository: String,
        /// Relative path inside the upstream repository.
        path: String,
        /// Pinned Git commit SHA (7 to 40 lowercase hexadecimal characters).
        commit: String,
    },
    /// Mirrored foreign data model from remote endpoint (DM-48).
    Remote {
        /// Remote endpoint URL from which the model was fetched.
        url: String,
        /// Semantic version of the remote model.
        version: SemVer,
        /// SHA-256 digest of the fetched schema (64 lowercase hexadecimal characters).
        sha256: String,
        /// UTC timestamp when the remote model was fetched.
        fetched_at: DateTime<Utc>,
    },
}

impl DataModelSource {
    /// Validates source repository, commit hash, URL, or digest according to provenance rules (DM-08, DM-48).
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Authored {} => Ok(()),
            Self::Imported {
                repository,
                path,
                commit,
            } => {
                if repository.trim().is_empty() {
                    return Err(Error::Name {
                        field: "source.repository",
                        value: repository.clone(),
                        reason: "repository must not be empty",
                    });
                }
                if path.trim().is_empty() {
                    return Err(Error::Name {
                        field: "source.path",
                        value: path.clone(),
                        reason: "path must not be empty",
                    });
                }
                let commit_len = commit.len();
                if !(7..=40).contains(&commit_len)
                    || !commit.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
                {
                    return Err(Error::Name {
                        field: "source.commit",
                        value: commit.clone(),
                        reason: "commit must be a 7 to 40 character lowercase hexadecimal Git commit hash",
                    });
                }
                Ok(())
            }
            Self::Remote { url, sha256, .. } => {
                if url.trim().is_empty() {
                    return Err(Error::Name {
                        field: "source.url",
                        value: url.clone(),
                        reason: "url must not be empty",
                    });
                }
                if sha256.len() != 64 || !sha256.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
                {
                    return Err(Error::Name {
                        field: "source.sha256",
                        value: sha256.clone(),
                        reason: "sha256 must be exactly 64 lowercase hexadecimal characters",
                    });
                }
                Ok(())
            }
        }
    }
}

/// Committed generated artifacts accompanying the LinkML source (DM-02).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GeneratedArtifacts {
    /// Relative path to compiled JSON Schema draft-07 (DM-02, DM-03).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json_schema: Option<String>,
    /// Relative path to compiled JSON-LD @context (DM-02).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    /// Relative path to generated model documentation (DM-02).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docs: Option<String>,
    /// Relative path to validated example entity (DM-02, DM-21).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example: Option<String>,
}

impl GeneratedArtifacts {
    /// Returns `true` if all four standard generated artifacts are present (DM-02).
    pub fn is_complete(&self) -> bool {
        self.json_schema.is_some()
            && self.context.is_some()
            && self.docs.is_some()
            && self.example.is_some()
    }
}

/// Validates that a path is relative, non-empty, and free of `..` segments.
fn validate_relative_path(path: &str, field_name: &'static str) -> Result<()> {
    if path.trim().is_empty() {
        return Err(Error::Name {
            field: field_name,
            value: path.to_string(),
            reason: "path must not be empty",
        });
    }
    if path.starts_with('/') || path.starts_with('\\') {
        return Err(Error::Name {
            field: field_name,
            value: path.to_string(),
            reason: "path must be relative (must not start with `/`)",
        });
    }
    for segment in path.split(['/', '\\']) {
        if segment == ".." {
            return Err(Error::Name {
                field: field_name,
                value: path.to_string(),
                reason: "path must not contain `..` path traversal segments",
            });
        }
    }
    Ok(())
}

/// Desired specification of a [`DataModel`] resource (DM-01..DM-53).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DataModelSpec {
    /// DNS-1123 label of the owning ContextSpace.
    pub context_space_ref: String,
    /// Semantic version of the data model (DM-22).
    pub version: SemVer,
    /// Lifecycle state of this data model version (DM-26).
    pub lifecycle: DataModelLifecycle,
    /// Source provenance and authoring origin of the model (DM-01, DM-08, DM-48).
    pub source: DataModelSource,
    /// Repository-relative path to the authoritative LinkML source file (DM-01).
    pub linkml_path: String,
    /// Generated and committed schema artifacts (DM-02).
    #[serde(default)]
    pub generated: GeneratedArtifacts,
    /// Whether entities of this model may contain undeclared attributes (DM-28).
    #[serde(default)]
    pub open_world: bool,
    /// Informational list of platform resources consuming this model version (DM-25).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consumers: Vec<TypedRef>,
}

impl Kind for DataModelSpec {
    const KIND: &'static str = "DataModel";
    const PLURAL: &'static str = "datamodels";
    const SCOPE: Scope = Scope::Project;
    const PATH_TEMPLATE: &'static str = "projects/{project}/spaces/{space}/datamodels/{name}.yaml";

    fn validate_spec(&self, meta: &ObjectMeta) -> Result<()> {
        names::validate_dns1123_label(&meta.name)?;
        self.validate()
    }

    fn context_space(&self) -> Option<&str> {
        Some(&self.context_space_ref)
    }
}

impl DataModelSpec {
    /// Validates context space reference, LinkML path, artifacts, lifecycle invariants, and source provenance.
    pub fn validate(&self) -> Result<()> {
        names::validate_dns1123_label(&self.context_space_ref).map_err(|e| match e {
            Error::Name { reason, .. } => Error::Name {
                field: "contextSpaceRef",
                value: self.context_space_ref.clone(),
                reason,
            },
            other => other,
        })?;

        validate_relative_path(&self.linkml_path, "linkmlPath")?;
        if !self.linkml_path.ends_with(".linkml.yaml") {
            return Err(Error::Name {
                field: "linkmlPath",
                value: self.linkml_path.clone(),
                reason: "linkmlPath must end with `.linkml.yaml` (DM-01)",
            });
        }

        if let Some(ref p) = self.generated.json_schema {
            validate_relative_path(p, "generated.jsonSchema")?;
        }
        if let Some(ref p) = self.generated.context {
            validate_relative_path(p, "generated.context")?;
        }
        if let Some(ref p) = self.generated.docs {
            validate_relative_path(p, "generated.docs")?;
        }
        if let Some(ref p) = self.generated.example {
            validate_relative_path(p, "generated.example")?;
        }

        if self.lifecycle == DataModelLifecycle::Published {
            if self.generated.json_schema.is_none() {
                return Err(Error::Name {
                    field: "generated.jsonSchema",
                    value: String::new(),
                    reason: "jsonSchema artifact is required when lifecycle is `published` (DM-02)",
                });
            }
            if self.generated.context.is_none() {
                return Err(Error::Name {
                    field: "generated.context",
                    value: String::new(),
                    reason: "context artifact is required when lifecycle is `published` (DM-02)",
                });
            }
            if self.generated.docs.is_none() {
                return Err(Error::Name {
                    field: "generated.docs",
                    value: String::new(),
                    reason: "docs artifact is required when lifecycle is `published` (DM-02)",
                });
            }
            if self.generated.example.is_none() {
                return Err(Error::Name {
                    field: "generated.example",
                    value: String::new(),
                    reason: "example artifact is required when lifecycle is `published` (DM-02)",
                });
            }
        }

        match (&self.lifecycle, &self.source) {
            (DataModelLifecycle::Mirrored, DataModelSource::Remote { .. }) => {}
            (DataModelLifecycle::Mirrored, _) => {
                return Err(Error::Name {
                    field: "source",
                    value: self.lifecycle.as_str().to_string(),
                    reason: "source must be `remote` when lifecycle is `mirrored` (DM-48)",
                });
            }
            (_, DataModelSource::Remote { .. }) => {
                return Err(Error::Name {
                    field: "source",
                    value: "remote".to_string(),
                    reason:
                        "source `remote` is only permitted when lifecycle is `mirrored` (DM-48)",
                });
            }
            _ => {}
        }

        self.source.validate()?;

        for consumer in &self.consumers {
            names::validate_dns1123_label(&consumer.name)?;
            if let Some(ref ns) = consumer.namespace {
                names::validate_namespace(ns)?;
            }
        }

        Ok(())
    }

    /// Returns the version-pinned schema URL path for this data model (DM-22, SP-13).
    pub fn schema_url_path(&self, name: &str) -> String {
        format!("schema/v{}/{name}.json", self.version.major())
    }

    /// Returns `true` if this data model version can be referenced by Endpoints and Pipelines (DM-26).
    pub fn can_be_referenced(&self) -> bool {
        self.lifecycle == DataModelLifecycle::Published
    }

    /// Returns `true` if transitioning from current lifecycle to `next` is permitted (DM-26).
    pub fn allows_transition_to(&self, next: DataModelLifecycle) -> bool {
        self.lifecycle.allows_transition_to(next)
    }
}
