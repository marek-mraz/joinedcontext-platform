//! Manifest kinds for LinkML-Map model-to-model transformations (T-0118, DM-33..DM-42).

use crate::envelope::{Kind, ObjectMeta, Scope};
use crate::error::{Error, Result};
use crate::kinds::data_model::SemVer;
use crate::names;
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::LazyLock;

static TARGET_SLOT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").expect("valid regex"));

/// Reference to a DataModel with name and semantic version (DM-33).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DataModelRef {
    /// Optional resource kind (must be `DataModel` if present) (MF-07).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Referenced DataModel name (DNS-1123 label).
    pub name: String,
    /// Referenced DataModel semantic version (DM-22, DM-33).
    pub version: SemVer,
}

impl DataModelRef {
    /// Creates a new data model reference with name and semantic version.
    pub fn new(name: impl Into<String>, version: SemVer) -> Self {
        Self {
            kind: Some("DataModel".to_string()),
            name: name.into(),
            version,
        }
    }

    /// Validates the data model name and optional kind string.
    pub fn validate(&self, field_prefix: &'static str) -> Result<()> {
        if let Some(ref k) = self.kind {
            if k != "DataModel" {
                return Err(Error::Kind {
                    expected: "DataModel",
                    got: k.clone(),
                });
            }
        }
        names::validate_dns1123_label(&self.name).map_err(|e| match e {
            Error::Name { reason, .. } => Error::Name {
                field: field_prefix,
                value: self.name.clone(),
                reason,
            },
            other => other,
        })
    }
}

/// Native code escape hatch block for logic LinkML-Map cannot express (DM-38).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NativeBlock {
    /// Target slot identifier to which this native block is attached (`^[A-Za-z_][A-Za-z0-9_]*$`, DM-38).
    pub target_slot: String,
    /// Native language of the code block (DM-37, DM-38).
    pub language: NativeLanguage,
    /// Source code of the native processor (non-empty, DM-38).
    pub source: String,
}

impl NativeBlock {
    /// Creates a new native code block.
    pub fn new(
        target_slot: impl Into<String>,
        language: NativeLanguage,
        source: impl Into<String>,
    ) -> Self {
        Self {
            target_slot: target_slot.into(),
            language,
            source: source.into(),
        }
    }

    /// Validates target slot identifier syntax and source non-emptiness (DM-38).
    pub fn validate(&self) -> Result<()> {
        if self.target_slot.is_empty() || !TARGET_SLOT_RE.is_match(&self.target_slot) {
            return Err(Error::Name {
                field: "spec.native.targetSlot",
                value: self.target_slot.clone(),
                reason: "targetSlot must be a non-empty identifier matching ^[A-Za-z_][A-Za-z0-9_]*$ (DM-38)",
            });
        }
        if self.source.trim().is_empty() {
            return Err(Error::Name {
                field: "spec.native.source",
                value: self.source.clone(),
                reason: "native source code must not be empty (DM-38)",
            });
        }
        Ok(())
    }
}

/// Supported native transformation language (DM-37, DM-38).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum NativeLanguage {
    /// Inline Bento Bloblang processor (DM-37, DM-38).
    Bloblang,
}

impl NativeLanguage {
    /// Returns the kebab-case wire name for this language.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Bloblang => "bloblang",
        }
    }
}

impl fmt::Display for NativeLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Golden test case asserting input entity produces expected output entity (DM-39).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MappingTest {
    /// Test case identifier (DNS-1123 label, DM-39).
    pub name: String,
    /// Sample input entity payload (JSON object, DM-39).
    pub input: serde_json::Value,
    /// Expected output entity payload (JSON object, DM-39).
    pub expected: serde_json::Value,
}

impl MappingTest {
    /// Creates a new golden test case with name, input, and expected output.
    pub fn new(
        name: impl Into<String>,
        input: serde_json::Value,
        expected: serde_json::Value,
    ) -> Self {
        Self {
            name: name.into(),
            input,
            expected,
        }
    }

    /// Validates test name and input/expected payloads (DM-39).
    pub fn validate(&self) -> Result<()> {
        names::validate_dns1123_label(&self.name).map_err(|e| match e {
            Error::Name { reason, .. } => Error::Name {
                field: "spec.tests.name",
                value: self.name.clone(),
                reason,
            },
            other => other,
        })?;

        if !self.input.is_object() {
            return Err(Error::Name {
                field: "spec.tests.input",
                value: self.input.to_string(),
                reason: "test input must be a JSON object (DM-39)",
            });
        }

        if !self.expected.is_object() {
            return Err(Error::Name {
                field: "spec.tests.expected",
                value: self.expected.to_string(),
                reason: "test expected must be a JSON object (DM-39)",
            });
        }

        Ok(())
    }
}

/// Desired specification of a [`Mapping`][crate::kinds::mapping::Mapping] resource (DM-33..DM-42).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MappingSpec {
    /// Context Space name to which this mapping belongs (PF-09, DM-33).
    pub context_space_ref: String,
    /// Source data model reference (DM-33).
    pub source: DataModelRef,
    /// Target data model reference (DM-33).
    pub target: DataModelRef,
    /// Verbatim LinkML-Map TransformationSpecification payload (DM-33).
    pub transformation: serde_json::Value,
    /// Native Bloblang escape hatch blocks (DM-38).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub native: Vec<NativeBlock>,
    /// Optional vocabulary alignment reference (DM-42).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vocabulary_alignment: Option<serde_json::Value>,
    /// Golden test cases asserting input entity produces expected output entity (DM-39).
    pub tests: Vec<MappingTest>,
}

impl Kind for MappingSpec {
    const KIND: &'static str = "Mapping";
    const PLURAL: &'static str = "mappings";
    const SCOPE: Scope = Scope::Project;
    const PATH_TEMPLATE: &'static str =
        "projects/{project}/spaces/{space}/datamodels/mappings/{name}.yaml";

    fn validate_spec(&self, meta: &ObjectMeta) -> Result<()> {
        names::validate_dns1123_label(&meta.name)?;
        self.validate()
    }

    fn context_space(&self) -> Option<&str> {
        Some(&self.context_space_ref)
    }
}

impl MappingSpec {
    /// Creates a new Mapping specification.
    pub fn new(
        context_space_ref: impl Into<String>,
        source: DataModelRef,
        target: DataModelRef,
        transformation: serde_json::Value,
        tests: Vec<MappingTest>,
    ) -> Self {
        Self {
            context_space_ref: context_space_ref.into(),
            source,
            target,
            transformation,
            native: Vec::new(),
            vocabulary_alignment: None,
            tests,
        }
    }

    /// Validates context space ref, source and target data models, transformation, native blocks, and tests.
    pub fn validate(&self) -> Result<()> {
        names::validate_space_name(&self.context_space_ref).map_err(|e| match e {
            Error::Name { reason, .. } => Error::Name {
                field: "spec.contextSpaceRef",
                value: self.context_space_ref.clone(),
                reason,
            },
            other => other,
        })?;

        self.source.validate("spec.source.name")?;
        self.target.validate("spec.target.name")?;

        if self.source.name == self.target.name && self.source.version == self.target.version {
            return Err(Error::Name {
                field: "spec.target",
                value: format!("{}:{}", self.target.name, self.target.version),
                reason: "source and target data models must not be identical (name, version) pair (DM-33)",
            });
        }

        let obj = match self.transformation.as_object() {
            Some(obj) => obj,
            None => {
                return Err(Error::Name {
                    field: "spec.transformation",
                    value: self.transformation.to_string(),
                    reason: "transformation must be a JSON object (DM-33)",
                });
            }
        };

        match obj
            .get("class_derivations")
            .or_else(|| obj.get("classDerivations"))
        {
            Some(cd) => match cd.as_object() {
                Some(cd_obj) if !cd_obj.is_empty() => {}
                _ => {
                    return Err(Error::Name {
                        field: "spec.transformation.class_derivations",
                        value: cd.to_string(),
                        reason: "transformation must carry a non-empty `class_derivations` object (DM-33)",
                    });
                }
            },
            None => {
                return Err(Error::Name {
                    field: "spec.transformation.class_derivations",
                    value: String::new(),
                    reason:
                        "transformation must carry a non-empty `class_derivations` object (DM-33)",
                });
            }
        }

        let mut seen_slots = std::collections::BTreeSet::new();
        for block in &self.native {
            block.validate()?;
            if !seen_slots.insert(&block.target_slot) {
                return Err(Error::Name {
                    field: "spec.native.targetSlot",
                    value: block.target_slot.clone(),
                    reason: "duplicate targetSlot in native blocks (DM-38)",
                });
            }
        }

        if self.tests.is_empty() {
            return Err(Error::Name {
                field: "spec.tests",
                value: String::new(),
                reason: "tests must contain at least one golden test case (DM-39)",
            });
        }

        let mut seen_test_names = std::collections::BTreeSet::new();
        for test in &self.tests {
            test.validate()?;
            if !seen_test_names.insert(&test.name) {
                return Err(Error::Name {
                    field: "spec.tests.name",
                    value: test.name.clone(),
                    reason: "duplicate test name in tests list (DM-39)",
                });
            }
        }

        Ok(())
    }

    /// Returns `true` if this mapping contains native Bloblang blocks requiring lane elevation (DM-38).
    pub fn requires_elevated_lane(&self) -> bool {
        !self.native.is_empty()
    }

    /// Returns the repository path for the compiled Bloblang mapping processor (DM-35).
    pub fn compiled_bloblang_path(&self, name: &str) -> String {
        format!("generated/{name}.blobl")
    }
}
