//! Manifest kinds for Bento data pipelines and CronJob schedules (T-0116, PL-01..PL-28).

use crate::envelope::{Kind, ObjectMeta, Ref, Scope, SecretRef};
use crate::error::{Error, Result};
use crate::names;
use crate::urn::Urn;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::LazyLock;

/// A Bento duration: a positive count and one of the units Bento accepts (PL-26, PL-27).
static PERIOD_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[1-9][0-9]*(ms|s|m|h)$").expect("valid regex"));

/// Desired specification of a [`Pipeline`][crate::kinds::Pipeline] resource (PL-01..PL-28).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PipelineSpec {
    /// Operational execution class (PL-04, PL-05).
    pub class: PipelineClass,
    /// Standard cron schedule expression for scheduled runs (PL-04, PL-26..PL-28).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
    /// How often the pipeline polls its source, as a Bento duration (`15s`, `5m`).
    ///
    /// The reconciler reads it to pick the class (PL-26) and copies it into the runner's
    /// `input.generate.interval` (PL-27). Absent means push-based: an MQTT or
    /// subscription input driven by its source rather than by a clock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<String>,
    /// Optional context source query or subscription trigger for derived pipelines (PL-31).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<PipelineSource>,
    /// Optional compute execution specification (PL-33).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compute: Option<Compute>,
    /// Target endpoint URN through which writes occur (PF-39, PL-18).
    pub target_endpoint: Urn,
    /// Optional output entity type and write mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<Output>,
    /// The author knows this resident pipeline triggers itself and accepts it (PL-37).
    ///
    /// A derived pipeline whose output type is the type its own subscription watches feeds its
    /// own trigger, and the reconciler refuses it. Setting this says the loop is deliberate,
    /// which is why PL-37 puts the change in the yellow lane: a person reviews it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_feedback: bool,
    /// Secret references injected into runner environments (PL-14..PL-16).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_refs: Vec<SecretRef>,
    /// Resource quotas allocated to this pipeline runner (PL-11).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quotas: Option<PipelineQuotas>,
}

/// Operational execution class of a data pipeline (PL-04, PL-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PipelineClass {
    /// Reconciler automatically determines class from cadence or input mode (PL-05, PL-26).
    Auto,
    /// Continuous process hosted inside project pipeline runner deployment.
    Resident,
    /// Ephemeral Kubernetes CronJob executed periodically.
    Scheduled,
}

impl PipelineClass {
    /// Returns the kebab-case wire name for this pipeline class.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Resident => "resident",
            Self::Scheduled => "scheduled",
        }
    }
}

impl fmt::Display for PipelineClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Source specification for derived pipelines (PL-31).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PipelineSource {
    /// Reference to source Endpoint for reading context entities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_ref: Option<Ref>,
    /// Query parameters for pulling entities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<SourceQuery>,
    /// Event subscription trigger for resident processing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger: Option<Trigger>,
    /// Reference to the `DataSource` whose connection becomes this pipeline's Bento input
    /// (PL-39, MF-35). Excludes `endpointRef`: a pipeline reads the outside world or the
    /// platform's own spaces, not both in one input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_source_ref: Option<Ref>,
}

impl PipelineSource {
    /// Validates the input side of a pipeline (PL-31, PL-39).
    ///
    /// One input: either the platform's own spaces through an Endpoint, or the outside world
    /// through a `DataSource`. A manifest naming both describes two inputs and the reconciler
    /// would have to choose one, so it is refused here instead.
    pub fn validate(&self) -> Result<()> {
        let Some(reference) = &self.data_source_ref else {
            return Ok(());
        };
        if self.endpoint_ref.is_some() {
            return Err(Error::Name {
                field: "spec.source.dataSourceRef",
                value: reference.name().to_owned(),
                reason: "a pipeline reads a DataSource or an Endpoint, not both (PL-39)",
            });
        }
        if let Some(kind) = reference.kind() {
            if kind != "DataSource" {
                return Err(Error::Kind {
                    expected: "DataSource",
                    got: kind.to_string(),
                });
            }
        }
        names::validate_dns1123_label(reference.name())
    }
}

/// NGSI-LD query parameters for pipeline source entity retrieval.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SourceQuery {
    /// Target entity type short name.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub entity_type: Option<String>,
    /// Attributes projection list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attrs: Vec<String>,
    /// Entity query filter string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,
    /// Scope query filter string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_q: Option<String>,
    /// Geographic query filter string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geo_q: Option<String>,
    /// Temporal window constraint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temporal_q: Option<TemporalWindow>,
}

/// ISO 8601 temporal window for source queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TemporalWindow {
    /// ISO 8601 duration string (e.g. `P1D`).
    pub window: String,
}

/// Subscription trigger for resident pipelines (PL-31).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Trigger {
    /// Underlying context subscription details.
    pub subscription: SubscriptionTrigger,
}

/// Subscription configuration triggering pipeline execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SubscriptionTrigger {
    /// Target entity type name.
    #[serde(rename = "type")]
    pub entity_type: String,
    /// Whitelist of watched attribute names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub watched_attributes: Vec<String>,
}

/// Compute execution specification (PL-33).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Compute {
    /// Engine kind executing compute logic.
    pub kind: ComputeKind,
    /// Path or package of the compute module (for wasm).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    /// Entry point function name (for wasm).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// Reference to a [`Mapping`][crate::kinds::Mapping] resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapping_ref: Option<Ref>,
}

/// Execution technology category for pipeline compute steps (PL-33).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ComputeKind {
    /// Inline Bento Bloblang processor.
    Bloblang,
    /// Compiled LinkML-Map mapping processor (PL-29).
    Mapping,
    /// Sandboxed WebAssembly WASI module (PL-34).
    Wasm,
    /// Ephemeral containerized job (PL-35).
    Container,
}

impl ComputeKind {
    /// Returns the kebab-case wire name for this compute kind.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Bloblang => "bloblang",
            Self::Mapping => "mapping",
            Self::Wasm => "wasm",
            Self::Container => "container",
        }
    }
}

impl fmt::Display for ComputeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Output specification for derived pipeline computations (PL-32).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Output {
    /// Target entity type name produced.
    #[serde(rename = "type")]
    pub entity_type: String,
    /// Write mode applied to target context space.
    pub mode: OutputMode,
}

/// Mutation mode for pipeline output writers (PL-32).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum OutputMode {
    /// Create or replace complete entity.
    Upsert,
    /// Update or append attributes onto existing entity.
    UpdateAttrs,
}

impl OutputMode {
    /// Returns the kebab-case wire name for this output mode.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Upsert => "upsert",
            Self::UpdateAttrs => "update-attrs",
        }
    }
}

impl fmt::Display for OutputMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Resource quotas for a pipeline runner (PL-11).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PipelineQuotas {
    /// Maximum allowed memory allocation in megabytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_memory_mb: Option<u32>,
    /// CPU allocation in millicores.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_millicores: Option<u32>,
}

impl Kind for PipelineSpec {
    const KIND: &'static str = "Pipeline";
    const PLURAL: &'static str = "pipelines";
    const SCOPE: Scope = Scope::Project;
    const PATH_TEMPLATE: &'static str = "projects/{project}/pipelines/{name}/pipeline.yaml";

    fn validate_spec(&self, meta: &ObjectMeta) -> Result<()> {
        names::validate_dns1123_label(&meta.name)?;
        self.validate()
    }
}

impl PipelineSpec {
    /// The polling period in whole seconds, `None` when the pipeline is push-based or the
    /// period does not parse (PL-26).
    ///
    /// A sub-second period floors to zero, which is still shorter than thirty seconds and
    /// therefore still resident.
    pub fn period_seconds(&self) -> Option<u64> {
        let period = self.period.as_deref()?;
        let split = period.find(|c: char| !c.is_ascii_digit())?;
        let (count, unit) = period.split_at(split);
        let count: u64 = count.parse().ok()?;
        match unit {
            "ms" => Some(count / 1000),
            "s" => Some(count),
            "m" => Some(count * 60),
            "h" => Some(count * 3600),
            _ => None,
        }
    }

    /// Validates class scheduling, target endpoint, compute engine, and resource bounds.
    pub fn validate(&self) -> Result<()> {
        if self.target_endpoint.entity_type() != "Endpoint" {
            return Err(Error::Kind {
                expected: "Endpoint",
                got: self.target_endpoint.entity_type().to_string(),
            });
        }

        if let Some(source) = &self.source {
            source.validate()?;
        }

        match self.class {
            PipelineClass::Scheduled => {
                if self.schedule.is_none() {
                    return Err(Error::Name {
                        field: "spec.schedule",
                        value: String::new(),
                        reason: "schedule is required when class is `scheduled`",
                    });
                }
            }
            PipelineClass::Resident => {
                if let Some(ref s) = self.schedule {
                    return Err(Error::Name {
                        field: "spec.schedule",
                        value: s.clone(),
                        reason: "schedule must not be present when class is `resident`",
                    });
                }
            }
            PipelineClass::Auto => {}
        }

        if let Some(ref period) = self.period {
            if !PERIOD_RE.is_match(period) {
                return Err(Error::Name {
                    field: "spec.period",
                    value: period.clone(),
                    reason: "period must be a Bento duration such as `250ms`, `15s`, `5m` or `1h`",
                });
            }
        }

        if let Some(ref sched) = self.schedule {
            // ponytail: we validate the cron expression by checking exactly five whitespace-separated
            // fields. Full cron syntax and range parsing is performed downstream by the Kubernetes
            // CronJob controller or Bento runner.
            let fields: Vec<&str> = sched.split_whitespace().collect();
            if fields.len() != 5 {
                return Err(Error::Name {
                    field: "spec.schedule",
                    value: sched.clone(),
                    reason: "schedule must contain exactly 5 whitespace-separated fields (standard cron expression)",
                });
            }
        }

        if let Some(ref c) = self.compute {
            match c.kind {
                ComputeKind::Wasm => {
                    if c.module.is_none() {
                        return Err(Error::Name {
                            field: "spec.compute.module",
                            value: String::new(),
                            reason: "module is required when compute.kind is `wasm`",
                        });
                    }
                    if c.function.is_none() {
                        return Err(Error::Name {
                            field: "spec.compute.function",
                            value: String::new(),
                            reason: "function is required when compute.kind is `wasm`",
                        });
                    }
                }
                ComputeKind::Mapping => {
                    if c.mapping_ref.is_none() {
                        return Err(Error::Name {
                            field: "spec.compute.mappingRef",
                            value: String::new(),
                            reason: "mappingRef is required when compute.kind is `mapping`",
                        });
                    }
                    if let Some(ref m) = c.module {
                        return Err(Error::Name {
                            field: "spec.compute.module",
                            value: m.clone(),
                            reason: "module is forbidden when compute.kind is `mapping`",
                        });
                    }
                    if let Some(ref f) = c.function {
                        return Err(Error::Name {
                            field: "spec.compute.function",
                            value: f.clone(),
                            reason: "function is forbidden when compute.kind is `mapping`",
                        });
                    }
                }
                _ => {}
            }

            if let Some(ref mr) = c.mapping_ref {
                names::validate_dns1123_label(mr.name())?;
                if let Some(kind) = mr.kind() {
                    if kind != "Mapping" {
                        return Err(Error::Kind {
                            expected: "Mapping",
                            got: kind.to_string(),
                        });
                    }
                }
            }
        }

        if let Some(ref out) = self.output {
            names::validate_entity_type(&out.entity_type)?;
        }

        if let Some(ref src) = self.source {
            if let Some(ref q) = src.query {
                if let Some(ref et) = q.entity_type {
                    names::validate_entity_type(et)?;
                }
            }
            if let Some(ref tr) = src.trigger {
                names::validate_entity_type(&tr.subscription.entity_type)?;
            }
            if let Some(ref er) = src.endpoint_ref {
                names::validate_dns1123_label(er.name())?;
                if let Some(kind) = er.kind() {
                    if kind != "Endpoint" {
                        return Err(Error::Kind {
                            expected: "Endpoint",
                            got: kind.to_string(),
                        });
                    }
                }
            }
        }

        if let Some(ref q) = self.quotas {
            if let Some(mem) = q.max_memory_mb {
                if mem == 0 {
                    return Err(Error::Name {
                        field: "spec.quotas.maxMemoryMb",
                        value: "0".to_string(),
                        reason: "maxMemoryMb must be >= 1",
                    });
                }
            }
            if let Some(cpu) = q.cpu_millicores {
                if cpu == 0 {
                    return Err(Error::Name {
                        field: "spec.quotas.cpuMillicores",
                        value: "0".to_string(),
                        reason: "cpuMillicores must be >= 1",
                    });
                }
            }
        }

        for sref in &self.secret_refs {
            names::validate_dns1123_label(&sref.name)?;
        }

        Ok(())
    }
}
