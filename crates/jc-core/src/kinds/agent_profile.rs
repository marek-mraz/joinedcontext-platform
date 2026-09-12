//! `kind: AgentProfile`, defining autonomous agent runtime constraints, model, limits, tools,
//! and network egress permissions (AG-26, AG-47..AG-50).
//!
//! **Security note**: `AgentProfileSpec` and all nested structures carry `deny_unknown_fields`,
//! ensuring no inline secrets, keys, or credentials can be defined within Git manifests.

use crate::envelope::{Kind, ObjectMeta, Scope};
use crate::error::{Error, Result};
use crate::names;
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

static DIGEST_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^sha256:[0-9a-f]{64}$").expect("valid regex"));
static DURATION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$").expect("valid regex"));
static DNS_HOST_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
        .expect("valid regex")
});

/// Profile execution role (AG-26, AG-47).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AgentProfileRole {
    /// Builder profile: coding tools in ephemeral workspace, egress allowlist.
    Builder,
    /// Steward profile: MCP only, no internet egress.
    Steward,
}

/// Container runtime image specification (AG-49).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgentRuntime {
    /// Container image repository and tag.
    pub image: String,
    /// Cryptographic container digest (`sha256:...`). Required for admission (AG-49).
    pub digest: String,
}

/// Model provider choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ModelProvider {
    /// Anthropic's Messages API.
    Anthropic,
    /// Any provider speaking the OpenAI chat-completions protocol.
    #[serde(rename = "openai-compatible")]
    OpenaiCompatible,
}

/// Model selection and token budgeting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgentModel {
    /// Which protocol the proxy speaks to the model provider.
    pub provider: ModelProvider,
    /// Model identifier the provider knows.
    pub name: String,
    /// Tokens one run may consume before the proxy ends it (AG-41).
    pub max_tokens_per_run: u64,
}

/// Computational, execution, and rate bounds per run (AG-41).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgentLimits {
    /// Agent steps one run may take before it stops and hands over the last log (AG-51).
    pub steps_per_run: u32,
    /// ISO 8601 duration (e.g. `PT20M`), maximum 1 hour (`PT1H`).
    pub wall_clock: String,
    /// Runs one organization may have in flight at once.
    pub concurrent_runs_per_organization: u32,
    /// Proxied requests per minute per run.
    pub requests_per_minute: u32,
    /// Bytes one proxied response may carry.
    pub max_response_bytes: u64,
}

/// Network egress allow-listing for package registries and documentation (AG-50).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgentEgress {
    /// Bare hostnames the package route may reach; everything else is refused (AG-50).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_hosts: Vec<String>,
}

/// Available coding and debugging tools in the builder workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AgentTool {
    /// A shell in the ephemeral workspace.
    Shell,
    /// The Rust toolchain.
    Cargo,
    /// The Node package manager.
    Pnpm,
    /// Git, reaching the forge through the proxy alone.
    Git,
    /// A headless browser for smoke tests.
    Playwright,
}

/// Workspace hardware resource allocations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgentWorkspace {
    /// CPU request and limit of the workspace container.
    pub cpu: String,
    /// Memory request and limit of the workspace container.
    pub memory: String,
    /// Size of the `emptyDir` the workspace works in.
    pub ephemeral_storage: String,
}

/// Specification for an [`AgentProfile`] resource (AG-47..AG-50).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgentProfileSpec {
    /// What the profile is allowed to be used for (AG-26).
    pub role: AgentProfileRole,
    /// The runtime image a run of this profile executes.
    pub runtime: AgentRuntime,
    /// The model the proxy calls on the run's behalf.
    pub model: AgentModel,
    /// The bounds every run of this profile is held to.
    pub limits: AgentLimits,
    /// Where the package route may go.
    pub egress: AgentEgress,
    /// Tools the workspace carries; a steward profile carries none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<AgentTool>,
    /// Resources the workspace container gets.
    pub workspace: AgentWorkspace,
}

impl Kind for AgentProfileSpec {
    const KIND: &'static str = "AgentProfile";
    const PLURAL: &'static str = "agentprofiles";
    const SCOPE: Scope = Scope::Organization;
    const PATH_TEMPLATE: &'static str = "agentprofiles/{name}.yaml";

    fn validate_spec(&self, meta: &ObjectMeta) -> Result<()> {
        names::validate_dns1123_label(&meta.name)?;
        self.validate()
    }
}

impl AgentProfileSpec {
    /// Validates runtime digest, limits, duration, tools, and host allowlists.
    pub fn validate(&self) -> Result<()> {
        if self.runtime.image.trim().is_empty() {
            return Err(Error::Name {
                field: "runtime.image",
                value: self.runtime.image.clone(),
                reason: "image must not be empty",
            });
        }
        if !DIGEST_RE.is_match(&self.runtime.digest) {
            return Err(Error::Name {
                field: "runtime.digest",
                value: self.runtime.digest.clone(),
                reason: "digest must match ^sha256:[0-9a-f]{64}$ (AG-49)",
            });
        }

        if self.model.name.trim().is_empty() {
            return Err(Error::Name {
                field: "model.name",
                value: self.model.name.clone(),
                reason: "model name must not be empty",
            });
        }
        if self.model.max_tokens_per_run == 0 {
            return Err(Error::Name {
                field: "model.maxTokensPerRun",
                value: "0".to_string(),
                reason: "maxTokensPerRun must be greater than 0",
            });
        }

        if self.limits.steps_per_run == 0 {
            return Err(Error::Name {
                field: "limits.stepsPerRun",
                value: "0".to_string(),
                reason: "stepsPerRun must be greater than 0",
            });
        }
        if self.limits.concurrent_runs_per_organization == 0 {
            return Err(Error::Name {
                field: "limits.concurrentRunsPerOrganization",
                value: "0".to_string(),
                reason: "concurrentRunsPerOrganization must be greater than 0",
            });
        }
        if self.limits.requests_per_minute == 0 {
            return Err(Error::Name {
                field: "limits.requestsPerMinute",
                value: "0".to_string(),
                reason: "requestsPerMinute must be greater than 0",
            });
        }
        if self.limits.max_response_bytes == 0 {
            return Err(Error::Name {
                field: "limits.maxResponseBytes",
                value: "0".to_string(),
                reason: "maxResponseBytes must be greater than 0",
            });
        }

        let wall_clock_secs = parse_iso_duration(&self.limits.wall_clock).ok_or(Error::Name {
            field: "limits.wallClock",
            value: self.limits.wall_clock.clone(),
            reason: "wallClock must be a valid ISO 8601 duration matching ^PT(?:(\\d+)H)?(?:(\\d+)M)?(?:(\\d+)S)?$",
        })?;

        if wall_clock_secs == 0 || wall_clock_secs > 3600 {
            return Err(Error::Name {
                field: "limits.wallClock",
                value: self.limits.wall_clock.clone(),
                reason:
                    "wallClock duration must be greater than 0 and at most 1 hour (PT1H, AG-41)",
            });
        }

        for host in &self.egress.allowed_hosts {
            if host.contains('/')
                || host.contains(':')
                || host.contains('*')
                || !DNS_HOST_RE.is_match(host)
            {
                return Err(Error::Name {
                    field: "egress.allowedHosts",
                    value: host.clone(),
                    reason: "allowed host must be a bare hostname without scheme, port, path, or wildcard (AG-50)",
                });
            }
        }

        match self.role {
            AgentProfileRole::Steward => {
                if !self.tools.is_empty() {
                    return Err(Error::Name {
                        field: "tools",
                        value: format!("{} tools declared", self.tools.len()),
                        reason: "steward profile cannot carry coding tools (AG-26)",
                    });
                }
                if !self.egress.allowed_hosts.is_empty() {
                    return Err(Error::Name {
                        field: "egress.allowedHosts",
                        value: format!("{} hosts declared", self.egress.allowed_hosts.len()),
                        reason: "steward profile has no internet access; allowedHosts must be empty (AG-26)",
                    });
                }
            }
            AgentProfileRole::Builder => {
                if self.egress.allowed_hosts.is_empty() {
                    return Err(Error::Name {
                        field: "egress.allowedHosts",
                        value: "empty".to_string(),
                        reason: "builder profile requires an egress allow-list; allowedHosts must not be empty (AG-26, AG-50)",
                    });
                }
            }
        }

        if self.workspace.cpu.trim().is_empty() || self.workspace.memory.trim().is_empty() {
            return Err(Error::Name {
                field: "workspace",
                value: "".to_string(),
                reason: "workspace cpu and memory limits must be specified",
            });
        }

        Ok(())
    }
}

/// Parses an ISO 8601 duration in format `PT[#H][#M][#S]` into total seconds.
pub fn parse_iso_duration(raw: &str) -> Option<u64> {
    let caps = DURATION_RE.captures(raw)?;
    let h: u64 = caps.get(1).map_or(0, |m| m.as_str().parse().unwrap_or(0));
    let m: u64 = caps.get(2).map_or(0, |m| m.as_str().parse().unwrap_or(0));
    let s: u64 = caps.get(3).map_or(0, |m| m.as_str().parse().unwrap_or(0));
    Some(h * 3600 + m * 60 + s)
}
