//! Tests for `kind: AgentProfile` (AG-26, AG-47..AG-50).

use jc_core::kinds::agent_profile::{AgentProfileRole, AgentTool, ModelProvider};
use jc_core::kinds::AgentProfile;

const VALID_YAML: &str = r#"
apiVersion: joinedcontext.com/v1alpha1
kind: AgentProfile
metadata:
  name: app-builder
  namespace: org
  title:
    en: Application builder
spec:
  role: builder
  runtime:
    image: ghcr.io/marek-mraz/jc-agent-runner
    digest: sha256:414ba5b2b1163480e9ed4213a989cd798579cfa88582a2359303273009b2b852
  model:
    provider: anthropic
    name: claude-3-7-sonnet
    maxTokensPerRun: 2000000
  limits:
    stepsPerRun: 120
    wallClock: PT20M
    concurrentRunsPerOrganization: 2
    requestsPerMinute: 240
    maxResponseBytes: 8388608
  egress:
    allowedHosts:
      - static.crates.io
      - index.crates.io
      - registry.npmjs.org
  tools:
    - shell
    - cargo
    - pnpm
    - git
    - playwright
  workspace:
    cpu: "2"
    memory: 4Gi
    ephemeralStorage: 8Gi
"#;

#[test]
fn valid_agent_profile_parses_validates_and_roundtrips() {
    let profile = AgentProfile::from_yaml(VALID_YAML).expect("valid yaml");
    profile.validate().expect("valid profile");

    assert_eq!(profile.spec.role, AgentProfileRole::Builder);
    assert_eq!(profile.spec.model.provider, ModelProvider::Anthropic);
    assert_eq!(profile.spec.tools.len(), 5);
    assert!(profile.spec.tools.contains(&AgentTool::Cargo));
    assert_eq!(profile.spec.egress.allowed_hosts.len(), 3);

    let serialized = profile.to_yaml().expect("serialize");
    assert_eq!(
        profile,
        AgentProfile::from_yaml(&serialized).expect("re-import")
    );
}

#[test]
fn reject_secret_refs_via_deny_unknown_fields() {
    let bad_yaml = format!("{VALID_YAML}\n  secretRef:\n    name: stolen-key\n");
    assert!(AgentProfile::from_yaml(&bad_yaml).is_err());
}

#[test]
fn unpinned_digest_is_rejected() {
    let bad_yaml = VALID_YAML.replace(
        "sha256:414ba5b2b1163480e9ed4213a989cd798579cfa88582a2359303273009b2b852",
        "latest",
    );
    let profile = AgentProfile::from_yaml(&bad_yaml).expect("parses");
    assert!(profile.validate().is_err());
}

#[test]
fn wall_clock_over_one_hour_is_rejected() {
    let bad_yaml = VALID_YAML.replace("PT20M", "PT2H");
    let profile = AgentProfile::from_yaml(&bad_yaml).expect("parses");
    assert!(profile.validate().is_err());
}

#[test]
fn invalid_egress_hosts_rejected() {
    for bad_host in [
        "https://crates.io",
        "crates.io/path",
        "*.npmjs.org",
        "crates.io:443",
    ] {
        // Quoted: a bare `*` or `:` in a YAML scalar is an alias or a mapping, not a host.
        let bad_yaml = VALID_YAML.replace("static.crates.io", &format!("\"{bad_host}\""));
        let profile = AgentProfile::from_yaml(&bad_yaml).expect("parses");
        assert!(
            profile.validate().is_err(),
            "host {bad_host} must be rejected"
        );
    }
}

#[test]
fn steward_profile_rules() {
    // Steward cannot have coding tools
    let steward_with_tools = VALID_YAML
        .replace("role: builder", "role: steward")
        .replace("allowedHosts:\n      - static.crates.io\n      - index.crates.io\n      - registry.npmjs.org", "allowedHosts: []");
    let profile = AgentProfile::from_yaml(&steward_with_tools).expect("parses");
    assert!(profile.validate().is_err(), "steward with tools must fail");

    // Steward cannot have internet egress
    let steward_with_egress = VALID_YAML
        .replace("role: builder", "role: steward")
        .replace(
            "tools:\n    - shell\n    - cargo\n    - pnpm\n    - git\n    - playwright",
            "tools: []",
        );
    let profile2 = AgentProfile::from_yaml(&steward_with_egress).expect("parses");
    assert!(
        profile2.validate().is_err(),
        "steward with egress must fail"
    );

    // Pure steward succeeds
    let valid_steward = VALID_YAML
        .replace("role: builder", "role: steward")
        .replace("allowedHosts:\n      - static.crates.io\n      - index.crates.io\n      - registry.npmjs.org", "allowedHosts: []")
        .replace("tools:\n    - shell\n    - cargo\n    - pnpm\n    - git\n    - playwright", "tools: []");
    let profile3 = AgentProfile::from_yaml(&valid_steward).expect("parses");
    profile3.validate().expect("valid steward profile");
}
