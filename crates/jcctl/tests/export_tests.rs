//! `jcctl export`: a live space copied out as the repository that would produce it
//! (T-0133, CC-22, MF-16, MF-17, PF-20).

mod common;

use common::*;
use jcctl::commands::{export, validate};
use jcctl::loader::RawManifest;
use jcctl::platform::{InMemory, Platform};

const POLICY: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: Policy
metadata:
  name: public-air-quality
  namespace: ovzdusie
spec:
  contextSpaceRef:
    kind: ContextSpace
    name: ovzdusie
  assigner: "did:web:banskabystrica.sk"
  assignee: { kind: role, id: public }
  operations: [queryEntity, retrieveEntity]
  information:
    - entities:
        - type: AirQualityObserved
      propertyNames: [pm10, pm25]
"#;

/// The same endpoint the platform would hand back: the declaration, plus the metadata the
/// reconciler keeps beside it.
const LIVE_ENDPOINT: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: Endpoint
metadata:
  name: public-air
  namespace: ovzdusie
  uid: 7c9f0f5a-2b41-4b6e-9f10-2f7a1c3e5d80
  resourceVersion: "418"
  generation: 3
  creationTimestamp: "2026-09-01T08:00:00Z"
  annotations:
    joinedcontext.com/revision: 3f9c2e1
    joinedcontext.com/last-applied: "2026-09-05T22:10:00Z"
    banskabystrica.sk/owner: odbor-zivotneho-prostredia
spec:
  contextSpaceRef: ovzdusie
  slug: zt4qm7ge2xdv6ksb3ncf5arw2y
  audience: public
  enabledRepresentations: ["ngsi-ld", "geojson"]
"#;

/// A space somebody else's project owns, which must not come out with ours.
const OTHER_SPACE_ENDPOINT: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: Endpoint
metadata:
  name: doprava-public
  namespace: ovzdusie
spec:
  contextSpaceRef: doprava
  slug: hj3wq8mzt6vhx3nbwrs5cjd8fk
  audience: public
  enabledRepresentations: ["ngsi-ld"]
"#;

fn live(manifests: &[&str]) -> InMemory {
    let mut platform = InMemory::new();
    for yaml in manifests {
        platform.put(&manifest(yaml)).expect("the platform accepts");
    }
    platform
}

fn exported<'a>(report: &'a export::Report, path: &str) -> &'a RawManifest {
    &report
        .resources
        .iter()
        .find(|resource| resource.path.to_str() == Some(path))
        .unwrap_or_else(|| panic!("{path} was exported"))
        .manifest
}

/// CC-22 and MF-06: what comes out is a repository — every manifest at the path its kind
/// prescribes, and every manifest valid.
#[test]
fn an_exported_space_is_a_repository_that_validates() {
    let platform = live(&[SPACE, LIVE_ENDPOINT, POLICY]);
    let report = export::collect(&platform, "ovzdusie", "ovzdusie").expect("the platform answers");

    let paths: Vec<&str> = report
        .resources
        .iter()
        .filter_map(|resource| resource.path.to_str())
        .collect();
    assert_eq!(
        paths,
        vec![
            "projects/ovzdusie/spaces/ovzdusie/endpoints/public-air.yaml",
            "projects/ovzdusie/spaces/ovzdusie/policies/public-air-quality.yaml",
            "projects/ovzdusie/spaces/ovzdusie/space.yaml",
        ]
    );

    let dir = temp_dir("export-repository");
    assert_eq!(export::write(&dir, &report).expect("written"), 3);

    // validate(export(x)): the whole point of the command, run the way CI runs it.
    let checked = validate::run(&dir);
    assert!(
        checked.is_valid(),
        "the export does not validate: {:?}",
        checked.findings
    );
    assert_eq!(checked.checked, 3);
    let _ = std::fs::remove_dir_all(&dir);
}

/// MF-16 and MF-04: an export is a declaration, not a snapshot. The platform's own
/// bookkeeping does not come out with it, and the operator's annotation does.
#[test]
fn system_metadata_is_stripped_and_hand_written_metadata_survives() {
    let platform = live(&[SPACE, LIVE_ENDPOINT]);
    let report = export::collect(&platform, "ovzdusie", "ovzdusie").expect("the platform answers");
    let endpoint = exported(
        &report,
        "projects/ovzdusie/spaces/ovzdusie/endpoints/public-air.yaml",
    );

    for owned in ["uid", "resourceVersion", "generation", "creationTimestamp"] {
        assert!(
            !endpoint.metadata.rest.contains_key(owned),
            "{owned} is the platform's, not the declaration's"
        );
    }
    let annotations = endpoint.metadata.rest["annotations"]
        .as_object()
        .expect("annotations");
    assert!(!annotations.contains_key("joinedcontext.com/revision"));
    assert!(!annotations.contains_key("joinedcontext.com/last-applied"));
    assert_eq!(
        annotations["banskabystrica.sk/owner"],
        serde_json::json!("odbor-zivotneho-prostredia"),
        "an annotation somebody wrote by hand is theirs"
    );

    assert_eq!(endpoint.metadata.name, "public-air");
    assert_eq!(
        endpoint.spec["slug"],
        serde_json::json!("zt4qm7ge2xdv6ksb3ncf5arw2y")
    );
}

/// MF-17 and MF-24: a manifest carries a `secretRef`, never a secret. A platform that
/// hands one back has it dropped and the operator is told, because a silent lossy export
/// is worse than a loud one.
#[test]
fn a_literal_credential_is_dropped_and_reported_while_its_reference_survives() {
    let mut spec = serde_json::json!({
        "contextSpaceRef": "ovzdusie",
        "slug": "zt4qm7ge2xdv6ksb3ncf5arw2y",
        "audience": "public",
        "password": "hunter2",
        "cachedTokenSecretRef": { "name": "gateway-token", "key": "token" },
        "tokenEndpoint": "https://keycloak.example.sk/realms/bb/protocol/openid-connect/token",
        "upstream": { "apiKey": "ak_live_9c1e", "url": "https://broker.internal" },
        "credentials": [{ "kind": "apiKey", "secretRef": { "name": "writer" } }],
    });
    let mut endpoint = manifest(LIVE_ENDPOINT);
    std::mem::swap(&mut endpoint.spec, &mut spec);

    let mut platform = live(&[SPACE]);
    platform.put(&endpoint).expect("the platform accepts");
    let report = export::collect(&platform, "ovzdusie", "ovzdusie").expect("the platform answers");
    let exported_endpoint = exported(
        &report,
        "projects/ovzdusie/spaces/ovzdusie/endpoints/public-air.yaml",
    );

    assert!(!exported_endpoint.spec.to_string().contains("hunter2"));
    assert!(!exported_endpoint.spec.to_string().contains("ak_live_9c1e"));
    assert_eq!(
        report.redactions,
        vec![
            "Endpoint/public-air: password",
            "Endpoint/public-air: apiKey"
        ],
        "every drop is named, so nobody discovers the loss in a diff"
    );

    // A reference is not a secret, and neither is a URL that happens to say `token`.
    assert_eq!(
        exported_endpoint.spec["cachedTokenSecretRef"]["name"],
        serde_json::json!("gateway-token")
    );
    assert!(exported_endpoint.spec["tokenEndpoint"].is_string());
    assert_eq!(
        exported_endpoint.spec["credentials"][0]["secretRef"]["name"],
        serde_json::json!("writer"),
        "a list of references is configuration, not a credential"
    );
}

/// CC-22: `export` copies one space out. Another space's endpoint and a resource that
/// belongs to no space at all stay where they are.
#[test]
fn only_the_named_space_comes_out() {
    let platform = live(&[ORG, PROJECT, SPACE, LIVE_ENDPOINT, OTHER_SPACE_ENDPOINT]);
    let report = export::collect(&platform, "ovzdusie", "ovzdusie").expect("the platform answers");

    let rendered = format!("{:?}", report.resources);
    assert!(
        !rendered.contains("doprava"),
        "another space came out: {rendered}"
    );
    assert!(
        !rendered.contains("Organization") && !rendered.contains("kind: \"Project\""),
        "an installation-level resource is not part of a space"
    );
    assert_eq!(report.resources.len(), 2, "the space and its one endpoint");
}

/// A fresh installation exports an empty repository rather than failing: `export` on
/// nothing is nothing, which is what `jcctl export` prints today.
#[test]
fn an_empty_platform_exports_an_empty_repository() {
    let report = export::collect(&InMemory::new(), "ovzdusie", "ovzdusie").expect("answers");
    assert!(report.resources.is_empty());
    assert!(report.redactions.is_empty());

    let dir = temp_dir("export-empty");
    assert_eq!(export::write(&dir, &report).expect("written"), 0);
    assert!(validate::run(&dir).is_valid());
    let _ = std::fs::remove_dir_all(&dir);
}
