//! The schema surface: what the data contains, narrowed to what the caller may read
//! (T-0162, EP-46…EP-52, DM-02, DM-22).
//!
//! Two halves are exercised, because a deployment will have both: a model whose artifacts
//! Model Tools committed beside the LinkML source, and one whose artifacts are not in the
//! checkout yet and is therefore derived from the grants.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use context_gateway::app::{router, Gateway};
use context_gateway::pdp::PolicyPdp;
use context_gateway::proxy::Broker;
use context_gateway::resolver::{Endpoint, Model};
use jc_core::kinds::{Audience, PolicySpec, Representation};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

const SLUG: &str = "k4y7pq2mzt6vhx3nbwrs5cjd8f";

fn policy(yaml: &str) -> PolicySpec {
    serde_norway::from_str(yaml).expect("the policy spec parses")
}

/// What Model Tools generates for the demo model: three readable slots, one the public
/// grant never names, and a class the public grant never names either.
fn compiled_schema() -> Value {
    json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$defs": {
            "AirQualityObserved": {
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "type": { "const": "AirQualityObserved" },
                    "pm10": { "type": "number" },
                    "pm25": { "type": "number" },
                    "location": { "$ref": "#/$defs/GeoProperty" },
                    "internalNote": { "type": "string" },
                },
                "patternProperties": { "^x-": { "type": "string" } },
                "required": ["id", "type", "pm10", "internalNote"],
            },
            "InternalIncident": {
                "type": "object",
                "properties": { "severity": { "type": "string" } },
            },
            "GeoProperty": { "type": "object" },
        },
    })
}

fn compiled_context() -> Value {
    json!({
        "@context": {
            "@vocab": "https://bb.example.sk/schema/air-quality/",
            "AirQualityObserved": "https://bb.example.sk/schema/air-quality/AirQualityObserved",
            "InternalIncident": "https://bb.example.sk/schema/air-quality/InternalIncident",
            "pm10": "https://bb.example.sk/schema/air-quality/pm10",
            "internalNote": "https://bb.example.sk/schema/air-quality/internalNote",
        }
    })
}

fn air_quality(with_artifacts: bool) -> Model {
    Model {
        name: "bb-air-quality".to_owned(),
        version: "1.4.0".to_owned(),
        major: 1,
        classes: vec![
            "AirQualityObserved".to_owned(),
            "InternalIncident".to_owned(),
        ],
        json_schema: with_artifacts.then(compiled_schema),
        context: with_artifacts.then(compiled_context),
    }
}

/// The public grant of DEMO step 4: three attributes of one type, and nothing else.
fn endpoint(models: Vec<Model>) -> Endpoint {
    Endpoint {
        slug: SLUG.to_owned(),
        space: "ovzdusie".to_owned(),
        project: "ovzdusie".to_owned(),
        audience: Audience::Public,
        allowed_projects: Vec::new(),
        representations: vec![Representation::NgsiLd],
        rate_limit: None,
        models,
        policies: vec![policy(
            r#"contextSpaceRef: ovzdusie
assigner: did:web:banskabystrica.sk
assignee: { kind: role, id: public }
operations: [queryEntity, retrieveEntity]
information:
  - entities:
      - type: AirQualityObserved
    propertyNames: [pm10, pm25]
    relationshipNames: [location]
"#,
        )],
    }
}

fn app(models: Vec<Model>) -> axum::Router {
    router(Arc::new(
        Gateway::new(
            Broker::new("http://127.0.0.1:1"),
            Box::new(PolicyPdp),
            "banskabystrica.sk",
        )
        .serve([endpoint(models)]),
    ))
}

async fn call(
    models: Vec<Model>,
    request: Request<Body>,
) -> (StatusCode, Vec<(String, String)>, Value) {
    let response = app(models)
        .oneshot(request)
        .await
        .expect("the gateway answers");
    let status = response.status();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                value.to_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    let body = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .expect("a readable body");
    (
        status,
        headers,
        serde_json::from_slice(&body).unwrap_or(Value::Null),
    )
}

fn get(path: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .body(Body::empty())
        .expect("a request")
}

fn accepting(path: &str, accept: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header("accept", accept)
        .body(Body::empty())
        .expect("a request")
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header, _)| header == name)
        .map(|(_, value)| value.as_str())
}

/// EP-46: the index names the model, the types the caller may see, and the artifacts the
/// gateway actually serves, each with the digest of the document it will hand back.
#[tokio::test]
async fn the_index_describes_what_this_endpoint_publishes() {
    let (status, _, document) = call(
        vec![air_quality(true)],
        get(&format!("/api/endpoint/{SLUG}/schema/index.json")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(document["endpoint"], json!(SLUG));
    let models = document["models"].as_array().expect("models");
    assert_eq!(models.len(), 1);
    assert_eq!(models[0]["name"], json!("bb-air-quality"));
    assert_eq!(
        models[0]["version"],
        json!(1),
        "the major is what is served"
    );
    assert_eq!(models[0]["semver"], json!("1.4.0"));
    assert_eq!(models[0]["types"], json!(["AirQualityObserved"]));

    let descriptor = &models[0]["artifacts"]["model.schema.json"];
    assert_eq!(descriptor["type"], json!("application/schema+json"));
    assert!(descriptor["bytes"].as_u64().is_some_and(|bytes| bytes > 0));
    let digest = descriptor["sha256"].as_str().expect("a digest");
    assert_eq!(digest.len(), 64, "sha256 as lowercase hex");

    // The digest in the index is the digest of the document the surface serves, or a
    // client that trusts the index revalidates against nothing.
    let (_, headers, _) = call(
        vec![air_quality(true)],
        get(&format!("/api/endpoint/{SLUG}/schema/v1/json-schema")),
    )
    .await;
    assert_eq!(
        header(&headers, "etag"),
        Some(format!("\"{digest}\"").as_str())
    );
}

/// EP-47 and the task's security property: a slot the endpoint's policy set forbids is
/// absent from the schema, from `required`, and from the index's type list.
#[tokio::test]
async fn a_forbidden_class_and_slot_are_projected_out() {
    let (status, headers, schema) = call(
        vec![air_quality(true)],
        get(&format!("/api/endpoint/{SLUG}/schema/v1/json-schema")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        header(&headers, "content-type"),
        Some("application/schema+json")
    );

    let air = &schema["$defs"]["AirQualityObserved"];
    for granted in ["id", "type", "pm10", "pm25", "location"] {
        assert!(
            !air["properties"][granted].is_null(),
            "{granted} is granted"
        );
    }
    assert!(
        air["properties"]["internalNote"].is_null(),
        "a slot no grant names is not described"
    );
    assert_eq!(
        air["required"],
        json!(["id", "type", "pm10"]),
        "a removed slot cannot stay required"
    );
    assert!(
        air["patternProperties"].is_null(),
        "a pattern could match a slot that was just removed"
    );

    assert!(
        schema["$defs"]["InternalIncident"].is_null(),
        "a class no grant names is not described"
    );
    // The shared definition a surviving class still `$ref`s stays, or the schema breaks.
    assert!(!schema["$defs"]["GeoProperty"].is_null());
    assert!(!schema.to_string().contains("severity"));
}

/// EP-47: the same projection on the `@context`, because a term is as much a disclosure
/// as a property.
#[tokio::test]
async fn the_context_carries_only_the_granted_terms() {
    let (status, headers, document) = call(
        vec![air_quality(true)],
        get(&format!("/api/endpoint/{SLUG}/schema/v1/context.jsonld")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        header(&headers, "content-type"),
        Some("application/ld+json")
    );

    let parts = document["@context"].as_array().expect("a context array");
    assert_eq!(
        parts[0],
        json!("https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context-v1.8.jsonld")
    );
    let terms = &parts[1];
    assert!(!terms["AirQualityObserved"].is_null());
    assert!(!terms["pm10"].is_null());
    assert!(
        !terms["@vocab"].is_null(),
        "keywords survive the projection"
    );
    assert!(terms["internalNote"].is_null());
    assert!(terms["InternalIncident"].is_null());
}

/// EP-49: `schema/v{major}/model` is negotiated, and the formalisms only Model Tools can
/// produce answer 406 rather than something else.
#[tokio::test]
async fn content_negotiation_serves_what_the_gateway_has_and_refuses_the_rest() {
    let path = format!("/api/endpoint/{SLUG}/schema/v1/model");

    let (status, headers, schema) = call(
        vec![air_quality(true)],
        accepting(&path, "application/schema+json"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        header(&headers, "content-type"),
        Some("application/schema+json")
    );
    assert!(!schema["$defs"]["AirQualityObserved"].is_null());

    let (status, headers, document) = call(
        vec![air_quality(true)],
        accepting(&path, "application/ld+json"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        header(&headers, "content-type"),
        Some("application/ld+json")
    );
    assert!(document["@context"].is_array());

    // Turtle is SHACL, OWL and RDF; YAML is the LinkML source. Neither is in the checkout
    // until Model Tools commits it (T-0168, T-0169).
    for accept in ["text/turtle", "text/turtle; profile=\"owl\"", "text/yaml"] {
        let (status, _, problem) = call(vec![air_quality(true)], accepting(&path, accept)).await;
        assert_eq!(status, StatusCode::NOT_ACCEPTABLE, "{accept}");
        assert_eq!(problem["status"], json!(406));
    }
    // And the same by name, which is how the index would link them.
    for name in [
        "model.shacl.ttl",
        "model.owl.ttl",
        "model.linkml.yaml",
        "model.md",
    ] {
        let (status, _, _) = call(
            vec![air_quality(true)],
            get(&format!("/api/endpoint/{SLUG}/schema/v1/{name}")),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_ACCEPTABLE, "{name}");
    }
}

/// EP-51: the document is a projection of the policy set, so it revalidates rather than
/// being cached as immutable — and a client holding the current bytes gets 304.
#[tokio::test]
async fn a_strong_etag_revalidates_instead_of_going_stale() {
    let path = format!("/api/endpoint/{SLUG}/schema/v1/json-schema");
    let (status, headers, _) = call(vec![air_quality(true)], get(&path)).await;
    assert_eq!(status, StatusCode::OK);

    let etag = header(&headers, "etag").expect("a strong ETag").to_owned();
    assert!(
        etag.starts_with('"') && etag.ends_with('"'),
        "{etag} is strong"
    );
    assert_eq!(
        header(&headers, "cache-control"),
        Some("no-cache"),
        "a grant that changes changes the schema"
    );

    let conditional = Request::builder()
        .uri(&path)
        .header("if-none-match", &etag)
        .body(Body::empty())
        .expect("a request");
    let (status, headers, _) = call(vec![air_quality(true)], conditional).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert_eq!(header(&headers, "etag"), Some(etag.as_str()));

    let stale = Request::builder()
        .uri(&path)
        .header(
            "if-none-match",
            "\"0000000000000000000000000000000000000000000000000000000000000000\"",
        )
        .body(Body::empty())
        .expect("a request");
    let (status, _, _) = call(vec![air_quality(true)], stale).await;
    assert_eq!(status, StatusCode::OK, "a stale copy is replaced");
}

/// DM-02: a model whose artifacts are not committed still describes itself, from the
/// grants alone — and still says nothing the grants do not cover.
#[tokio::test]
async fn a_model_without_artifacts_is_derived_from_the_grants() {
    let (status, _, schema) = call(
        vec![air_quality(false)],
        get(&format!("/api/endpoint/{SLUG}/schema/v1/json-schema")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let air = &schema["$defs"]["AirQualityObserved"];
    assert_eq!(air["type"], json!("object"));
    assert_eq!(
        air["properties"]["type"]["const"],
        json!("AirQualityObserved")
    );
    for granted in ["pm10", "pm25", "location"] {
        assert!(!air["properties"][granted].is_null(), "{granted}");
    }
    assert!(air["properties"]["internalNote"].is_null());
    assert!(
        schema["$defs"]["InternalIncident"].is_null(),
        "a class outside the grant is not derived either"
    );

    let (status, _, document) = call(
        vec![air_quality(false)],
        get(&format!("/api/endpoint/{SLUG}/schema/v1/context.jsonld")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let terms = &document["@context"][1];
    assert!(!terms["pm10"].is_null());
    assert!(terms["internalNote"].is_null());
}

/// DM-22: `v{major}` names a major the space actually publishes; anything else is not a
/// document, and an unknown slug says nothing about whether it exists (EP-03).
#[tokio::test]
async fn an_unknown_major_slug_or_document_is_a_miss() {
    for path in [
        format!("/api/endpoint/{SLUG}/schema/v9/json-schema"),
        format!("/api/endpoint/{SLUG}/schema/2/json-schema"),
        format!("/api/endpoint/{SLUG}/schema/v1/model.parquet"),
        "/api/endpoint/nosuchendpoint/schema/index.json".to_owned(),
        "/api/endpoint/nosuchendpoint/schema/v1/json-schema".to_owned(),
    ] {
        let (status, _, _) = call(vec![air_quality(true)], get(&path)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
}
