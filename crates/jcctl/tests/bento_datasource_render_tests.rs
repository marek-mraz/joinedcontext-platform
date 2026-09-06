//! T-0291: what a `DataSource` becomes in the generated `bento.yaml` (PL-39, PL-16, PL-03).
//!
//! The golden strings below are the contract with the runner: Bento's own field names, the
//! credential as an interpolation and never a value, and the author's processors and output
//! exactly as they were written.

use jc_core::envelope::ResourceEnvelope;
use jc_core::kinds::DataSourceSpec;
use jcctl::bento::{input_of, render, InputContext, RenderError};

fn source(yaml: &str) -> DataSourceSpec {
    let parsed = ResourceEnvelope::<DataSourceSpec>::from_yaml(yaml).expect("parses");
    parsed.validate().expect("valid");
    parsed.spec
}

fn context<'a>(name: &'a str) -> InputContext<'a> {
    InputContext {
        source: name,
        project: "bb-ovzdusie",
        pipeline: "aq-mqtt-ingest",
    }
}

fn rendered(spec: &DataSourceSpec, name: &str) -> String {
    serde_norway::to_string(&input_of(spec, &context(name))).expect("serializes")
}

const MQTT: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: DataSource
metadata: { name: mqtt-mesto, namespace: bb-ovzdusie }
spec:
  type: mqtt
  mqtt:
    urls: ["tls://mqtt.banskabystrica.sk:8883"]
    topics: ["sensors/aq/+/reading"]
    qos: 1
    cleanSession: false
    username: bb-collector
    passwordRef: { name: mqtt-mesto, key: password }
  tls:
    caCertRef: { name: city-ca, key: ca.crt }
"#;

const MQTT_INPUT: &str = r#"mqtt:
  urls:
  - tls://mqtt.banskabystrica.sk:8883
  topics:
  - sensors/aq/+/reading
  client_id: jc-bb-ovzdusie-aq-mqtt-ingest
  qos: 1
  clean_session: false
  user: bb-collector
  password: ${DS_MQTT_MESTO_PASSWORD}
  tls:
    enabled: true
    root_cas: ${DS_MQTT_MESTO_CA_CRT}
"#;

const HTTP: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: DataSource
metadata: { name: aq-opendata, namespace: bb-ovzdusie }
spec:
  type: http
  http:
    url: https://opendata.banskabystrica.sk/aq.json
    headers: { Accept: application/json }
    authorization: { scheme: Bearer, headerRef: { name: aq-api, key: token } }
    timeout: 10s
"#;

const HTTP_INPUT: &str = r#"http_client:
  url: https://opendata.banskabystrica.sk/aq.json
  verb: GET
  headers:
    Accept: application/json
    Authorization: Bearer ${DS_AQ_OPENDATA_TOKEN}
  timeout: 10s
  tls:
    enabled: true
"#;

const WEB_SOCKET: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: DataSource
metadata: { name: aq-stream, namespace: bb-ovzdusie }
spec:
  type: websocket
  webSocket:
    url: wss://feed.banskabystrica.sk/aq
    openMessage: '{"subscribe":"aq"}'
"#;

const WEB_SOCKET_INPUT: &str = r#"websocket:
  url: wss://feed.banskabystrica.sk/aq
  open_message: '{"subscribe":"aq"}'
  open_message_type: text
"#;

const GTFS_RT: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: DataSource
metadata: { name: mhd-vehicles, namespace: bb-doprava }
spec:
  type: gtfs-rt
  gtfsRt:
    url: https://gtfs.banskabystrica.sk/vehiclepositions.pb
    feed: vehiclePositions
"#;

/// What the author wrote: the meaning of the payload, and nothing about where it comes from.
const AUTHORED: &str = r#"pipeline:
  processors:
  - mapping: |
      let domain = env("JC_ORG_DOMAIN")
      root.id = "urn:ngsi-ld:%v:%v:%v:%v".format("AirQualityObserved", $domain, "ovzdusie", this.station)
output:
  http_client:
    url: ${JC_ENDPOINT_URL}/entityOperations/upsert
    verb: POST
"#;

#[test]
fn an_mqtt_connection_becomes_bentos_mqtt_input() {
    assert_eq!(rendered(&source(MQTT), "mqtt-mesto"), MQTT_INPUT);
}

#[test]
fn an_http_connection_becomes_an_http_client_poll() {
    assert_eq!(rendered(&source(HTTP), "aq-opendata"), HTTP_INPUT);
}

#[test]
fn a_websocket_connection_becomes_a_websocket_input() {
    assert_eq!(rendered(&source(WEB_SOCKET), "aq-stream"), WEB_SOCKET_INPUT);
}

/// PL-16: the generated config carries the interpolation and the manifest carries the
/// reference, so the secret itself exists in neither.
#[test]
fn no_rendered_input_contains_a_credential() {
    for (yaml, name) in [(MQTT, "mqtt-mesto"), (HTTP, "aq-opendata")] {
        let input = rendered(&source(yaml), name);
        assert!(input.contains("${DS_"), "no interpolation in:\n{input}");
        for leak in ["hunter2", "secret", "password: ", "token: "] {
            assert!(
                !input.contains(&format!("{leak}bb")) && !input.contains("Bearer eyJ"),
                "{name} leaked something that looks like a credential:\n{input}"
            );
        }
    }
}

#[test]
fn the_authors_processors_and_output_come_back_untouched() {
    let out = render(AUTHORED, &source(MQTT), &context("mqtt-mesto")).expect("renders");
    assert!(out.starts_with("input:"), "the input comes first:\n{out}");
    assert!(out.contains("env(\"JC_ORG_DOMAIN\")"));
    assert!(out.contains(
        "\"urn:ngsi-ld:%v:%v:%v:%v\".format(\"AirQualityObserved\", $domain, \"ovzdusie\", this.station)"
    ));
    assert!(out.contains("${JC_ENDPOINT_URL}/entityOperations/upsert"));

    // The author's half survives a round trip through the renderer unchanged.
    let parsed: serde_norway::Value = serde_norway::from_str(&out).expect("parses");
    let authored: serde_norway::Value = serde_norway::from_str(AUTHORED).expect("parses");
    for key in ["pipeline", "output"] {
        assert_eq!(
            parsed.get(key),
            authored.get(key),
            "{key} changed while rendering the input"
        );
    }
}

/// The GTFS-realtime feed is the one type that contributes a processor: the protobuf decoder
/// runs before the author's mapping, which then sees plain JSON.
#[test]
fn the_gtfs_decoder_runs_before_the_authors_processors() {
    let out = render(AUTHORED, &source(GTFS_RT), &context("mhd-vehicles")).expect("renders");
    let parsed: serde_norway::Value = serde_norway::from_str(&out).expect("parses");
    let processors = parsed
        .get("pipeline")
        .and_then(|p| p.get("processors"))
        .and_then(|p| p.as_sequence())
        .expect("processors");
    assert_eq!(processors.len(), 2, "decoder plus the author's mapping");
    assert_eq!(
        processors[0]
            .get("protobuf")
            .and_then(|p| p.get("message"))
            .and_then(|m| m.as_str()),
        Some("transit_realtime.FeedMessage")
    );
    assert!(
        processors[1].get("mapping").is_some(),
        "the author's is second"
    );
}

/// PL-39: two inputs in one config is a merge nobody can review, so the plan fails instead.
#[test]
fn an_authored_input_and_a_reference_cannot_both_stand() {
    let with_input = format!("input:\n  generate:\n    interval: 10s\n{AUTHORED}");
    assert_eq!(
        render(&with_input, &source(MQTT), &context("mqtt-mesto")),
        Err(RenderError::InputAlreadyDeclared)
    );
}

#[test]
fn a_pipeline_without_a_bento_file_yet_still_renders() {
    let out = render("", &source(WEB_SOCKET), &context("aq-stream")).expect("renders");
    assert!(out.starts_with("input:"), "{out}");
    assert!(out.contains("wss://feed.banskabystrica.sk/aq"));
}

#[test]
fn a_bento_file_that_is_not_a_mapping_is_refused_by_name() {
    assert_eq!(
        render("- one\n- two\n", &source(MQTT), &context("mqtt-mesto")),
        Err(RenderError::NotAMapping)
    );
    assert!(matches!(
        render("input: [\n", &source(MQTT), &context("mqtt-mesto")),
        Err(RenderError::Parse(_))
    ));
}
