//! T-0290: the `DataSource` kind, one connection and its references (MF-35, PL-39, CC-06).

use jc_core::envelope::ResourceEnvelope;
use jc_core::kinds::{DataSourceSpec, DataSourceType, GtfsFeed, PipelineSpec};
use jc_core::registry;

type DataSource = ResourceEnvelope<DataSourceSpec>;

const MQTT: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: DataSource
metadata:
  name: mqtt-mesto
  namespace: bb-ovzdusie
  title: { sk: "Mestský MQTT broker", en: "City MQTT broker" }
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

const HTTP: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: DataSource
metadata:
  name: aq-opendata
  namespace: bb-ovzdusie
spec:
  type: http
  http:
    url: https://opendata.banskabystrica.sk/aq.json
    verb: GET
    headers: { Accept: application/json }
    authorization: { scheme: Bearer, headerRef: { name: aq-api, key: token } }
    timeout: 10s
"#;

const WEB_SOCKET: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: DataSource
metadata:
  name: aq-stream
  namespace: bb-ovzdusie
spec:
  type: websocket
  webSocket:
    url: wss://feed.banskabystrica.sk/aq
    openMessage: '{"subscribe":"aq"}'
"#;

const GTFS_RT: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: DataSource
metadata:
  name: mhd-vehicles
  namespace: bb-doprava
spec:
  type: gtfs-rt
  gtfsRt:
    url: https://gtfs.banskabystrica.sk/vehiclepositions.pb
    feed: vehiclePositions
"#;

/// Every variant survives the round trip byte for byte in its meaning: what a reviewer read in
/// Git is what the reconciler renders from, and a field the parser drops silently is a change
/// nobody approved.
#[test]
fn every_connection_type_round_trips() {
    for (name, text, expected) in [
        ("mqtt", MQTT, DataSourceType::Mqtt),
        ("http", HTTP, DataSourceType::Http),
        ("webSocket", WEB_SOCKET, DataSourceType::WebSocket),
        ("gtfsRt", GTFS_RT, DataSourceType::GtfsRt),
    ] {
        let parsed = DataSource::from_yaml(text).unwrap_or_else(|e| panic!("{name}: {e}"));
        parsed.validate().unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(parsed.spec.source_type, expected);

        let again = DataSource::from_yaml(&serde_norway::to_string(&parsed).expect("serialize"))
            .unwrap_or_else(|e| panic!("{name} re-parse: {e}"));
        assert_eq!(parsed, again, "{name} does not survive a round trip");
    }
}

/// T-0393: the wire value is `websocket`, one word, and `web-socket` is not an alias.
///
/// The kind is documented before it is written (CC-11), so a manifest copied out of
/// `Architecture/08 §6` has to parse. Keeping the kebab-case spelling alive as a second
/// accepted value would be the friendlier change and the wrong one: two spellings for one type
/// is two things to write in every Portal form, every example and every locale bundle, and the
/// day they disagree is the day a manifest means different things to the reconciler and the UI.
#[test]
fn the_websocket_type_is_one_word() {
    let parsed = DataSource::from_yaml(WEB_SOCKET).expect("the documented spelling parses");
    parsed.validate().expect("valid");
    assert_eq!(parsed.spec.source_type, DataSourceType::WebSocket);
    assert_eq!(DataSourceType::WebSocket.to_string(), "websocket");
    assert!(
        serde_norway::to_string(&parsed)
            .expect("serialize")
            .contains("type: websocket"),
        "what is written back is what the documentation shows"
    );

    let kebab = WEB_SOCKET.replace("type: websocket", "type: web-socket");
    assert!(
        DataSource::from_yaml(&kebab).is_err(),
        "the old kebab-case spelling is refused, not silently accepted"
    );
}

#[test]
fn the_mqtt_connection_keeps_every_field_it_was_given() {
    let source = DataSource::from_yaml(MQTT).expect("parses");
    let mqtt = source.spec.mqtt.as_ref().expect("mqtt block");
    assert_eq!(mqtt.urls, ["tls://mqtt.banskabystrica.sk:8883"]);
    assert_eq!(mqtt.topics, ["sensors/aq/+/reading"]);
    assert_eq!(mqtt.qos, Some(1));
    assert_eq!(mqtt.clean_session, Some(false));
    assert_eq!(mqtt.username.as_deref(), Some("bb-collector"));
    assert_eq!(
        mqtt.password_ref.as_ref().map(|r| r.name.as_str()),
        Some("mqtt-mesto")
    );
    assert_eq!(source.spec.secret_refs().len(), 2, "password and CA");
}

#[test]
fn the_gtfs_feed_names_which_of_the_three_it_is() {
    let source = DataSource::from_yaml(GTFS_RT).expect("parses");
    assert_eq!(
        source.spec.gtfs_rt.as_ref().map(|g| g.feed),
        Some(GtfsFeed::VehiclePositions)
    );
    assert!(
        source.spec.secret_refs().is_empty(),
        "a public feed has none"
    );
}

/// CC-06: the type has no member a password could be written into, so the plaintext version of
/// the manifest above does not parse at all. This is the security property of MF-35.
#[test]
fn a_plaintext_credential_is_not_a_field_that_exists() {
    let plaintext = MQTT.replace(
        "passwordRef: { name: mqtt-mesto, key: password }",
        "password: hunter2",
    );
    let error = DataSource::from_yaml(&plaintext).expect_err("plaintext password is refused");
    assert!(
        error.to_string().contains("password"),
        "the error should name the offending field, got: {error}"
    );
}

#[test]
fn the_block_has_to_be_the_one_the_type_names() {
    let wrong = MQTT.replace("type: mqtt", "type: http");
    let error = DataSource::from_yaml(&wrong)
        .expect("parses")
        .validate()
        .expect_err("a type without its block is refused");
    assert!(error.to_string().contains("type"), "{error}");

    let both = MQTT.replace(
        "  tls:",
        "  http:\n    url: https://example.sk/a.json\n  tls:",
    );
    assert!(
        DataSource::from_yaml(&both)
            .expect("parses")
            .validate()
            .is_err(),
        "two connections in one source is refused"
    );
}

#[test]
fn a_connection_cannot_point_at_a_scheme_it_does_not_speak() {
    let file = MQTT.replace("tls://mqtt.banskabystrica.sk:8883", "file:///etc/passwd");
    assert!(DataSource::from_yaml(&file)
        .expect("parses")
        .validate()
        .is_err());

    let broker = HTTP.replace(
        "https://opendata.banskabystrica.sk/aq.json",
        "tcp://mqtt.banskabystrica.sk:1883",
    );
    assert!(DataSource::from_yaml(&broker)
        .expect("parses")
        .validate()
        .is_err());
}

#[test]
fn tls_verification_is_not_something_a_manifest_can_turn_off() {
    let insecure = MQTT.replace(
        "  tls:\n    caCertRef: { name: city-ca, key: ca.crt }",
        "  tls:\n    insecureSkipVerify: true",
    );
    let error = DataSource::from_yaml(&insecure)
        .expect("parses")
        .validate()
        .expect_err("skipping verification is refused");
    assert!(error.to_string().contains("caCertRef"), "{error}");
}

#[test]
fn the_environment_variable_of_a_reference_is_derived_or_stated() {
    let source = DataSource::from_yaml(MQTT).expect("parses");
    let password = source.spec.secret_refs()[0];
    assert_eq!(
        jc_core::kinds::data_source::env_var_of("mqtt-mesto", password),
        "DS_MQTT_MESTO_PASSWORD"
    );

    let stated = HTTP.replace(
        "headerRef: { name: aq-api, key: token }",
        "headerRef: { name: aq-api, key: token, envVar: AQ_TOKEN }",
    );
    let source = DataSource::from_yaml(&stated).expect("parses");
    assert_eq!(
        jc_core::kinds::data_source::env_var_of("aq-opendata", source.spec.secret_refs()[0]),
        "AQ_TOKEN"
    );
}

/// MF-09: the kind is in the catalogue, so the resource API, `jcctl` and the Portal form all
/// see it without another line of code anywhere.
#[test]
fn the_kind_is_in_the_catalogue_with_a_draft07_schema() {
    let info = registry::by_kind("DataSource").expect("catalogued");
    assert_eq!(info.plural, "datasources");
    assert_eq!(
        info.repo_path("bb-ovzdusie", "ovzdusie", "mqtt-mesto"),
        "projects/bb-ovzdusie/datasources/mqtt-mesto.yaml"
    );
    assert_eq!(registry::by_plural("datasources"), Some(info));

    let schema = registry::schema_of("DataSource").expect("schema");
    assert_eq!(
        schema.get("$schema").and_then(|v| v.as_str()),
        Some("http://json-schema.org/draft-07/schema#")
    );
    assert!(registry::validate_yaml("DataSource", MQTT)
        .expect("known kind")
        .is_ok());
}

/// PL-39: the reference is the pipeline's input, so it excludes the other input.
#[test]
fn a_pipeline_reads_a_data_source_or_an_endpoint_but_not_both() {
    let one_input = r#"class: resident
source:
  dataSourceRef: { kind: DataSource, name: mqtt-mesto }
targetEndpoint: urn:ngsi-ld:Endpoint:banskabystrica.sk:ovzdusie:ep-air
"#;
    let spec: PipelineSpec = serde_norway::from_str(one_input).expect("parses");
    spec.validate().expect("one input is valid");
    assert_eq!(
        spec.source
            .as_ref()
            .and_then(|s| s.data_source_ref.as_ref())
            .map(|r| r.name()),
        Some("mqtt-mesto")
    );

    let two_inputs = one_input.replace(
        "  dataSourceRef: { kind: DataSource, name: mqtt-mesto }",
        "  dataSourceRef: { kind: DataSource, name: mqtt-mesto }\n  endpointRef: { kind: Endpoint, name: ovzdusie-internal }",
    );
    let spec: PipelineSpec = serde_norway::from_str(&two_inputs).expect("parses");
    assert!(spec.validate().is_err(), "two inputs is refused");

    let wrong_kind = one_input.replace("kind: DataSource", "kind: Endpoint");
    let spec: PipelineSpec = serde_norway::from_str(&wrong_kind).expect("parses");
    assert!(spec.validate().is_err(), "the reference names its kind");
}
