use jc_core::kinds::{ComputeKind, OutputMode, Pipeline, PipelineClass};
use jc_core::urn::Urn;

const GOLDEN_MQTT: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: Pipeline
metadata:
  name: smart-meter-mqtt
  namespace: bb-energie
spec:
  class: resident             # resident | scheduled | auto
  targetEndpoint: urn:ngsi-ld:Endpoint:banskabystrica.sk:energie:ep-smart-meters
  secretRefs:
    - name: mqtt-credentials
      key: password
      envVar: MQTT_PASSWORD
  quotas:
    maxMemoryMb: 128
    cpuMillicores: 250
"#;

const GOLDEN_DERIVED: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: Pipeline
metadata:
  name: district-air-index-daily
  namespace: bb-ovzdusie
spec:
  class: scheduled
  schedule: "10 0 * * *"                   # once a day, after midnight
  source:
    endpointRef: { kind: Endpoint, name: ovzdusie-internal }   # read grant, same or another space
    query: { type: AirQualityObserved, attrs: [pm10, pm25, refDistrict], temporalQ: { window: P1D } }
    # resident alternative: trigger: { subscription: { type: AirQualityObserved, watchedAttributes: [pm10, pm25] } }
  compute:
    kind: wasm                             # bloblang | mapping | wasm | container
    module: ./compute                      # Rust crate beside the pipeline, built in CI to wasm32-wasip1
    function: process
  targetEndpoint: urn:ngsi-ld:Endpoint:banskabystrica.sk:ovzdusie:ep-derived   # write grant; may point into another space
  output:
    type: AirQualityIndexDaily
    mode: upsert                           # upsert | update-attrs (same entity, new attributes)
"#;

#[test]
fn test_pipeline_smart_meter_mqtt_golden() {
    let p1 = Pipeline::from_yaml(GOLDEN_MQTT).expect("parses mqtt pipeline");
    p1.validate().expect("mqtt pipeline is valid");

    assert_eq!(p1.spec.class, PipelineClass::Resident);
    assert_eq!(
        p1.spec.target_endpoint.to_string(),
        "urn:ngsi-ld:Endpoint:banskabystrica.sk:energie:ep-smart-meters"
    );
    assert_eq!(p1.spec.secret_refs.len(), 1);
    assert_eq!(p1.spec.secret_refs[0].name, "mqtt-credentials");
    assert_eq!(p1.spec.secret_refs[0].key.as_deref(), Some("password"));
    assert_eq!(
        p1.spec.secret_refs[0].env_var.as_deref(),
        Some("MQTT_PASSWORD")
    );

    let quotas = p1.spec.quotas.as_ref().expect("quotas present");
    assert_eq!(quotas.max_memory_mb, Some(128));
    assert_eq!(quotas.cpu_millicores, Some(250));

    let yaml = p1.to_yaml().expect("serializes to yaml");
    let roundtripped = Pipeline::from_yaml(&yaml).expect("deserializes back");
    assert_eq!(p1, roundtripped);

    let path = p1.resource_path().expect("resource path");
    assert_eq!(
        path,
        "projects/bb-energie/pipelines/smart-meter-mqtt/pipeline.yaml"
    );
}

#[test]
fn test_pipeline_district_air_index_daily_golden() {
    let p2 = Pipeline::from_yaml(GOLDEN_DERIVED).expect("parses derived pipeline");
    p2.validate().expect("derived pipeline is valid");

    assert_eq!(p2.spec.class, PipelineClass::Scheduled);
    assert_eq!(p2.spec.schedule.as_deref(), Some("10 0 * * *"));

    let source = p2.spec.source.as_ref().expect("source present");
    assert_eq!(
        source.endpoint_ref.as_ref().map(|r| r.name()),
        Some("ovzdusie-internal")
    );

    let query = source.query.as_ref().expect("source query present");
    assert_eq!(query.entity_type.as_deref(), Some("AirQualityObserved"));
    assert_eq!(query.attrs, vec!["pm10", "pm25", "refDistrict"]);
    assert_eq!(
        query.temporal_q.as_ref().map(|t| t.window.as_str()),
        Some("P1D")
    );

    let compute = p2.spec.compute.as_ref().expect("compute present");
    assert_eq!(compute.kind, ComputeKind::Wasm);
    assert_eq!(compute.module.as_deref(), Some("./compute"));
    assert_eq!(compute.function.as_deref(), Some("process"));

    assert_eq!(
        p2.spec.target_endpoint.to_string(),
        "urn:ngsi-ld:Endpoint:banskabystrica.sk:ovzdusie:ep-derived"
    );

    let output = p2.spec.output.as_ref().expect("output present");
    assert_eq!(output.entity_type, "AirQualityIndexDaily");
    assert_eq!(output.mode, OutputMode::Upsert);

    let yaml = p2.to_yaml().expect("serializes to yaml");
    let roundtripped = Pipeline::from_yaml(&yaml).expect("deserializes back");
    assert_eq!(p2, roundtripped);
}

#[test]
fn test_pipeline_class_and_schedule_rules() {
    let mut p_sched = Pipeline::from_yaml(GOLDEN_DERIVED).expect("golden");
    p_sched.spec.schedule = None;
    assert!(
        p_sched.validate().is_err(),
        "scheduled class without schedule must fail"
    );

    let mut p_res = Pipeline::from_yaml(GOLDEN_MQTT).expect("golden");
    p_res.spec.schedule = Some("*/5 * * * *".to_string());
    assert!(
        p_res.validate().is_err(),
        "resident class with schedule must fail"
    );

    let mut p_auto = Pipeline::from_yaml(GOLDEN_MQTT).expect("golden");
    p_auto.spec.class = PipelineClass::Auto;
    p_auto.spec.schedule = None;
    assert!(
        p_auto.validate().is_ok(),
        "auto class without schedule must pass"
    );

    p_auto.spec.schedule = Some("0 * * * *".to_string());
    assert!(
        p_auto.validate().is_ok(),
        "auto class with schedule must pass"
    );
}

#[test]
fn test_cron_expression_validation() {
    let mut p = Pipeline::from_yaml(GOLDEN_DERIVED).expect("golden");

    // 4 fields
    p.spec.schedule = Some("0 0 * *".to_string());
    assert!(p.validate().is_err(), "4-field cron must fail");

    // 6 fields
    p.spec.schedule = Some("0 0 * * * *".to_string());
    assert!(p.validate().is_err(), "6-field cron must fail");
}

#[test]
fn test_compute_wasm_and_mapping_rules() {
    let mut p = Pipeline::from_yaml(GOLDEN_DERIVED).expect("golden");

    // wasm without function
    p.spec.compute.as_mut().unwrap().function = None;
    assert!(p.validate().is_err(), "wasm without function must fail");

    // mapping with module
    p.spec.compute.as_mut().unwrap().kind = ComputeKind::Mapping;
    p.spec.compute.as_mut().unwrap().mapping_ref =
        Some(jc_core::envelope::Ref::Name("mapping-name".to_string()));
    p.spec.compute.as_mut().unwrap().module = Some("./compute".to_string());
    p.spec.compute.as_mut().unwrap().function = None;
    assert!(p.validate().is_err(), "mapping with module must fail");
}

#[test]
fn test_target_endpoint_must_have_endpoint_type() {
    let mut p = Pipeline::from_yaml(GOLDEN_MQTT).expect("golden");
    p.spec.target_endpoint = "urn:ngsi-ld:Policy:banskabystrica.sk:energie:public-air-quality"
        .parse::<Urn>()
        .expect("valid urn");
    assert!(
        p.validate().is_err(),
        "targetEndpoint with non-Endpoint entity type must fail"
    );
}

#[test]
fn test_pl14_secret_ref_rejects_inline_secret() {
    let bad_yaml = r#"
apiVersion: joinedcontext.com/v1alpha1
kind: Pipeline
metadata:
  name: smart-meter-mqtt
  namespace: bb-energie
spec:
  class: resident
  targetEndpoint: urn:ngsi-ld:Endpoint:banskabystrica.sk:energie:ep-smart-meters
  secretRefs:
    - name: mqtt-credentials
      key: password
      password: inline-plain-secret
"#;
    let res = Pipeline::from_yaml(bad_yaml);
    assert!(
        res.is_err(),
        "expected deserialization failure when secretRefs has inline password field"
    );
}

#[test]
fn test_quotas_zero_bounds_fail() {
    let mut p = Pipeline::from_yaml(GOLDEN_MQTT).expect("golden");
    p.spec.quotas.as_mut().unwrap().max_memory_mb = Some(0);
    assert!(p.validate().is_err(), "maxMemoryMb: 0 must fail");
}
