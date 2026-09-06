use jc_core::error::Error;
use jc_core::kinds::data_model::SemVer;
use jc_core::kinds::mapping::{DataModelRef, NativeBlock, NativeLanguage};
use jc_core::kinds::Mapping;
use serde_json::json;

const GOLDEN: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: Mapping
metadata:
  name: sdm-airquality-to-bb
  namespace: bb-ovzdusie
  title:
    sk: "SDM AirQualityObserved → BB kvalita ovzdušia"
    en: "SDM AirQualityObserved → BB air quality"
spec:
  contextSpaceRef: ovzdusie
  source:
    kind: DataModel
    name: sdm-airqualityobserved
    version: "1.0.0"
  target:
    kind: DataModel
    name: bb-air-quality
    version: "2.0.0"
  transformation:
    id: https://bb.example.sk/mappings/sdm-airquality-to-bb
    class_derivations:
      BBAirQuality:
        populated_from: AirQualityObserved
        slot_derivations:
          id:
            populated_from: id
          pm10:
            populated_from: pm10
          pm25:
            populated_from: pm2p5
          temperatureC:
            populated_from: temperature
            unit_conversion:
              target_unit: Cel
          observedAt:
            populated_from: dateObserved
          label:
            expr: "{stationName} + ' (' + {areaServed} + ')'"
          qualityBand:
            populated_from: airQualityLevel
            value_mappings:
              good: A
              moderate: B
              unhealthy: C
  vocabularyAlignment:
    sssomRef:
      kind: Mapping
      name: sdm-to-bb-terms
  tests:
    - name: golden-sdm-to-bb
      input:
        id: "urn:ngsi-ld:AirQualityObserved:sdm:station-01"
        type: AirQualityObserved
        pm10: 25.4
        pm2p5: 12.1
        temperature: 21.5
        dateObserved: "2026-09-01T12:00:00Z"
        stationName: "Radvan"
        areaServed: "Banska Bystrica"
        airQualityLevel: "good"
      expected:
        id: "urn:ngsi-ld:BBAirQuality:banskabystrica.sk:ovzdusie:station-01"
        type: BBAirQuality
        pm10: 25.4
        pm25: 12.1
        temperatureC: 21.5
        observedAt: "2026-09-01T12:00:00Z"
        label: "Radvan (Banska Bystrica)"
        qualityBand: "A"
"#;

#[test]
fn golden_mapping_parses_validates_and_roundtrips() {
    let mapping = Mapping::from_yaml(GOLDEN).expect("valid golden YAML");
    mapping.validate().expect("golden mapping validates");

    assert_eq!(
        mapping.resource_path().expect("resource path"),
        "projects/bb-ovzdusie/spaces/ovzdusie/datamodels/mappings/sdm-airquality-to-bb.yaml"
    );

    assert_eq!(mapping.spec.context_space_ref, "ovzdusie");
    assert_eq!(mapping.spec.source.name, "sdm-airqualityobserved");
    assert_eq!(mapping.spec.source.version.as_str(), "1.0.0");
    assert_eq!(mapping.spec.target.name, "bb-air-quality");
    assert_eq!(mapping.spec.target.version.as_str(), "2.0.0");
    assert!(!mapping.spec.requires_elevated_lane());
    assert_eq!(
        mapping.spec.compiled_bloblang_path(&mapping.metadata.name),
        "generated/sdm-airquality-to-bb.blobl"
    );

    let serialized_yaml = mapping.to_yaml().expect("serialize to yaml");
    let reimported_yaml = Mapping::from_yaml(&serialized_yaml).expect("re-import yaml");
    assert_eq!(mapping, reimported_yaml);

    let serialized_json = mapping.to_json().expect("serialize to json");
    let reimported_json = Mapping::from_json(&serialized_json).expect("re-import json");
    assert_eq!(mapping, reimported_json);
}

#[test]
fn tests_empty_fails_validation_dm39() {
    let mapping = Mapping::from_yaml(GOLDEN).expect("valid golden YAML");
    let mut bad = mapping;
    bad.spec.tests = vec![];

    let err = bad.validate().expect_err("tests: [] must be rejected");
    match err {
        Error::Name { field, .. } => assert_eq!(field, "spec.tests"),
        other => panic!("expected Error::Name for spec.tests, got: {other:?}"),
    }
}

#[test]
fn duplicate_test_names_fail_validation() {
    let mapping = Mapping::from_yaml(GOLDEN).expect("valid golden YAML");
    let mut bad = mapping;
    let duplicate_test = bad.spec.tests[0].clone();
    bad.spec.tests.push(duplicate_test);

    let err = bad
        .validate()
        .expect_err("duplicate test name must be rejected");
    match err {
        Error::Name { field, .. } => assert_eq!(field, "spec.tests.name"),
        other => panic!("expected Error::Name for spec.tests.name, got: {other:?}"),
    }
}

#[test]
fn test_input_and_expected_must_be_json_objects() {
    let mapping = Mapping::from_yaml(GOLDEN).expect("valid golden YAML");

    // Input is an array instead of object
    let mut bad_input = mapping.clone();
    bad_input.spec.tests[0].input = json!(["not", "an", "object"]);
    let err_in = bad_input
        .validate()
        .expect_err("non-object input must fail");
    match err_in {
        Error::Name { field, .. } => assert_eq!(field, "spec.tests.input"),
        other => panic!("expected Error::Name for spec.tests.input, got: {other:?}"),
    }

    // Expected is a string instead of object
    let mut bad_expected = mapping;
    bad_expected.spec.tests[0].expected = json!("not-an-object");
    let err_exp = bad_expected
        .validate()
        .expect_err("non-object expected must fail");
    match err_exp {
        Error::Name { field, .. } => assert_eq!(field, "spec.tests.expected"),
        other => panic!("expected Error::Name for spec.tests.expected, got: {other:?}"),
    }
}

#[test]
fn transformation_class_derivations_validation_dm33() {
    let mapping = Mapping::from_yaml(GOLDEN).expect("valid golden YAML");

    // transformation is a string, not an object
    let mut bad_not_obj = mapping.clone();
    bad_not_obj.spec.transformation = json!("invalid-string-spec");
    let err1 = bad_not_obj
        .validate()
        .expect_err("non-object transformation must fail");
    match err1 {
        Error::Name { field, .. } => assert_eq!(field, "spec.transformation"),
        other => panic!("expected Error::Name for spec.transformation, got: {other:?}"),
    }

    // transformation missing class_derivations
    let mut bad_no_cd = mapping.clone();
    bad_no_cd.spec.transformation = json!({ "id": "https://example.com/spec" });
    let err2 = bad_no_cd
        .validate()
        .expect_err("missing class_derivations must fail");
    match err2 {
        Error::Name { field, .. } => {
            assert_eq!(field, "spec.transformation.class_derivations")
        }
        other => panic!("expected Error::Name, got: {other:?}"),
    }

    // transformation with empty class_derivations object
    let mut bad_empty_cd = mapping.clone();
    bad_empty_cd.spec.transformation = json!({
        "id": "https://example.com/spec",
        "class_derivations": {}
    });
    let err3 = bad_empty_cd
        .validate()
        .expect_err("empty class_derivations must fail");
    match err3 {
        Error::Name { field, .. } => {
            assert_eq!(field, "spec.transformation.class_derivations")
        }
        other => panic!("expected Error::Name, got: {other:?}"),
    }

    // transformation with non-object class_derivations
    let mut bad_cd_str = mapping;
    bad_cd_str.spec.transformation = json!({
        "id": "https://example.com/spec",
        "class_derivations": "not-an-object"
    });
    let err4 = bad_cd_str
        .validate()
        .expect_err("string class_derivations must fail");
    match err4 {
        Error::Name { field, .. } => {
            assert_eq!(field, "spec.transformation.class_derivations")
        }
        other => panic!("expected Error::Name, got: {other:?}"),
    }
}

#[test]
fn native_block_and_lane_elevation_dm38() {
    let mapping = Mapping::from_yaml(GOLDEN).expect("valid golden YAML");
    assert!(!mapping.spec.requires_elevated_lane());

    let mut with_native = mapping;
    with_native.spec.native.push(NativeBlock::new(
        "qualityBand",
        NativeLanguage::Bloblang,
        "root.qualityBand = if this.pm10 > 50 { \"C\" } else { \"A\" }",
    ));

    assert!(with_native.spec.requires_elevated_lane());
    with_native
        .validate()
        .expect("valid native block validates");

    let yaml = with_native.to_yaml().expect("serialize with native");
    let reimported = Mapping::from_yaml(&yaml).expect("re-import with native");
    assert_eq!(with_native, reimported);
}

#[test]
fn native_block_validation_rules_dm38() {
    let mapping = Mapping::from_yaml(GOLDEN).expect("valid golden YAML");

    // Duplicate targetSlot
    let mut dup_slot = mapping.clone();
    dup_slot.spec.native.push(NativeBlock::new(
        "slot_a",
        NativeLanguage::Bloblang,
        "root.slot_a = 1",
    ));
    dup_slot.spec.native.push(NativeBlock::new(
        "slot_a",
        NativeLanguage::Bloblang,
        "root.slot_a = 2",
    ));
    let err_dup = dup_slot
        .validate()
        .expect_err("duplicate targetSlot must fail");
    match err_dup {
        Error::Name { field, .. } => assert_eq!(field, "spec.native.targetSlot"),
        other => panic!("expected Error::Name for spec.native.targetSlot, got: {other:?}"),
    }

    // Invalid targetSlot syntax (starts with digit or has dash)
    for bad_slot in ["123bad", "bad-slot", "bad slot", ""] {
        let mut bad_syntax = mapping.clone();
        bad_syntax.spec.native.push(NativeBlock::new(
            bad_slot,
            NativeLanguage::Bloblang,
            "root.x = 1",
        ));
        let err = bad_syntax
            .validate()
            .expect_err("invalid slot name must fail");
        match err {
            Error::Name { field, .. } => assert_eq!(field, "spec.native.targetSlot"),
            other => panic!("expected Error::Name for spec.native.targetSlot, got: {other:?}"),
        }
    }

    // Empty source code
    let mut empty_src = mapping;
    empty_src
        .spec
        .native
        .push(NativeBlock::new("slot_b", NativeLanguage::Bloblang, "   "));
    let err_src = empty_src
        .validate()
        .expect_err("empty source code must fail");
    match err_src {
        Error::Name { field, .. } => assert_eq!(field, "spec.native.source"),
        other => panic!("expected Error::Name for spec.native.source, got: {other:?}"),
    }
}

#[test]
fn source_and_target_identical_pair_fails_dm33() {
    let mapping = Mapping::from_yaml(GOLDEN).expect("valid golden YAML");
    let mut bad = mapping;
    bad.spec.target = bad.spec.source.clone();

    let err = bad
        .validate()
        .expect_err("identical source and target must fail");
    match err {
        Error::Name { field, .. } => assert_eq!(field, "spec.target"),
        other => panic!("expected Error::Name for spec.target, got: {other:?}"),
    }
}

#[test]
fn source_and_target_same_name_different_version_is_valid_migration() {
    let mapping = Mapping::from_yaml(GOLDEN).expect("valid golden YAML");
    let mut v1_to_v2 = mapping;
    v1_to_v2.spec.source = DataModelRef::new("air-quality", SemVer::new("1.0.0").expect("semver"));
    v1_to_v2.spec.target = DataModelRef::new("air-quality", SemVer::new("2.0.0").expect("semver"));

    v1_to_v2
        .validate()
        .expect("migration v1 -> v2 with same model name is valid");
}

#[test]
fn datamodel_ref_validation() {
    let mapping = Mapping::from_yaml(GOLDEN).expect("valid golden YAML");

    // Invalid DNS-1123 label for model name
    let mut bad_name = mapping.clone();
    bad_name.spec.source.name = "Invalid_Upper_Name".to_string();
    let err1 = bad_name
        .validate()
        .expect_err("invalid DNS label must fail");
    match err1 {
        Error::Name { field, .. } => assert_eq!(field, "spec.source.name"),
        other => panic!("expected Error::Name for spec.source.name, got: {other:?}"),
    }

    // Invalid kind
    let mut bad_kind = mapping;
    bad_kind.spec.target.kind = Some("ContextSpace".to_string());
    let err2 = bad_kind
        .validate()
        .expect_err("wrong kind on DataModelRef must fail");
    match err2 {
        Error::Kind { expected, got } => {
            assert_eq!(expected, "DataModel");
            assert_eq!(got, "ContextSpace");
        }
        other => panic!("expected Error::Kind, got: {other:?}"),
    }
}

#[test]
fn context_space_ref_validation() {
    let mapping = Mapping::from_yaml(GOLDEN).expect("valid golden YAML");
    let mut bad = mapping;
    bad.spec.context_space_ref = "Invalid_Space_Name".to_string();

    let err = bad.validate().expect_err("invalid space name must fail");
    match err {
        Error::Name { field, .. } => assert_eq!(field, "spec.contextSpaceRef"),
        other => panic!("expected Error::Name for spec.contextSpaceRef, got: {other:?}"),
    }
}

#[test]
fn deny_unknown_fields_rejection() {
    let bad_yaml = GOLDEN.replace(
        "contextSpaceRef: ovzdusie",
        "contextSpaceRef: ovzdusie\n  unexpectedField: forbidden",
    );
    assert!(Mapping::from_yaml(&bad_yaml).is_err());
}
