use chrono::{DateTime, Utc};
use jc_core::envelope::TypedRef;
use jc_core::error::Error;
use jc_core::kinds::data_model::{
    DataModelLifecycle, DataModelSource, DataModelSpec, GeneratedArtifacts, SemVer,
};
use jc_core::kinds::DataModel;

const GOLDEN: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: DataModel
metadata:
  name: bb-air-quality
  namespace: bb-ovzdusie
  title:
    sk: "Kvalita ovzdušia"
    en: "Air quality"
spec:
  contextSpaceRef: ovzdusie
  version: 2.1.0
  lifecycle: published
  source:
    kind: imported
    repository: https://github.com/smart-data-models/dataModel.Environment
    path: AirQualityObserved
    commit: 9f1c2b7d4e6a8c0b2d4f6a8c0e2b4d6f8a0c2e4b
  linkmlPath: datamodels/bb-air-quality.linkml.yaml
  generated:
    jsonSchema: json-schema/bb-air-quality.v2.json
    context: context/bb-air-quality.v2.jsonld
    docs: docs/bb-air-quality.md
    example: examples/bb-air-quality.example.jsonld
  openWorld: false
"#;

#[test]
fn golden_data_model_parses_validates_and_roundtrips() {
    let dm = DataModel::from_yaml(GOLDEN).expect("parse golden data model");
    dm.validate().expect("golden data model validates");

    assert_eq!(dm.metadata.name, "bb-air-quality");
    assert_eq!(dm.metadata.namespace.as_deref(), Some("bb-ovzdusie"));
    assert_eq!(dm.spec.context_space_ref, "ovzdusie");
    assert_eq!(dm.spec.version.as_str(), "2.1.0");
    assert_eq!(dm.spec.version.major(), 2);
    assert_eq!(dm.spec.version.minor(), 1);
    assert_eq!(dm.spec.version.patch(), 0);
    assert_eq!(dm.spec.lifecycle, DataModelLifecycle::Published);
    assert!(dm.spec.can_be_referenced());
    assert_eq!(
        dm.spec.schema_url_path(&dm.metadata.name),
        "schema/v2/bb-air-quality.json"
    );

    assert_eq!(
        dm.resource_path().expect("resource path"),
        "projects/bb-ovzdusie/spaces/ovzdusie/datamodels/bb-air-quality.yaml"
    );

    let serialized = dm.to_yaml().expect("serialize to yaml");
    let reimported = DataModel::from_yaml(&serialized).expect("deserialize serialized yaml");
    assert_eq!(dm, reimported);

    let json = dm.to_json().expect("serialize to json");
    let reimported_json = DataModel::from_json(&json).expect("deserialize json");
    assert_eq!(dm, reimported_json);
}

#[test]
fn authored_data_model_draft_parses_and_validates() {
    let yaml = r#"apiVersion: joinedcontext.com/v1alpha1
kind: DataModel
metadata:
  name: noise-level
  namespace: bb-ovzdusie
spec:
  contextSpaceRef: hluk
  version: 0.1.0
  lifecycle: draft
  source:
    kind: authored
  linkmlPath: datamodels/noise-level.linkml.yaml
"#;

    let dm = DataModel::from_yaml(yaml).expect("parse authored draft");
    dm.validate().expect("draft validates");

    assert_eq!(dm.spec.lifecycle, DataModelLifecycle::Draft);
    assert!(!dm.spec.can_be_referenced());
    assert!(!dm.spec.generated.is_complete());
    assert_eq!(dm.spec.source, DataModelSource::Authored {});

    let roundtripped =
        DataModel::from_yaml(&dm.to_yaml().expect("to yaml")).expect("from yaml roundtrip");
    assert_eq!(dm, roundtripped);
}

#[test]
fn remote_data_model_mirrored_parses_and_validates() {
    let yaml = r#"apiVersion: joinedcontext.com/v1alpha1
kind: DataModel
metadata:
  name: peer-transport
  namespace: bb-doprava
spec:
  contextSpaceRef: doprava
  version: 1.0.0
  lifecycle: mirrored
  source:
    kind: remote
    url: https://remote.city.sk/api/endpoint/traffic
    version: 1.0.0
    sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    fetchedAt: "2026-09-01T10:00:00Z"
  linkmlPath: datamodels/peer-transport.linkml.yaml
"#;

    let dm = DataModel::from_yaml(yaml).expect("parse remote mirrored");
    dm.validate().expect("mirrored validates");

    assert_eq!(dm.spec.lifecycle, DataModelLifecycle::Mirrored);
    assert!(!dm.spec.can_be_referenced());
    match &dm.spec.source {
        DataModelSource::Remote {
            url,
            version,
            sha256,
            fetched_at,
        } => {
            assert_eq!(url, "https://remote.city.sk/api/endpoint/traffic");
            assert_eq!(version.as_str(), "1.0.0");
            assert_eq!(
                sha256,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            );
            assert_eq!(
                *fetched_at,
                "2026-09-01T10:00:00Z".parse::<DateTime<Utc>>().unwrap()
            );
        }
        _ => panic!("expected remote source"),
    }

    let roundtripped =
        DataModel::from_yaml(&dm.to_yaml().expect("to yaml")).expect("from yaml roundtrip");
    assert_eq!(dm, roundtripped);
}

#[test]
fn semver_parsing_table() {
    let valid_cases = [
        ("0.0.1", 0, 0, 1),
        ("0.1.0", 0, 1, 0),
        ("1.0.0", 1, 0, 0),
        ("2.1.0", 2, 1, 0),
        ("10.20.30", 10, 20, 30),
        ("0.0.0", 0, 0, 0),
        ("100.200.300", 100, 200, 300),
    ];

    for (s, major, minor, patch) in valid_cases {
        let v = SemVer::new(s).expect("valid semver");
        assert_eq!(v.major(), major);
        assert_eq!(v.minor(), minor);
        assert_eq!(v.patch(), patch);
        assert_eq!(v.as_str(), s);
        assert_eq!(v.to_string(), s);
        assert_eq!(s.parse::<SemVer>().expect("parse semver"), v);
    }

    let invalid_cases = [
        "",
        "1",
        "1.0",
        "1.0.0.0",
        "01.0.0",
        "1.02.0",
        "1.0.03",
        "1.0.0-alpha",
        "1.0.0+build",
        "v1.0.0",
        "-1.0.0",
        "a.b.c",
        "1.0.0.",
        ".1.0.0",
        "1..0",
        "1.0. 0",
    ];

    for bad in invalid_cases {
        assert!(
            SemVer::new(bad).is_err(),
            "expected `{bad}` to be rejected as invalid semver"
        );
    }
}

#[test]
fn lifecycle_transition_matrix() {
    let states = [
        DataModelLifecycle::Draft,
        DataModelLifecycle::Published,
        DataModelLifecycle::Deprecated,
        DataModelLifecycle::Retired,
        DataModelLifecycle::Mirrored,
    ];

    // Every state may transition to itself.
    for s in states {
        assert!(s.allows_transition_to(s), "{s} must allow self-transition");
    }

    // Allowed forward transitions.
    assert!(DataModelLifecycle::Draft.allows_transition_to(DataModelLifecycle::Published));
    assert!(DataModelLifecycle::Published.allows_transition_to(DataModelLifecycle::Deprecated));
    assert!(DataModelLifecycle::Deprecated.allows_transition_to(DataModelLifecycle::Retired));

    // Forbidden transitions from Draft.
    assert!(!DataModelLifecycle::Draft.allows_transition_to(DataModelLifecycle::Deprecated));
    assert!(!DataModelLifecycle::Draft.allows_transition_to(DataModelLifecycle::Retired));
    assert!(!DataModelLifecycle::Draft.allows_transition_to(DataModelLifecycle::Mirrored));

    // Forbidden transitions from Published.
    assert!(!DataModelLifecycle::Published.allows_transition_to(DataModelLifecycle::Draft));
    assert!(!DataModelLifecycle::Published.allows_transition_to(DataModelLifecycle::Retired));
    assert!(!DataModelLifecycle::Published.allows_transition_to(DataModelLifecycle::Mirrored));

    // Forbidden transitions from Deprecated.
    assert!(!DataModelLifecycle::Deprecated.allows_transition_to(DataModelLifecycle::Draft));
    assert!(!DataModelLifecycle::Deprecated.allows_transition_to(DataModelLifecycle::Published));
    assert!(!DataModelLifecycle::Deprecated.allows_transition_to(DataModelLifecycle::Mirrored));

    // Retired is terminal.
    assert!(!DataModelLifecycle::Retired.allows_transition_to(DataModelLifecycle::Draft));
    assert!(!DataModelLifecycle::Retired.allows_transition_to(DataModelLifecycle::Published));
    assert!(!DataModelLifecycle::Retired.allows_transition_to(DataModelLifecycle::Deprecated));
    assert!(!DataModelLifecycle::Retired.allows_transition_to(DataModelLifecycle::Mirrored));

    // Mirrored only transitions to itself.
    assert!(!DataModelLifecycle::Mirrored.allows_transition_to(DataModelLifecycle::Draft));
    assert!(!DataModelLifecycle::Mirrored.allows_transition_to(DataModelLifecycle::Published));
    assert!(!DataModelLifecycle::Mirrored.allows_transition_to(DataModelLifecycle::Deprecated));
    assert!(!DataModelLifecycle::Mirrored.allows_transition_to(DataModelLifecycle::Retired));
}

#[test]
fn can_be_referenced_only_for_published() {
    let mut dm = DataModel::from_yaml(GOLDEN).expect("golden");

    dm.spec.lifecycle = DataModelLifecycle::Published;
    assert!(dm.spec.can_be_referenced());

    dm.spec.lifecycle = DataModelLifecycle::Draft;
    assert!(!dm.spec.can_be_referenced());

    dm.spec.lifecycle = DataModelLifecycle::Deprecated;
    assert!(!dm.spec.can_be_referenced());

    dm.spec.lifecycle = DataModelLifecycle::Retired;
    assert!(!dm.spec.can_be_referenced());

    dm.spec.lifecycle = DataModelLifecycle::Mirrored;
    assert!(!dm.spec.can_be_referenced());
}

#[test]
fn schema_url_path_formatting() {
    let mut dm = DataModel::from_yaml(GOLDEN).expect("golden");

    dm.spec.version = SemVer::new("2.1.0").unwrap();
    assert_eq!(
        dm.spec.schema_url_path("bb-air-quality"),
        "schema/v2/bb-air-quality.json"
    );

    dm.spec.version = SemVer::new("0.1.0").unwrap();
    assert_eq!(
        dm.spec.schema_url_path("temp-sensor"),
        "schema/v0/temp-sensor.json"
    );

    dm.spec.version = SemVer::new("15.0.3").unwrap();
    assert_eq!(
        dm.spec.schema_url_path("waste-station"),
        "schema/v15/waste-station.json"
    );
}

#[test]
fn context_space_ref_validation() {
    let mut dm = DataModel::from_yaml(GOLDEN).expect("golden");

    for bad in ["-bad", "bad_space", "BadSpace", "", &"a".repeat(64)] {
        dm.spec.context_space_ref = bad.to_string();
        let err = dm.spec.validate().expect_err("bad contextSpaceRef");
        match err {
            Error::Name { field, .. } => assert_eq!(field, "contextSpaceRef"),
            other => panic!("expected Error::Name for contextSpaceRef, got {other:?}"),
        }
    }
}

#[test]
fn linkml_path_validation() {
    let base = DataModel::from_yaml(GOLDEN).expect("golden");

    // Does not end in .linkml.yaml
    let mut dm = base.clone();
    dm.spec.linkml_path = "datamodels/bb-air-quality.yaml".to_string();
    let err = dm
        .spec
        .validate()
        .expect_err("does not end in .linkml.yaml");
    assert!(matches!(
        err,
        Error::Name {
            field: "linkmlPath",
            ..
        }
    ));

    // Absolute path
    let mut dm = base.clone();
    dm.spec.linkml_path = "/datamodels/bb-air-quality.linkml.yaml".to_string();
    let err = dm.spec.validate().expect_err("absolute linkml_path");
    assert!(matches!(
        err,
        Error::Name {
            field: "linkmlPath",
            ..
        }
    ));

    // Path traversal ..
    let mut dm = base.clone();
    dm.spec.linkml_path = "../datamodels/bb-air-quality.linkml.yaml".to_string();
    let err = dm.spec.validate().expect_err("path traversal");
    assert!(matches!(
        err,
        Error::Name {
            field: "linkmlPath",
            ..
        }
    ));

    let mut dm = base.clone();
    dm.spec.linkml_path = "a/../b.linkml.yaml".to_string();
    let err = dm.spec.validate().expect_err("inner path traversal");
    assert!(matches!(
        err,
        Error::Name {
            field: "linkmlPath",
            ..
        }
    ));

    // Empty path
    let mut dm = base.clone();
    dm.spec.linkml_path = "".to_string();
    let err = dm.spec.validate().expect_err("empty linkml_path");
    assert!(matches!(
        err,
        Error::Name {
            field: "linkmlPath",
            ..
        }
    ));
}

#[test]
fn generated_artifacts_path_validation() {
    let base = DataModel::from_yaml(GOLDEN).expect("golden");

    // Absolute path in jsonSchema
    let mut dm = base.clone();
    dm.spec.generated.json_schema = Some("/schema.json".to_string());
    let err = dm.spec.validate().expect_err("absolute jsonSchema");
    assert!(matches!(
        err,
        Error::Name {
            field: "generated.jsonSchema",
            ..
        }
    ));

    // Path traversal in context
    let mut dm = base.clone();
    dm.spec.generated.context = Some("../context.jsonld".to_string());
    let err = dm.spec.validate().expect_err("traversal context");
    assert!(matches!(
        err,
        Error::Name {
            field: "generated.context",
            ..
        }
    ));

    // Absolute path in docs
    let mut dm = base.clone();
    dm.spec.generated.docs = Some("/docs/model.md".to_string());
    let err = dm.spec.validate().expect_err("absolute docs");
    assert!(matches!(
        err,
        Error::Name {
            field: "generated.docs",
            ..
        }
    ));

    // Path traversal in example
    let mut dm = base.clone();
    dm.spec.generated.example = Some("a/../example.jsonld".to_string());
    let err = dm.spec.validate().expect_err("traversal example");
    assert!(matches!(
        err,
        Error::Name {
            field: "generated.example",
            ..
        }
    ));
}

#[test]
fn published_lifecycle_requires_all_four_generated_artifacts() {
    let base = DataModel::from_yaml(GOLDEN).expect("golden");

    // Missing jsonSchema
    let mut dm = base.clone();
    dm.spec.generated.json_schema = None;
    let err = dm.spec.validate().expect_err("missing jsonSchema");
    assert!(matches!(
        err,
        Error::Name {
            field: "generated.jsonSchema",
            ..
        }
    ));

    // Missing context
    let mut dm = base.clone();
    dm.spec.generated.context = None;
    let err = dm.spec.validate().expect_err("missing context");
    assert!(matches!(
        err,
        Error::Name {
            field: "generated.context",
            ..
        }
    ));

    // Missing docs
    let mut dm = base.clone();
    dm.spec.generated.docs = None;
    let err = dm.spec.validate().expect_err("missing docs");
    assert!(matches!(
        err,
        Error::Name {
            field: "generated.docs",
            ..
        }
    ));

    // Missing example
    let mut dm = base.clone();
    dm.spec.generated.example = None;
    let err = dm.spec.validate().expect_err("missing example");
    assert!(matches!(
        err,
        Error::Name {
            field: "generated.example",
            ..
        }
    ));

    // In draft lifecycle, all artifacts may be None
    let mut draft = base.clone();
    draft.spec.lifecycle = DataModelLifecycle::Draft;
    draft.spec.source = DataModelSource::Authored {};
    draft.spec.generated = GeneratedArtifacts::default();
    assert!(draft.spec.validate().is_ok());
}

#[test]
fn mirrored_lifecycle_and_remote_source_mutual_requirement() {
    let base = DataModel::from_yaml(GOLDEN).expect("golden");

    // Mirrored with Authored source
    let mut dm = base.clone();
    dm.spec.lifecycle = DataModelLifecycle::Mirrored;
    dm.spec.source = DataModelSource::Authored {};
    let err = dm.spec.validate().expect_err("mirrored with authored");
    assert!(matches!(
        err,
        Error::Name {
            field: "source",
            ..
        }
    ));

    // Mirrored with Imported source
    let mut dm = base.clone();
    dm.spec.lifecycle = DataModelLifecycle::Mirrored;
    let err = dm.spec.validate().expect_err("mirrored with imported");
    assert!(matches!(
        err,
        Error::Name {
            field: "source",
            ..
        }
    ));

    // Published with Remote source
    let mut dm = base.clone();
    dm.spec.source = DataModelSource::Remote {
        url: "https://remote.example.com".to_string(),
        version: SemVer::new("1.0.0").unwrap(),
        sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        fetched_at: "2026-09-05T10:00:00Z"
            .parse::<DateTime<Utc>>()
            .expect("fixed timestamp"),
    };
    let err = dm.spec.validate().expect_err("published with remote");
    assert!(matches!(
        err,
        Error::Name {
            field: "source",
            ..
        }
    ));

    // Draft with Remote source
    let mut dm_draft = dm.clone();
    dm_draft.spec.lifecycle = DataModelLifecycle::Draft;
    let err = dm_draft.spec.validate().expect_err("draft with remote");
    assert!(matches!(
        err,
        Error::Name {
            field: "source",
            ..
        }
    ));
}

#[test]
fn source_imported_validation() {
    let base = DataModel::from_yaml(GOLDEN).expect("golden");

    // Empty repository
    let mut dm = base.clone();
    dm.spec.source = DataModelSource::Imported {
        repository: "   ".to_string(),
        path: "AirQualityObserved".to_string(),
        commit: "9f1c2b7d4e6a8c0b2d4f6a8c0e2b4d6f8a0c2e4b".to_string(),
    };
    let err = dm.spec.validate().expect_err("empty repo");
    assert!(matches!(
        err,
        Error::Name {
            field: "source.repository",
            ..
        }
    ));

    // Empty path
    let mut dm = base.clone();
    dm.spec.source = DataModelSource::Imported {
        repository: "https://github.com/models".to_string(),
        path: "".to_string(),
        commit: "9f1c2b7d4e6a8c0b2d4f6a8c0e2b4d6f8a0c2e4b".to_string(),
    };
    let err = dm.spec.validate().expect_err("empty path");
    assert!(matches!(
        err,
        Error::Name {
            field: "source.path",
            ..
        }
    ));

    // Commit too short (< 7 chars)
    let mut dm = base.clone();
    dm.spec.source = DataModelSource::Imported {
        repository: "https://github.com/models".to_string(),
        path: "AirQualityObserved".to_string(),
        commit: "9f1c2b".to_string(),
    };
    let err = dm.spec.validate().expect_err("commit too short");
    assert!(matches!(
        err,
        Error::Name {
            field: "source.commit",
            ..
        }
    ));

    // Commit too long (> 40 chars)
    let mut dm = base.clone();
    dm.spec.source = DataModelSource::Imported {
        repository: "https://github.com/models".to_string(),
        path: "AirQualityObserved".to_string(),
        commit: "9f1c2b7d4e6a8c0b2d4f6a8c0e2b4d6f8a0c2e4b0".to_string(),
    };
    let err = dm.spec.validate().expect_err("commit too long");
    assert!(matches!(
        err,
        Error::Name {
            field: "source.commit",
            ..
        }
    ));

    // Commit uppercase hex
    let mut dm = base.clone();
    dm.spec.source = DataModelSource::Imported {
        repository: "https://github.com/models".to_string(),
        path: "AirQualityObserved".to_string(),
        commit: "9F1C2B7D4E6A8C0B2D4F6A8C0E2B4D6F8A0C2E4B".to_string(),
    };
    let err = dm.spec.validate().expect_err("commit uppercase");
    assert!(matches!(
        err,
        Error::Name {
            field: "source.commit",
            ..
        }
    ));

    // Commit non-hex
    let mut dm = base.clone();
    dm.spec.source = DataModelSource::Imported {
        repository: "https://github.com/models".to_string(),
        path: "AirQualityObserved".to_string(),
        commit: "9f1c2b7d4e6a8c0b2d4f6a8c0e2b4d6f8a0c2e4g".to_string(),
    };
    let err = dm.spec.validate().expect_err("commit non-hex");
    assert!(matches!(
        err,
        Error::Name {
            field: "source.commit",
            ..
        }
    ));

    // Valid 7-char prefix
    let mut dm = base.clone();
    dm.spec.source = DataModelSource::Imported {
        repository: "https://github.com/models".to_string(),
        path: "AirQualityObserved".to_string(),
        commit: "9f1c2b7".to_string(),
    };
    assert!(dm.spec.validate().is_ok());
}

#[test]
fn source_remote_validation() {
    let mut dm = DataModel::from_yaml(GOLDEN).expect("golden");
    dm.spec.lifecycle = DataModelLifecycle::Mirrored;

    // Empty URL
    dm.spec.source = DataModelSource::Remote {
        url: "".to_string(),
        version: SemVer::new("1.0.0").unwrap(),
        sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        fetched_at: "2026-09-05T10:00:00Z"
            .parse::<DateTime<Utc>>()
            .expect("fixed timestamp"),
    };
    let err = dm.spec.validate().expect_err("empty remote url");
    assert!(matches!(
        err,
        Error::Name {
            field: "source.url",
            ..
        }
    ));

    // Sha256 length != 64
    dm.spec.source = DataModelSource::Remote {
        url: "https://remote.example.com".to_string(),
        version: SemVer::new("1.0.0").unwrap(),
        sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde".to_string(),
        fetched_at: "2026-09-05T10:00:00Z"
            .parse::<DateTime<Utc>>()
            .expect("fixed timestamp"),
    };
    let err = dm.spec.validate().expect_err("sha256 63 chars");
    assert!(matches!(
        err,
        Error::Name {
            field: "source.sha256",
            ..
        }
    ));

    // Sha256 uppercase
    dm.spec.source = DataModelSource::Remote {
        url: "https://remote.example.com".to_string(),
        version: SemVer::new("1.0.0").unwrap(),
        sha256: "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF".to_string(),
        fetched_at: "2026-09-05T10:00:00Z"
            .parse::<DateTime<Utc>>()
            .expect("fixed timestamp"),
    };
    let err = dm.spec.validate().expect_err("sha256 uppercase");
    assert!(matches!(
        err,
        Error::Name {
            field: "source.sha256",
            ..
        }
    ));
}

#[test]
fn consumers_validation() {
    let mut dm = DataModel::from_yaml(GOLDEN).expect("golden");

    dm.spec.consumers = vec![TypedRef {
        kind: "Endpoint".to_string(),
        name: "air-quality-public".to_string(),
        namespace: Some("bb-ovzdusie".to_string()),
    }];
    assert!(dm.spec.validate().is_ok());

    dm.spec.consumers = vec![TypedRef {
        kind: "Endpoint".to_string(),
        name: "Invalid_Name".to_string(),
        namespace: Some("bb-ovzdusie".to_string()),
    }];
    assert!(dm.spec.validate().is_err());
}

#[test]
fn deny_unknown_fields_rejections() {
    let bad_spec = GOLDEN.replace(
        "openWorld: false",
        "openWorld: false\n  unknownField: forbidden",
    );
    assert!(DataModel::from_yaml(&bad_spec).is_err());

    let bad_generated = GOLDEN.replace(
        "example: examples/bb-air-quality.example.jsonld",
        "example: examples/bb-air-quality.example.jsonld\n    unknownArtifact: bad",
    );
    assert!(DataModel::from_yaml(&bad_generated).is_err());

    let bad_source = GOLDEN.replace(
        "commit: 9f1c2b7d4e6a8c0b2d4f6a8c0e2b4d6f8a0c2e4b",
        "commit: 9f1c2b7d4e6a8c0b2d4f6a8c0e2b4d6f8a0c2e4b\n    unknownProvenance: bad",
    );
    assert!(DataModel::from_yaml(&bad_source).is_err());
}

#[test]
fn schema_generation_smoke() {
    let schema = schemars::schema_for!(DataModelSpec);
    let json = serde_json::to_string(&schema).expect("schema serialize");
    assert!(json.contains("SemVer"));
}
