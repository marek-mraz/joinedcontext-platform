use jc_core::error::Error;
use jc_core::kinds::app::{AppClass, AppLifecycle, AppLimits, AppVisibility};
use jc_core::kinds::policy::{Operation, OperationRef};
use jc_core::kinds::App;

const GOLDEN: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: App
metadata:
  name: air-quality-today
  namespace: bb-ovzdusie
  title:
    sk: "Kvalita ovzdušia dnes"
    en: "Air quality today"
  annotations:
    joinedcontext.com/generated-by: "agent:app-builder@bb"
    joinedcontext.com/prompt-digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
spec:
  kind: fullstack
  visibility: public
  lifecycle: published
  source:
    path: ./src
    image: ghcr.io/banskabystrica/air-quality-today@sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
  dataNeeds:
    - contextSpaceRef: ovzdusie
      entityTypes:
        - AirQualityObserved
        - District
      attributes:
        - pm10
        - pm25
        - airQualityIndex
        - location
        - name
        - refDistrict
      operations:
        - queryEntity
        - retrieveEntity
        - queryTemporal
      q: "pm10>=0"
      scopeQ: "/geo/SK/BB"
      geoQ: "georel=within;geometry=Polygon;coordinates=[[[19.10,48.70],[19.20,48.70],[19.20,48.76],[19.10,48.76],[19.10,48.70]]]"
  limits:
    cpu: "500m"
    memory: "256Mi"
    replicas: 2
  routes:
    - /apps/air-quality-today
"#;

#[test]
fn golden_app_manifest_parses_validates_and_roundtrips() {
    let app = App::from_yaml(GOLDEN).expect("valid golden YAML");
    app.validate().expect("golden app validates");

    assert_eq!(app.api_version, "joinedcontext.com/v1alpha1");
    assert_eq!(app.kind, "App");
    assert_eq!(app.metadata.name, "air-quality-today");
    assert_eq!(app.metadata.namespace.as_deref(), Some("bb-ovzdusie"));

    let title = app.metadata.title.as_ref().expect("title exists");
    assert_eq!(title.get("sk"), Some("Kvalita ovzdušia dnes"));
    assert_eq!(title.get("en"), Some("Air quality today"));

    assert_eq!(app.spec.class, AppClass::Fullstack);
    assert_eq!(app.spec.visibility, AppVisibility::Public);
    assert_eq!(app.spec.lifecycle, AppLifecycle::Published);

    let src = &app.spec.source;
    assert_eq!(src.path.as_deref(), Some("./src"));
    assert_eq!(
        src.image.as_deref(),
        Some("ghcr.io/banskabystrica/air-quality-today@sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );

    assert_eq!(app.spec.data_needs.len(), 1);
    let need = &app.spec.data_needs[0];
    assert_eq!(need.context_space_ref, "ovzdusie");
    assert_eq!(need.entity_types, vec!["AirQualityObserved", "District"]);
    assert_eq!(
        need.attributes,
        vec![
            "pm10",
            "pm25",
            "airQualityIndex",
            "location",
            "name",
            "refDistrict"
        ]
    );
    assert_eq!(need.operations.len(), 3);
    assert_eq!(need.q.as_deref(), Some("pm10>=0"));
    assert_eq!(need.scope_q.as_deref(), Some("/geo/SK/BB"));

    let limits = app.spec.limits.as_ref().expect("limits exist");
    assert_eq!(limits.cpu.as_deref(), Some("500m"));
    assert_eq!(limits.memory.as_deref(), Some("256Mi"));
    assert_eq!(limits.replicas, Some(2));

    assert_eq!(app.spec.routes, vec!["/apps/air-quality-today"]);
    assert!(!app.spec.write_operations());

    assert_eq!(
        app.resource_path().expect("resource path"),
        "projects/bb-ovzdusie/apps/air-quality-today/app.yaml"
    );

    let serialized = app.to_yaml().expect("serialize to yaml");
    let reimported = App::from_yaml(&serialized).expect("re-import yaml");
    assert_eq!(app, reimported);
}

#[test]
fn secret_ref_rejected_at_parse_time_under_spec_and_source_ap16() {
    let with_spec_secret = format!("{GOLDEN}  secretRef:\n    name: database-credentials\n");
    let err_spec = App::from_yaml(&with_spec_secret);
    assert!(
        err_spec.is_err(),
        "deny_unknown_fields must reject secretRef under spec"
    );

    let with_source_secret = GOLDEN.replace(
        "    path: ./src\n",
        "    path: ./src\n    secretRef:\n      name: git-credentials\n",
    );
    let err_source = App::from_yaml(&with_source_secret);
    assert!(
        err_source.is_err(),
        "deny_unknown_fields must reject secretRef under spec.source"
    );
}

#[test]
fn service_and_fullstack_apps_require_data_needs_ap05() {
    let mut app = App::from_yaml(GOLDEN).expect("valid golden YAML");

    app.spec.class = AppClass::Service;
    app.spec.data_needs.clear();
    let err_svc = app
        .validate()
        .expect_err("service without dataNeeds must fail");
    assert!(matches!(
        err_svc,
        Error::Name {
            field: "spec.dataNeeds",
            ..
        }
    ));

    app.spec.class = AppClass::Fullstack;
    app.spec.data_needs.clear();
    let err_full = app
        .validate()
        .expect_err("fullstack without dataNeeds must fail");
    assert!(matches!(
        err_full,
        Error::Name {
            field: "spec.dataNeeds",
            ..
        }
    ));

    app.spec.class = AppClass::Static;
    app.spec.data_needs.clear();
    app.validate().expect("static app may have empty dataNeeds");
}

#[test]
fn cim009_operation_validation_accepts_valid_and_rejects_unknown() {
    let bad_op_yaml = GOLDEN.replace("- queryEntity\n", "- upsertEntity\n");
    let err = App::from_yaml(&bad_op_yaml);
    assert!(
        err.is_err(),
        "proprietary operation `upsertEntity` must be rejected at deserialization"
    );

    let read_op_yaml = GOLDEN.replace("- queryEntity\n", "- read\n");
    let err_read = App::from_yaml(&read_op_yaml);
    assert!(
        err_read.is_err(),
        "proprietary operation `read` must be rejected at deserialization"
    );

    let valid_ops = [
        "queryEntity",
        "createEntity",
        "deleteBatch",
        "federationOps",
    ];
    for op in valid_ops {
        let json = format!("\"{op}\"");
        let parsed: OperationRef = serde_json::from_str(&json).expect("valid operation");
        assert_eq!(parsed.as_str(), op);
    }
}

#[test]
fn write_operations_classification_ap09() {
    let mut app = App::from_yaml(GOLDEN).expect("valid golden YAML");
    assert!(!app.spec.write_operations());

    app.spec.data_needs[0]
        .operations
        .push(OperationRef::Single(Operation::CreateEntity));
    assert!(app.spec.write_operations());

    app.spec.data_needs[0].operations = vec![OperationRef::Single(Operation::DeleteAttrs)];
    assert!(app.spec.write_operations());

    app.spec.data_needs[0].operations = vec![
        OperationRef::Single(Operation::QueryEntity),
        OperationRef::Single(Operation::RetrieveTemporal),
    ];
    assert!(!app.spec.write_operations());
}

#[test]
fn app_lifecycle_transitions_forward_only_ap18() {
    let states = [
        AppLifecycle::Draft,
        AppLifecycle::Preview,
        AppLifecycle::Published,
        AppLifecycle::Retired,
    ];

    for (from_idx, from) in states.iter().enumerate() {
        for (to_idx, to) in states.iter().enumerate() {
            let allowed = from.allows_transition_to(*to);
            if to_idx >= from_idx {
                assert!(
                    allowed,
                    "transition from {:?} to {:?} must be allowed",
                    from, to
                );
            } else {
                assert!(
                    !allowed,
                    "transition from {:?} to {:?} must be forbidden",
                    from, to
                );
            }
        }
    }

    assert!(AppLifecycle::Retired.allows_transition_to(AppLifecycle::Retired));
    assert!(!AppLifecycle::Retired.allows_transition_to(AppLifecycle::Draft));
    assert!(!AppLifecycle::Retired.allows_transition_to(AppLifecycle::Preview));
    assert!(!AppLifecycle::Retired.allows_transition_to(AppLifecycle::Published));
}

#[test]
fn published_app_requires_non_private_visibility_and_routes_ap14_ap18() {
    let mut app = App::from_yaml(GOLDEN).expect("valid golden YAML");

    app.spec.lifecycle = AppLifecycle::Published;
    app.spec.visibility = AppVisibility::Private;
    let err_vis = app.validate().expect_err("published private app must fail");
    assert!(matches!(
        err_vis,
        Error::Name {
            field: "spec.visibility",
            ..
        }
    ));

    app.spec.visibility = AppVisibility::Public;
    app.spec.routes.clear();
    let err_route = app
        .validate()
        .expect_err("published fullstack app with no routes must fail");
    assert!(matches!(
        err_route,
        Error::Name {
            field: "spec.routes",
            ..
        }
    ));

    app.spec.class = AppClass::Static;
    app.spec.routes.clear();
    let err_static_route = app
        .validate()
        .expect_err("published static app with no routes must fail");
    assert!(matches!(
        err_static_route,
        Error::Name {
            field: "spec.routes",
            ..
        }
    ));

    app.spec.lifecycle = AppLifecycle::Draft;
    app.spec.visibility = AppVisibility::Private;
    app.spec.routes.clear();
    assert!(app.validate().is_ok());
}

#[test]
fn source_image_digest_pinning_ap13() {
    let mut app = App::from_yaml(GOLDEN).expect("valid golden YAML");

    app.spec.source.image = Some("ghcr.io/banskabystrica/air-quality-today:latest".to_string());
    let err_latest = app.validate().expect_err("image with tag must fail AP-13");
    assert!(matches!(
        err_latest,
        Error::Name {
            field: "spec.source.image",
            ..
        }
    ));

    app.spec.source.image =
        Some("ghcr.io/banskabystrica/air-quality-today@sha256:short".to_string());
    let err_short = app
        .validate()
        .expect_err("image with malformed digest must fail");
    assert!(matches!(
        err_short,
        Error::Name {
            field: "spec.source.image",
            ..
        }
    ));

    app.spec.source.image = None;
    app.spec.source.path = None;
    app.spec.source.repository = None;
    let err_empty_src = app
        .validate()
        .expect_err("source with all None fields must fail");
    assert!(matches!(
        err_empty_src,
        Error::Name {
            field: "spec.source",
            ..
        }
    ));
}

#[test]
fn limits_validation_bounds() {
    let mut app = App::from_yaml(GOLDEN).expect("valid golden YAML");

    app.spec.limits = Some(AppLimits {
        cpu: Some("".to_string()),
        memory: Some("256Mi".to_string()),
        replicas: Some(1),
    });
    let err_cpu = app.validate().expect_err("empty cpu limit must fail");
    assert!(matches!(
        err_cpu,
        Error::Name {
            field: "spec.limits.cpu",
            ..
        }
    ));

    app.spec.limits = Some(AppLimits {
        cpu: Some("500m".to_string()),
        memory: Some("".to_string()),
        replicas: Some(1),
    });
    let err_mem = app.validate().expect_err("empty memory limit must fail");
    assert!(matches!(
        err_mem,
        Error::Name {
            field: "spec.limits.memory",
            ..
        }
    ));

    app.spec.limits = Some(AppLimits {
        cpu: Some("500m".to_string()),
        memory: Some("256Mi".to_string()),
        replicas: Some(0),
    });
    let err_rep = app.validate().expect_err("replicas: 0 must fail");
    assert!(matches!(
        err_rep,
        Error::Name {
            field: "spec.limits.replicas",
            ..
        }
    ));
}

#[test]
fn routes_must_start_with_slash() {
    let mut app = App::from_yaml(GOLDEN).expect("valid golden YAML");
    app.spec.routes = vec!["apps/air-quality-today".to_string()];
    let err = app
        .validate()
        .expect_err("route without leading slash must fail");
    assert!(matches!(
        err,
        Error::Name {
            field: "spec.routes",
            ..
        }
    ));
}

#[test]
fn data_need_validation_invariants() {
    let mut app = App::from_yaml(GOLDEN).expect("valid golden YAML");

    app.spec.data_needs[0].context_space_ref = "Ovzdusie_Invalid".to_string();
    let err_space = app.validate().expect_err("non-DNS-1123 spaceRef must fail");
    assert!(matches!(
        err_space,
        Error::Name {
            field: "dataNeeds.contextSpaceRef",
            ..
        }
    ));

    let mut app2 = App::from_yaml(GOLDEN).expect("valid golden YAML");
    app2.spec.data_needs[0].entity_types.clear();
    let err_empty_types = app2.validate().expect_err("empty entityTypes must fail");
    assert!(matches!(
        err_empty_types,
        Error::Name {
            field: "dataNeeds.entityTypes",
            ..
        }
    ));

    let mut app3 = App::from_yaml(GOLDEN).expect("valid golden YAML");
    app3.spec.data_needs[0].entity_types = vec!["airQualityObserved".to_string()];
    let err_type = app3.validate().expect_err("non-PascalCase type must fail");
    assert!(matches!(
        err_type,
        Error::Name {
            field: "entityType",
            ..
        }
    ));

    let mut app4 = App::from_yaml(GOLDEN).expect("valid golden YAML");
    app4.spec.data_needs[0].entity_types = vec![
        "AirQualityObserved".to_string(),
        "AirQualityObserved".to_string(),
    ];
    let err_dup_type = app4
        .validate()
        .expect_err("duplicate entityTypes must fail");
    assert!(matches!(
        err_dup_type,
        Error::Name {
            field: "dataNeeds.entityTypes",
            ..
        }
    ));

    let mut app5 = App::from_yaml(GOLDEN).expect("valid golden YAML");
    app5.spec.data_needs[0].attributes = vec!["pm10".to_string(), "pm10".to_string()];
    let err_dup_attr = app5.validate().expect_err("duplicate attributes must fail");
    assert!(matches!(
        err_dup_attr,
        Error::Name {
            field: "dataNeeds.attributes",
            ..
        }
    ));

    let mut app6 = App::from_yaml(GOLDEN).expect("valid golden YAML");
    app6.spec.data_needs[0].operations.clear();
    let err_empty_ops = app6.validate().expect_err("empty operations must fail");
    assert!(matches!(
        err_empty_ops,
        Error::Name {
            field: "dataNeeds.operations",
            ..
        }
    ));

    let mut app7 = App::from_yaml(GOLDEN).expect("valid golden YAML");
    app7.spec.data_needs[0].operations = vec![
        OperationRef::Single(Operation::QueryEntity),
        OperationRef::Single(Operation::QueryEntity),
    ];
    let err_dup_ops = app7.validate().expect_err("duplicate operations must fail");
    assert!(matches!(
        err_dup_ops,
        Error::Name {
            field: "dataNeeds.operations",
            ..
        }
    ));
}
