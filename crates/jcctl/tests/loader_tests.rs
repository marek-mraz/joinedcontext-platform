use jcctl::loader::{LoadError, Repository, ResourceId};
use std::path::{Path, PathBuf};

fn unique_temp_dir(test_name: &str) -> PathBuf {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "jcctl-load-{test_name}-{}-{now}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn loads_valid_repository_with_expected_count_and_ids() {
    let dir = unique_temp_dir("valid-repo");

    std::fs::write(
        dir.join("org.yaml"),
        r#"apiVersion: joinedcontext.com/v1alpha1
kind: Organization
metadata:
  name: my-city
  namespace: org
spec:
  domain: banskabystrica.sk
  locales: ["sk", "en"]
  defaultLocale: sk
"#,
    )
    .unwrap();

    let p1_dir = dir.join("projects/doprava");
    std::fs::create_dir_all(&p1_dir).unwrap();
    std::fs::write(
        p1_dir.join("project.yaml"),
        r#"apiVersion: joinedcontext.com/v1alpha1
kind: Project
metadata:
  name: doprava
  namespace: org
spec:
  organizationRef: my-city
"#,
    )
    .unwrap();

    let p2_dir = dir.join("projects/odpady");
    std::fs::create_dir_all(&p2_dir).unwrap();
    std::fs::write(
        p2_dir.join("project.yaml"),
        r#"apiVersion: joinedcontext.com/v1alpha1
kind: Project
metadata:
  name: odpady
  namespace: org
spec:
  organizationRef: my-city
"#,
    )
    .unwrap();

    let space_dir = p1_dir.join("spaces/senzory");
    std::fs::create_dir_all(&space_dir).unwrap();
    std::fs::write(
        space_dir.join("space.yaml"),
        r#"apiVersion: joinedcontext.com/v1alpha1
kind: ContextSpace
metadata:
  name: senzory
  namespace: doprava
spec:
  isSandbox: false
"#,
    )
    .unwrap();

    let ep_dir = space_dir.join("endpoints");
    std::fs::create_dir_all(&ep_dir).unwrap();
    std::fs::write(
        ep_dir.join("public-stream.yaml"),
        r#"apiVersion: joinedcontext.com/v1alpha1
kind: Endpoint
metadata:
  name: public-stream
  namespace: doprava
spec:
  contextSpaceRef: senzory
  slug: abcdefghijklmnopqrstuvwxyz
  audience: public
  enabledRepresentations: ["ngsi-ld"]
"#,
    )
    .unwrap();

    let pol_dir = space_dir.join("policies");
    std::fs::create_dir_all(&pol_dir).unwrap();
    std::fs::write(
        pol_dir.join("read-access.yaml"),
        r#"apiVersion: joinedcontext.com/v1alpha1
kind: Policy
metadata:
  name: read-access
  namespace: doprava
spec:
  contextSpaceRef: senzory
  assigner: did:web:banskabystrica.sk
  assignee:
    kind: role
    id: viewer
  operations: ["retrieveEntity"]
"#,
    )
    .unwrap();

    let repo = Repository::load(&dir).expect("valid repository loads");
    assert_eq!(repo.len(), 6);
    assert!(!repo.is_empty());
    assert_eq!(repo.root(), &dir);

    let org_id = ResourceId::new(
        "joinedcontext.com",
        "Organization",
        Some("org".into()),
        "my-city",
    );
    assert!(repo.get(&org_id).is_some());

    let p1_id = ResourceId::new(
        "joinedcontext.com",
        "Project",
        Some("org".into()),
        "doprava",
    );
    assert!(repo.get(&p1_id).is_some());

    let space_id = ResourceId::new(
        "joinedcontext.com",
        "ContextSpace",
        Some("doprava".into()),
        "senzory",
    );
    assert!(repo.get(&space_id).is_some());

    let ep_id = ResourceId::new(
        "joinedcontext.com",
        "Endpoint",
        Some("doprava".into()),
        "public-stream",
    );
    assert!(repo.get(&ep_id).is_some());

    assert!(repo.misplaced().is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn multi_document_file_yields_expected_line_and_document_numbers() {
    let dir = unique_temp_dir("multi-doc");

    let multi_content = r#"---
apiVersion: joinedcontext.com/v1alpha1
kind: Project
metadata:
  name: proj-a
  namespace: org
spec:
  organizationRef: my-city
---

---
apiVersion: joinedcontext.com/v1alpha1
kind: Project
metadata:
  name: proj-b
  namespace: org
spec:
  organizationRef: my-city
---
"#;
    std::fs::write(dir.join("projects.yaml"), multi_content).unwrap();

    let repo = Repository::load(&dir).expect("loads multi-document manifest");
    assert_eq!(repo.len(), 2);

    let id_a = ResourceId::new("joinedcontext.com", "Project", Some("org".into()), "proj-a");
    let res_a = repo.get(&id_a).expect("proj-a exists");
    assert_eq!(res_a.document, 1);
    assert_eq!(res_a.line, 1);

    let id_b = ResourceId::new("joinedcontext.com", "Project", Some("org".into()), "proj-b");
    let res_b = repo.get(&id_b).expect("proj-b exists");
    assert_eq!(res_b.document, 3);
    assert_eq!(res_b.line, 11);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn skips_native_linkml_bento_git_and_markdown_files() {
    let dir = unique_temp_dir("skip-files");

    std::fs::write(
        dir.join("org.yaml"),
        r#"apiVersion: joinedcontext.com/v1alpha1
kind: Organization
metadata:
  name: test-org
  namespace: org
spec:
  domain: banskabystrica.sk
  locales: ["sk"]
  defaultLocale: sk
"#,
    )
    .unwrap();

    std::fs::write(dir.join("README.md"), "# Test Readme\n").unwrap();
    std::fs::write(dir.join("bento.yaml"), "input: {}\noutput: {}\n").unwrap();
    std::fs::write(dir.join("model.linkml.yaml"), "id: urn:test\n").unwrap();

    let git_dir = dir.join(".git");
    std::fs::create_dir_all(&git_dir).unwrap();
    std::fs::write(git_dir.join("config.yaml"), "invalid yaml\n").unwrap();

    let repo = Repository::load(&dir).expect("loads repository skipping ignored files");
    assert_eq!(repo.len(), 1);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn duplicate_identity_across_files_returns_duplicate_identity_error() {
    let dir = unique_temp_dir("dup-id");

    std::fs::write(
        dir.join("file1.yaml"),
        r#"apiVersion: joinedcontext.com/v1alpha1
kind: Project
metadata:
  name: shared-proj
  namespace: org
spec:
  organizationRef: org-1
"#,
    )
    .unwrap();

    std::fs::write(
        dir.join("file2.yaml"),
        r#"apiVersion: joinedcontext.com/v1alpha1
kind: Project
metadata:
  name: shared-proj
  namespace: org
spec:
  organizationRef: org-2
"#,
    )
    .unwrap();

    let err = Repository::load(&dir).expect_err("duplicate identity must fail");
    match err {
        LoadError::DuplicateIdentity { id, first, second } => {
            assert_eq!(id.name, "shared-proj");
            assert_eq!(first, Path::new("file1.yaml"));
            assert_eq!(second, Path::new("file2.yaml"));
        }
        other => panic!("expected DuplicateIdentity, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unknown_kind_and_wrong_api_version_fail() {
    let dir = unique_temp_dir("invalid-manifest");

    let unknown_file = dir.join("unknown.yaml");
    std::fs::write(
        &unknown_file,
        r#"apiVersion: joinedcontext.com/v1alpha1
kind: UnknownKind
metadata:
  name: foo
  namespace: org
spec: {}
"#,
    )
    .unwrap();

    let err_kind = Repository::load(&dir).expect_err("unknown kind must fail");
    assert!(matches!(err_kind, LoadError::UnknownKind { ref kind, .. } if kind == "UnknownKind"));

    std::fs::remove_file(unknown_file).unwrap();

    std::fs::write(
        dir.join("wrong-api.yaml"),
        r#"apiVersion: joinedcontext.com/v2beta1
kind: Organization
metadata:
  name: bar
  namespace: org
spec: {}
"#,
    )
    .unwrap();

    let err_api = Repository::load(&dir).expect_err("wrong apiVersion must fail");
    assert!(
        matches!(err_api, LoadError::ApiVersion { ref got, .. } if got == "joinedcontext.com/v2beta1")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn symlink_pointing_outside_repository_root_is_refused() {
    let root = unique_temp_dir("symlink-root");
    let outside = unique_temp_dir("symlink-outside");

    let target = outside.join("outside.yaml");
    std::fs::write(
        &target,
        r#"apiVersion: joinedcontext.com/v1alpha1
kind: Project
metadata:
  name: outside-proj
  namespace: org
spec:
  organizationRef: outside-org
"#,
    )
    .unwrap();

    let link = root.join("link.yaml");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let err = Repository::load(&root).expect_err("symlink escaping repository must fail");
    assert!(matches!(err, LoadError::PathEscapesRepository { .. }));

    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&outside);
}

#[test]
fn misplaced_reports_resource_at_wrong_path_and_is_empty_when_correct() {
    let dir = unique_temp_dir("misplaced");

    let wrong_dir = dir.join("projects/doprava/wrong-folder");
    std::fs::create_dir_all(&wrong_dir).unwrap();
    std::fs::write(
        wrong_dir.join("public-stream.yaml"),
        r#"apiVersion: joinedcontext.com/v1alpha1
kind: Endpoint
metadata:
  name: public-stream
  namespace: doprava
spec:
  contextSpaceRef: senzory
  slug: abcdefghijklmnopqrstuvwxyz
  audience: public
  enabledRepresentations: ["ngsi-ld"]
"#,
    )
    .unwrap();

    let repo = Repository::load(&dir).expect("loads misplaced resource");
    let misplaced = repo.misplaced();
    assert_eq!(misplaced.len(), 1);

    let (id, actual, expected) = &misplaced[0];
    assert_eq!(id.name, "public-stream");
    assert_eq!(
        actual,
        &PathBuf::from("projects/doprava/wrong-folder/public-stream.yaml")
    );
    assert_eq!(
        expected,
        "projects/doprava/spaces/senzory/endpoints/public-stream.yaml"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A `linkml:` payload is an embedded YAML document; its indented `---` lines belong to
/// the block scalar and must not split the manifest into fragments (MF-05).
#[test]
fn indented_separator_inside_a_block_scalar_does_not_split_the_document() {
    let dir = unique_temp_dir("block-scalar");

    std::fs::write(
        dir.join("model.yaml"),
        r#"apiVersion: joinedcontext.com/v1alpha1
kind: DataModel
metadata:
  name: traffic
  namespace: doprava
spec:
  contextSpaceRef: senzory
  linkml: |
    id: https://banskabystrica.sk/schemas/traffic
    ---
    name: traffic
"#,
    )
    .unwrap();

    let repo = Repository::load(&dir).expect("block scalar loads as one document");
    assert_eq!(repo.len(), 1);

    let id = ResourceId::new(
        "joinedcontext.com",
        "DataModel",
        Some("doprava".into()),
        "traffic",
    );
    let linkml = repo.get(&id).expect("the data model").manifest.spec["linkml"]
        .as_str()
        .expect("linkml is a string");
    assert!(linkml.contains("---"), "the separator stays in the payload");

    let _ = std::fs::remove_dir_all(&dir);
}

/// MF-06 and MF-07: `contextSpaceRef` is written two ways and both name the same space.
/// Reading only the bare-label form put every `Policy` at `.../spaces//policies/…`, so
/// `validate` reported a correctly placed manifest as misplaced.
#[test]
fn a_typed_context_space_reference_resolves_the_space_placeholder() {
    let dir = unique_temp_dir("typed-space-ref");
    let policies = dir.join("projects/ovzdusie/spaces/ovzdusie/policies");
    std::fs::create_dir_all(&policies).unwrap();

    std::fs::write(
        policies.parent().unwrap().join("space.yaml"),
        r#"apiVersion: joinedcontext.com/v1alpha1
kind: ContextSpace
metadata:
  name: ovzdusie
  namespace: ovzdusie
spec:
  isSandbox: false
"#,
    )
    .unwrap();
    std::fs::write(
        policies.join("public-air-quality.yaml"),
        r#"apiVersion: joinedcontext.com/v1alpha1
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
  operations: [queryEntity]
  information:
    - entities:
        - type: AirQualityObserved
"#,
    )
    .unwrap();

    let repo = Repository::load(&dir).expect("the repository loads");
    assert!(
        repo.misplaced().is_empty(),
        "a typed reference names its space too: {:?}",
        repo.misplaced()
    );
    let _ = std::fs::remove_dir_all(&dir);
}
