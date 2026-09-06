use jcctl::commands::validate;
use std::path::{Path, PathBuf};

fn temp_repo(test_name: &str) -> PathBuf {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "jcctl-validate-{test_name}-{}-{now}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp repo");
    dir
}

fn write(dir: &Path, rel: &str, body: &str) {
    let path = dir.join(rel);
    std::fs::create_dir_all(path.parent().expect("relative path has a parent"))
        .expect("create parent directory");
    std::fs::write(path, body).expect("write manifest");
}

/// The demo repository: an organization, its project, one space and one endpoint, each at
/// the path its kind prescribes (MF-06).
fn valid_repo(test_name: &str) -> PathBuf {
    let dir = temp_repo(test_name);
    write(
        &dir,
        "org.yaml",
        r#"apiVersion: joinedcontext.com/v1alpha1
kind: Organization
metadata:
  name: banskabystrica
  namespace: org
spec:
  domain: banskabystrica.sk
  locales: ["sk"]
  defaultLocale: sk
"#,
    );
    write(
        &dir,
        "projects/ovzdusie/project.yaml",
        r#"apiVersion: joinedcontext.com/v1alpha1
kind: Project
metadata:
  name: ovzdusie
  namespace: org
spec:
  organizationRef: banskabystrica
"#,
    );
    write(
        &dir,
        "projects/ovzdusie/spaces/ovzdusie/space.yaml",
        r#"apiVersion: joinedcontext.com/v1alpha1
kind: ContextSpace
metadata:
  name: ovzdusie
  namespace: ovzdusie
spec:
  isSandbox: false
"#,
    );
    write(&dir, ENDPOINT_PATH, ENDPOINT);
    dir
}

const ENDPOINT_PATH: &str = "projects/ovzdusie/spaces/ovzdusie/endpoints/public-air.yaml";

const ENDPOINT: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: Endpoint
metadata:
  name: public-air
  namespace: ovzdusie
spec:
  contextSpaceRef: ovzdusie
  slug: zt4qm7ge2xdv6ksb3ncf5arw2y
  audience: public
  enabledRepresentations: ["ngsi-ld", "geojson"]
"#;

#[test]
fn a_valid_repository_has_no_findings() {
    let dir = valid_repo("valid");

    let report = validate::run(&dir);
    assert_eq!(report.findings, vec![]);
    assert_eq!(report.checked, 4);
    assert!(report.is_valid());

    let _ = std::fs::remove_dir_all(&dir);
}

/// An invariant no JSON Schema can express: a public endpoint that also lists projects
/// would silently narrow its own audience (EP-14, EP-15).
#[test]
fn a_cross_field_invariant_is_reported_with_the_file_that_broke_it() {
    let dir = valid_repo("invariant");
    write(
        &dir,
        ENDPOINT_PATH,
        &ENDPOINT.replace(
            "  audience: public\n",
            "  audience: public\n  allowedProjects: [\"bb-doprava\"]\n",
        ),
    );

    let report = validate::run(&dir);
    assert_eq!(report.checked, 3);
    assert_eq!(report.findings.len(), 1);

    let finding = &report.findings[0];
    assert_eq!(finding.path, Path::new(ENDPOINT_PATH));
    assert_eq!(finding.line, 1);
    assert!(
        finding.message.contains("allowedProjects"),
        "{}",
        finding.message
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `deny_unknown_fields` is the control that keeps a credential out of Git: a token
/// written beside the `secretRef` that should carry it fails to parse at all.
#[test]
fn a_field_that_is_not_in_the_kind_is_refused() {
    let dir = valid_repo("unknown-field");
    write(
        &dir,
        ENDPOINT_PATH,
        &ENDPOINT.replace(
            "  audience: public\n",
            "  audience: public\n  token: hunter2\n",
        ),
    );

    let report = validate::run(&dir);
    assert_eq!(report.checked, 3);
    assert_eq!(report.findings.len(), 1);
    assert!(
        report.findings[0].message.contains("token"),
        "{}",
        report.findings[0].message
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A manifest that parses but sits in the wrong folder is still a defect: the path is the
/// resource's address in the repository (MF-06).
#[test]
fn a_manifest_at_the_wrong_path_is_reported() {
    let dir = valid_repo("misplaced");
    std::fs::remove_file(dir.join(ENDPOINT_PATH)).expect("move the endpoint");
    write(&dir, "projects/ovzdusie/public-air.yaml", ENDPOINT);

    let report = validate::run(&dir);
    assert_eq!(report.checked, 4);
    assert_eq!(report.findings.len(), 1);
    assert!(
        report.findings[0].message.contains(ENDPOINT_PATH),
        "{}",
        report.findings[0].message
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A document that is not a manifest at all stops the walk, and the finding still points
/// at the file, document and line.
#[test]
fn a_malformed_document_reports_its_line() {
    let dir = valid_repo("malformed");
    write(
        &dir,
        "projects/ovzdusie/spaces/ovzdusie/space.yaml",
        "apiVersion: joinedcontext.com/v1alpha1\nkind: ContextSpace\nmetadata: [not, a, map]\nspec: {}\n",
    );

    let report = validate::run(&dir);
    assert!(!report.is_valid());
    assert_eq!(report.checked, 0);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].document, 1);

    let _ = std::fs::remove_dir_all(&dir);
}
