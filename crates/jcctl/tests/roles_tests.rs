//! T-0527: the bindings under users/ compiled into CODEOWNERS, roles.json and the gate input
//! (PF-51, PF-52, CC-41, CC-42).

mod common;

use common::*;
use jcctl::roles::{self, RolesError};
use std::path::Path;
use std::process::Command;

const ROLE_DEVELOPER: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: Role
metadata: { name: pipeline-developer, namespace: org }
spec:
  rules:
    - kinds: [Pipeline, DataSource, Mapping]
      verbs: [propose]
    - kinds: [Endpoint]
      verbs: [propose]
      constraints:
        - { field: spec.audience, notIn: [public] }
"#;

const ROLE_ADMIN: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: Role
metadata: { name: org-admin, namespace: org }
spec:
  rules:
    - kinds: [Endpoint, Pipeline, Role, RoleBinding]
      verbs: [propose, approve, delete]
"#;

const BINDING_DEVELOPERS: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: RoleBinding
metadata: { name: ovzdusie-developers, namespace: org }
spec:
  subjects: [{ group: air-quality-team }, { user: jana.kovacova@banskabystrica.sk }]
  role: pipeline-developer
  scope: { project: ovzdusie }
"#;

const BINDING_ADMINS: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: RoleBinding
metadata: { name: admins, namespace: org }
spec:
  subjects: [{ user: admin }, { group: platform-admins }]
  role: org-admin
  scope: { organization: banskabystrica }
"#;

const BINDING_SPACE_REVIEWERS: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: RoleBinding
metadata: { name: parking-reviewers, namespace: org }
spec:
  subjects: [{ user: peter }]
  role: org-admin
  scope: { contextSpace: parking }
"#;

fn users_repo(test_name: &str) -> std::path::PathBuf {
    let dir = demo_repo(test_name);
    write(&dir, "users/roles/pipeline-developer.yaml", ROLE_DEVELOPER);
    write(&dir, "users/roles/org-admin.yaml", ROLE_ADMIN);
    write(
        &dir,
        "users/assignments/ovzdusie-developers.yaml",
        BINDING_DEVELOPERS,
    );
    write(&dir, "users/assignments/admins.yaml", BINDING_ADMINS);
    write(
        &dir,
        "users/assignments/parking-reviewers.yaml",
        BINDING_SPACE_REVIEWERS,
    );
    dir
}

#[test]
fn codeowners_gives_the_rule_setting_paths_to_organization_approvers_only() {
    let dir = users_repo("codeowners");
    let compiled = roles::compile(&load(&dir)).expect("compiles");
    let owners = &compiled.codeowners;

    // Organization scope owns everything and alone owns what sets the rules (CC-42, CC-70).
    for path in [
        "/CODEOWNERS",
        "/users/",
        "/platform/",
        "/policies/",
        "/.gitea/",
        "/",
    ] {
        assert!(
            owners.contains(&format!("{path} @admin @banskabystrica/platform-admins\n")),
            "{path} is owned by the organization approvers:\n{owners}"
        );
    }
    // A developer proposes but never approves: no line of theirs, on any path.
    assert!(!owners.contains("air-quality-team"), "{owners}");
    assert!(!owners.contains("jana"), "{owners}");
    // A context space binding that approves owns the space under whichever project holds it.
    assert!(
        owners.contains("/projects/*/spaces/parking/ @peter\n"),
        "{owners}"
    );
    assert!(owners.starts_with("# Written by `jcctl roles render`"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn roles_json_carries_the_bindings_as_the_gate_reads_them() {
    let dir = users_repo("roles-json");
    let compiled = roles::compile(&load(&dir)).expect("compiles");
    let data: serde_json::Value = serde_json::from_str(&compiled.roles_json).expect("json");

    assert_eq!(
        data["roles"]["pipeline-developer"]["rules"][1]["constraints"][0]["notIn"][0],
        "public"
    );
    let bindings = data["bindings"].as_array().expect("bindings");
    assert_eq!(bindings.len(), 3);
    assert_eq!(bindings[0]["name"], "admins", "sorted by name");
    assert_eq!(bindings[0]["scope"]["organization"], "banskabystrica");
    assert_eq!(bindings[1]["subjects"][0]["group"], "air-quality-team");
    assert_eq!(bindings[2]["scope"]["contextSpace"], "parking");
    assert!(compiled.roles_json.ends_with('\n'));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_binding_to_a_role_the_repository_lacks_is_refused() {
    let dir = demo_repo("missing-role");
    write(&dir, "users/assignments/admins.yaml", BINDING_ADMINS);
    let err = roles::compile(&load(&dir)).expect_err("no such role");
    assert!(
        matches!(err, RolesError::MissingRole { ref role, .. } if role == "org-admin"),
        "{err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn render_writes_the_five_files_and_is_idempotent() {
    let dir = users_repo("render");
    let written = roles::render(&dir).expect("renders");
    assert_eq!(written.len(), 5);
    for rel in [
        roles::CODEOWNERS,
        roles::ROLES_JSON,
        roles::ROLES_REGO,
        roles::ROLES_TEST_REGO,
        roles::WORKFLOW,
    ] {
        assert!(dir.join(rel).is_file(), "{rel} exists");
    }
    let first = std::fs::read_to_string(dir.join(roles::CODEOWNERS)).expect("read");
    roles::render(&dir).expect("renders again");
    assert_eq!(
        first,
        std::fs::read_to_string(dir.join(roles::CODEOWNERS)).expect("read")
    );
    let workflow = std::fs::read_to_string(dir.join(roles::WORKFLOW)).expect("workflow");
    assert!(
        workflow.contains("validate --repo-dir /repo"),
        "jcctl validate runs at the repository root"
    );
    assert!(workflow.contains("conftest test /tmp/input.json -p policies -d policies/roles.json"));

    let _ = std::fs::remove_dir_all(&dir);
}

const PUBLIC_ENDPOINT: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: Endpoint
metadata:
  name: air
  namespace: ovzdusie
spec:
  contextSpaceRef: ovzdusie
  slug: mluyob4nz52lok3ssk7pgn5vwt
  audience: public
  enabledRepresentations: ["ngsi-ld"]
"#;

const PIPELINE: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: Pipeline
metadata:
  name: aq
  namespace: ovzdusie
spec:
  class: resident
  source: { dataSourceRef: { kind: DataSource, name: mqtt-mesto } }
  compute: { kind: bloblang, bloblang: "root = this" }
  targetEndpoint: urn:ngsi-ld:Endpoint:banskabystrica.sk:ovzdusie:public-air
"#;

/// The diff of a merge request as `git diff --name-status base...HEAD` lists it.
const NAME_STATUS: &str = "A\tprojects/ovzdusie/spaces/ovzdusie/endpoints/air.yaml\nD\tprojects/ovzdusie/pipelines/aq/pipeline.yaml\nM\tREADME.md\nM\tprojects/ovzdusie/spaces/ovzdusie/datamodels/x.linkml.yaml\n";

fn merge_request(test_name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let head = users_repo(test_name);
    write(
        &head,
        "projects/ovzdusie/spaces/ovzdusie/endpoints/air.yaml",
        PUBLIC_ENDPOINT,
    );
    write(&head, "README.md", "# repo\n");
    let base = temp_dir(&format!("{test_name}-base"));
    write(
        &base,
        "projects/ovzdusie/pipelines/aq/pipeline.yaml",
        PIPELINE,
    );
    (head, base)
}

#[test]
fn input_lists_added_manifests_from_head_and_deleted_ones_from_base() {
    let (head, base) = merge_request("input");
    let input = roles::input(
        &head,
        &base,
        NAME_STATUS,
        "jana",
        Some("jana.kovacova@banskabystrica.sk"),
        &["air-quality-team".to_owned()],
    )
    .expect("input");
    assert_eq!(input.author, "jana");
    assert_eq!(input.groups, vec!["air-quality-team"]);
    assert_eq!(
        input.changes.len(),
        2,
        "README and the LinkML source are not manifests: {:?}",
        input.changes
    );
    let endpoint = &input.changes[0];
    assert_eq!(
        (
            endpoint.action,
            endpoint.kind.as_str(),
            endpoint.name.as_str()
        ),
        ("propose", "Endpoint", "air")
    );
    assert_eq!(endpoint.project.as_deref(), Some("ovzdusie"));
    assert_eq!(endpoint.manifest["spec"]["audience"], "public");
    let pipeline = &input.changes[1];
    assert_eq!(
        (pipeline.action, pipeline.kind.as_str()),
        ("delete", "Pipeline")
    );

    let _ = std::fs::remove_dir_all(&head);
    let _ = std::fs::remove_dir_all(&base);
}

/// The whole gate, when conftest is installed (CI installs it; a sandbox may not).
#[test]
fn conftest_denies_a_developers_public_endpoint_and_lets_an_admin_through() {
    let Ok(conftest) = which("conftest") else {
        eprintln!("conftest is not installed: skipping the gate run");
        return;
    };
    let (head, base) = merge_request("gate");
    roles::render(&head).expect("renders");
    let verify = Command::new(&conftest)
        .current_dir(&head)
        .args(["verify", "-p", "policies"])
        .output()
        .expect("conftest verify");
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stdout)
    );

    let run = |author: &str, groups: &[String]| {
        let input = roles::input(&head, &base, NAME_STATUS, author, None, groups).expect("input");
        let file = head.join("input.json");
        std::fs::write(&file, serde_json::to_string(&input).expect("json")).expect("write");
        Command::new(&conftest)
            .current_dir(&head)
            .args([
                "test",
                "input.json",
                "-p",
                "policies",
                "-d",
                "policies/roles.json",
            ])
            .output()
            .expect("conftest test")
    };
    let developer = run("jana", &["air-quality-team".to_owned()]);
    assert!(
        !developer.status.success(),
        "a developer's public endpoint is red"
    );
    let out = String::from_utf8_lossy(&developer.stdout);
    assert!(
        out.contains("Endpoint") && out.contains("Pipeline"),
        "both the public endpoint and the deletion are named:\n{out}"
    );
    let admin = run("admin", &[]);
    assert!(
        admin.status.success(),
        "{}",
        String::from_utf8_lossy(&admin.stdout)
    );

    let _ = std::fs::remove_dir_all(&head);
    let _ = std::fs::remove_dir_all(&base);
}

fn which(binary: &str) -> Result<std::path::PathBuf, ()> {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .map(|dir| dir.join(binary))
        .find(|candidate| Path::new(candidate).is_file())
        .ok_or(())
}

#[test]
fn a_repository_without_users_gets_no_files() {
    let dir = demo_repo("roles_no_users");
    assert!(roles::files(&load(&dir)).expect("compiles").is_none());
    assert!(roles::render(&dir).expect("renders").is_empty());
    assert!(!dir.join(roles::CODEOWNERS).exists());
}
