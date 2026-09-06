//! `jcctl validate --repo-dir <path>` (T-0125, CC-12, MF-09, TS-18).
//!
//! Every manifest is parsed into its typed kind and validated by `jc-core`, which is
//! strictly stronger than checking it against the exported JSON Schema: the typed parse
//! refuses unknown fields, so an inline secret beside a `secretRef` is a parse error, and
//! it then runs the cross-field invariants a schema cannot express. Finally each manifest
//! must sit at the path its kind prescribes (MF-06).

use crate::loader::{LoadError, Repository};
use jc_core::registry;
use std::fmt;
use std::path::{Path, PathBuf};

/// One rejected manifest, located well enough to fix it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Repository-relative file the manifest came from.
    pub path: PathBuf,
    /// 1-based YAML document inside that file.
    pub document: usize,
    /// 1-based line the document starts at.
    pub line: usize,
    /// What is wrong, naming the failing field where the parser knows it.
    pub message: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} (document {}): {}",
            self.path.display(),
            self.line,
            self.document,
            self.message
        )
    }
}

/// What `validate` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Manifests that parsed and validated.
    pub checked: usize,
    /// Manifests that did not, in repository order.
    pub findings: Vec<Finding>,
}

impl Report {
    /// Whether every manifest in the repository is valid.
    pub fn is_valid(&self) -> bool {
        self.findings.is_empty()
    }
}

/// Validates every manifest under `repo_dir` (CC-12, MF-09).
///
/// A repository that cannot be walked at all (a malformed document, an unknown kind, a
/// symlink out of the tree) yields the one finding that stopped the walk: the loader
/// refuses to build a half-repository it would then validate against itself.
pub fn run(repo_dir: &Path) -> Report {
    let repo = match Repository::load(repo_dir) {
        Ok(repo) => repo,
        Err(err) => {
            return Report {
                checked: 0,
                findings: vec![finding_of(err)],
            }
        }
    };

    let mut report = Report {
        checked: 0,
        findings: Vec::new(),
    };

    for (id, resource) in repo.iter() {
        let yaml = match serde_norway::to_string(&resource.manifest) {
            Ok(yaml) => yaml,
            Err(err) => {
                report.findings.push(Finding {
                    path: resource.path.clone(),
                    document: resource.document,
                    line: resource.line,
                    message: err.to_string(),
                });
                continue;
            }
        };

        match registry::validate_yaml(&id.kind, &yaml) {
            Some(Ok(())) => report.checked += 1,
            Some(Err(err)) => report.findings.push(Finding {
                path: resource.path.clone(),
                document: resource.document,
                line: resource.line,
                message: err.to_string(),
            }),
            None => report.findings.push(Finding {
                path: resource.path.clone(),
                document: resource.document,
                line: resource.line,
                message: format!("kind `{}` is not in the kind registry", id.kind),
            }),
        }
    }

    for (id, resource, reference) in dangling_data_sources(&repo) {
        report.findings.push(Finding {
            path: resource.0,
            document: resource.1,
            line: resource.2,
            message: format!(
                "{id} references DataSource `{reference}`, which no manifest of this project declares (PL-39)"
            ),
        });
    }

    for (id, actual, expected) in repo.misplaced() {
        let resource = repo.get(&id).expect("misplaced reports loaded resources");
        report.findings.push(Finding {
            path: actual,
            document: resource.document,
            line: resource.line,
            message: format!("{id} belongs at `{expected}` (MF-06)"),
        });
    }

    report
}

/// Where a finding sits: the file, the document inside it and its first line.
type Location = (PathBuf, usize, usize);

/// Every `spec.source.dataSourceRef` that names no `DataSource` of the same project (PL-39).
///
/// The reference is resolved here, at plan time, and not by the runner: a pipeline whose
/// connection is missing would otherwise start, fail to build an input and restart forever,
/// with the reason three layers away from the person who wrote the reference.
fn dangling_data_sources(repo: &Repository) -> Vec<(String, Location, String)> {
    let declared: std::collections::BTreeSet<(Option<String>, String)> = repo
        .iter()
        .filter(|(id, _)| id.kind == "DataSource")
        .map(|(id, _)| (id.namespace.clone(), id.name.clone()))
        .collect();

    let mut dangling = Vec::new();
    for (id, resource) in repo.iter() {
        if id.kind != "Pipeline" {
            continue;
        }
        let Some(reference) = resource
            .manifest
            .spec
            .get("source")
            .and_then(|source| source.get("dataSourceRef"))
        else {
            continue;
        };
        // A reference is a bare name or a typed `{kind, name, namespace?}`; the namespace of a
        // typed one is the pipeline's own, because a connection is owned by the team that owns
        // its credentials.
        let name = match reference {
            serde_json::Value::String(name) => Some(name.clone()),
            serde_json::Value::Object(map) => {
                map.get("name").and_then(|n| n.as_str()).map(str::to_owned)
            }
            _ => None,
        };
        let Some(name) = name else { continue };
        if !declared.contains(&(id.namespace.clone(), name.clone())) {
            dangling.push((
                id.to_string(),
                (resource.path.clone(), resource.document, resource.line),
                name,
            ));
        }
    }
    dangling
}

/// Turns the error that stopped the walk into a finding, keeping whatever location it
/// carries.
fn finding_of(err: LoadError) -> Finding {
    let (path, document, line) = match &err {
        LoadError::Parse {
            path,
            document,
            line,
            ..
        } => (path.clone(), *document, *line),
        LoadError::ApiVersion { path, document, .. }
        | LoadError::UnknownKind { path, document, .. } => (path.clone(), *document, 1),
        LoadError::DuplicateIdentity { second, .. } => (second.clone(), 1, 1),
        LoadError::PathEscapesRepository { path } | LoadError::Io { path, .. } => {
            (path.clone(), 1, 1)
        }
    };
    Finding {
        path,
        document,
        line,
        message: err.to_string(),
    }
}
