//! `jcctl export --space <id> --out-dir <path>` (T-0133, CC-22, MF-16, MF-17, PF-20).
//!
//! The inverse of `apply`: the platform is read and the answer is written as the
//! repository that would produce it, so a space someone built by hand can be adopted into
//! Git without retyping it. Two properties make the output usable rather than merely
//! informative.
//!
//! It is *clean*. `status` never survives the [`RawManifest`] boundary at all — the type
//! refuses unknown members (MF-04) — and the system metadata the platform keeps beside
//! the declaration (`uid`, `resourceVersion`, the reconciler's own annotations) is
//! stripped here, because a manifest carrying them is a snapshot, not a declaration
//! (MF-16).
//!
//! It is *safe*. A live platform may hand back a credential where a manifest is only ever
//! allowed a `secretRef` (MF-17, MF-24). Exporting that would write a secret into Git,
//! which is the one thing the whole configuration-as-code story forbids, so the member is
//! dropped and named in the report: a lossy export the operator can see beats a faithful
//! one nobody may commit.

use crate::loader::{extract_space, RawManifest};
use crate::platform::{Platform, PlatformError};
use jc_core::registry;
use jc_core::Scope;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Metadata the platform owns and a declaration never carries (MF-16).
const SYSTEM_METADATA: &[&str] = &[
    "uid",
    "resourceVersion",
    "generation",
    "creationTimestamp",
    "deletionTimestamp",
    "managedFields",
    "selfLink",
    "revision",
    "status",
];

/// Annotation prefixes the reconciler writes and owns; a `joinedcontext.com/` annotation
/// an operator wrote by hand is theirs and survives (MF-08).
const SYSTEM_ANNOTATIONS: &[&str] = &[
    "joinedcontext.com/last-applied",
    "joinedcontext.com/revision",
    "joinedcontext.com/managed-attributes",
    "joinedcontext.com/reconciled-at",
];

/// Members that hold a credential itself rather than a reference to one (MF-17, MF-24).
///
/// Matched whole and case-insensitively, never as a substring: `tokenEndpoint` is a URL
/// and `secretRef` is a reference, and dropping either would corrupt the export to guard
/// something that was never a secret.
const CREDENTIAL_MEMBERS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "token",
    "secret",
    "clientsecret",
    "apikey",
    "privatekey",
    "credential",
    "credentials",
    "dsn",
    "connectionstring",
    "accesskey",
    "secretkey",
];

/// One resource, cleaned, and the repository path it belongs at (MF-06).
#[derive(Debug, Clone, PartialEq)]
pub struct Exported {
    /// Repository-relative path, from the kind's own template.
    pub path: PathBuf,
    /// The manifest as it will be written.
    pub manifest: RawManifest,
}

/// What `export` produced (API/03 section 1).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    /// The manifests, in repository path order.
    pub resources: Vec<Exported>,
    /// `kind/name: member` for every credential that was dropped (MF-17).
    pub redactions: Vec<String>,
}

/// Reads one space off the platform and cleans it, writing nothing (CC-22).
///
/// `project` is the namespace the space lives in; the platform has no project directory,
/// so the caller names it. A resource that names no context space is not part of a space
/// and is left where it is: `export` copies a space out, not a whole installation.
pub fn collect(
    platform: &impl Platform,
    project: &str,
    space: &str,
) -> Result<Report, PlatformError> {
    let mut report = Report::default();

    // Two kinds may share a plural — `Policy` and `ScopeDefinition` are both `policies` —
    // so the answer to a query is not one kind's resources and the path template comes
    // from each manifest's own kind, not from the query.
    let queries: BTreeSet<(&str, &str)> = registry::KINDS
        .iter()
        .map(|info| {
            let namespace = match info.scope {
                Scope::Organization => "org",
                Scope::Project => project,
            };
            (namespace, info.plural)
        })
        .collect();

    let mut found: BTreeMap<String, RawManifest> = BTreeMap::new();
    for (namespace, plural) in queries {
        for manifest in platform.list(namespace, plural)? {
            let Some(info) = registry::by_kind(&manifest.kind) else {
                continue;
            };
            if !belongs_to(&manifest, space) {
                continue;
            }
            found.insert(
                info.repo_path(project, space, &manifest.metadata.name),
                manifest,
            );
        }
    }

    for (path, mut manifest) in found {
        strip_system_metadata(&mut manifest.metadata.rest);
        let mut dropped = Vec::new();
        redact(&mut manifest.spec, &mut dropped);
        report.redactions.extend(
            dropped
                .into_iter()
                .map(|member| format!("{}/{}: {member}", manifest.kind, manifest.metadata.name)),
        );

        report.resources.push(Exported {
            path: PathBuf::from(path),
            manifest,
        });
    }

    Ok(report)
}

/// Writes a collected report as a repository under `out_dir`.
pub fn write(out_dir: &Path, report: &Report) -> std::io::Result<usize> {
    for resource in &report.resources {
        let path = out_dir.join(&resource.path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let yaml = serde_norway::to_string(&resource.manifest)
            .map_err(|err| std::io::Error::other(err.to_string()))?;
        std::fs::write(path, yaml)?;
    }
    Ok(report.resources.len())
}

/// Whether a live resource belongs to the space being exported.
///
/// The space itself is in its own export; everything else is in it if it says so. A
/// resource that names no space (a Project, a ServiceAccount) belongs to the installation
/// rather than to this space and is not copied out with it.
fn belongs_to(manifest: &RawManifest, space: &str) -> bool {
    if manifest.kind == "ContextSpace" {
        return manifest.metadata.name == space;
    }
    extract_space(&manifest.spec) == space
}

/// Removes the metadata the platform owns, so the export is a declaration (MF-16).
fn strip_system_metadata(metadata: &mut Map<String, Value>) {
    metadata.retain(|member, _| !SYSTEM_METADATA.contains(&member.as_str()));
    if let Some(Value::Object(annotations)) = metadata.get_mut("annotations") {
        annotations.retain(|name, _| !SYSTEM_ANNOTATIONS.contains(&name.as_str()));
        if annotations.is_empty() {
            metadata.remove("annotations");
        }
    }
}

/// Drops every literal credential from a spec, naming what went (MF-17).
///
/// Only a scalar is dropped: a member called `credentials` holding a list of `secretRef`
/// entries is a declaration, and removing it would be removing the configuration rather
/// than the secret.
fn redact(spec: &mut Value, dropped: &mut Vec<String>) {
    match spec {
        Value::Object(members) => {
            members.retain(|name, value| {
                let literal = value.is_string()
                    && CREDENTIAL_MEMBERS.contains(&name.to_ascii_lowercase().as_str());
                if literal {
                    dropped.push(name.clone());
                }
                !literal
            });
            for value in members.values_mut() {
                redact(value, dropped);
            }
        }
        Value::Array(values) => values.iter_mut().for_each(|value| redact(value, dropped)),
        _ => {}
    }
}
