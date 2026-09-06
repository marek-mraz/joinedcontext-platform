//! Building the endpoint table from the manifest repository (T-0005, EP-01, CC-08).
//!
//! The repository is the configuration, so the gateway's table is a projection of it and
//! nothing else: an `Endpoint` manifest, plus every `Policy` of the same project that
//! names the same context space. A manifest the gateway cannot make sense of is left out
//! rather than half-applied — an endpoint that is not in the table answers 404, which is
//! the same thing an endpoint that does not exist answers (EP-03).

use crate::auth::accounts::{accounts_of, ServiceAccounts};
use crate::resolver::{Endpoint, Model};
use jc_core::kinds::{DataModelSpec, EndpointSpec, PolicySpec};
use jcctl::loader::{RawManifest, Repository};
use std::collections::BTreeMap;
use std::path::Path;

/// Loads the endpoint table and the identity table from the repository under `dir`
/// (CC-08, PF-46).
pub fn load(dir: &Path) -> Result<(Vec<Endpoint>, ServiceAccounts), jcctl::LoadError> {
    let repo = Repository::load(dir)?;
    Ok((endpoints_with_models(&repo, Some(dir)), accounts_of(&repo)))
}

/// The endpoint table a loaded repository describes.
///
/// Deterministic: the repository is indexed by resource identity, so two runs on the same
/// commit build the same table in the same order (CC-27).
pub fn endpoints_of(repo: &Repository) -> Vec<Endpoint> {
    endpoints_with_models(repo, None)
}

/// The endpoint table, with the model artifacts read from `root` when one is given.
///
/// `DataModel.spec.artifacts` names files committed beside the LinkML source, so the
/// schema surface publishes what was reviewed rather than what a compiler produces now
/// (DM-02, EP-46).
pub fn endpoints_with_models(repo: &Repository, root: Option<&Path>) -> Vec<Endpoint> {
    let mut policies: BTreeMap<(String, String), Vec<PolicySpec>> = BTreeMap::new();
    for (id, resource) in repo.iter() {
        if id.kind != "Policy" {
            continue;
        }
        if let Some(spec) = spec_of::<PolicySpec>(&resource.manifest) {
            let project = id.namespace.clone().unwrap_or_default();
            let space = spec.context_space_ref.name().to_owned();
            policies.entry((project, space)).or_default().push(spec);
        }
    }

    let mut models: BTreeMap<(String, String), Vec<Model>> = BTreeMap::new();
    for (id, resource) in repo.iter() {
        if id.kind != "DataModel" {
            continue;
        }
        if let Some(spec) = spec_of::<DataModelSpec>(&resource.manifest) {
            let project = id.namespace.clone().unwrap_or_default();
            let space = spec.context_space_ref.clone();
            models.entry((project, space)).or_default().push(model_of(
                &id.name,
                &spec,
                root,
                &resource.path,
            ));
        }
    }

    let mut endpoints = Vec::new();
    for (id, resource) in repo.iter() {
        if id.kind != "Endpoint" {
            continue;
        }
        let Some(spec) = spec_of::<EndpointSpec>(&resource.manifest) else {
            continue;
        };
        let project = id.namespace.clone().unwrap_or_default();
        let space = spec.context_space_ref.name().to_owned();
        let key = (project.clone(), space.clone());
        endpoints.push(Endpoint {
            slug: spec.slug.to_string(),
            policies: policies.get(&key).cloned().unwrap_or_default(),
            models: models.get(&key).cloned().unwrap_or_default(),
            space,
            project,
            audience: spec.audience,
            allowed_projects: spec.allowed_projects,
            representations: spec.enabled_representations,
            rate_limit: spec.rate_limits,
        });
    }
    endpoints
}

/// Deserializes one manifest's `spec`, discarding a manifest the gateway cannot read.
///
/// The Portal and `jcctl validate` reject a malformed manifest before it is ever
/// committed; a gateway that refused to start over one would take the whole surface down
/// for a resource it does not serve.
fn spec_of<T: serde::de::DeserializeOwned>(manifest: &RawManifest) -> Option<T> {
    match serde_json::from_value(manifest.spec.clone()) {
        Ok(spec) => Some(spec),
        Err(error) => {
            tracing::warn!(
                kind = %manifest.kind,
                name = %manifest.metadata.name,
                %error,
                "manifest left out of the endpoint table"
            );
            None
        }
    }
}

/// One data model, with whatever artifacts the checkout carries beside its manifest.
///
/// An artifact that is missing or unreadable is simply absent: the schema surface falls
/// back to deriving the document from the endpoint's grants, which is a narrower answer
/// but never a wrong one.
fn model_of(name: &str, spec: &DataModelSpec, root: Option<&Path>, manifest_path: &Path) -> Model {
    let beside = |relative: &Option<String>| -> Option<serde_json::Value> {
        let (root, relative) = (root?, relative.as_deref()?);
        let directory = manifest_path.parent().unwrap_or(Path::new(""));
        let path = normalize(&root.join(directory).join(relative))?;
        // The artifacts live beside their manifest; a path that climbs out of the
        // repository is a manifest bug and reads nothing.
        if !path.starts_with(root) {
            tracing::warn!(model = %name, "artifact path leaves the repository");
            return None;
        }
        match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).ok(),
            Err(error) => {
                tracing::warn!(model = %name, path = %path.display(), %error, "artifact not read");
                None
            }
        }
    };

    Model {
        name: name.to_owned(),
        version: spec.version.to_string(),
        major: spec.version.major(),
        classes: spec.classes.clone(),
        json_schema: beside(&spec.artifacts.json_schema),
        context: beside(&spec.artifacts.context),
    }
}

/// Resolves `.` and `..` without touching the filesystem, so a path that escapes the
/// repository is visible before anything is opened.
fn normalize(path: &Path) -> Option<std::path::PathBuf> {
    let mut out = std::path::PathBuf::new();
    for part in path.components() {
        match part {
            std::path::Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            std::path::Component::CurDir => {}
            other => out.push(other),
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::normalize;
    use std::path::{Path, PathBuf};

    /// An artifact path is checked before anything is opened, so a manifest that names
    /// `../../.secrets/x` is visible as leaving the repository rather than being read.
    #[test]
    fn normalize_resolves_traversal_without_touching_the_filesystem() {
        let root = Path::new("/repo");
        assert_eq!(
            normalize(&root.join("projects/a/./model.schema.json")),
            Some(PathBuf::from("/repo/projects/a/model.schema.json"))
        );
        assert_eq!(
            normalize(&root.join("projects/a/../b/model.schema.json")),
            Some(PathBuf::from("/repo/projects/b/model.schema.json"))
        );

        // Two ways out of the repository, and neither is readable: one resolves to a
        // path outside it, the other climbs past the filesystem root and resolves to
        // nothing at all.
        let escaped = normalize(&root.join("projects/../../etc/passwd")).expect("resolves");
        assert_eq!(escaped, PathBuf::from("/etc/passwd"));
        assert!(!escaped.starts_with(root), "{}", escaped.display());
        assert_eq!(normalize(&root.join("../../etc/passwd")), None);
    }
}
