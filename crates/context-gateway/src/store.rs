//! Building the endpoint table from the manifest repository (T-0005, EP-01, CC-08).
//!
//! The repository is the configuration, so the gateway's table is a projection of it and
//! nothing else: an `Endpoint` manifest, plus every `Policy` of the same project that
//! names the same context space. A manifest the gateway cannot make sense of is left out
//! rather than half-applied — an endpoint that is not in the table answers 404, which is
//! the same thing an endpoint that does not exist answers (EP-03).

use crate::auth::accounts::{accounts_of, ServiceAccounts};
use crate::federation::{federations_of, Federations};
use crate::resolver::{Endpoint, Model, Space};
use jc_core::kinds::{
    Audience, ContextSpaceSpec, DataModelLifecycle, DataModelSpec, EndpointSpec, PolicySpec,
    Representation,
};
use jcctl::loader::{RawManifest, Repository};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

/// Loads the endpoint table and the identity table from the repository under `dir`
/// (CC-08, PF-46).
pub fn load(
    dir: &Path,
) -> Result<(Vec<Endpoint>, Vec<Space>, ServiceAccounts, Federations), jcctl::LoadError> {
    let repo = Repository::load(dir)?;
    Ok((
        endpoints_with_models(&repo, Some(dir)),
        spaces_of(&repo, Some(dir)),
        accounts_of(&repo),
        federations_of(&repo),
    ))
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
    let policies = policies_by_space(repo);
    let models = models_by_space(repo, root);

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
            file_limits: spec.file_limits,
            hidden_attributes: spec
                .projection
                .map(|projection| projection.hidden_attributes.into_iter().collect())
                .unwrap_or_default(),
            base_path: format!("/api/endpoint/{}", spec.slug),
        });
    }
    endpoints
}

/// The space table a loaded repository describes (SP-01, SP-10).
///
/// A space is served through the same enforcement record an endpoint is, built from the
/// same policy set: `/cs/{space}/ngsi-ld/v1/` and an endpoint on the same space evaluate
/// the same grants because they read the same `Vec<PolicySpec>`. The audience is `public`
/// so that the decision belongs to the policy set alone: a space with no grant for the
/// caller answers 404, which is what a space that does not exist answers (SP-06, SP-11).
pub fn spaces_of(repo: &Repository, root: Option<&Path>) -> Vec<Space> {
    let policies = policies_by_space(repo);
    let models = models_by_space(repo, root);

    let mut spaces = Vec::new();
    for (id, resource) in repo.iter() {
        if id.kind != "ContextSpace" {
            continue;
        }
        let Some(spec) = spec_of::<ContextSpaceSpec>(&resource.manifest) else {
            continue;
        };
        let project = id.namespace.clone().unwrap_or_default();
        let key = (project.clone(), id.name.clone());
        spaces.push(Space {
            endpoint: Arc::new(Endpoint {
                slug: id.name.clone(),
                space: id.name.clone(),
                project,
                audience: Audience::Public,
                allowed_projects: Vec::new(),
                representations: vec![Representation::NgsiLd, Representation::Mcp],
                rate_limit: None,
                file_limits: None,
                // A space is the whole space: narrowing is a decision of a published
                // endpoint, and the canonical surface publishes nothing of its own.
                hidden_attributes: BTreeSet::new(),
                policies: policies.get(&key).cloned().unwrap_or_default(),
                models: models.get(&key).cloned().unwrap_or_default(),
                base_path: format!("/cs/{}", id.name),
            }),
            title: language_map(&resource.manifest.metadata.rest, "title"),
            description: language_map(&resource.manifest.metadata.rest, "description"),
            is_sandbox: spec.is_sandbox,
            default_locale: spec.default_locale,
        });
    }
    spaces
}

/// One `metadata` language map, or an empty one when the manifest carries none (PF-24).
///
/// The loader keeps metadata beyond name and namespace as raw JSON, so this reads the
/// shape rather than a type: a `title` that is not a map of locale to string is a
/// manifest the Portal would have rejected, and here it simply describes nothing.
fn language_map(
    metadata: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> BTreeMap<String, String> {
    metadata
        .get(key)
        .and_then(serde_json::Value::as_object)
        .map(|map| {
            map.iter()
                .filter_map(|(locale, text)| Some((locale.clone(), text.as_str()?.to_owned())))
                .collect()
        })
        .unwrap_or_default()
}

/// The policies of every space, keyed by the project and space they name (GW8).
fn policies_by_space(repo: &Repository) -> BTreeMap<(String, String), Vec<PolicySpec>> {
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
    policies
}

/// The data models of every space, with the artifacts the checkout carries (DM-02).
///
/// A mirrored foreign model is left out: it is a read-only copy of what a peer publishes, and
/// an endpoint that served it under its own schema surface would be claiming another
/// organisation's model as its own, which is exactly what DM-49 forbids. The reconciler
/// commits such a model beside the reference that fetched it, and the Mappings that read it
/// are how it reaches local data (DM-48, DM-49).
fn models_by_space(
    repo: &Repository,
    root: Option<&Path>,
) -> BTreeMap<(String, String), Vec<Model>> {
    let mut models: BTreeMap<(String, String), Vec<Model>> = BTreeMap::new();
    for (id, resource) in repo.iter() {
        if id.kind != "DataModel" {
            continue;
        }
        if let Some(spec) = spec_of::<DataModelSpec>(&resource.manifest) {
            if spec.lifecycle == DataModelLifecycle::Mirrored {
                continue;
            }
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
    models
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
