//! Building the endpoint table from the manifest repository (T-0005, EP-01, CC-08).
//!
//! The repository is the configuration, so the gateway's table is a projection of it and
//! nothing else: an `Endpoint` manifest, plus every `Policy` of the same project that
//! names the same context space. A manifest the gateway cannot make sense of is left out
//! rather than half-applied — an endpoint that is not in the table answers 404, which is
//! the same thing an endpoint that does not exist answers (EP-03).

use crate::resolver::Endpoint;
use jc_core::kinds::{EndpointSpec, PolicySpec};
use jcctl::loader::{RawManifest, Repository};
use std::collections::BTreeMap;
use std::path::Path;

/// Loads every endpoint the repository under `dir` declares (CC-08).
pub fn load(dir: &Path) -> Result<Vec<Endpoint>, jcctl::LoadError> {
    Ok(endpoints_of(&Repository::load(dir)?))
}

/// The endpoint table a loaded repository describes.
///
/// Deterministic: the repository is indexed by resource identity, so two runs on the same
/// commit build the same table in the same order (CC-27).
pub fn endpoints_of(repo: &Repository) -> Vec<Endpoint> {
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
        endpoints.push(Endpoint {
            slug: spec.slug.to_string(),
            policies: policies
                .get(&(project.clone(), space.clone()))
                .cloned()
                .unwrap_or_default(),
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
