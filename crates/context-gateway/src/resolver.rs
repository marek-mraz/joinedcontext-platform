//! The in-memory endpoint table (T-0144, EP-17, EP-18, EP-19, EP-03).
//!
//! Every request on the endpoint surface starts by turning an opaque slug into the space
//! behind it, so this lookup is on the hot path of the whole gateway. The table is read
//! far more often than it is written: the reconciler replaces it when an `Endpoint`
//! changes, readers never block, and a reader that is mid-request keeps the snapshot it
//! started with (EP-18, EP-19).
//!
//! The table answers with the space name only after the slug matched. An unknown slug
//! yields nothing at all, so the caller cannot learn whether a space exists behind a slug
//! it guessed (EP-03, EP-23).

use arc_swap::ArcSwap;
use jc_core::kinds::{Audience, PolicySpec, RateLimits, Representation};
use std::collections::HashMap;
use std::sync::Arc;

/// Everything the gateway needs about one endpoint, resolved in a single lookup.
#[derive(Debug, Clone, PartialEq)]
pub struct Endpoint {
    /// The opaque slug the client uses; the key of the table.
    pub slug: String,
    /// The context space behind it, which becomes the pinned `NGSILD-Tenant` (EP-22).
    pub space: String,
    /// The project the space belongs to, for audience checks (EP-14, EP-15).
    pub project: String,
    /// Who may use the endpoint at all (EP-14).
    pub audience: Audience,
    /// The projects allowed when the audience is `project-list` (EP-15).
    pub allowed_projects: Vec<String>,
    /// The representations this endpoint serves; anything else is 404 (EP-05).
    pub representations: Vec<Representation>,
    /// The token-bucket configuration, absent when the endpoint sets no limit (EP-20).
    pub rate_limit: Option<RateLimits>,
    /// The policies the PDP evaluates for callers of this endpoint (GW8).
    pub policies: Vec<PolicySpec>,
    /// The data models of the space, with whatever artifacts the repository carries
    /// beside them (EP-46, DM-02).
    pub models: Vec<Model>,
}

/// One version of one data model, as the schema surface publishes it (EP-46, DM-22).
#[derive(Debug, Clone, PartialEq)]
pub struct Model {
    /// The manifest name.
    pub name: String,
    /// The full semantic version, as written.
    pub version: String,
    /// The major, which is the `schema/v{major}` the endpoint serves (DM-22).
    pub major: u32,
    /// The NGSI-LD entity types the model defines.
    pub classes: Vec<String>,
    /// The generated JSON Schema, when the repository carries it (DM-02).
    pub json_schema: Option<serde_json::Value>,
    /// The generated JSON-LD `@context`, when the repository carries it (DM-02).
    pub context: Option<serde_json::Value>,
}

impl Endpoint {
    /// Whether this endpoint serves the representation, so an unlisted one can be refused
    /// before any work is done (EP-05).
    pub fn serves(&self, representation: Representation) -> bool {
        self.representations.contains(&representation)
    }

    /// Whether a caller from `project` may use this endpoint at all (EP-14, EP-15).
    ///
    /// `None` is an anonymous caller: only a public endpoint serves one.
    pub fn admits(&self, project: Option<&str>) -> bool {
        match self.audience {
            Audience::Public => true,
            Audience::Organization => project.is_some(),
            Audience::ProjectList => project.is_some_and(|caller| {
                caller == self.project || self.allowed_projects.iter().any(|p| p == caller)
            }),
        }
    }
}

/// The slug table, swapped whole when the reconciler changes an endpoint (EP-17, EP-19).
#[derive(Debug, Default)]
pub struct SlugResolver {
    table: ArcSwap<HashMap<String, Arc<Endpoint>>>,
}

impl SlugResolver {
    /// An empty table: every slug resolves to nothing until the reconciler fills it.
    pub fn new() -> Self {
        Self::default()
    }

    /// A table holding the given endpoints.
    pub fn with(endpoints: impl IntoIterator<Item = Endpoint>) -> Self {
        let resolver = Self::new();
        resolver.replace(endpoints);
        resolver
    }

    /// The endpoint behind a slug, or nothing (EP-18).
    ///
    /// Wait-free: the reader takes the current snapshot and never blocks a writer or
    /// another reader.
    pub fn resolve(&self, slug: &str) -> Option<Arc<Endpoint>> {
        self.table.load().get(slug).map(Arc::clone)
    }

    /// Replaces the whole table in one atomic step (EP-19).
    ///
    /// A reader either sees the entire old table or the entire new one, never a mixture,
    /// so an endpoint is never briefly missing while its space is being updated.
    pub fn replace(&self, endpoints: impl IntoIterator<Item = Endpoint>) {
        let table: HashMap<String, Arc<Endpoint>> = endpoints
            .into_iter()
            .map(|endpoint| (endpoint.slug.clone(), Arc::new(endpoint)))
            .collect();
        self.table.store(Arc::new(table));
    }

    /// How many endpoints the table currently holds.
    pub fn len(&self) -> usize {
        self.table.load().len()
    }

    /// Whether the table is empty, which is how the gateway starts.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
