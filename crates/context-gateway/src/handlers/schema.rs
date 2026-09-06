//! What the data behind an endpoint contains, narrowed to the grant (T-0162, EP-46…EP-52).
//!
//! The gateway is not a compiler. `DataModel.spec.artifacts` names the files Model Tools
//! generated beside the LinkML source and committed in the same commit (DM-02), so what
//! an endpoint publishes is exactly what was reviewed. A model whose artifacts are not in
//! the checkout is still described: the JSON Schema and the `@context` are derived from
//! the grants, which is a narrower answer than the compiled one but never a wrong one.
//!
//! Whichever half answers, the document is a projection of the policy set: a class or a
//! slot the caller may not read is absent, and named in `redactedSlots` so the absence is
//! visible rather than mysterious (EP-47).

use crate::pdp::evaluator::{effective, granted_attrs, granted_types, Subject};
use crate::resolver::{Endpoint, Model};
use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

/// The media type of a JSON Schema document (EP-49).
pub const JSON_SCHEMA: &str = "application/schema+json";
/// The media type of a JSON-LD `@context` (EP-49).
pub const JSON_LD: &str = "application/ld+json";

/// The NGSI-LD core context every derived `@context` starts from, so a client that
/// expands a derived document still resolves `id`, `type` and the core terms.
const CORE_CONTEXT: &str = "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context-v1.8.jsonld";

/// Members of an NGSI-LD entity that are the format rather than the data: no grant lists
/// them and no projection may remove them, or the schema stops describing NGSI-LD.
const STRUCTURAL: &[&str] = &[
    "id",
    "type",
    "@id",
    "@type",
    "@context",
    "scope",
    "createdAt",
    "modifiedAt",
    "deletedAt",
];

/// Which schema document was asked for (EP-49).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Artifact {
    /// The JSON Schema draft-07 of the model, `model.schema.json` (DM-03).
    JsonSchema,
    /// The JSON-LD `@context` of the model (DM-05).
    Context,
    /// A formalism only Model Tools produces: SHACL, OWL, RDF, LinkML, Markdown.
    Uncompiled,
}

impl Artifact {
    /// The media type the artifact is served as.
    pub fn media_type(self) -> &'static str {
        match self {
            Artifact::JsonSchema => JSON_SCHEMA,
            _ => JSON_LD,
        }
    }
}

/// Names the artifact behind one path segment, or `None` when the surface has no such
/// document at all.
///
/// `model` is the negotiated name: `Accept` picks the formalism (EP-49), and the two
/// formalisms the gateway can produce itself are the JSON Schema and the `@context`.
pub fn artifact_of(segment: &str, accept: &str) -> Option<Artifact> {
    match segment {
        "json-schema" | "model.schema.json" => Some(Artifact::JsonSchema),
        "context.jsonld" | "context" => Some(Artifact::Context),
        "model" => Some(negotiated(accept)),
        // The names Model Tools generates, answered 406 rather than 404: the document
        // exists in the model, it is the compiled form the checkout has not got.
        _ if segment.ends_with(".ttl")
            || segment.ends_with(".linkml.yaml")
            || segment.ends_with(".md") =>
        {
            Some(Artifact::Uncompiled)
        }
        _ => None,
    }
}

/// The formalism an `Accept` header asks `schema/v{major}/model` for (EP-49).
fn negotiated(accept: &str) -> Artifact {
    if accept.contains("turtle") || accept.contains("yaml") || accept.contains("markdown") {
        Artifact::Uncompiled
    } else if accept.contains("ld+json") {
        Artifact::Context
    } else {
        Artifact::JsonSchema
    }
}

/// What one caller may read here: the union of the permissions in force, less whatever a
/// prohibition takes back (GW8, EP-47).
#[derive(Debug, Clone, Default)]
pub struct Visible {
    /// The entity types the caller may read; empty means every type the model declares.
    types: BTreeSet<String>,
    /// The attributes the caller may read; empty means every attribute of those types.
    attrs: BTreeSet<String>,
    /// Types no permission reaches any more because a prohibition covers them whole.
    denied_types: BTreeSet<String>,
    /// Attributes a prohibition takes back.
    denied_attrs: BTreeSet<String>,
}

impl Visible {
    /// Whether the model may describe this entity type at all.
    fn covers_type(&self, name: &str) -> bool {
        !self.denied_types.contains(name) && (self.types.is_empty() || self.types.contains(name))
    }

    /// Whether the model may describe this attribute.
    fn covers_attr(&self, name: &str) -> bool {
        STRUCTURAL.contains(&name)
            || (!self.denied_attrs.contains(name)
                && (self.attrs.is_empty() || self.attrs.contains(name)))
    }
}

/// The caller's visible surface, from the same policy set the data paths enforce.
pub fn visible(subject: &Subject, endpoint: &Endpoint, now: DateTime<Utc>) -> Visible {
    let (prohibitions, grants): (Vec<_>, Vec<_>) = effective(subject, &endpoint.policies, now)
        .into_iter()
        .partition(|policy| policy.effect.is_prohibition());

    let mut visible = Visible::default();
    for policy in &grants {
        visible.types.extend(granted_types(&policy.information));
        visible.attrs.extend(granted_attrs(&policy.information));
    }
    for policy in &prohibitions {
        let attrs = granted_attrs(&policy.information);
        // A prohibition that names attributes takes those back; one that names none takes
        // the whole type back.
        if attrs.is_empty() {
            visible
                .denied_types
                .extend(granted_types(&policy.information));
        } else {
            visible.denied_attrs.extend(attrs);
        }
    }
    visible
}

/// The catalogue of what this endpoint publishes (EP-46).
///
/// Only the artifacts the gateway can actually serve are listed, with the size and digest
/// of the projected document rather than of the file on disk: what a client fetches is
/// the projection, so that is what its `ETag` has to match.
pub fn index(endpoint: &Endpoint, visible: &Visible, digest: impl Fn(&Value) -> String) -> Value {
    let mut models = Vec::new();
    for model in &endpoint.models {
        let mut redacted = Vec::new();
        let schema = json_schema(std::slice::from_ref(&model), visible, &mut redacted);
        let context = context(std::slice::from_ref(&model), visible, &mut Vec::new());

        let types: Vec<&String> = model
            .classes
            .iter()
            .filter(|class| visible.covers_type(class))
            .collect();
        redacted.sort();
        redacted.dedup();

        models.push(json!({
            "name": model.name,
            "version": model.major,
            "semver": model.version,
            "types": types,
            "redactedSlots": redacted,
            "artifacts": {
                "model.schema.json": descriptor(&schema, JSON_SCHEMA, &digest),
                "context.jsonld": descriptor(&context, JSON_LD, &digest),
            },
        }));
    }

    json!({ "endpoint": endpoint.slug, "models": models })
}

/// One entry of the index's `artifacts` map.
fn descriptor(document: &Value, media_type: &str, digest: impl Fn(&Value) -> String) -> Value {
    json!({
        "type": media_type,
        "bytes": serde_json::to_vec(document).map(|bytes| bytes.len()).unwrap_or_default(),
        "sha256": digest(document),
    })
}

/// The JSON Schema of every model of one major, projected to the grant (EP-47, DM-03).
///
/// A model whose artifact the checkout carries is projected; one whose artifact is
/// missing is derived from the grant, so the two halves of a mixed major answer in one
/// document rather than one of them answering nothing.
pub fn json_schema(models: &[&Model], visible: &Visible, redacted: &mut Vec<String>) -> Value {
    let mut defs = Map::new();
    let mut title = Vec::new();
    for model in models {
        title.push(format!("{} {}", model.name, model.version));
        match &model.json_schema {
            Some(compiled) => project_defs(compiled, model, visible, redacted, &mut defs),
            None => derive_defs(model, visible, &mut defs),
        }
    }

    json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": title.join(", "),
        "$defs": defs,
    })
}

/// Copies the class definitions of a compiled schema across, without the classes and the
/// slots the grant does not reach.
fn project_defs(
    compiled: &Value,
    model: &Model,
    visible: &Visible,
    redacted: &mut Vec<String>,
    into: &mut Map<String, Value>,
) {
    // LinkML writes classes into `$defs`, older generators into `definitions`; anything
    // that is neither is left where it is, because a `$ref` may point at it.
    let sources = ["$defs", "definitions"]
        .into_iter()
        .filter_map(|key| compiled.get(key).and_then(Value::as_object));

    for definitions in sources {
        for (name, definition) in definitions {
            // A definition that is not one of the model's own classes is a shared type or
            // an enum: removing it would break the `$ref` of a class that survives.
            if model.classes.contains(name) && !visible.covers_type(name) {
                redacted.push(name.clone());
                continue;
            }
            let mut definition = definition.clone();
            redact_slots(&mut definition, name, visible, redacted);
            into.insert(name.clone(), definition);
        }
    }

    // A compiled schema that describes one class inline, without a `$defs` map at all.
    if into.is_empty() && compiled.get("properties").is_some() {
        for class in model.classes.iter().filter(|c| visible.covers_type(c)) {
            let mut definition = compiled.clone();
            redact_slots(&mut definition, class, visible, redacted);
            into.insert(class.clone(), definition);
        }
    }
}

/// Removes the properties the grant does not reach, and every mention of them.
fn redact_slots(
    definition: &mut Value,
    class: &str,
    visible: &Visible,
    redacted: &mut Vec<String>,
) {
    let Some(properties) = definition
        .get_mut("properties")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    properties.retain(|name, _| {
        let kept = visible.covers_attr(name);
        if !kept {
            redacted.push(format!("{class}.{name}"));
        }
        kept
    });
    let surviving: BTreeSet<String> = properties.keys().cloned().collect();

    if let Some(Value::Array(required)) = definition.get_mut("required") {
        required.retain(|name| name.as_str().is_some_and(|name| surviving.contains(name)));
    }
    // A pattern could match a slot that was just removed, and a form generated from the
    // schema would then offer a field the caller may not read.
    if let Some(members) = definition.as_object_mut() {
        members.remove("patternProperties");
    }
}

/// The description of a model the checkout has no artifact for: the entity types the
/// grant names, carrying the attributes the grant names.
fn derive_defs(model: &Model, visible: &Visible, into: &mut Map<String, Value>) {
    for class in model.classes.iter().filter(|c| visible.covers_type(c)) {
        let mut properties = Map::new();
        properties.insert(
            "id".to_owned(),
            json!({ "type": "string", "format": "uri" }),
        );
        properties.insert("type".to_owned(), json!({ "const": class }));
        for attr in visible.attrs.iter().filter(|a| visible.covers_attr(a)) {
            // Without the compiled model there is no datatype to state, and stating one
            // the model never declared would be an invention.
            properties.insert(attr.clone(), json!({}));
        }

        into.insert(
            class.clone(),
            json!({
                "type": "object",
                "description": format!(
                    "derived from the endpoint's grants; {} has no committed artifacts",
                    model.name
                ),
                "properties": properties,
                "required": ["id", "type"],
                // The grant names what may be read, never what the model declares, so the
                // derived schema cannot claim to be closed.
                "additionalProperties": true,
            }),
        );
    }
}

/// The JSON-LD `@context` of every model of one major, projected to the grant (DM-05).
pub fn context(models: &[&Model], visible: &Visible, redacted: &mut Vec<String>) -> Value {
    let mut terms = Map::new();
    let mut derived = false;
    for model in models {
        match model.context.as_ref().and_then(inner_context) {
            Some(compiled) => {
                for (term, definition) in compiled {
                    if term.starts_with('@')
                        || visible.covers_attr(term)
                        || visible.covers_type(term)
                    {
                        terms.insert(term.clone(), definition.clone());
                    } else {
                        redacted.push(term.clone());
                    }
                }
            }
            None => {
                derived = true;
                for class in model.classes.iter().filter(|c| visible.covers_type(c)) {
                    terms.insert(class.clone(), json!(format!("#{class}")));
                }
                for attr in visible.attrs.iter().filter(|a| visible.covers_attr(a)) {
                    terms.insert(attr.clone(), json!(format!("#{attr}")));
                }
            }
        }
    }

    // A derived context has no vocabulary IRI of its own to point at, and inventing an
    // external one would be claiming an ontology nobody published: the terms resolve
    // against the document that carries them.
    if derived && !terms.contains_key("@vocab") {
        terms.insert("@vocab".to_owned(), json!("#"));
    }
    json!({ "@context": [CORE_CONTEXT, terms] })
}

/// The term map of a committed `@context`, whether the file is the map itself or the
/// usual `{"@context": {…}}` wrapper.
fn inner_context(document: &Value) -> Option<&Map<String, Value>> {
    match document.get("@context") {
        Some(Value::Object(terms)) => Some(terms),
        Some(Value::Array(parts)) => parts.iter().rev().find_map(Value::as_object),
        _ => document.as_object(),
    }
}
