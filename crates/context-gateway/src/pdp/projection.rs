//! Cutting the response down to what the grants cover (T-0151, R9, GW11).
//!
//! The broker answers with whole entities. What the caller is allowed to see is usually
//! less than that, and the difference must never reach the wire: an attribute omitted
//! from a grant is not a display preference, it is data the caller has no right to.
//!
//! Projection preserves NGSI-LD shape. `id`, `type` and the JSON-LD keywords stay, because
//! an entity without them is not an entity; every other member survives only if the
//! constraint set names it.

use serde_json::{Map, Value};
use std::collections::BTreeSet;

/// The members every entity keeps, whatever the grants say: without them the answer is
/// not a valid NGSI-LD entity.
const STRUCTURAL: &[&str] = &["id", "type", "@context", "@id", "@type", "scope"];

/// Strips from one entity every attribute the grants do not name (R9).
///
/// An empty `granted` set means the grants named no attribute whitelist at all, which is
/// a grant over the whole entity: nothing is stripped.
pub fn project_entity(entity: &mut Value, granted: &BTreeSet<String>) {
    if granted.is_empty() {
        return;
    }
    let Some(members) = entity.as_object_mut() else {
        return;
    };
    members.retain(|name, _| STRUCTURAL.contains(&name.as_str()) || granted.contains(name));
}

/// Strips a whole broker answer, whether it is one entity or an array of them (R9).
pub fn project(body: &mut Value, granted: &BTreeSet<String>) {
    match body {
        Value::Array(entities) => {
            for entity in entities {
                project_entity(entity, granted);
            }
        }
        entity => project_entity(entity, granted),
    }
}

/// The attributes an entity carries that the grants do not cover (R9, GW17).
///
/// A read strips them; a write that touches any of them is denied whole, because silently
/// dropping an attribute from a write would store something the caller did not ask for.
pub fn ungranted<'a>(entity: &'a Value, granted: &BTreeSet<String>) -> Vec<&'a str> {
    if granted.is_empty() {
        return Vec::new();
    }
    let Some(members) = entity.as_object() else {
        return Vec::new();
    };
    members
        .keys()
        .map(String::as_str)
        .filter(|name| !STRUCTURAL.contains(name) && !granted.contains(*name))
        .collect()
}

/// Whether the answer was narrowed, so the response can say so (R22).
pub fn was_projected(before: &Map<String, Value>, after: &Map<String, Value>) -> bool {
    before.len() != after.len()
}
