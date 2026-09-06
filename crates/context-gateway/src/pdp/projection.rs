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

/// Strips from one entity every attribute the grants do not name and every attribute the
/// endpoint hides (R9, EP-61).
///
/// An empty `granted` set means the grants named no attribute whitelist at all, which is
/// a grant over the whole entity. `hidden` is the opposite kind of set: a denial that
/// applies whether or not there is a whitelist, which is why the endpoint's narrowing
/// cannot be expressed by shrinking `granted`.
pub fn project_entity(entity: &mut Value, granted: &BTreeSet<String>, hidden: &BTreeSet<String>) {
    if granted.is_empty() && hidden.is_empty() {
        return;
    }
    let Some(members) = entity.as_object_mut() else {
        return;
    };
    members.retain(|name, _| {
        STRUCTURAL.contains(&name.as_str())
            || ((granted.is_empty() || granted.contains(name)) && !hidden.contains(name))
    });
}

/// Strips a whole broker answer, whether it is one entity or an array of them (R9, EP-61).
pub fn project(body: &mut Value, granted: &BTreeSet<String>, hidden: &BTreeSet<String>) {
    match body {
        Value::Array(entities) => {
            for entity in entities {
                project_entity(entity, granted, hidden);
            }
        }
        entity => project_entity(entity, granted, hidden),
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

/// Whether an entity may be returned at all, given the anchored id patterns of the
/// matching grants (R24, GW11).
///
/// No pattern is no restriction. A pattern that does not compile matches nothing: a
/// grant the gateway cannot evaluate must not become a grant that lets everything
/// through. `jcctl validate` and the Portal reject an uncompilable pattern before it is
/// committed, so this is the second line, not the first.
pub fn permitted(entity: &Value, id_patterns: &BTreeSet<String>) -> bool {
    if id_patterns.is_empty() {
        return true;
    }
    let Some(id) = entity
        .get("id")
        .or_else(|| entity.get("@id"))
        .and_then(Value::as_str)
    else {
        return false;
    };
    id_patterns
        .iter()
        .any(|pattern| regex::Regex::new(pattern).is_ok_and(|compiled| compiled.is_match(id)))
}
