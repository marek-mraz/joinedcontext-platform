//! What a write payload has to satisfy before it reaches a broker (T-0153, GW16..GW19).
//!
//! Reads are narrowed; writes are not. A write either falls entirely inside one grant or
//! it is refused whole, because a partially applied write stores something nobody asked
//! for. Three things are checked against the payload itself, not against the query
//! parameters a client could simply omit: the entity's identifier, its `scope`, and the
//! coordinates of its own `location`.

use crate::pdp::evaluator::Constraints;
use crate::pdp::geo::{entity_point, granted_polygon};
use crate::pdp::projection::ungranted;
use jc_core::{ProblemDetails, Urn};
use serde_json::Value;

/// Why a write was refused (GW16, GW17).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The payload carries no usable entity id, or one that is not an NGSI-LD URN (PF-42).
    #[error("entity id is not a valid NGSI-LD URN: {0}")]
    MalformedId(String),
    /// The id belongs to another organization or another space (PF-10, GW16).
    #[error("entity id `{id}` does not belong to space `{space}`")]
    ForeignUrn {
        /// The id the payload carried.
        id: String,
        /// The space the endpoint pinned.
        space: String,
    },
    /// The entity's type is outside every grant (GW11).
    #[error("entity type `{0}` is outside the grant")]
    TypeOutsideGrant(String),
    /// The payload touches an attribute no grant covers (GW17).
    #[error("attribute `{0}` is outside the grant")]
    AttributeOutsideGrant(String),
    /// The entity's `scope` is outside the granted scope tree (R29, R31).
    #[error("scope `{0}` is outside the granted scopes")]
    ScopeOutsideGrant(String),
    /// The entity's own location lies outside the granted area (GW16).
    #[error("the entity's location lies outside the granted area")]
    LocationOutsideGrant,
    /// The payload tries to carry access control inside the data (GW29).
    #[error("attribute `{0}` is access control and does not belong in an entity")]
    SmuggledPolicyAttribute(String),
}

impl From<Refusal> for ProblemDetails {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            // A malformed or foreign identifier is a bad request: the caller can see and
            // fix what is wrong with it (PF-42).
            Refusal::MalformedId(_) | Refusal::ForeignUrn { .. } => {
                ProblemDetails::urn_scheme().with_detail(refusal.to_string())
            }
            // Everything else is a policy decision, and the body never says which rule
            // decided it (GW6).
            _ => ProblemDetails::forbidden(),
        }
    }
}

/// Attribute names an entity may never carry: policy belongs in `Policy` entities, never
/// inside the data it guards (GW28, GW29).
const POLICY_VOCABULARY: &[&str] = &[
    "owner",
    "acl",
    "allowedRoles",
    "visibility",
    "permissions",
    "policy",
];

/// Checks one write payload against the constraint set (GW16, GW17, GW19).
///
/// The payload must be a single NGSI-LD entity; a batch is checked per entity by the
/// caller, so a mixed outcome can answer 207 (GW18).
pub fn check(
    entity: &Value,
    constraints: &Constraints,
    space: &str,
    org_domain: &str,
) -> Result<(), Refusal> {
    check_no_smuggled_policy(entity)?;
    check_id(entity, space, org_domain)?;
    check_type(entity, constraints)?;
    check_attributes(entity, constraints)?;
    check_scope(entity, constraints)?;
    check_location(entity, constraints)?;
    Ok(())
}

/// GW16: "may edit only data in location X" is a statement about the entity's own
/// coordinates, so the grant's area is tested against the payload, not against a query
/// parameter the caller could leave out.
fn check_location(entity: &Value, constraints: &Constraints) -> Result<(), Refusal> {
    let Some(geo_q) = constraints.geo_q.as_deref() else {
        return Ok(());
    };
    // No location at all is not a location outside the area: an entity that says nothing
    // about where it is cannot be placed outside the grant.
    let Some(point) = entity_point(entity) else {
        return match entity.get("location") {
            // A location the parser cannot read must not pass an area check it never ran.
            Some(_) => Err(Refusal::LocationOutsideGrant),
            None => Ok(()),
        };
    };

    match granted_polygon(geo_q) {
        Some(area) if area.contains(point) => Ok(()),
        // An area the parser cannot read is an area the write cannot be shown to be in.
        _ => Err(Refusal::LocationOutsideGrant),
    }
}

/// The id must be an NGSI-LD URN of this organization and this space (PF-10, PF-42).
fn check_id(entity: &Value, space: &str, org_domain: &str) -> Result<(), Refusal> {
    let raw = entity
        .get("id")
        .or_else(|| entity.get("@id"))
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::MalformedId(String::new()))?;

    let urn: Urn = raw
        .parse()
        .map_err(|_| Refusal::MalformedId(raw.to_owned()))?;

    if urn.org_domain() != org_domain || urn.space() != space {
        return Err(Refusal::ForeignUrn {
            id: raw.to_owned(),
            space: space.to_owned(),
        });
    }

    // The URN carries the type, and it must be the type the payload declares (PF-44).
    if let Some(declared) = entity.get("type").and_then(Value::as_str) {
        if declared != urn.entity_type() {
            return Err(Refusal::MalformedId(raw.to_owned()));
        }
    }
    Ok(())
}

fn check_type(entity: &Value, constraints: &Constraints) -> Result<(), Refusal> {
    if constraints.types.is_empty() {
        return Ok(());
    }
    let declared = entity
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::TypeOutsideGrant(String::new()))?;

    if constraints.types.contains(declared) {
        Ok(())
    } else {
        Err(Refusal::TypeOutsideGrant(declared.to_owned()))
    }
}

/// GW17: a write touching any attribute outside the grant is denied whole, never trimmed.
fn check_attributes(entity: &Value, constraints: &Constraints) -> Result<(), Refusal> {
    match ungranted(entity, &constraints.attrs).first() {
        Some(name) => Err(Refusal::AttributeOutsideGrant((*name).to_owned())),
        None => Ok(()),
    }
}

fn check_no_smuggled_policy(entity: &Value) -> Result<(), Refusal> {
    let Some(members) = entity.as_object() else {
        return Ok(());
    };
    match members
        .keys()
        .find(|name| POLICY_VOCABULARY.contains(&name.as_str()))
    {
        Some(name) => Err(Refusal::SmuggledPolicyAttribute(name.clone())),
        None => Ok(()),
    }
}

/// The entity's `scope` must sit inside the granted scope tree: a grant on `/geo/SK/BB`
/// covers `/geo/SK/BB/Sasova`, never `/geo/SK/ZA` and never `/geo/SK/BBB` (R13, R29, R30).
fn check_scope(entity: &Value, constraints: &Constraints) -> Result<(), Refusal> {
    let Some(granted) = constraints.scope_q.as_deref() else {
        return Ok(());
    };
    let scopes = match entity.get("scope") {
        None => return Ok(()),
        Some(Value::String(scope)) => vec![scope.as_str()],
        Some(Value::Array(values)) => values.iter().filter_map(Value::as_str).collect(),
        Some(_) => return Err(Refusal::ScopeOutsideGrant(String::new())),
    };

    for scope in scopes {
        if !granted_scopes(granted).any(|prefix| covers(prefix, scope)) {
            return Err(Refusal::ScopeOutsideGrant(scope.to_owned()));
        }
    }
    Ok(())
}

/// The individual scope paths of a `scopeQ`, whose operators (`;`, `|`, `(`, `)`) separate
/// the paths themselves.
fn granted_scopes(scope_q: &str) -> impl Iterator<Item = &str> {
    scope_q
        .split(['(', ')', ';', '|', ','])
        .map(str::trim)
        .filter(|path| path.starts_with('/'))
}

/// Whether a granted scope path covers a scope, as a path prefix rather than a string
/// prefix: `/geo/SK/BB` covers `/geo/SK/BB/Sasova` but not `/geo/SK/BBB`.
fn covers(granted: &str, scope: &str) -> bool {
    let granted = granted.trim_end_matches("/#").trim_end_matches('/');
    scope == granted
        || scope
            .strip_prefix(granted)
            .is_some_and(|rest| rest.starts_with('/'))
}
