//! Notifications leave through the gateway, not around it (T-0156, R46, GW27).
//!
//! A subscription is a standing query whose answers arrive later and elsewhere. The broker
//! holds no policy, so a notification delivered straight from the broker to a webhook would
//! be the one answer on the platform nobody projected.
//!
//! Two halves close it. At creation the subscription is narrowed to the caller's grants and
//! its `notification.endpoint.uri` is rewritten to point back at this gateway, carrying the
//! caller's own endpoint in `to`. At delivery the gateway reads the stored subscription,
//! projects the entities to what that subscription was narrowed to, re-checks its `q`
//! against the stored state, and forwards what is left to `to`.
//!
//! The stored subscription is the authority for both the projection and the target. That is
//! what makes the delivery path safe to leave unauthenticated, which it has to be: the
//! broker calling it holds no token of its own.

use crate::app::Gateway;
use crate::pdp::evaluator::{conjoin, narrow, Constraints};
use crate::pdp::projection;
use crate::proxy::Broker;
use crate::query;
use crate::resolver::Endpoint;
use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, HOST};
use axum::http::{HeaderMap, HeaderValue, Method, Response, StatusCode};
use axum::response::IntoResponse;
use jc_core::ProblemDetails;
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::sync::Arc;

/// The path under an endpoint that a rewritten notification endpoint points at.
pub const EGRESS_PATH: &str = "/egress/notifications";

/// The parameter carrying the endpoint the subscriber actually asked for.
const TARGET: &str = "to";

/// The tenant header the gateway pins on the internal hop (GW20).
const TENANT: &str = "NGSILD-Tenant";

/// The largest notification the gateway will project. A notification carries a page of
/// entities, so it is bounded the same way a read is.
const MAX_NOTIFICATION: usize = 8 * 1024 * 1024;

/// Narrows a subscription to the caller's grants and routes its delivery through the
/// gateway (GW27, R46).
///
/// `is_create` separates the two shapes this is called with. A `POST` carries the whole
/// subscription, so what it leaves out has to be filled in from the grants. A `PATCH`
/// carries a fragment, and what it leaves out was already narrowed when it was stored:
/// filling that in from the grants would replace the subscriber's own selection with the
/// widest one the grants allow.
pub fn narrow_subscription(
    subscription: &mut Value,
    constraints: &Constraints,
    endpoint: &Endpoint,
    base_url: &str,
    is_create: bool,
) -> Result<(), Box<ProblemDetails>> {
    let Some(members) = subscription.as_object_mut() else {
        return Err(Box::new(
            ProblemDetails::bad_request().with_detail("the subscription is not an object"),
        ));
    };

    // A geo or scope condition cannot be folded into a stored subscription faithfully yet,
    // and a subscription stored half-narrowed would deliver what the grant does not cover.
    if constraints.geo_q.is_some()
        || !constraints.geo_grants.is_empty()
        || constraints.granted_scopes.is_some()
    {
        return Err(Box::new(unsupported(
            "a grant with a geographic or scope condition cannot be narrowed into a stored \
             subscription yet; the notifications it would produce cannot be shown to stay \
             inside the grant, so the subscription is refused rather than stored (R46, GW27)",
        )));
    }

    narrow_selectors(members, constraints, is_create)?;
    narrow_filter(members, constraints, is_create);
    narrow_names(
        members,
        "watchedAttributes",
        constraints,
        &endpoint.hidden_attributes,
    )?;

    let Some(notification) = members
        .get_mut("notification")
        .and_then(Value::as_object_mut)
    else {
        return match is_create {
            true => Err(Box::new(
                ProblemDetails::bad_request()
                    .with_detail("a subscription needs a notification endpoint"),
            )),
            false => Ok(()),
        };
    };
    narrow_names(
        notification,
        "attributes",
        constraints,
        &endpoint.hidden_attributes,
    )?;
    if !constraints.attrs.is_empty() && !notification.contains_key("attributes") {
        // The grant is a whitelist, so the notification carries that whitelist rather than
        // whatever the entity happens to hold when it fires (R9).
        notification.insert(
            "attributes".to_owned(),
            Value::Array(names(&constraints.attrs)),
        );
    }

    let Some(endpoint_of) = notification
        .get_mut("endpoint")
        .and_then(Value::as_object_mut)
    else {
        return match is_create {
            true => Err(Box::new(
                ProblemDetails::bad_request()
                    .with_detail("a subscription needs a notification endpoint"),
            )),
            false => Ok(()),
        };
    };
    let Some(uri) = endpoint_of.get("uri").and_then(Value::as_str) else {
        return match is_create {
            true => Err(Box::new(
                ProblemDetails::bad_request().with_detail("the notification endpoint names no uri"),
            )),
            false => Ok(()),
        };
    };
    let routed = route(uri, base_url, &endpoint.base_path)?;
    endpoint_of.insert("uri".to_owned(), Value::String(routed));
    Ok(())
}

/// The delivery path: the broker's notification, projected and forwarded (R46).
pub async fn deliver(
    State(gateway): State<Arc<Gateway>>,
    Path(slug): Path<String>,
    request: Request,
) -> Response<Body> {
    let Some(endpoint) = gateway.resolver.resolve(&slug) else {
        return ProblemDetails::not_found().into_response();
    };

    let (parts, body) = request.into_parts();
    let Ok(sent) = axum::body::to_bytes(body, MAX_NOTIFICATION).await else {
        return ProblemDetails::bad_request()
            .with_detail("the notification is unreadable or larger than the gateway accepts")
            .into_response();
    };
    let Ok(mut notification) = serde_json::from_slice::<Value>(&sent) else {
        return ProblemDetails::bad_request()
            .with_detail("the notification is not JSON")
            .into_response();
    };
    let Some(subscription_id) = notification
        .get("subscriptionId")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return ProblemDetails::bad_request()
            .with_detail("a notification names the subscription it belongs to")
            .into_response();
    };

    // The stored subscription decides what may be sent and where. A forged delivery can
    // therefore neither widen the projection nor choose the target.
    let stored = match read_subscription(&gateway.broker, &endpoint.space, &subscription_id).await {
        Ok(Some(stored)) => stored,
        Ok(None) => return ProblemDetails::not_found().into_response(),
        Err(problem) => return problem.into_response(),
    };
    let Some(target) = original_uri(&stored) else {
        tracing::warn!(
            subscription = %subscription_id,
            "a delivery names a subscription whose notification endpoint does not route \
             through this gateway"
        );
        return ProblemDetails::not_found().into_response();
    };

    let granted = attributes_of(&stored);
    if let Some(data) = notification.get_mut("data") {
        projection::project(data, &granted, &endpoint.hidden_attributes);
        if let Some(filter) = stored.get("q").and_then(Value::as_str) {
            if let Err(problem) =
                keep_matching(&gateway.broker, &endpoint.space, filter, data).await
            {
                return problem.into_response();
            }
        }
    }

    if notification
        .get("data")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        // Everything the broker matched has since stopped matching the narrowed condition,
        // or was projected away entirely. Nothing leaves the platform.
        return StatusCode::NO_CONTENT.into_response();
    }
    dispatch(&target, &parts.headers, &notification).await
}

/// Rewrites one notification endpoint to point back at this gateway.
fn route(uri: &str, base_url: &str, base_path: &str) -> Result<String, Box<ProblemDetails>> {
    if uri.starts_with("https://") {
        return Err(Box::new(unsupported(
            "the gateway's egress dispatcher speaks HTTP only, so a notification endpoint \
             it cannot reach is refused rather than stored and silently never delivered",
        )));
    }
    if !uri.starts_with("http://") {
        return Err(Box::new(ProblemDetails::bad_request().with_detail(
            "a notification endpoint the gateway delivers to has to be an HTTP URL",
        )));
    }
    if uri.contains(EGRESS_PATH) {
        return Err(Box::new(ProblemDetails::bad_request().with_detail(
            "the notification endpoint already points at the gateway's egress path",
        )));
    }
    if base_url.is_empty() {
        return Err(Box::new(unsupported(
            "this gateway does not know its own public URL, so it cannot route a notification \
             back through itself; set JC_GATEWAY_PUBLIC_URL",
        )));
    }
    Ok(format!(
        "{base_url}{base_path}{EGRESS_PATH}?{TARGET}={}",
        query::encode(uri)
    ))
}

/// The endpoint the subscriber asked for, read back out of a stored subscription.
///
/// `None` for a subscription this gateway did not route, which is the answer for one
/// created directly on the broker: the gateway delivers nothing it did not narrow.
fn original_uri(stored: &Value) -> Option<String> {
    let uri = stored
        .get("notification")?
        .get("endpoint")?
        .get("uri")?
        .as_str()?;
    let (path, target) = uri.split_once(&format!("?{TARGET}="))?;
    if !path.ends_with(EGRESS_PATH) {
        return None;
    }
    let decoded = query::decode(target);
    decoded.starts_with("http://").then_some(decoded)
}

/// The attributes a stored subscription was narrowed to; empty is a subscription over
/// whatever the entity carries.
fn attributes_of(stored: &Value) -> BTreeSet<String> {
    stored
        .get("notification")
        .and_then(|notification| notification.get("attributes"))
        .and_then(Value::as_array)
        .map(|names| {
            names
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Drops the entities the subscription's own filter no longer matches (R46).
///
/// The filter is evaluated by the broker, on the state it holds now, because a notification
/// says what changed and not whether the entity still satisfies the condition the grant was
/// narrowed with.
async fn keep_matching(
    broker: &Broker,
    space: &str,
    filter: &str,
    data: &mut Value,
) -> Result<(), Box<ProblemDetails>> {
    let Some(entities) = data.as_array_mut() else {
        return Ok(());
    };
    let ids: Vec<String> = entities
        .iter()
        .filter_map(|entity| entity.get("id").and_then(Value::as_str))
        .map(query::encode)
        .collect();
    if ids.is_empty() {
        return Ok(());
    }

    let target = format!(
        "/ngsi-ld/v1/entities?id={}&q={}",
        ids.join(","),
        query::encode(filter)
    );
    let (status, answer) = read(broker, space, &target).await?;
    if !(200..300).contains(&status) {
        tracing::error!(
            status,
            "the broker refused the condition re-check of a notification"
        );
        return Err(Box::new(ProblemDetails::new(
            502,
            "upstream-unavailable",
            "Broker Unavailable",
        )));
    }

    let matching: BTreeSet<&str> = answer
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entity| entity.get("id").and_then(Value::as_str))
        .collect();
    entities.retain(|entity| {
        entity
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| matching.contains(id))
    });
    Ok(())
}

/// Reads one stored subscription, or `None` when the broker does not hold it.
async fn read_subscription(
    broker: &Broker,
    space: &str,
    id: &str,
) -> Result<Option<Value>, Box<ProblemDetails>> {
    let target = format!("/ngsi-ld/v1/subscriptions/{}", query::encode(id));
    let (status, body) = read(broker, space, &target).await?;
    match status {
        200..=299 => Ok(Some(body)),
        404 => Ok(None),
        status => {
            tracing::error!(
                status,
                "the broker did not hand back the stored subscription"
            );
            Err(Box::new(ProblemDetails::new(
                502,
                "upstream-unavailable",
                "Broker Unavailable",
            )))
        }
    }
}

/// One read the gateway makes on its own account, with the tenant pinned from the endpoint.
async fn read(
    broker: &Broker,
    space: &str,
    target: &str,
) -> Result<(u16, Value), Box<ProblemDetails>> {
    let mut headers = HeaderMap::new();
    if let Ok(tenant) = HeaderValue::from_str(space) {
        headers.insert(TENANT, tenant);
    }
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

    let answer = broker
        .send(Method::GET, target, headers, Body::empty())
        .await
        .map_err(|error| Box::new(ProblemDetails::from(error)))?;
    let status = answer.status().as_u16();
    let Ok(bytes) = axum::body::to_bytes(answer.into_body(), MAX_NOTIFICATION).await else {
        return Err(Box::new(ProblemDetails::internal()));
    };
    Ok((
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    ))
}

/// Sends the projected notification to the endpoint the subscriber asked for.
///
/// The broker's own headers are relayed, so the `receiverInfo` a secured subscription
/// carries reaches the receiver that expects it (ADR 009, R27).
async fn dispatch(target: &str, from: &HeaderMap, notification: &Value) -> Response<Body> {
    let Some((origin, path)) = split(target) else {
        tracing::error!("a stored subscription carries an endpoint the gateway cannot address");
        return ProblemDetails::internal().into_response();
    };
    let Ok(body) = serde_json::to_vec(notification) else {
        return ProblemDetails::internal().into_response();
    };

    let mut headers = from.clone();
    // The projected notification is a different length and a different message from the one
    // the broker sent, and it is addressed to somebody else.
    headers.remove(CONTENT_LENGTH);
    headers.remove(HOST);
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(CONTENT_LENGTH, HeaderValue::from(body.len() as u64));

    // ponytail: one connection pool per delivery. A shared client is worth it when the
    // delivery rate makes it measurable; the correctness of the projection does not depend
    // on it, and the proxy already handles the hop-by-hop rules and the error mapping.
    match Broker::new(origin)
        .send(Method::POST, &path, headers, Body::from(body))
        .await
    {
        Ok(answer) => answer,
        Err(error) => {
            tracing::warn!(%error, "a notification could not be delivered");
            ProblemDetails::from(error).into_response()
        }
    }
}

/// Splits an HTTP URL into the origin the proxy takes and the path it forwards.
fn split(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("http://")?;
    Some(match rest.split_once('/') {
        Some((authority, path)) if !authority.is_empty() => {
            (format!("http://{authority}"), format!("/{path}"))
        }
        Some(_) => return None,
        None if rest.is_empty() => return None,
        None => (format!("http://{rest}"), "/".to_owned()),
    })
}

/// Narrows one array of attribute names in place, when the payload carries it.
fn narrow_names(
    members: &mut Map<String, Value>,
    field: &str,
    constraints: &Constraints,
    hidden: &BTreeSet<String>,
) -> Result<(), Box<ProblemDetails>> {
    let Some(asked) = members.get(field).and_then(Value::as_array) else {
        return Ok(());
    };
    let asked: BTreeSet<String> = asked
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();

    let mut kept = narrow(&asked, &constraints.attrs);
    kept.retain(|name| !hidden.contains(name));
    if kept.is_empty() && !asked.is_empty() {
        return Err(Box::new(ProblemDetails::forbidden().with_detail(format!(
            "no attribute named in `{field}` is granted"
        ))));
    }
    members.insert(field.to_owned(), Value::Array(names(&kept)));
    Ok(())
}

/// Narrows the subscription's entity selectors to the granted types (GW27).
fn narrow_selectors(
    members: &mut Map<String, Value>,
    constraints: &Constraints,
    is_create: bool,
) -> Result<(), Box<ProblemDetails>> {
    if constraints.types.is_empty() {
        return Ok(());
    }
    match members.get_mut("entities").and_then(Value::as_array_mut) {
        Some(selectors) => {
            selectors.retain(|selector| {
                selector
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|entity_type| constraints.types.contains(entity_type))
            });
            if selectors.is_empty() {
                return Err(Box::new(ProblemDetails::forbidden().with_detail(
                    "no entity type this subscription watches is granted",
                )));
            }
        }
        // A creation that names no type would stand for every type in the tenant, which is
        // wider than the grant. The grant's own types become the selector.
        None if is_create => {
            members.insert(
                "entities".to_owned(),
                Value::Array(
                    constraints
                        .types
                        .iter()
                        .map(|entity_type| serde_json::json!({ "type": entity_type }))
                        .collect(),
                ),
            );
        }
        None => {}
    }
    Ok(())
}

/// Conjoins the subscription's own filter with the grants' (R12, R13, GW27).
fn narrow_filter(members: &mut Map<String, Value>, constraints: &Constraints, is_create: bool) {
    let Some(grants) = constraints.q.clone() else {
        return;
    };
    let own = members.get("q").and_then(Value::as_str).map(str::to_owned);
    // A `PATCH` that says nothing about `q` leaves the stored one alone: it was narrowed
    // when it was stored, and replacing it with the grants alone would drop the
    // subscriber's own filter.
    if own.is_none() && !is_create {
        return;
    }
    // `constraints.q` is already one complete expression, so it is conjoined rather than
    // folded in again as a term. The subscriber's own filter goes through `conjoin` alone,
    // which is what parenthesises it and what drops it when its parentheses do not balance
    // (ADR 006: an unbalanced filter would consume the wrapping and regroup what follows).
    let folded = match conjoin(own.as_deref(), &[]) {
        Some(own) => format!("{own};{grants}"),
        None => grants,
    };
    members.insert("q".to_owned(), Value::String(folded));
}

/// A sorted set as a JSON array of strings.
fn names(set: &BTreeSet<String>) -> Vec<Value> {
    set.iter().map(|name| Value::String(name.clone())).collect()
}

/// The refusal for a subscription this gateway cannot route or narrow faithfully.
fn unsupported(detail: &str) -> ProblemDetails {
    ProblemDetails::new(501, "subscription-not-routable", "Not Implemented").with_detail(detail)
}
