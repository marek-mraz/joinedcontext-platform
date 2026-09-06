//! The HTTP surface: what a request passes on its way to the broker (T-0005, EP-01, GW1).
//!
//! One handler serves the whole ETSI resource tree, because every request on it goes
//! through the same six steps and skipping one of them for a "simple" path is how a
//! gateway leaks:
//!
//! 1. remove everything the client claimed about its identity or tenancy (GW20),
//! 2. resolve the slug, or answer 404 without saying whether it exists (EP-03),
//! 3. name the operation, or answer 404: an unmapped path is not an NGSI-LD operation,
//! 4. ask the PDP, and refuse on anything but a rewrite (GW1),
//! 5. check a write payload whole, and narrow a read's query to the grants (GW11, GW17),
//! 6. forward with the tenant pinned, then project the answer back down (R9, R22).

use crate::pdp::evaluator::{Constraints, Subject, Verdict};
use crate::pdp::write_guard;
use crate::pdp::{projection, Pdp};
use crate::proxy::{self, Broker};
use crate::resolver::{Endpoint, SlugResolver};
use crate::{middleware::tenancy, operations, query};
use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderValue, Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{any, get};
use axum::Router;
use jc_core::kinds::{Operation, Representation};
use jc_core::ProblemDetails;
use serde_json::Value;
use std::sync::Arc;

/// The largest request or response body the gateway will hold in memory.
///
/// A write has to be inspected whole before any of it is applied and a read has to be
/// projected before any of it is sent, so neither can stream today.
// ponytail: one buffer, one limit. Streaming the untouched representations is a separate
// task, and a limit is a better answer than an out-of-memory kill either way.
const MAX_BODY: usize = 8 * 1024 * 1024;

/// The header that tells a caller their answer was narrowed by policy (R22).
const RESULTS_RESTRICTED: &str = "ngsild-results-restricted";

/// Everything the surface needs, built once at start-up.
pub struct Gateway {
    /// The endpoint table, replaced whole when the reconciler changes an endpoint.
    pub resolver: SlugResolver,
    /// The broker every endpoint forwards to.
    pub broker: Broker,
    /// What decides.
    pub pdp: Box<dyn Pdp>,
    /// The organization's verified domain, the middle segment of every entity URN.
    pub org_domain: String,
}

impl Gateway {
    /// A gateway with an empty endpoint table.
    pub fn new(broker: Broker, pdp: Box<dyn Pdp>, org_domain: impl Into<String>) -> Self {
        Self {
            resolver: SlugResolver::new(),
            broker,
            pdp,
            org_domain: org_domain.into(),
        }
    }

    /// Replaces the endpoint table (EP-19).
    pub fn serve(self, endpoints: impl IntoIterator<Item = Endpoint>) -> Self {
        self.resolver.replace(endpoints);
        self
    }
}

/// The router: two probes and the endpoint surface.
pub fn router(gateway: Arc<Gateway>) -> Router {
    Router::new()
        .route("/healthz", get(ok))
        .route("/livez", get(ok))
        .route(
            "/api/endpoint/{slug}/ngsi-ld/v1/{*rest}",
            any(ngsi_ld).with_state(gateway),
        )
        .fallback(missing)
}

async fn ok() -> &'static str {
    "ok"
}

/// Anything off the surface answers the same problem document as an unknown slug.
async fn missing() -> Response<Body> {
    ProblemDetails::not_found().into_response()
}

async fn ngsi_ld(
    State(gateway): State<Arc<Gateway>>,
    Path((slug, _rest)): Path<(String, String)>,
    mut request: Request,
) -> Response<Body> {
    // Before routing, before authentication, before anything reads a header (EP-21).
    tenancy::strip_client_headers(&mut request);

    let Some(endpoint) = gateway.resolver.resolve(&slug) else {
        return ProblemDetails::not_found().into_response();
    };
    if !endpoint.serves(Representation::NgsiLd) {
        return ProblemDetails::not_found().into_response();
    }

    // T-0228 puts the verified token's principal here; until then every caller is the
    // anonymous one, which is exactly the caller DEMO steps 4 and 5 use.
    let subject = Subject::anonymous();
    if !endpoint.admits(None) {
        return ProblemDetails::unauthorized().into_response();
    }

    let method = request.method().clone();
    let uri = request.uri().clone();
    // The path as it came off the wire: decoding it would corrupt the URN in an entity
    // path, and re-encoding it is not the gateway's business.
    let path = uri
        .path()
        .strip_prefix(&format!("/api/endpoint/{slug}/ngsi-ld/v1"))
        .unwrap_or_default()
        .to_owned();
    let params = query::parse(uri.query().unwrap_or_default());
    let details = query::first(&params, "details") == Some("true");

    let Some(operation) = operations::operation_of(&method, &path, details) else {
        return ProblemDetails::not_found().into_response();
    };

    let verdict = gateway
        .pdp
        .decide(&subject, operation, &query::requested(&params), &endpoint);
    let Verdict::Rewrite(constraints) = verdict else {
        return refused(operation, &path);
    };

    // The identifier in the path belongs to this organization and this space or the
    // request is malformed, whichever verb carries it (PF-10, PF-42).
    if let Some(raw) = operations::addressed_entity(&path) {
        if let Err(refusal) = write_guard::check_identifier(
            &query::decode(raw),
            None,
            &endpoint.space,
            &gateway.org_domain,
        ) {
            return ProblemDetails::from(refusal).into_response();
        }
    }

    if let Err(problem) = tenancy::pin_tenant(&mut request, &endpoint.space) {
        tracing::error!(space = %endpoint.space, %problem, "endpoint names an unusable space");
        return ProblemDetails::internal().into_response();
    }

    let (parts, body) = request.into_parts();
    let Ok(sent) = axum::body::to_bytes(body, MAX_BODY).await else {
        return ProblemDetails::bad_request()
            .with_detail("request body is unreadable or larger than the gateway accepts")
            .into_response();
    };

    if operation.is_write() && !sent.is_empty() {
        if let Some(problem) =
            refuse_write(&sent, &path, &constraints, &endpoint, &gateway.org_domain)
        {
            return problem.into_response();
        }
    }

    let sent_query = if operation.is_write() {
        query::passthrough(&params)
    } else {
        query::upstream(&params, &constraints)
    };
    let target = format!("/ngsi-ld/v1{path}?{sent_query}");
    let answer = match gateway
        .broker
        .send(method, &target, parts.headers, Body::from(sent))
        .await
    {
        Ok(answer) => answer,
        Err(error) => return ProblemDetails::from(error).into_response(),
    };

    project_answer(answer, operation, &constraints).await
}

/// GW1 and R20: a refused read of one entity is indistinguishable from a miss; everything
/// else is refused openly, without naming the rule that refused it.
fn refused(operation: Operation, path: &str) -> Response<Body> {
    if !operation.is_write() && operations::addressed_entity(path).is_some() {
        ProblemDetails::not_found().into_response()
    } else {
        ProblemDetails::forbidden().into_response()
    }
}

/// Checks a write payload whole and answers with the problem that refuses it, or nothing
/// (GW17, GW18).
///
/// The body of a `PATCH .../attrs/{name}` is the bare attribute value, so it is wrapped
/// back under its name before the grant is consulted; anything else is an entity, or a
/// batch of them.
fn refuse_write(
    body: &[u8],
    path: &str,
    constraints: &Constraints,
    endpoint: &Endpoint,
    org_domain: &str,
) -> Option<ProblemDetails> {
    let Ok(payload) = serde_json::from_slice::<Value>(body) else {
        return Some(ProblemDetails::bad_request().with_detail("request body is not JSON"));
    };
    let payload = match operations::targeted_attribute(path) {
        Some(name) => serde_json::json!({ name: payload }),
        None => payload,
    };

    let entities: Vec<&Value> = match &payload {
        Value::Array(entities) => entities.iter().collect(),
        other => vec![other],
    };
    for entity in entities {
        let outcome = if entity.get("id").is_some() || entity.get("@id").is_some() {
            write_guard::check(entity, constraints, &endpoint.space, org_domain)
        } else {
            write_guard::check_fragment(entity, constraints)
        };
        if let Err(refusal) = outcome {
            tracing::info!(slug = %endpoint.slug, %refusal, "write refused");
            return Some(ProblemDetails::from(refusal));
        }
    }
    None
}

/// Cuts the broker's answer down to what the grants cover (R9, R22, R24).
///
/// A single entity the grants do not reach is a miss, not a refusal: the caller must not
/// learn that it exists (R20).
async fn project_answer(
    answer: Response<Body>,
    operation: Operation,
    constraints: &Constraints,
) -> Response<Body> {
    let (mut parts, body) = answer.into_parts();
    if constraints.restricted {
        parts
            .headers
            .insert(RESULTS_RESTRICTED, HeaderValue::from_static("true"));
    }
    if operation.is_write() || !parts.status.is_success() {
        return Response::from_parts(parts, body);
    }

    let Ok(bytes) = axum::body::to_bytes(body, MAX_BODY).await else {
        tracing::error!("the broker's answer is larger than the gateway can project");
        return ProblemDetails::internal().into_response();
    };
    let Ok(mut payload) = serde_json::from_slice::<Value>(&bytes) else {
        // Not JSON, so there is nothing to project and nothing to leak through a member
        // the gateway did not understand.
        return proxy::with_body(parts, bytes.to_vec());
    };

    match &mut payload {
        Value::Array(entities) => {
            entities.retain(|entity| projection::permitted(entity, &constraints.id_patterns));
            projection::project(&mut payload, &constraints.attrs);
        }
        entity if entity.is_object() && entity.get("id").is_some() => {
            if !projection::permitted(entity, &constraints.id_patterns) {
                return ProblemDetails::not_found().into_response();
            }
            projection::project(&mut payload, &constraints.attrs);
        }
        // A type list, an attribute list, a problem document: not entities, nothing to
        // project.
        _ => {}
    }

    match serde_json::to_vec(&payload) {
        Ok(bytes) => proxy::with_body(parts, bytes),
        Err(error) => {
            tracing::error!(%error, "the projected answer does not serialize");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
