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

use crate::auth::accounts::ServiceAccounts;
use crate::auth::token::{self, Claims, Verifier};
use crate::handlers::{schema, space_surface};
use crate::middleware::rate_limit::{self, RateLimiter};
use crate::pdp::evaluator::{Constraints, Subject, Verdict};
use crate::pdp::write_guard;
use crate::pdp::{geo, projection, temporal, Pdp};
use crate::proxy::{self, Broker};
use crate::resolver::{Endpoint, Model, SlugResolver, Space};
use crate::translators::{geojson, tabular};
use crate::{handlers, mcp, middleware::tenancy, operations, query};
use arc_swap::ArcSwap;
use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, HeaderValue, Method, Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{any, get, post};
use axum::Router;
use jc_core::kinds::{Audience, Operation, Representation};
use jc_core::ProblemDetails;
use serde_json::Value;
use std::collections::BTreeSet;
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

/// How many entities a file representation asks the broker for at a time (EP-44).
///
/// Large enough that a normal download is one or two round trips, small enough that one
/// page fits comfortably inside `MAX_BODY` whatever the entities look like.
const PAGE: usize = 1_000;

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
    /// The realm's token verifier; absent means no token is accepted at all (PF-46).
    pub verifier: Option<Arc<Verifier>>,
    /// The service accounts a token's `azp` can name; swapped whole when the repository
    /// changes, so a withdrawn credential stops resolving without a restart (R48).
    accounts: ArcSwap<ServiceAccounts>,
    /// The gateway's public base URL, when the deployment names one.
    pub public_url: Option<String>,
    /// One token bucket per endpoint and caller (EP-20).
    pub rate_limiter: RateLimiter,
}

impl Gateway {
    /// A gateway with an empty endpoint table.
    pub fn new(broker: Broker, pdp: Box<dyn Pdp>, org_domain: impl Into<String>) -> Self {
        Self {
            resolver: SlugResolver::new(),
            broker,
            pdp,
            org_domain: org_domain.into(),
            verifier: None,
            accounts: ArcSwap::from_pointee(ServiceAccounts::new()),
            public_url: None,
            rate_limiter: RateLimiter::new(),
        }
    }

    /// Accepts tokens from one realm, and maps their `azp` to these accounts (PF-46).
    pub fn authenticate(
        mut self,
        verifier: Arc<Verifier>,
        accounts: ServiceAccounts,
        public_url: Option<String>,
    ) -> Self {
        self.verifier = Some(verifier);
        self.accounts.store(Arc::new(accounts));
        self.public_url = public_url;
        self
    }

    /// Every value that names this endpoint as an RFC 8707 resource.
    fn audiences_for(&self, endpoint: &Endpoint) -> Vec<String> {
        let mut audiences = vec![endpoint.slug.clone()];
        if let Some(base) = &self.public_url {
            audiences.push(format!("{base}{}", endpoint.base_path));
        }
        audiences
    }

    /// Replaces the service account table (R48, PF-46).
    ///
    /// Called by the reaper when the repository changed: `azp` values the repository no
    /// longer names stop resolving from the next request on.
    pub fn replace_accounts(&self, accounts: ServiceAccounts) {
        self.accounts.store(Arc::new(accounts));
    }

    /// Replaces the endpoint table (EP-19).
    pub fn serve(self, endpoints: impl IntoIterator<Item = Endpoint>) -> Self {
        self.resolver.replace(endpoints);
        self
    }

    /// Replaces the space table, which is the `/cs/{space}` surface (SP-01, EP-19).
    pub fn serve_spaces(self, spaces: impl IntoIterator<Item = Space>) -> Self {
        self.resolver.replace_spaces(spaces);
        self
    }

    /// The gateway's public base URL, or the empty string when none is configured.
    fn base_url(&self) -> &str {
        self.public_url.as_deref().unwrap_or_default()
    }
}

/// The router: two probes and the endpoint surface.
pub fn router(gateway: Arc<Gateway>) -> Router {
    Router::new()
        .route("/api/endpoint/{slug}/ngsi-ld/v1/{*rest}", any(ngsi_ld))
        .route("/api/endpoint/{slug}/access", get(access))
        .route("/api/endpoint/{slug}/mcp", post(mcp_message))
        .route("/api/endpoint/{slug}/access/check", post(access_check))
        .route("/api/endpoint/{slug}/file.geojson", get(file_geojson))
        .route("/api/endpoint/{slug}/file.csv", get(file_csv))
        .route("/api/endpoint/{slug}/file.xlsx", get(file_xlsx))
        .route("/cs", get(space_catalog))
        .route("/cs/{space}", get(space_record))
        .route("/cs/{space}/ngsi-ld/v1/{*rest}", any(space_ngsi_ld))
        .route("/cs/{space}/mcp", post(space_mcp_message))
        .route(
            "/api/endpoint/{slug}/.well-known/oauth-protected-resource",
            get(protected_resource),
        )
        .route("/api/endpoint/{slug}/schema/index.json", get(schema_index))
        .route(
            "/api/endpoint/{slug}/schema/{version}/{artifact}",
            get(schema_artifact),
        )
        // Every endpoint surface passes the limiter; the two probes do not, so a full
        // bucket can never make a pod look unhealthy (EP-20).
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&gateway),
            rate_limit::enforce,
        ))
        .route("/healthz", get(ok))
        .route("/livez", get(ok))
        .with_state(gateway)
        .fallback(missing)
}

async fn ok() -> &'static str {
    "ok"
}

/// Anything off the surface answers the same problem document as an unknown slug.
async fn missing() -> Response<Body> {
    ProblemDetails::not_found().into_response()
}

/// The ETSI resource tree under an endpoint slug, with every refusal rendered the way an
/// NGSI-LD client reads it.
async fn ngsi_ld(
    State(gateway): State<Arc<Gateway>>,
    Path((slug, _rest)): Path<(String, String)>,
    mut request: Request,
) -> Response<Body> {
    // Before routing, before authentication, before anything reads a header (EP-21).
    tenancy::strip_client_headers(&mut request);
    let admitted = admit(
        &gateway,
        &slug,
        Some(Representation::NgsiLd),
        request.headers(),
    );
    let prefix = format!("/api/endpoint/{slug}/ngsi-ld/v1");
    as_ngsi_ld_error(serve_ngsi_ld(&gateway, admitted, &prefix, request).await).await
}

/// The same tree under a context space name (SP-03).
///
/// A stock NGSI-LD client pointed at `/cs/{space}` works unmodified, and it works through
/// the same handler an endpoint slug goes through: the only difference between the two
/// surfaces is the name in the path and the audience the token has to carry (SP-01, R15).
async fn space_ngsi_ld(
    State(gateway): State<Arc<Gateway>>,
    Path((space, _rest)): Path<(String, String)>,
    mut request: Request,
) -> Response<Body> {
    tenancy::strip_client_headers(&mut request);
    let admitted = admit_space(
        &gateway,
        &space,
        Some(Representation::NgsiLd),
        request.headers(),
    )
    .map(|(space, subject)| (Arc::clone(&space.endpoint), subject));
    let prefix = format!("/cs/{space}/ngsi-ld/v1");
    as_ngsi_ld_error(serve_ngsi_ld(&gateway, admitted, &prefix, request).await).await
}

/// Runs one NGSI-LD request through the very pipeline the HTTP surfaces run (T-0166, SP-16).
///
/// The MCP façade turns a tool call into the NGSI-LD request it stands for and hands it
/// here, so the PDP, the query narrowing, the write guard and the response projection are
/// literally the same code for an agent as for any other client, and discovery can never
/// drift from enforcement.
///
/// `path` is the part under `/ngsi-ld/v1`, already percent-encoded; only the caller's own
/// token crosses over, because a header of the MCP request describes that request and not
/// this one.
pub async fn ngsi_ld_request(
    gateway: Arc<Gateway>,
    endpoint: &Endpoint,
    method: Method,
    path: &str,
    query: &str,
    body: Option<Vec<u8>>,
    authorization: Option<HeaderValue>,
) -> Response<Body> {
    let prefix = format!("{}/ngsi-ld/v1", endpoint.base_path);
    let uri = match query.is_empty() {
        true => format!("{prefix}{path}"),
        false => format!("{prefix}{path}?{query}"),
    };
    let mut builder = axum::http::Request::builder().method(method).uri(uri);
    if let Some(token) = authorization {
        builder = builder.header(AUTHORIZATION, token);
    }
    if body.is_some() {
        builder = builder.header(axum::http::header::CONTENT_TYPE, "application/json");
    }
    let Ok(request) = builder.body(body.map_or_else(Body::empty, Body::from)) else {
        return ProblemDetails::bad_request()
            .with_detail("the arguments do not form a request this endpoint can serve")
            .into_response();
    };

    // Admitted again from the token alone, so a tool call carries no privilege the same
    // call over HTTP would not have (EP-26). The record says which of the two surfaces it
    // belongs to, so a space instance re-resolves through the space table (SP-14).
    let admitted = match endpoint.base_path.strip_prefix("/cs/") {
        Some(space) => admit_space(
            &gateway,
            space,
            Some(Representation::Mcp),
            request.headers(),
        )
        .map(|(space, subject)| (Arc::clone(&space.endpoint), subject)),
        None => admit(
            &gateway,
            &endpoint.slug,
            Some(Representation::Mcp),
            request.headers(),
        ),
    };
    as_ngsi_ld_error(serve_ngsi_ld(&gateway, admitted, &prefix, request).await).await
}

/// The error types of CIM 009 clause 5.5.2 the gateway's own refusals map to, by status.
///
/// The clause defines no type for 401, 403 (other than the two query-size ones), 415 or
/// 502, so those keep the joinedcontext type URI: a made-up ETSI URI would be a lie a
/// client could act on, and a joinedcontext one is at least documented.
fn ngsi_ld_error_type(status: u16) -> Option<&'static str> {
    Some(match status {
        400 => "https://uri.etsi.org/ngsi-ld/errors/BadRequestData",
        404 => "https://uri.etsi.org/ngsi-ld/errors/ResourceNotFound",
        409 => "https://uri.etsi.org/ngsi-ld/errors/AlreadyExists",
        422 => "https://uri.etsi.org/ngsi-ld/errors/OperationNotSupported",
        500 => "https://uri.etsi.org/ngsi-ld/errors/InternalError",
        503 => "https://uri.etsi.org/ngsi-ld/errors/LdContextNotAvailable",
        _ => return None,
    })
}

/// Re-renders a problem document the way CIM 009 clause 5.5.3 wants it (T-0272).
///
/// The clause is explicit: errors on the NGSI-LD surface use `application/json`, not the
/// RFC 7807 media type, and carry `type`, `title` and `detail`. The broker already answers
/// that way; this makes the gateway's own refusals indistinguishable from it, so a client
/// that keys on `type` learns the same thing whichever of the two refused. The Portal API
/// keeps `application/problem+json`: a different surface, a different contract.
async fn as_ngsi_ld_error(response: Response<Body>) -> Response<Body> {
    let is_problem = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with(jc_core::PROBLEM_JSON));
    if !is_problem {
        return response;
    }

    let (mut parts, body) = response.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, 64 * 1024).await else {
        return ProblemDetails::internal().into_response();
    };
    let Ok(mut problem) = serde_json::from_slice::<Value>(&bytes) else {
        return Response::from_parts(parts, Body::from(bytes));
    };

    if let Some(members) = problem.as_object_mut() {
        if let Some(etsi) = ngsi_ld_error_type(parts.status.as_u16()) {
            members.insert("type".to_owned(), Value::String(etsi.to_owned()));
        }
        // Clause 6.3.3: `detail` is one of the three terms an error carries; a refusal that
        // names no reason still says so in a sentence rather than omitting the member.
        if !members.contains_key("detail") {
            let title = members.get("title").cloned().unwrap_or(Value::Null);
            members.insert("detail".to_owned(), title);
        }
    }
    parts.headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    match serde_json::to_vec(&problem) {
        Ok(rendered) => proxy::with_body(parts, rendered),
        Err(_) => Response::from_parts(parts, Body::from(bytes)),
    }
}

async fn serve_ngsi_ld(
    gateway: &Gateway,
    admitted: Result<(Arc<Endpoint>, Subject), Box<Response<Body>>>,
    prefix: &str,
    mut request: Request,
) -> Response<Body> {
    let (endpoint, subject) = match admitted {
        Ok(admitted) => admitted,
        Err(problem) => return *problem,
    };

    let method = request.method().clone();
    let uri = request.uri().clone();
    // The path as it came off the wire: decoding it would corrupt the URN in an entity
    // path, and re-encoding it is not the gateway's business.
    let path = uri
        .path()
        .strip_prefix(prefix)
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
    // The audit line names the principal the gateway established, never the one the
    // request claimed (PF-46).
    tracing::info!(
        slug = %endpoint.slug,
        space = %endpoint.space,
        principal = %principal_of(&subject),
        operation = %operation.as_str(),
        allowed = !verdict.is_deny(),
        "decision"
    );
    let Verdict::Rewrite(constraints) = verdict else {
        return refused(operation, &path);
    };

    // The caller asked for a period no grant reaches. The request was well formed and its
    // answer is genuinely nothing, so it is answered here: forwarding it without a
    // temporal window would ask the broker for everything (GW26).
    if constraints.empty {
        return match operations::addressed_entity(&path) {
            Some(_) => ProblemDetails::not_found().into_response(),
            None => empty_list(&constraints),
        };
    }

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

    // A payload the surface does not accept is refused for its media type, before anything
    // tries to parse it (CIM 009 clauses 6.3.2 and 6.3.5). Stricter than forwarding, not
    // looser: the write guard sees every body that gets past this line.
    if operation.is_write() && !sent.is_empty() && !accepted_payload(&parts.headers) {
        return unsupported_media_type().into_response();
    }

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
        query::upstream(&params, &constraints, &[])
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

/// The request payload media types the NGSI-LD surface accepts (CIM 009 clause 6.3.5).
const PAYLOAD_TYPES: &[&str] = &[
    "application/json",
    "application/ld+json",
    "application/merge-patch+json",
];

/// Whether the request names a payload media type the surface accepts, parameters aside.
fn accepted_payload(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or_default().trim())
        .is_some_and(|media| {
            PAYLOAD_TYPES
                .iter()
                .any(|accepted| media.eq_ignore_ascii_case(accepted))
        })
}

/// 415, the answer to a payload in a media type the surface does not take (clause 6.3.2).
fn unsupported_media_type() -> ProblemDetails {
    ProblemDetails::new(415, "unsupported-media-type", "Unsupported Media Type").with_detail(
        "the request payload must be application/json, application/ld+json or application/merge-patch+json",
    )
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
/// The answer to a read whose granted window the caller's request does not reach (GW26).
fn empty_list(constraints: &Constraints) -> Response<Body> {
    let mut response = json_response(&Value::Array(Vec::new()));
    if constraints.restricted {
        response
            .headers_mut()
            .insert(RESULTS_RESTRICTED, HeaderValue::from_static("true"));
    }
    response
}

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

    let areas = geo::Areas::of(&constraints.geo_grants, constraints.geo_caller.as_deref());
    match &mut payload {
        Value::Array(entities) => {
            entities.retain(|entity| {
                projection::permitted(entity, &constraints.id_patterns)
                    && areas.as_ref().is_none_or(|areas| areas.admits(entity))
            });
            projection::project(&mut payload, &constraints.attrs, &constraints.hidden);
        }
        entity if entity.is_object() && entity.get("id").is_some() => {
            if !projection::permitted(entity, &constraints.id_patterns)
                || !areas.as_ref().is_none_or(|areas| areas.admits(entity))
            {
                return ProblemDetails::not_found().into_response();
            }
            projection::project(&mut payload, &constraints.attrs, &constraints.hidden);
        }
        // A type list, an attribute list, a problem document: not entities, nothing to
        // project.
        _ => {}
    }
    // The forwarded window is the hull of several grants; what falls in the gaps between
    // them was never granted (GW26).
    temporal::keep_windows(&mut payload, &constraints.temporal_windows);

    match serde_json::to_vec(&payload) {
        Ok(bytes) => proxy::with_body(parts, bytes),
        Err(error) => {
            tracing::error!(%error, "the projected answer does not serialize");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Establishes who is calling, from the verified token or from nobody (PF-45, PF-46).
///
/// The three answers are: a verified principal, the anonymous `public` role on an endpoint
/// that admits it, or 401. There is no fourth answer where a claim the client made is
/// believed without a signature behind it.
fn authenticate(
    gateway: &Gateway,
    endpoint: &Endpoint,
    headers: &HeaderMap,
) -> Result<Subject, Box<ProblemDetails>> {
    let presented = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok());

    let raw = match token::bearer(presented) {
        Ok(raw) => raw,
        // No token at all: the anonymous caller, which only a public endpoint admits
        // (EP-16, GW22).
        Err(token::Rejected::NoToken) if endpoint.admits(None) => return Ok(Subject::anonymous()),
        Err(rejected) => return Err(Box::new(rejected.into())),
    };

    // A token was presented and the gateway has no realm to check it against. Believing
    // it would be believing the client.
    let Some(verifier) = &gateway.verifier else {
        tracing::warn!("a token was presented but no realm is configured");
        return Err(Box::new(ProblemDetails::unauthorized()));
    };
    let claims = verifier
        .verify(raw, &gateway.audiences_for(endpoint))
        .map_err(|rejected| Box::new(ProblemDetails::from(rejected)))?;

    subject_of(&claims, endpoint, gateway)
}

/// Turns verified claims into the subject the PDP evaluates.
fn subject_of(
    claims: &Claims,
    endpoint: &Endpoint,
    gateway: &Gateway,
) -> Result<Subject, Box<ProblemDetails>> {
    let groups: BTreeSet<String> = claims
        .groups
        .iter()
        .map(|group| group.trim_start_matches('/').to_owned())
        .collect();

    // A workload: `azp` has to name a ServiceAccount this repository declares, or the
    // token is valid and the account is unknown, which is an account with no grants
    // (PF-46).
    if let Some(azp) = claims.azp.as_deref() {
        if let Some(account) = gateway.accounts.load().resolve(azp) {
            if !endpoint.admits(Some(&account.project)) {
                return Err(Box::new(ProblemDetails::forbidden()));
            }
            return Ok(Subject {
                user: None,
                service_account: Some(account.name.clone()),
                roles: account.roles_in(&account.project, &endpoint.space),
                groups,
                did: None,
            });
        }
        if claims.preferred_username.is_none() {
            tracing::warn!(azp, "token from a client no ServiceAccount manifest names");
            return Err(Box::new(ProblemDetails::forbidden()));
        }
    }

    // A human. The token says they are a member of the organization; a group names the
    // project when the endpoint's audience is a list of them (EP-14, EP-15).
    let Some(user) = claims.preferred_username.clone() else {
        return Err(Box::new(ProblemDetails::unauthorized()));
    };
    let project = std::iter::once(&endpoint.project)
        .chain(endpoint.allowed_projects.iter())
        .find(|project| groups.contains(*project))
        .cloned()
        .unwrap_or_default();
    if !endpoint.admits(Some(&project)) {
        return Err(Box::new(ProblemDetails::forbidden()));
    }

    Ok(Subject {
        user: Some(user),
        service_account: None,
        roles: claims.roles().iter().cloned().collect(),
        groups,
        did: None,
    })
}

/// The principal, as one string for the audit log.
fn principal_of(subject: &Subject) -> String {
    match (&subject.user, &subject.service_account) {
        (Some(user), _) => format!("user:{user}"),
        (_, Some(account)) => format!("serviceAccount:{account}"),
        _ => "anonymous".to_owned(),
    }
}

/// Resolving the slug and establishing the caller: the two steps every surface starts
/// with (EP-03, EP-14, GW20).
///
/// `representation` is the one the surface serves, and `None` for the surfaces that are
/// not a representation of the data at all, like `access`.
fn admit(
    gateway: &Gateway,
    slug: &str,
    representation: Option<Representation>,
    headers: &HeaderMap,
) -> Result<(Arc<Endpoint>, Subject), Box<Response<Body>>> {
    let endpoint = gateway
        .resolver
        .resolve(slug)
        .ok_or_else(|| Box::new(ProblemDetails::not_found().into_response()))?;

    // An endpoint that does not serve the representation is not an endpoint at this URL
    // (EP-05).
    if representation.is_some_and(|wanted| !endpoint.serves(wanted)) {
        return Err(Box::new(ProblemDetails::not_found().into_response()));
    }
    let subject = authenticate(gateway, &endpoint, headers)
        .map_err(|problem| Box::new(problem.into_response()))?;
    Ok((endpoint, subject))
}

/// The endpoint's own MCP instance: one JSON-RPC message in, one out (T-0166, EP-24, SP-14).
///
/// Streamable HTTP without a session: no `GET` stream to open, nothing kept between calls,
/// so a grant withdrawn a second ago is already gone from the next `tools/list` (SP-19).
async fn mcp_message(
    State(gateway): State<Arc<Gateway>>,
    Path(slug): Path<String>,
    mut request: Request,
) -> Response<Body> {
    tenancy::strip_client_headers(&mut request);

    // AG-32: a client with no token is told where to get one, instead of being refused in
    // a way it cannot act on. A public MCP instance needs none, so it is served first.
    let public = gateway
        .resolver
        .resolve(&slug)
        .is_some_and(|endpoint| endpoint.audience == Audience::Public);
    if !public && request.headers().get(AUTHORIZATION).is_none() {
        return unauthorized(&gateway, &slug);
    }

    let (endpoint, subject) = match admit(
        &gateway,
        &slug,
        Some(Representation::Mcp),
        request.headers(),
    ) {
        Ok(admitted) => admitted,
        Err(problem) => return *problem,
    };

    mcp_answer(gateway, endpoint, subject, request).await
}

/// One JSON-RPC message, whichever surface it arrived on.
async fn mcp_answer(
    gateway: Arc<Gateway>,
    endpoint: Arc<Endpoint>,
    subject: Subject,
    request: Request,
) -> Response<Body> {
    let authorization = request.headers().get(AUTHORIZATION).cloned();
    let (_, body) = request.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, MAX_BODY).await else {
        return mcp::endpoint_facade::parse_error();
    };
    let Ok(message) = serde_json::from_slice::<Value>(&bytes) else {
        return mcp::endpoint_facade::parse_error();
    };

    match mcp::endpoint_facade::handle(gateway, endpoint, subject, authorization, message).await {
        Some(answer) => mcp::endpoint_facade::json_response(StatusCode::OK, &answer),
        // A notification is acknowledged and nothing more: there is no state to change.
        None => StatusCode::ACCEPTED.into_response(),
    }
}

/// The space's own MCP instance, the same façade the endpoint surface runs (SP-14).
async fn space_mcp_message(
    State(gateway): State<Arc<Gateway>>,
    Path(space): Path<String>,
    mut request: Request,
) -> Response<Body> {
    tenancy::strip_client_headers(&mut request);
    let (space, subject) = match admit_space(
        &gateway,
        &space,
        Some(Representation::Mcp),
        request.headers(),
    ) {
        Ok(admitted) => admitted,
        Err(problem) => return *problem,
    };
    mcp_answer(gateway, Arc::clone(&space.endpoint), subject, request).await
}

/// The protected-resource metadata of one MCP route (RFC 9728, AG-32).
///
/// Answered for every slug, whether or not one resolves: the document names the resource
/// URL the caller already typed and the realm the deployment already publishes, so it
/// discloses nothing, and a phone that has to discover its authorization server always
/// can (R20, EP-23).
async fn protected_resource(
    State(gateway): State<Arc<Gateway>>,
    Path(slug): Path<String>,
) -> Response<Body> {
    let Some(issuer) = gateway.verifier.as_ref().map(|verifier| verifier.issuer()) else {
        // No realm configured is a deployment that serves public endpoints only; there is
        // no authorization server to point a client at.
        return ProblemDetails::not_found().into_response();
    };
    json_response(&serde_json::json!({
        "resource": format!("{}/api/endpoint/{slug}/mcp", gateway.base_url()),
        "authorization_servers": [issuer],
        "bearer_methods_supported": ["header"],
        "resource_documentation": format!("{}/api/endpoint/{slug}/", gateway.base_url()),
    }))
}

/// The `401` a client needs in order to find its authorization server (RFC 9728, AG-32).
///
/// Sent for every unauthenticated call that is not on a public MCP instance, whether the
/// slug resolves or not, so the answer is the same for an endpoint that needs a login and
/// for one that does not exist (R20).
fn unauthorized(gateway: &Gateway, slug: &str) -> Response<Body> {
    let metadata = format!(
        "{}/api/endpoint/{slug}/.well-known/oauth-protected-resource",
        gateway.base_url()
    );
    let mut response = ProblemDetails::new(401, "unauthorized", "Unauthorized")
        .with_detail("this endpoint needs an access token; its authorization server is named by the resource metadata")
        .into_response();
    if let Ok(challenge) =
        HeaderValue::from_str(&format!("Bearer resource_metadata=\"{metadata}\""))
    {
        response
            .headers_mut()
            .insert(axum::http::header::WWW_AUTHENTICATE, challenge);
    }
    response
}

/// What the caller may do here, from the same PDP that enforces it (T-0163, EP-55).
async fn access(
    State(gateway): State<Arc<Gateway>>,
    Path(slug): Path<String>,
    mut request: Request,
) -> Response<Body> {
    tenancy::strip_client_headers(&mut request);
    let (endpoint, subject) = match admit(&gateway, &slug, None, request.headers()) {
        Ok(admitted) => admitted,
        Err(problem) => return *problem,
    };

    // The ODRL and UCAST representations are T-0164 and T-0165; a caller that asks for one
    // by name is told it is not served rather than handed something else (EP-58).
    let accept = request
        .headers()
        .get(axum::http::header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("*/*");
    if accept.contains("odrl") || accept.contains("grant-ast") {
        return (
            StatusCode::NOT_ACCEPTABLE,
            ProblemDetails::new(406, "not-acceptable", "Representation Not Served")
                .with_detail("this endpoint serves the access surface as application/json"),
        )
            .into_response();
    }

    json_response(&handlers::access::permissions(
        &subject,
        &endpoint,
        crate::pdp::now(),
    ))
}

/// One prospective request, answered yes or no (T-0163, R51).
async fn access_check(
    State(gateway): State<Arc<Gateway>>,
    Path(slug): Path<String>,
    mut request: Request,
) -> Response<Body> {
    tenancy::strip_client_headers(&mut request);
    let (endpoint, subject) = match admit(&gateway, &slug, None, request.headers()) {
        Ok(admitted) => admitted,
        Err(problem) => return *problem,
    };

    let (_, body) = request.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, 64 * 1024).await else {
        return ProblemDetails::bad_request().into_response();
    };
    let Ok(query) = serde_json::from_slice::<Value>(&bytes) else {
        return ProblemDetails::bad_request()
            .with_detail("request body is not JSON")
            .into_response();
    };
    let Some(action) = query
        .get("action")
        .and_then(|action| action.get("name"))
        .and_then(Value::as_str)
    else {
        return ProblemDetails::bad_request()
            .with_detail("action.name is required")
            .into_response();
    };

    json_response(&handlers::access::check(
        &subject,
        &endpoint,
        action,
        query
            .get("resource")
            .and_then(|resource| resource.get("type"))
            .and_then(Value::as_str),
        crate::pdp::now(),
    ))
}

/// The catalogue of what this endpoint publishes about its data (T-0162, EP-46).
async fn schema_index(
    State(gateway): State<Arc<Gateway>>,
    Path(slug): Path<String>,
    mut request: Request,
) -> Response<Body> {
    tenancy::strip_client_headers(&mut request);
    let (endpoint, subject) = match admit(&gateway, &slug, None, request.headers()) {
        Ok(admitted) => admitted,
        Err(problem) => return *problem,
    };

    let visible = schema::visible(&subject, &endpoint, crate::pdp::now());
    let document = schema::index(&endpoint, &visible, |body| {
        serde_json::to_vec(body)
            .map(|bytes| sha256_hex(&bytes))
            .unwrap_or_default()
    });
    revalidated(&document, "application/json", request.headers())
}

/// One schema document of one major version, projected to the grant (T-0162, EP-47, EP-49).
async fn schema_artifact(
    State(gateway): State<Arc<Gateway>>,
    Path((slug, version, artifact)): Path<(String, String, String)>,
    mut request: Request,
) -> Response<Body> {
    tenancy::strip_client_headers(&mut request);
    let (endpoint, subject) = match admit(&gateway, &slug, None, request.headers()) {
        Ok(admitted) => admitted,
        Err(problem) => return *problem,
    };

    // `schema/v2/...`: the major of the model, never its full version (DM-22).
    let Some(major) = version
        .strip_prefix('v')
        .and_then(|n| n.parse::<u32>().ok())
    else {
        return ProblemDetails::not_found().into_response();
    };
    let accept = request
        .headers()
        .get(axum::http::header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("*/*");
    let Some(wanted) = schema::artifact_of(&artifact, accept) else {
        return ProblemDetails::not_found().into_response();
    };

    let models: Vec<&Model> = endpoint
        .models
        .iter()
        .filter(|model| model.major == major)
        .collect();
    if models.is_empty() {
        return ProblemDetails::not_found().into_response();
    }
    // SHACL, OWL, RDF, LinkML and Markdown are Model Tools output: the gateway cannot
    // produce them, and says so rather than handing back a formalism nobody asked for.
    if wanted == schema::Artifact::Uncompiled {
        return (
            StatusCode::NOT_ACCEPTABLE,
            ProblemDetails::new(406, "not-acceptable", "Representation Not Served").with_detail(
                "this formalism is served once Model Tools has committed it beside the model",
            ),
        )
            .into_response();
    }

    let visible = schema::visible(&subject, &endpoint, crate::pdp::now());
    let mut redacted = Vec::new();
    let document = match wanted {
        schema::Artifact::JsonSchema => schema::json_schema(&models, &visible, &mut redacted),
        _ => schema::context(&models, &visible, &mut redacted),
    };
    revalidated(&document, wanted.media_type(), request.headers())
}

/// A schema document with the strong `ETag` a client revalidates against (EP-51).
///
/// The document is a projection of the policy set, so it is never immutable: a grant that
/// changes changes the schema, and a client holding a stale copy has to find out. What it
/// gets instead is a digest of exactly the bytes it holds, and a 304 whenever they still
/// match.
fn revalidated(document: &Value, media_type: &str, headers: &HeaderMap) -> Response<Body> {
    let Ok(bytes) = serde_json::to_vec(document) else {
        tracing::error!("a schema document does not serialize");
        return ProblemDetails::internal().into_response();
    };
    let etag = format!("\"{}\"", sha256_hex(&bytes));

    let mut response = if matches_etag(headers, &etag) {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        (
            [(axum::http::header::CONTENT_TYPE, media_type)],
            Body::from(bytes),
        )
            .into_response()
    };
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&etag) {
        headers.insert(axum::http::header::ETAG, value);
    }
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache"),
    );
    response
}

/// Whether `If-None-Match` names the document the gateway just built (RFC 9110 13.1.2).
fn matches_etag(headers: &HeaderMap, etag: &str) -> bool {
    let Some(presented) = headers
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    presented
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate == "*" || candidate.trim_start_matches("W/") == etag)
}

/// The lowercase hex sha256 of a body, which is what every `ETag` here is.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The same data as a `FeatureCollection` (T-0158, EP-09, EP-10).
async fn file_geojson(
    State(gateway): State<Arc<Gateway>>,
    Path(slug): Path<String>,
    mut request: Request,
) -> Response<Body> {
    tenancy::strip_client_headers(&mut request);
    let (endpoint, subject) = match admit(
        &gateway,
        &slug,
        Some(Representation::GeoJson),
        request.headers(),
    ) {
        Ok(admitted) => admitted,
        Err(problem) => return *problem,
    };

    let params = query::parse(request.uri().query().unwrap_or_default());
    let (entities, restricted) =
        match query_entities(&gateway, &endpoint, &subject, &params, &mut request).await {
            Ok(answer) => answer,
            Err(problem) => return *problem,
        };

    match geojson::feature_collection(&entities) {
        Ok(collection) => {
            let mut response = json_response(&collection);
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static(geojson::MEDIA_TYPE),
            );
            if restricted {
                response
                    .headers_mut()
                    .insert(RESULTS_RESTRICTED, HeaderValue::from_static("true"));
            }
            response
        }
        Err(untranslatable) => ProblemDetails::bad_request()
            .with_detail(untranslatable.to_string())
            .into_response(),
    }
}

/// Every entity type the pinned tenant holds, as the broker's own `EntityTypeList` reports it.
///
/// Used only as the selector of last resort for a file download. It can only narrow: the PDP
/// has already decided what this caller may see, and every constraint it produced is applied
/// either upstream or on the way back. An empty list means an empty space, which is an empty
/// file rather than an error.
async fn dataset_types(
    gateway: &Gateway,
    headers: &HeaderMap,
) -> Result<Vec<String>, Box<Response<Body>>> {
    let answer = gateway
        .broker
        .send(
            axum::http::Method::GET,
            "/ngsi-ld/v1/types",
            headers.clone(),
            Body::empty(),
        )
        .await
        .map_err(|error| Box::new(ProblemDetails::from(error).into_response()))?;

    let (parts, body) = answer.into_parts();
    if !parts.status.is_success() {
        return Err(Box::new(Response::from_parts(parts, body)));
    }
    let bytes = axum::body::to_bytes(body, MAX_BODY)
        .await
        .map_err(|_| Box::new(ProblemDetails::internal().into_response()))?;
    let list: Value = serde_json::from_slice(&bytes)
        .map_err(|_| Box::new(ProblemDetails::internal().into_response()))?;

    Ok(list["typeList"]
        .as_array()
        .map(|types| {
            types
                .iter()
                .filter_map(|entry| entry.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default())
}

/// Queries the entities behind an endpoint through the PDP, projected (GW11, R9).
///
/// This is the read half of the `file.*` downloads, shared by every representation that is a
/// different rendering of the same dataset. The NGSI-LD surface does not come through here:
/// it forwards the caller's own query, and an unselected one stays the `400` the
/// specification asks for.
async fn query_entities(
    gateway: &Gateway,
    endpoint: &Endpoint,
    subject: &Subject,
    params: &[(String, String)],
    request: &mut Request,
) -> Result<(Value, bool), Box<Response<Body>>> {
    let verdict = gateway.pdp.decide(
        subject,
        Operation::QueryEntity,
        &query::requested(params),
        endpoint,
    );
    let Verdict::Rewrite(constraints) = verdict else {
        return Err(Box::new(ProblemDetails::forbidden().into_response()));
    };
    if constraints.empty {
        return Ok((Value::Array(Vec::new()), true));
    }
    tenancy::pin_tenant(request, &endpoint.space)
        .map_err(|_| Box::new(ProblemDetails::internal().into_response()))?;

    // Nothing the caller sent and nothing the grants added selects anything, and a query that
    // selects nothing is a `400` upstream (CIM 009 5.7.2). A download is not a query though:
    // asking for `file.geojson` is asking for the dataset, so the selector is every type the
    // space holds (EP-09, EP-07). It can only narrow, never widen: the PDP has already spoken.
    let fallback = if query::selects(&constraints) {
        Vec::new()
    } else {
        let types = dataset_types(gateway, request.headers()).await?;
        // A space holding nothing is an empty file, not a `400` and not a second broker call.
        if types.is_empty() {
            return Ok((Value::Array(Vec::new()), constraints.restricted));
        }
        types
    };

    let target = format!(
        "/ngsi-ld/v1/entities?{}",
        query::upstream(params, &constraints, &fallback)
    );
    let answer = gateway
        .broker
        .send(
            axum::http::Method::GET,
            &target,
            request.headers().clone(),
            Body::empty(),
        )
        .await
        .map_err(|error| Box::new(ProblemDetails::from(error).into_response()))?;

    let (parts, body) = answer.into_parts();
    if !parts.status.is_success() {
        return Err(Box::new(Response::from_parts(parts, body)));
    }
    let bytes = axum::body::to_bytes(body, MAX_BODY)
        .await
        .map_err(|_| Box::new(ProblemDetails::internal().into_response()))?;
    let mut entities: Value = serde_json::from_slice(&bytes)
        .map_err(|_| Box::new(ProblemDetails::internal().into_response()))?;

    let areas = geo::Areas::of(&constraints.geo_grants, constraints.geo_caller.as_deref());
    if let Value::Array(list) = &mut entities {
        list.retain(|entity| {
            projection::permitted(entity, &constraints.id_patterns)
                && areas.as_ref().is_none_or(|areas| areas.admits(entity))
        });
    }
    projection::project(&mut entities, &constraints.attrs, &constraints.hidden);
    Ok((entities, constraints.restricted))
}

/// Resolving a space name and establishing the caller (SP-06, SP-11).
///
/// A space the caller may not reach and a space that does not exist answer the same 404,
/// so a probe over the space namespace learns nothing either way (R20).
fn admit_space(
    gateway: &Gateway,
    name: &str,
    representation: Option<Representation>,
    headers: &HeaderMap,
) -> Result<(Arc<Space>, Subject), Box<Response<Body>>> {
    let space = gateway
        .resolver
        .resolve_space(name)
        .ok_or_else(|| Box::new(ProblemDetails::not_found().into_response()))?;
    if representation.is_some_and(|wanted| !space.endpoint.serves(wanted)) {
        return Err(Box::new(ProblemDetails::not_found().into_response()));
    }
    let subject = authenticate(gateway, &space.endpoint, headers)
        .map_err(|problem| Box::new(problem.into_response()))?;
    Ok((space, subject))
}

/// Whether this caller holds any grant that reaches this space (SP-11).
///
/// The same PDP that enforces a request decides who may see the space exists, so the
/// catalog cannot list a space the data surface would refuse.
fn discoverable(gateway: &Gateway, space: &Space, subject: &Subject) -> bool {
    !gateway
        .pdp
        .decide(
            subject,
            Operation::QueryEntity,
            &query::requested(&[]),
            &space.endpoint,
        )
        .is_deny()
}

/// The catalog of spaces this caller may discover (SP-11).
async fn space_catalog(State(gateway): State<Arc<Gateway>>, request: Request) -> Response<Body> {
    let headers = request.headers();
    // A token is minted for one resource, so a token that names space A does not verify
    // against space B. That is not an error here, it is the narrowing: a space whose
    // authentication the caller cannot satisfy is a space they cannot discover.
    let visible: Vec<Arc<Space>> = gateway
        .resolver
        .spaces()
        .into_iter()
        .filter(|space| {
            authenticate(&gateway, &space.endpoint, headers)
                .is_ok_and(|subject| discoverable(&gateway, space, &subject))
        })
        .collect();

    let catalog = space_surface::catalog(&visible, gateway.base_url());
    let mut response = json_response(&catalog);
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static(space_surface::JSON_LD),
    );
    response
}

/// The DCAT-AP record of one space, in the representation the caller asked for (SP-10).
async fn space_record(
    State(gateway): State<Arc<Gateway>>,
    Path(name): Path<String>,
    request: Request,
) -> Response<Body> {
    let (space, subject) = match admit_space(&gateway, &name, None, request.headers()) {
        Ok(admitted) => admitted,
        Err(problem) => return *problem,
    };
    if !discoverable(&gateway, &space, &subject) {
        return ProblemDetails::not_found().into_response();
    }

    let accept = request
        .headers()
        .get(axum::http::header::ACCEPT)
        .and_then(|value| value.to_str().ok());
    let base = gateway.base_url();
    let format = space_surface::negotiate(accept);
    let body = match format {
        space_surface::Format::JsonLd => {
            serde_json::to_string(&space_surface::dataset(&space, base)).unwrap_or_default()
        }
        space_surface::Format::Turtle => space_surface::dataset_turtle(&space, base),
        space_surface::Format::Html => space_surface::dataset_html(&space, base),
    };
    match HeaderValue::from_str(format.media_type()) {
        Ok(media) => ([(axum::http::header::CONTENT_TYPE, media)], body).into_response(),
        Err(_) => ProblemDetails::internal().into_response(),
    }
}

/// `file.csv`: the whole answer as one flat table (EP-08, EP-44, EP-45).
async fn file_csv(
    State(gateway): State<Arc<Gateway>>,
    Path(slug): Path<String>,
    request: Request,
) -> Response<Body> {
    tabular_download(gateway, slug, request, Representation::Csv).await
}

/// `file.xlsx`: the same rows as `file.csv`, in a workbook (EP-08, EP-44).
async fn file_xlsx(
    State(gateway): State<Arc<Gateway>>,
    Path(slug): Path<String>,
    request: Request,
) -> Response<Body> {
    tabular_download(gateway, slug, request, Representation::Xlsx).await
}

/// The two tabular representations, which differ only in how the same table is written.
async fn tabular_download(
    gateway: Arc<Gateway>,
    slug: String,
    mut request: Request,
    representation: Representation,
) -> Response<Body> {
    tenancy::strip_client_headers(&mut request);
    let (endpoint, subject) = match admit(&gateway, &slug, Some(representation), request.headers())
    {
        Ok(admitted) => admitted,
        Err(problem) => return *problem,
    };

    let params = query::parse(request.uri().query().unwrap_or_default());
    let limits = tabular::Limits::of(endpoint.file_limits.as_ref());
    let (entities, restricted) = match paged_entities(
        &gateway,
        &endpoint,
        &subject,
        &params,
        &mut request,
        &limits,
    )
    .await
    {
        Ok(answer) => answer,
        Err(problem) => return *problem,
    };

    let mut table = match tabular::table(&entities, &limits) {
        Ok(table) => table,
        Err(_) => return too_large(),
    };
    if query::first(&params, "humanHeaders") == Some("true") {
        tabular::humanize(&mut table);
    }

    let (body, media, extension) = match representation {
        Representation::Xlsx => {
            let metadata = workbook_metadata(&endpoint, &params, table.len());
            match tabular::xlsx(&table, &metadata) {
                Ok(bytes) => (Body::from(bytes), tabular::XLSX_MEDIA_TYPE, "xlsx"),
                Err(error) => {
                    tracing::error!(%error, "the workbook does not serialize");
                    return ProblemDetails::internal().into_response();
                }
            }
        }
        _ => match tabular::csv(&table, &limits) {
            Ok(text) => (Body::from(text), tabular::CSV_MEDIA_TYPE, "csv"),
            Err(_) => return too_large(),
        },
    };

    let mut response = Response::new(body);
    let headers = response.headers_mut();
    if let Ok(media) = HeaderValue::from_str(media) {
        headers.insert(axum::http::header::CONTENT_TYPE, media);
    }
    // The slug is base32 and the extension is one of two literals, so the filename needs
    // no quoting beyond the quotes themselves (EP-43).
    if let Ok(disposition) = HeaderValue::from_str(&format!(
        "attachment; filename=\"{}.{extension}\"",
        endpoint.slug
    )) {
        headers.insert(axum::http::header::CONTENT_DISPOSITION, disposition);
    }
    if restricted {
        headers.insert(RESULTS_RESTRICTED, HeaderValue::from_static("true"));
    }
    response
}

/// What the `metadata` sheet of a workbook says about the download that produced it.
fn workbook_metadata(
    endpoint: &Endpoint,
    params: &[(String, String)],
    rows: usize,
) -> Vec<(String, String)> {
    vec![
        ("space".to_owned(), endpoint.space.clone()),
        ("endpoint".to_owned(), endpoint.slug.clone()),
        ("exportedAt".to_owned(), crate::pdp::now().to_rfc3339()),
        (
            "query".to_owned(),
            params
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("&"),
        ),
        ("rows".to_owned(), rows.to_string()),
    ]
}

/// The answer is bigger than this endpoint allows one download to be (EP-44).
fn too_large() -> Response<Body> {
    let mut response = ProblemDetails::new(413, "payload-too-large", "Payload Too Large")
        .with_detail(tabular::TooLarge.to_string())
        .into_response();
    *response.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;
    response
}

/// Every entity the query reaches, read from the broker one page at a time (EP-44).
///
/// A file representation answers with the whole result set rather than one broker page,
/// so it pages until the broker runs out or the endpoint's row ceiling is reached. The
/// ceiling is a refusal and not a truncation: a short CSV looks exactly like a complete
/// one, and a caller who cannot tell will act on half the data.
async fn paged_entities(
    gateway: &Gateway,
    endpoint: &Endpoint,
    subject: &Subject,
    params: &[(String, String)],
    request: &mut Request,
    limits: &tabular::Limits,
) -> Result<(Value, bool), Box<Response<Body>>> {
    let verdict = gateway.pdp.decide(
        subject,
        Operation::QueryEntity,
        &query::requested(params),
        endpoint,
    );
    let Verdict::Rewrite(constraints) = verdict else {
        return Err(Box::new(ProblemDetails::forbidden().into_response()));
    };
    if constraints.empty {
        return Ok((Value::Array(Vec::new()), true));
    }
    tenancy::pin_tenant(request, &endpoint.space)
        .map_err(|_| Box::new(ProblemDetails::internal().into_response()))?;

    // The caller's own window is a ceiling on the download, not the page size: paging is
    // the gateway's business and the caller asked for a file, not for a page of one.
    let wanted = query::first(params, "limit")
        .and_then(|limit| limit.parse::<u64>().ok())
        .unwrap_or(u64::from(limits.max_rows))
        .min(u64::from(limits.max_rows));
    let windowless: Vec<(String, String)> = params
        .iter()
        .filter(|(name, _)| name != "limit" && name != "offset")
        .cloned()
        .collect();
    // The same selector of last resort as `query_entities`: a download names a dataset.
    let fallback = if query::selects(&constraints) {
        Vec::new()
    } else {
        let types = dataset_types(gateway, request.headers()).await?;
        if types.is_empty() {
            return Ok((Value::Array(Vec::new()), constraints.restricted));
        }
        types
    };
    let narrowed = query::upstream(&windowless, &constraints, &fallback);
    let areas = geo::Areas::of(&constraints.geo_grants, constraints.geo_caller.as_deref());

    let mut collected: Vec<Value> = Vec::new();
    let mut offset = 0usize;
    loop {
        let target = format!("/ngsi-ld/v1/entities?{narrowed}&limit={PAGE}&offset={offset}");
        let answer = gateway
            .broker
            .send(
                axum::http::Method::GET,
                &target,
                request.headers().clone(),
                Body::empty(),
            )
            .await
            .map_err(|error| Box::new(ProblemDetails::from(error).into_response()))?;

        let (parts, body) = answer.into_parts();
        if !parts.status.is_success() {
            return Err(Box::new(Response::from_parts(parts, body)));
        }
        let bytes = axum::body::to_bytes(body, MAX_BODY)
            .await
            .map_err(|_| Box::new(ProblemDetails::internal().into_response()))?;
        let page: Value = serde_json::from_slice(&bytes)
            .map_err(|_| Box::new(ProblemDetails::internal().into_response()))?;
        let page = match page {
            Value::Array(entities) => entities,
            entity if entity.is_object() => vec![entity],
            _ => Vec::new(),
        };

        let fetched = page.len();
        collected.extend(page.into_iter().filter(|entity| {
            projection::permitted(entity, &constraints.id_patterns)
                && areas.as_ref().is_none_or(|areas| areas.admits(entity))
        }));
        if collected.len() as u64 > wanted {
            return Err(Box::new(too_large()));
        }
        // A short page is the last page; a full one may not be.
        if fetched < PAGE {
            break;
        }
        offset += PAGE;
    }

    let mut entities = Value::Array(collected);
    projection::project(&mut entities, &constraints.attrs, &constraints.hidden);
    Ok((entities, constraints.restricted))
}

/// A JSON body, serialized once.
fn json_response(payload: &Value) -> Response<Body> {
    match serde_json::to_vec(payload) {
        Ok(bytes) => (
            [(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            bytes,
        )
            .into_response(),
        Err(error) => {
            tracing::error!(%error, "the answer does not serialize");
            ProblemDetails::internal().into_response()
        }
    }
}
