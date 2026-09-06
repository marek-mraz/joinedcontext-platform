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
use crate::handlers::schema;
use crate::pdp::evaluator::{Constraints, Subject, Verdict};
use crate::pdp::write_guard;
use crate::pdp::{projection, Pdp};
use crate::proxy::{self, Broker};
use crate::resolver::{Endpoint, Model, SlugResolver};
use crate::translators::geojson;
use crate::{handlers, middleware::tenancy, operations, query};
use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{any, get, post};
use axum::Router;
use jc_core::kinds::{Operation, Representation};
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
    /// The service accounts a token's `azp` can name.
    pub accounts: ServiceAccounts,
    /// The gateway's public base URL, when the deployment names one.
    pub public_url: Option<String>,
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
            accounts: ServiceAccounts::new(),
            public_url: None,
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
        self.accounts = accounts;
        self.public_url = public_url;
        self
    }

    /// Every value that names this endpoint as an RFC 8707 resource.
    fn audiences_for(&self, endpoint: &Endpoint) -> Vec<String> {
        let mut audiences = vec![endpoint.slug.clone()];
        if let Some(base) = &self.public_url {
            audiences.push(format!("{base}/api/endpoint/{}", endpoint.slug));
        }
        audiences
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
        .route("/api/endpoint/{slug}/ngsi-ld/v1/{*rest}", any(ngsi_ld))
        .route("/api/endpoint/{slug}/access", get(access))
        .route("/api/endpoint/{slug}/access/check", post(access_check))
        .route("/api/endpoint/{slug}/file.geojson", get(file_geojson))
        .route("/api/endpoint/{slug}/schema/index.json", get(schema_index))
        .route(
            "/api/endpoint/{slug}/schema/{version}/{artifact}",
            get(schema_artifact),
        )
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

async fn ngsi_ld(
    State(gateway): State<Arc<Gateway>>,
    Path((slug, _rest)): Path<(String, String)>,
    mut request: Request,
) -> Response<Body> {
    // Before routing, before authentication, before anything reads a header (EP-21).
    tenancy::strip_client_headers(&mut request);

    let (endpoint, subject) = match admit(
        &gateway,
        &slug,
        Some(Representation::NgsiLd),
        request.headers(),
    ) {
        Ok(admitted) => admitted,
        Err(problem) => return *problem,
    };

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
        if let Some(account) = gateway.accounts.resolve(azp) {
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
fn sha256_hex(bytes: &[u8]) -> String {
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

/// Queries the entities behind an endpoint through the PDP, projected (GW11, R9).
///
/// This is the read half of the NGSI-LD handler, reused by every representation that is a
/// different rendering of the same query.
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
    tenancy::pin_tenant(request, &endpoint.space)
        .map_err(|_| Box::new(ProblemDetails::internal().into_response()))?;

    let target = format!(
        "/ngsi-ld/v1/entities?{}",
        query::upstream(params, &constraints)
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

    if let Value::Array(list) = &mut entities {
        list.retain(|entity| projection::permitted(entity, &constraints.id_patterns));
    }
    projection::project(&mut entities, &constraints.attrs);
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
