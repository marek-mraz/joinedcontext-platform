//! The endpoint's own MCP instance (T-0166, EP-24, EP-25, EP-26, AG-04, AG-05, SP-14…SP-20).
//!
//! One MCP service per endpoint slug, spoken over Streamable HTTP: a JSON-RPC request in a
//! `POST`, a JSON-RPC response out, no session and no stream. Stateless is what SP-19 asks
//! for — with nothing kept between calls, the next `tools/list` already reflects a grant
//! that changed a second ago, and there is no live session to notify.
//!
//! Two properties hold by construction rather than by care:
//!
//! * **The space comes from the URL and nowhere else** (SP-14, AG-05). A tool argument is
//!   data: `space`, `tenant` and their spellings are refused as arguments rather than
//!   quietly ignored, so a caller can never aim a tool at another space, and a probe for
//!   one is indistinguishable from a tool that does not exist (SP-20).
//! * **The façade holds no authorization logic** (SP-16, EP-26). Every tool call is turned
//!   into the NGSI-LD request it stands for and handed to the same handler the HTTP surface
//!   uses, with the caller's own token. The PDP, the query narrowing, the write guard and
//!   the response projection are therefore literally the same code, and discovery cannot
//!   drift from enforcement: the tool list is rendered by asking that same PDP which
//!   operations this caller is granted (EP-25, SP-15).
//!
//! The catalogue is the one Architecture/07 section 2 names, minus the two pieces this
//! gateway has nothing to serve yet: `create_subscription`, because subscriptions do not
//! pass through the gateway at all, and the artifacts as MCP resources, because
//! `resources/list` needs the artifact store of Architecture/17. `describe_schema` renders
//! the two formalisms the gateway compiles and names the rest as served beside the model.

use crate::app::{ngsi_ld_request, sha256_hex, Gateway};
use crate::handlers::{access, schema};
use crate::pdp::evaluator::{Request as PolicyRequest, Subject, Verdict};
use crate::resolver::{Endpoint, Model};
use axum::body::Body;
use axum::http::{HeaderValue, Method, Response, StatusCode};
use jc_core::kinds::Operation;
use serde_json::{json, Map, Value};
use std::sync::Arc;

/// The revision of the MCP specification this façade speaks.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// Arguments that would choose a space instead of describing data (AG-05, SP-14, SP-20).
const SELECTOR_ARGUMENTS: &[&str] = &["space", "tenant", "contextspace", "slug", "endpoint"];

/// One tool of the catalogue of Architecture/07 section 2.
struct Tool {
    name: &'static str,
    /// The operations that make this tool worth advertising: the caller holding any one of
    /// them sees it. Empty is a tool that describes the endpoint rather than its data, and
    /// that every caller the endpoint admits may call (EP-55).
    operations: &'static [Operation],
    description: &'static str,
    schema: fn() -> Value,
}

const TOOLS: &[Tool] = &[
    Tool {
        name: "query_entities",
        operations: &[Operation::QueryEntity],
        description: "Query the entities of this context space by type and NGSI-LD filter.",
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "type": { "type": "string", "description": "NGSI-LD entity type, e.g. AirQualityObserved" },
                    "q": { "type": "string", "description": "NGSI-LD query filter, e.g. pm25>35" },
                    "scopeQ": { "type": "string", "description": "NGSI-LD scope query, e.g. /geo/SK/BB" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 1000 },
                },
                "required": ["type"],
                "additionalProperties": false,
            })
        },
    },
    Tool {
        name: "get_entity",
        operations: &[Operation::RetrieveEntity],
        description: "Retrieve one entity of this context space by its exact URN.",
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string", "description": "Entity URN, urn:ngsi-ld:{Type}:{domain}:{space}:{localId}" },
                    "attrs": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "The attributes to return; all the grant covers when absent",
                    },
                },
                "required": ["id"],
                "additionalProperties": false,
            })
        },
    },
    Tool {
        name: "describe_access",
        operations: &[],
        description:
            "The caller's effective grants here: operations, attributes, residual constraints.",
        schema: || json!({ "type": "object", "properties": {}, "additionalProperties": false }),
    },
    Tool {
        name: "describe_schema",
        // The schema is the description of what a read returns, so any read is enough to
        // be shown it; what it then contains is projected to the grant (EP-47).
        operations: &[
            Operation::QueryEntity,
            Operation::RetrieveEntity,
            Operation::RetrieveEntityTypes,
        ],
        description:
            "Inspect the data model of this context space, narrowed to the caller's grant.",
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "format": {
                        "type": "string",
                        "enum": ["summary", "json-schema", "context"],
                        "description": "summary lists the models and their artifacts; the others render one",
                    },
                    "version": { "type": "integer", "minimum": 1, "description": "Model major version" },
                },
                "additionalProperties": false,
            })
        },
    },
    Tool {
        name: "query_temporal",
        operations: &[Operation::QueryTemporal, Operation::RetrieveTemporal],
        description: "Query the history of this context space's entities in a time window.",
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string", "description": "One entity's URN; every matching entity when absent" },
                    "type": { "type": "string" },
                    "timerel": { "type": "string", "enum": ["before", "after", "between"] },
                    "timeAt": { "type": "string", "description": "ISO 8601 instant" },
                    "endTimeAt": { "type": "string", "description": "ISO 8601 instant, with timerel=between" },
                    "timeproperty": { "type": "string", "description": "The temporal property, observedAt by default" },
                },
                "required": ["timerel", "timeAt"],
                "additionalProperties": false,
            })
        },
    },
    Tool {
        name: "upsert_entity",
        operations: &[Operation::UpsertBatch],
        description: "Create or update one entity of this context space.",
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "entity": { "type": "object", "description": "The NGSI-LD entity, id and type included" },
                },
                "required": ["entity"],
                "additionalProperties": false,
            })
        },
    },
];

/// The tools this caller may see: the ones whose operation their grants cover (EP-25, SP-15).
pub fn tools_for(gateway: &Gateway, endpoint: &Endpoint, subject: &Subject) -> Vec<Value> {
    TOOLS
        .iter()
        .filter(|tool| granted(gateway, endpoint, subject, tool.operations))
        .map(|tool| {
            json!({
                "name": tool.name,
                "description": tool.description,
                "inputSchema": (tool.schema)(),
            })
        })
        .collect()
}

/// Whether the caller holds any of the tool's operations, asked of the PDP that also
/// enforces them, so discovery and enforcement cannot drift (SP-16).
fn granted(
    gateway: &Gateway,
    endpoint: &Endpoint,
    subject: &Subject,
    operations: &[Operation],
) -> bool {
    operations.is_empty()
        || operations.iter().any(|operation| {
            !matches!(
                gateway
                    .pdp
                    .decide(subject, *operation, &PolicyRequest::default(), endpoint),
                Verdict::Deny
            )
        })
}

/// Handles one JSON-RPC message of the endpoint's MCP instance.
///
/// `Ok(None)` is a notification: nothing to answer, and the caller sends 202.
pub async fn handle(
    gateway: Arc<Gateway>,
    endpoint: Arc<Endpoint>,
    subject: Subject,
    authorization: Option<HeaderValue>,
    message: Value,
) -> Option<Value> {
    let method = message.get("method").and_then(Value::as_str).unwrap_or("");
    let params = message.get("params").cloned().unwrap_or(json!({}));

    // No id is a notification. `notifications/initialized` is the only one that matters,
    // and nothing is kept between calls for it to change, so there is nothing to do.
    let id = message.get("id").cloned()?;

    match method {
        "initialize" => Some(result(
            id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                // No `listChanged`: a stateless server has nobody to tell, and the next
                // `tools/list` is already current (SP-19).
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": {
                    "name": format!("joinedcontext-endpoint-{}", endpoint.slug),
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "instructions": format!(
                    "Every tool of this server reads and writes the one context space behind this URL. \
                     Entity identifiers are URNs of the form urn:ngsi-ld:{{Type}}:{{domain}}:{}:{{localId}}.",
                    endpoint.space
                ),
            }),
        )),
        "ping" => Some(result(id, json!({}))),
        "tools/list" => Some(result(
            id,
            json!({ "tools": tools_for(&gateway, &endpoint, &subject) }),
        )),
        "tools/call" => {
            Some(call_tool(gateway, endpoint, subject, authorization, id, &params).await)
        }
        _ => Some(error(id, -32601, "method not found")),
    }
}

/// Runs one tool by making the NGSI-LD request it stands for and forwarding it through the
/// gateway's own enforcement path (EP-26, SP-16).
async fn call_tool(
    gateway: Arc<Gateway>,
    endpoint: Arc<Endpoint>,
    subject: Subject,
    authorization: Option<HeaderValue>,
    id: Value,
    params: &Value,
) -> Value {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let arguments = params
        .get("arguments")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    // A tool the caller may not see does not exist for them, exactly as a tool nobody has
    // ever defined does not: the two answers are byte-identical (SP-20).
    let Some(tool) = TOOLS.iter().find(|tool| tool.name == name) else {
        return error(id, -32602, "unknown tool");
    };
    if !granted(&gateway, &endpoint, &subject, tool.operations) {
        return error(id, -32602, "unknown tool");
    }
    if let Some(selector) = arguments
        .keys()
        .find(|key| SELECTOR_ARGUMENTS.contains(&key.to_ascii_lowercase().as_str()))
    {
        return error(
            id,
            -32602,
            &format!("`{selector}` is not an argument: this server serves one context space, the one its URL names"),
        );
    }

    // Two tools describe the endpoint rather than its data, and are answered from the very
    // projections the access and schema surfaces serve (EP-47, EP-55).
    match tool.name {
        "describe_access" => {
            let permissions = access::permissions(&subject, &endpoint, crate::pdp::now());
            return result(id, answered(&permissions));
        }
        "describe_schema" => {
            return match describe_schema(&endpoint, &subject, &arguments) {
                Ok(document) => result(id, answered(&document)),
                Err(message) => result(id, refused(&message, &Value::Null)),
            };
        }
        _ => {}
    }

    let (method, path, query, body) = match request_for(tool.name, &arguments) {
        Ok(parts) => parts,
        Err(message) => return error(id, -32602, &message),
    };

    // The caller's own token rides along and nothing else: the façade holds no identity of
    // its own, and the handler authenticates the caller again from that token (EP-26).
    let answer = ngsi_ld_request(
        Arc::clone(&gateway),
        &endpoint.slug,
        method,
        &path,
        &query,
        body,
        authorization,
    )
    .await;

    let status = answer.status();
    let payload = axum::body::to_bytes(answer.into_body(), 8 * 1024 * 1024)
        .await
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .unwrap_or(Value::Null);

    // A refusal is a tool error the agent can read, never an empty result it would mistake
    // for "there is nothing there" (SP-17, MIM0-R8).
    match status.is_success() {
        true => result(id, answered(&payload)),
        false => result(id, refused(&refusal_text(status, &payload), &payload)),
    }
}

/// A tool result an agent can both read and parse.
fn answered(payload: &Value) -> Value {
    json!({
        "isError": false,
        "content": [{
            "type": "text",
            "text": serde_json::to_string(payload).unwrap_or_else(|_| "null".to_owned()),
        }],
        "structuredContent": payload,
    })
}

/// A tool error: what was refused, in the agent's own channel for it.
fn refused(text: &str, payload: &Value) -> Value {
    json!({
        "isError": true,
        "content": [{ "type": "text", "text": text }],
        "structuredContent": payload,
    })
}

/// The data model, in the formalism asked for and narrowed to the caller's grant (EP-47).
///
/// The gateway renders the two artifacts it can compile from the model; SHACL, OWL, RDF,
/// LinkML and Markdown come from Model Tools and are served beside the model, so they are
/// named as not served here rather than approximated.
fn describe_schema(
    endpoint: &Endpoint,
    subject: &Subject,
    arguments: &Map<String, Value>,
) -> Result<Value, String> {
    let visible = schema::visible(subject, endpoint, crate::pdp::now());
    let format = arguments
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or("summary");
    if format == "summary" {
        return Ok(schema::index(endpoint, &visible, |body| {
            serde_json::to_vec(body)
                .map(|bytes| sha256_hex(&bytes))
                .unwrap_or_default()
        }));
    }

    let major = arguments.get("version").and_then(Value::as_u64);
    let models: Vec<&Model> = endpoint
        .models
        .iter()
        .filter(|model| major.is_none_or(|wanted| u64::from(model.major) == wanted))
        .collect();
    if models.is_empty() {
        return Err("this endpoint publishes no model of that version".to_owned());
    }

    let mut redacted = Vec::new();
    match format {
        "json-schema" => Ok(schema::json_schema(&models, &visible, &mut redacted)),
        "context" => Ok(schema::context(&models, &visible, &mut redacted)),
        other => Err(format!(
            "`{other}` is not rendered here: this endpoint serves summary, json-schema and context, \
             and the other formalisms are served beside the model once Model Tools has committed them"
        )),
    }
}

/// What an agent is told about a refusal: the status, and the problem document's own words
/// when the gateway or the broker wrote any.
fn refusal_text(status: StatusCode, payload: &Value) -> String {
    let detail = payload
        .get("detail")
        .or_else(|| payload.get("title"))
        .and_then(Value::as_str)
        .unwrap_or("the request was refused");
    format!(
        "{} {}: {detail}",
        status.as_u16(),
        status.canonical_reason().unwrap_or("")
    )
}

/// The NGSI-LD request one tool call stands for: method, path under `/ngsi-ld/v1`, query
/// string, body.
type NgsiLdCall = (Method, String, String, Option<Vec<u8>>);

/// The request one tool call stands for, or why its arguments do not make one.
fn request_for(tool: &str, arguments: &Map<String, Value>) -> Result<NgsiLdCall, String> {
    let text = |key: &str| {
        arguments
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    // NGSI-LD takes a comma-separated list where MCP takes an array of strings.
    let list = |key: &str| {
        let values: Vec<&str> = arguments
            .get(key)?
            .as_array()?
            .iter()
            .filter_map(Value::as_str)
            .collect();
        (!values.is_empty()).then(|| values.join(","))
    };
    let mut query: Vec<String> = Vec::new();
    let mut add = |key: &str, value: &str| {
        query.push(format!("{key}={}", percent_encode(value)));
    };

    match tool {
        "query_entities" => {
            let entity_type = text("type").ok_or("`type` is required")?;
            add("type", &entity_type);
            for key in ["q", "scopeQ"] {
                if let Some(value) = text(key) {
                    add(key, &value);
                }
            }
            if let Some(limit) = arguments.get("limit").and_then(Value::as_u64) {
                add("limit", &limit.to_string());
            }
            Ok((Method::GET, "/entities".to_owned(), query.join("&"), None))
        }
        "get_entity" => {
            let entity = text("id").ok_or("`id` is required")?;
            if let Some(attrs) = list("attrs") {
                add("attrs", &attrs);
            }
            Ok((
                Method::GET,
                format!("/entities/{}", percent_encode(&entity)),
                query.join("&"),
                None,
            ))
        }
        "query_temporal" => {
            for key in ["timerel", "timeAt"] {
                add(key, &text(key).ok_or(format!("`{key}` is required"))?);
            }
            for key in ["endTimeAt", "timeproperty", "type"] {
                if let Some(value) = text(key) {
                    add(key, &value);
                }
            }
            // One entity's history or every matching one: the same tool, and the PDP is
            // asked about whichever operation the path then is.
            let path = match text("id") {
                Some(entity) => format!("/temporal/entities/{}", percent_encode(&entity)),
                None => "/temporal/entities".to_owned(),
            };
            Ok((Method::GET, path, query.join("&"), None))
        }
        "upsert_entity" => {
            let entity = arguments.get("entity").ok_or("`entity` is required")?;
            // The batch upsert is the one NGSI-LD operation that both creates and updates,
            // so one entity is sent as a batch of one rather than as a guess between POST
            // and PATCH.
            let body = serde_json::to_vec(&json!([entity]))
                .map_err(|_| "`entity` is not JSON".to_owned())?;
            Ok((
                Method::POST,
                "/entityOperations/upsert".to_owned(),
                String::new(),
                Some(body),
            ))
        }
        _ => Err("unknown tool".to_owned()),
    }
}

/// Percent-encodes everything that is not unreserved, so a URN's colons and a filter's
/// operators survive the trip into a URL instead of splitting it.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// A JSON-RPC result.
fn result(id: Value, value: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": value })
}

/// A JSON-RPC error.
fn error(id: Value, code: i32, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// The JSON-RPC parse error, as an HTTP answer.
pub fn parse_error() -> Response<Body> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": Value::Null,
        "error": { "code": -32700, "message": "parse error" },
    });
    json_response(StatusCode::OK, &body)
}

/// A JSON-RPC message as the HTTP answer Streamable HTTP expects.
pub fn json_response(status: StatusCode, body: &Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec()),
        ))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}
