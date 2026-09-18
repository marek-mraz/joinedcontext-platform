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
//! The catalogue is the one Architecture/07 section 2 names: one tool per CIM 009 read and
//! temporal operation, so nothing a REST client can ask is missing from what an agent can
//! ask (AG-29). Three things are worth knowing about it:
//!
//! * **Arguments are checked against the tool's own published JSON Schema** before a path,
//!   a query string or a body is built from them, and every schema says
//!   `additionalProperties: false`, so an unknown field is an error rather than a
//!   parameter that is quietly dropped (AG-21, AG-31).
//! * **The temporal grammar is forwarded as written** (`timerel`, `timeAt`, `endTimeAt`,
//!   `lastN`, `aggrMethods`, `aggrPeriodDuration`), so history is neither a second query
//!   language nor a second authorization path (AG-30).
//! * **`create_subscription` needs the operator's answer.** The first call answers an
//!   elicitation and creates nothing; the client shows it to the person and repeats the same
//!   call with `params.elicitation = {elicitationId, action}`. The id is the server's, one
//!   shot, bound to the caller, the space and the arguments, so the answer cannot be the
//!   model's own (AG-08, Architecture/07 §3).
//!
//! `resources/list` serves the entity types, the access document and the schema artifacts
//! the gateway can render; `describe_schema` renders the two formalisms the gateway
//! compiles and names the rest as served beside the model.

use crate::app::{ngsi_ld_request, sha256_hex, Gateway};
use crate::handlers::{access, schema};
use crate::mcp::elicitation;
use crate::pdp::evaluator::{Request as PolicyRequest, Subject, Verdict};
use crate::resolver::{Endpoint, Model};
use axum::body::Body;
use axum::http::{HeaderValue, Method, Response, StatusCode};
use jc_core::kinds::Operation;
use serde_json::{json, Map, Value};
use std::sync::{Arc, LazyLock};

/// The revision of the MCP specification this façade speaks.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// Arguments that would choose a space instead of describing data (AG-05, SP-14, SP-20).
const SELECTOR_ARGUMENTS: &[&str] = &["space", "tenant", "contextspace", "slug", "endpoint"];

/// An NGSI-LD entity type name, as the models of this platform spell it: a term, never a
/// path, a URL or an escape sequence (AG-21).
///
/// A value outside this is a bad request and is refused by name. Answering it with an empty
/// result would tell the caller the argument was accepted, which is how a traversal probe
/// reads `[]`: as "the parameter went through and there was nothing there".
const TYPE_NAME: &str = "^[A-Za-z][A-Za-z0-9_-]*$";

/// An NGSI-LD entity id, which on this platform is always the URN of ADR 001.
const ENTITY_URN: &str = "^urn:ngsi-ld:[^\\s]+$";

/// One tool of the catalogue of Architecture/07 section 2.
struct Tool {
    name: &'static str,
    /// The operations that make this tool worth advertising: the caller holding any one of
    /// them sees it. Empty is a tool that describes the endpoint rather than its data, and
    /// that every caller the endpoint admits may call (EP-55).
    operations: &'static [Operation],
    description: &'static str,
    schema: fn() -> Value,
    /// What the broker's answer is called in the structured half of the result. MCP's
    /// `structuredContent` is an object matching the tool's output schema, so a bare list
    /// is read as nothing by every client that reads it by name (T-0946, AG-13).
    result_key: &'static str,
}

impl Tool {
    /// Whether the tool only reads, from the operations it stands for rather than from a
    /// boolean somebody set beside them (T-1066, AG-07).
    ///
    /// This is what an agent runtime reads before it decides whether a person has to confirm
    /// the call, and what the elicitation gate asks, so it has to state what the tool does. A
    /// tool that writes at all is not read-only: *any* write is a write, and a rule that asked
    /// whether *any* operation reads would let a mixed tool through the gate.
    fn read_only(&self) -> bool {
        !self.operations.iter().any(Operation::is_write)
    }
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
                    "type": type_schema(),
                    "q": { "type": "string", "maxLength": 4096, "description": "NGSI-LD query filter, e.g. pm25>35" },
                    "scopeQ": { "type": "string", "maxLength": 1024, "description": "NGSI-LD scope query, e.g. /geo/SK/BB" },
                    "georel": { "type": "string", "maxLength": 256, "description": "NGSI-LD geo relation, e.g. near;maxDistance==2000" },
                    "geometry": { "type": "string", "enum": ["Point", "LineString", "Polygon", "MultiPoint", "MultiLineString", "MultiPolygon"] },
                    "coordinates": { "type": "string", "maxLength": 8192, "description": "GeoJSON coordinates of the reference geometry" },
                    "attrs": attrs_schema(),
                    "limit": { "type": "integer", "minimum": 1, "maximum": 1000 },
                    "cursor": { "type": "integer", "minimum": 0, "description": "Rows to skip; the previous page's offset plus its size" },
                },
                "required": ["type"],
                "additionalProperties": false,
            })
        },
        result_key: "entities",
    },
    Tool {
        name: "get_entity",
        operations: &[Operation::RetrieveEntity],
        description: "Retrieve one entity of this context space by its exact URN.",
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "id": id_schema(),
                    "attrs": attrs_schema(),
                },
                "required": ["id"],
                "additionalProperties": false,
            })
        },
        result_key: "entity",
    },
    Tool {
        name: "list_types",
        operations: &[
            Operation::RetrieveEntityTypes,
            Operation::RetrieveEntityTypeDetails,
        ],
        description: "The entity types this context space holds, as the caller may see them.",
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "details": { "type": "boolean", "description": "Include each type's attribute names" },
                },
                "additionalProperties": false,
            })
        },
        result_key: "entityTypes",
    },
    Tool {
        name: "list_attributes",
        operations: &[
            Operation::RetrieveAttrTypes,
            Operation::RetrieveAttrTypeDetails,
        ],
        description: "The attributes this context space holds, as the caller may see them.",
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "details": { "type": "boolean", "description": "Include each attribute's types and value kinds" },
                },
                "additionalProperties": false,
            })
        },
        result_key: "attributes",
    },
    Tool {
        name: "query_temporal",
        operations: &[Operation::QueryTemporal],
        description: "Query the history of this context space's entities in a time window.",
        schema: temporal_schema,
        result_key: "entities",
    },
    Tool {
        name: "retrieve_temporal",
        operations: &[Operation::RetrieveTemporal],
        description: "The history of one entity of this context space in a time window.",
        schema: || {
            let mut schema = temporal_schema();
            let object = schema
                .as_object_mut()
                .expect("the temporal schema is an object");
            object["properties"]["id"] = id_schema();
            object["required"] = json!(["id", "timerel", "timeAt"]);
            schema
        },
        result_key: "entity",
    },
    Tool {
        name: "batch_query",
        operations: &[Operation::QueryBatch],
        description: "Query many entities of this context space by id or type in one call.",
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "ids": {
                        "type": "array",
                        "items": id_schema(),
                        "description": "Entity URNs to fetch; a type may be given instead",
                    },
                    "type": type_schema(),
                    "q": { "type": "string", "maxLength": 4096, "description": "NGSI-LD query filter" },
                    "attrs": attrs_schema(),
                    "limit": { "type": "integer", "minimum": 1, "maximum": 1000 },
                },
                "additionalProperties": false,
            })
        },
        result_key: "entities",
    },
    Tool {
        name: "list_subscriptions",
        operations: &[Operation::QuerySubscription],
        description: "The context subscriptions of this space the caller may see.",
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "minimum": 1, "maximum": 1000 },
                },
                "additionalProperties": false,
            })
        },
        result_key: "subscriptions",
    },
    Tool {
        name: "describe_access",
        operations: &[],
        description:
            "The caller's effective grants here: operations, attributes, residual constraints. \
             `format` picks the language: `permissions` (AuthZEN, the default), `odrl` (ODRL 2.2) \
             or `grant-ast` (UCAST); the grants are the same in all three (EP-60).",
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "format": { "type": "string", "enum": ACCESS_FORMATS },
                },
                "additionalProperties": false,
            })
        },
        result_key: "access",
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
                        "enum": [
                            "summary", "json-schema", "context",
                            "linkml", "shacl", "owl", "rdf", "markdown",
                        ],
                        "description": "summary lists the models and their artifacts; the others render one, the text formalisms as {format, mediaType, document}",
                    },
                    "entityType": type_schema(),
                    "version": { "type": "integer", "minimum": 1, "description": "Model major version" },
                },
                "additionalProperties": false,
            })
        },
        result_key: "schema",
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
        result_key: "entity",
    },
    Tool {
        name: "create_subscription",
        operations: &[Operation::CreateSubscription],
        description: "Create a context subscription",
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "subscription": { "type": "object", "description": "The NGSI-LD Subscription, entities and notification included" },
                },
                "required": ["subscription"],
                "additionalProperties": false,
            })
        },
        result_key: "subscription",
    },
];

/// Who is asking, as an elicitation binds it: the account, the person, or the participant the
/// token names, and `anonymous` when it names nobody.
///
/// An anonymous caller never reaches this — a destructive tool needs a write grant, which the
/// `public` role does not hold — but the binding is written for whoever does reach it.
fn caller_of(subject: &Subject) -> String {
    subject
        .service_account
        .as_deref()
        .or(subject.user.as_deref())
        .or(subject.did.as_deref())
        .unwrap_or("anonymous")
        .to_owned()
}

/// The form the person fills to allow one destructive call (AG-08).
fn confirmation_schema(tool: &str) -> Value {
    json!({
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["accept", "decline"],
                "description": format!("Whether `{tool}` may run"),
            },
        },
        "required": ["action"],
    })
}

/// The `type` argument, which every tool that takes one spells the same way (AG-21).
fn type_schema() -> Value {
    json!({
        "type": "string",
        "maxLength": 256,
        "pattern": TYPE_NAME,
        "description": "NGSI-LD entity type, e.g. AirQualityObserved",
    })
}

/// The `id` argument: one entity, named by the URN of ADR 001 (AG-21).
fn id_schema() -> Value {
    json!({
        "type": "string",
        "maxLength": 512,
        "pattern": ENTITY_URN,
        "description": "Entity URN, urn:ngsi-ld:{Type}:{domain}:{space}:{localId}",
    })
}

/// The `attrs` argument, which every read tool spells the same way.
fn attrs_schema() -> Value {
    json!({
        "type": "array",
        // Bounded like every other argument (T-0972): the broker parses what arrives, so an
        // unbounded list is a way to spend its memory through a tool the grant allows.
        "maxItems": 256,
        "items": { "type": "string", "maxLength": 256 },
        "description": "The attributes to return; all the grant covers when absent",
    })
}

/// The temporal query grammar, forwarded to the broker unchanged (AG-30).
///
/// One schema for both temporal tools: `retrieve_temporal` is this plus a required `id`,
/// which is the only difference CIM 009 makes between them.
fn temporal_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "type": type_schema(),
            "q": { "type": "string", "maxLength": 4096, "description": "NGSI-LD query filter" },
            "attrs": attrs_schema(),
            "timerel": { "type": "string", "enum": ["before", "after", "between"] },
            "timeAt": { "type": "string", "description": "ISO 8601 instant" },
            "endTimeAt": { "type": "string", "description": "ISO 8601 instant, with timerel=between" },
            "timeproperty": { "type": "string", "description": "The temporal property, observedAt by default" },
            "lastN": { "type": "integer", "minimum": 1, "description": "Keep only the N most recent instances per attribute" },
            "aggrMethods": {
                "type": "array",
                "items": { "type": "string", "enum": ["totalCount", "distinctCount", "sum", "avg", "min", "max", "stddev", "sumsq"] },
                "description": "Aggregate instead of returning every instance",
            },
            "aggrPeriodDuration": { "type": "string", "description": "ISO 8601 duration of one aggregation bucket, e.g. PT1H" },
            "limit": { "type": "integer", "minimum": 1, "maximum": 1000 },
        },
        "required": ["timerel", "timeAt"],
        "additionalProperties": false,
    })
}

/// One compiled validator per tool, in the order of `TOOLS` (AG-31).
///
/// Compiled once rather than per call: the schemas are constants, and an agent that asks
/// twice pays for the compilation once. A schema that does not compile leaves its tool
/// without a validator, and `validate` then refuses every call to it rather than letting
/// unvalidated arguments through.
static VALIDATORS: LazyLock<Vec<Option<jsonschema::Validator>>> = LazyLock::new(|| {
    TOOLS
        .iter()
        .map(|tool| jsonschema::draft7::new(&(tool.schema)()).ok())
        .collect()
});

/// Checks one tool's arguments against its published JSON Schema before anything is built
/// from them (AG-21, AG-31).
///
/// `additionalProperties: false` is in every schema, so an unknown field is an error here
/// rather than a parameter that is silently dropped and an answer that quietly means
/// something else.
fn validate(index: usize, arguments: &Map<String, Value>) -> Result<(), String> {
    let Some(Some(validator)) = VALIDATORS.get(index) else {
        return Err(
            "this tool's schema does not compile, so its arguments cannot be checked".to_owned(),
        );
    };
    let instance = Value::Object(arguments.clone());
    let problems: Vec<String> = validator
        .iter_errors(&instance)
        .map(|error| {
            let at = error.instance_path().to_string();
            let rule = broken_rule(&error);
            match at.is_empty() {
                true => rule,
                false => format!("{at}: {rule}"),
            }
        })
        .collect();
    match problems.is_empty() {
        true => Ok(()),
        false => Err(problems.join("; ")),
    }
}

/// Names the rule an argument broke, without repeating what the caller sent (GW31, AG-21).
///
/// A validator writes the offending value into its own message, and a tool error is read by a
/// model: a refusal that quotes the argument carries whatever was typed into the next prompt.
/// The place and the rule are what a caller needs to correct the call; the value it already has.
fn broken_rule(error: &jsonschema::ValidationError<'_>) -> String {
    use jsonschema::error::ValidationErrorKind as Rule;
    match error.kind() {
        Rule::AdditionalProperties { unexpected } => {
            format!(
                "no argument of this tool is called {}",
                unexpected.join(", ")
            )
        }
        Rule::Required { property } => format!("{property} is required"),
        Rule::Type { .. } => "is not of the type the schema declares".to_owned(),
        Rule::Pattern { pattern } => format!("does not match {pattern}"),
        Rule::MaxLength { limit } => format!("is longer than {limit} characters"),
        Rule::MinLength { limit } => format!("is shorter than {limit} characters"),
        Rule::MaxItems { limit } => format!("has more than {limit} items"),
        Rule::MinItems { limit } => format!("has fewer than {limit} items"),
        Rule::Maximum { limit } => format!("is above {limit}"),
        Rule::Minimum { limit } => format!("is below {limit}"),
        Rule::Enum { options } => format!("is not one of {options}"),
        Rule::Format { format } => format!("is not a {format}"),
        _ => {
            let keyword = error.schema_path().to_string();
            let keyword = keyword.rsplit('/').next().unwrap_or_default().to_owned();
            match keyword.is_empty() {
                true => "is not what the schema allows".to_owned(),
                false => format!("breaks the schema's {keyword}"),
            }
        }
    }
}

/// The tools this caller may see: the ones whose operation their grants cover (EP-25, SP-15).
pub fn tools_for(gateway: &Gateway, endpoint: &Endpoint, subject: &Subject) -> Vec<Value> {
    let federates = member_names(gateway, endpoint);
    TOOLS
        .iter()
        .filter(|tool| granted(gateway, endpoint, subject, tool.operations))
        .map(|tool| {
            json!({
                "name": tool.name,
                "description": described(tool, &federates),
                "inputSchema": (tool.schema)(),
                "outputSchema": output_schema(tool),
                "annotations": {
                    "readOnlyHint": tool.read_only(),
                    "destructiveHint": !tool.read_only(),
                },
            })
        })
        .collect()
}

/// One tool's description, with what a federated space adds to a read (EP-71, AG-30).
///
/// Only a read: a write goes to the space this URL names and to no member, so saying "over
/// the union" on `create_entity` would describe something the platform does not do.
fn described(tool: &Tool, federates: &[String]) -> String {
    match (tool.read_only(), federates) {
        (true, [_, ..]) => format!(
            "{} This space federates {}: the answer is the union of their data and can be \
             partial.",
            tool.description,
            federates.join(", ")
        ),
        _ => tool.description.to_owned(),
    }
}

/// What the server tells a client about itself before the first call.
///
/// A federated space gets one more sentence, because everything that follows from it — a union
/// instead of one store, an answer that can be partial — changes how a model should read a
/// result (EP-70, EP-71, AG-30). Members are named and never addressed.
fn instructions(gateway: &Gateway, endpoint: &Endpoint) -> String {
    let base = format!(
        "Every tool of this server reads and writes the one context space behind this URL. \
         Entity identifiers are URNs of the form urn:ngsi-ld:{{Type}}:{{domain}}:{}:{{localId}}.",
        endpoint.space
    );
    match member_names(gateway, endpoint).as_slice() {
        [] => base,
        names => format!(
            "{base} This space federates {}: every read answers over their union, a result \
             carries the names it came from as `jc:source`, and an answer can be partial when \
             one of them does not respond.",
            names.join(", ")
        ),
    }
}

/// The registrations of the endpoint's space, by name (EP-71).
fn member_names(gateway: &Gateway, endpoint: &Endpoint) -> Vec<String> {
    gateway
        .members_of(&endpoint.project, &endpoint.space)
        .into_iter()
        .map(|member| member.name)
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
    let params = message.get("params").cloned().unwrap_or(json!({}));

    // No id is a notification. `notifications/initialized` is the only one that matters,
    // and nothing is kept between calls for it to change, so there is nothing to do.
    let id = message.get("id").cloned()?;

    // A request that is not JSON-RPC 2.0, or names no method, is an Invalid Request (SP-14).
    let Some(method) = message
        .get("method")
        .and_then(Value::as_str)
        .filter(|_| message.get("jsonrpc").and_then(Value::as_str) == Some("2.0"))
    else {
        return Some(error(
            id,
            -32600,
            "invalid request: a JSON-RPC 2.0 request names \"jsonrpc\": \"2.0\" and a method",
        ));
    };

    match method {
        "initialize" => Some(result(
            id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                // No `listChanged`: a stateless server has nobody to tell, and the next
                // `tools/list` is already current (SP-19).
                "capabilities": {
                    "tools": { "listChanged": false },
                    "resources": { "listChanged": false, "subscribe": false },
                },
                "serverInfo": {
                    "name": format!("joinedcontext-endpoint-{}", endpoint.slug),
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "instructions": instructions(&gateway, &endpoint),
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
        "resources/list" => Some(result(id, resources(&endpoint, &subject))),
        "resources/templates/list" => Some(result(
            id,
            json!({
                "resourceTemplates": [{
                    "uriTemplate": format!("ngsi-ld://{}/entities/{{id}}", endpoint.space),
                    "name": "entity",
                    "description": "One entity of this context space, projected to the grant.",
                    "mimeType": "application/json",
                }],
            }),
        )),
        "resources/read" => {
            Some(read_resource(gateway, endpoint, subject, authorization, id, &params).await)
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
    let Some((index, tool)) = TOOLS.iter().enumerate().find(|(_, tool)| tool.name == name) else {
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

    // AG-31: the arguments are checked against the tool's own published schema before a
    // path, a query string or a body exists to be built from them.
    if let Err(problem) = validate(index, &arguments) {
        return result(id, refused(&problem, &Value::Null));
    }

    // Two tools describe the endpoint rather than its data, and are answered from the very
    // projections the access and schema surfaces serve (EP-47, EP-55).
    match tool.name {
        "describe_access" => {
            // The schema's enum already refused any other word (AG-31).
            let format = arguments
                .get("format")
                .and_then(Value::as_str)
                .unwrap_or("permissions");
            let document = access_document(&gateway, &subject, &endpoint, format);
            return result(id, answered(&document, tool.result_key, false, &[]));
        }
        "describe_schema" => {
            return match describe_schema(&endpoint, &subject, &arguments) {
                Ok(document) => result(id, answered(&document, tool.result_key, false, &[])),
                Err(message) => result(id, refused(&message, &Value::Null)),
            };
        }
        _ => {}
    }

    // AG-08: a subscription outlives the conversation that made it, so the person decides,
    // not the model. The first call answers an elicitation and creates nothing; the client
    // shows it and repeats the same call carrying the answer. The id is the server's, which
    // is what makes the second call the person's — a boolean the model writes into its own
    // call proves nothing, because the model writes both calls (T-0849, Architecture/07 §3).
    if !tool.read_only() {
        let owner = caller_of(&subject);
        let surface = endpoint.base_path.clone();
        let digest = elicitation::digest_of(&arguments);
        match params.get("elicitation") {
            None => {
                let elicitation_id = gateway
                    .elicitations
                    .ask(&owner, &surface, tool.name, &digest);
                return result(
                    id,
                    elicitation::document(
                        &elicitation_id,
                        &format!(
                            "{} on the context space `{}`. Nothing has been created: show the \
                             person what this would do and send this call again with their \
                             answer.",
                            tool.description, endpoint.space
                        ),
                        confirmation_schema(tool.name),
                    ),
                );
            }
            Some(sent) => match gateway
                .elicitations
                .answer(&owner, &surface, tool.name, &digest, sent)
            {
                elicitation::Answer::Accepted => {}
                elicitation::Answer::Declined => {
                    return result(
                        id,
                        refused(
                            "the person declined this call; nothing was created (AG-08)",
                            &Value::Null,
                        ),
                    );
                }
                elicitation::Answer::Unknown => {
                    return result(
                        id,
                        refused(
                            "that answer belongs to no open question of this call: an answer is \
                             spent once, expires in ten minutes and is bound to this caller, \
                             this space and these arguments. Call again without `elicitation` \
                             to ask anew (AG-08)",
                            &Value::Null,
                        ),
                    );
                }
            },
        }
    }

    let (method, path, query, body) = match request_for(tool.name, &arguments) {
        Ok(parts) => parts,
        Err(message) => return error(id, -32602, &message),
    };

    // The caller's own token rides along and nothing else: the façade holds no identity of
    // its own, and the handler authenticates the caller again from that token (EP-26).
    let answer = ngsi_ld_request(
        Arc::clone(&gateway),
        &endpoint,
        method,
        &path,
        &query,
        body,
        authorization,
    )
    .await;

    let status = answer.status();
    // What this endpoint federates, by registration name: the answer is a union over these,
    // and a model reading it has no other way to know that (EP-71, AG-30).
    let members: Vec<String> = gateway
        .members_of(&endpoint.project, &endpoint.space)
        .into_iter()
        .map(|member| member.name)
        .collect();
    // The handler sets this whenever it narrowed, and it is read here rather than from the
    // wire: the response layer removes it again from the answer a caller who did not ask
    // sees, and a tool result has no request header to ask with (AG-13, R22).
    let restricted = answer
        .headers()
        .contains_key(&crate::middleware::response::RESULTS_RESTRICTED);
    let payload = axum::body::to_bytes(answer.into_body(), 8 * 1024 * 1024)
        .await
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .unwrap_or(Value::Null);

    // A refusal is a tool error the agent can read, never an empty result it would mistake
    // for "there is nothing there" (SP-17, MIM0-R8).
    match status.is_success() {
        true => result(
            id,
            answered(&payload, tool.result_key, restricted, &members),
        ),
        false => result(id, refused(&refusal_text(status, &payload), &payload)),
    }
}

/// What this caller may attach to their context without calling a tool (EP-52, EP-60).
///
/// The entity types come from the same projection the schema surface uses, so a type the
/// caller may not read is not listed here either; an unlisted resource read by name
/// answers exactly as an unknown one does (SP-20).
fn resources(endpoint: &Endpoint, subject: &Subject) -> Value {
    let visible = schema::visible(subject, endpoint, crate::pdp::now());
    let mut listed: Vec<Value> = schema::visible_types(endpoint, &visible)
        .into_iter()
        .map(|entity_type| {
            json!({
                "uri": format!("ngsi-ld://{}/types/{}", endpoint.space, entity_type),
                "name": entity_type,
                "description": "The entities of this type, as the caller may read them.",
                "mimeType": "application/json",
            })
        })
        .collect();

    listed.push(json!({
        "uri": format!("access://{}", endpoint.slug),
        "name": "access",
        "description": "The caller's effective grants on this endpoint.",
        "mimeType": "application/json",
    }));

    for model in &endpoint.models {
        for artifact in ["json-schema", "context"] {
            listed.push(json!({
                "uri": format!("schema://{}/v{}/{}", endpoint.slug, model.major, artifact),
                "name": format!("{} v{} {}", model.name, model.major, artifact),
                "description": "A rendered schema artifact of this space's data model.",
                "mimeType": "application/json",
            }));
        }
    }

    json!({ "resources": listed })
}

/// Reads one resource, through the same enforcement path a tool call takes (EP-26).
async fn read_resource(
    gateway: Arc<Gateway>,
    endpoint: Arc<Endpoint>,
    subject: Subject,
    authorization: Option<HeaderValue>,
    id: Value,
    params: &Value,
) -> Value {
    let uri = params.get("uri").and_then(Value::as_str).unwrap_or("");

    // Two of the four are answered from the projections the access and schema surfaces
    // serve; the other two are ordinary NGSI-LD reads.
    let arguments: Map<String, Value> = Map::new();
    let (tool, call): (&str, Map<String, Value>) = match parse_resource(&endpoint, uri) {
        Some(Resource::Access(format)) => {
            let document = access_document(&gateway, &subject, &endpoint, &format);
            return result(id, contents(uri, &document));
        }
        Some(Resource::Schema { major, format }) => {
            let mut asked = arguments;
            asked.insert("format".to_owned(), Value::String(format));
            asked.insert("version".to_owned(), Value::from(major));
            return match describe_schema(&endpoint, &subject, &asked) {
                Ok(document) => result(id, contents(uri, &document)),
                Err(message) => result(id, refused(&message, &Value::Null)),
            };
        }
        Some(Resource::Type(entity_type)) => {
            let mut asked = arguments;
            asked.insert("type".to_owned(), Value::String(entity_type));
            ("query_entities", asked)
        }
        Some(Resource::Entity(entity)) => {
            let mut asked = arguments;
            asked.insert("id".to_owned(), Value::String(entity));
            ("get_entity", asked)
        }
        // A URI this server does not serve, and a space that is not this one, answer the
        // same way: the caller learns nothing about what exists elsewhere (SP-20, R20).
        None => return error(id, -32602, "unknown resource"),
    };

    let Some((index, definition)) = TOOLS.iter().enumerate().find(|(_, t)| t.name == tool) else {
        return error(id, -32602, "unknown resource");
    };
    if !granted(&gateway, &endpoint, &subject, definition.operations) {
        return error(id, -32602, "unknown resource");
    }
    if let Err(problem) = validate(index, &call) {
        return result(id, refused(&problem, &Value::Null));
    }
    let (method, path, query, body) = match request_for(tool, &call) {
        Ok(parts) => parts,
        Err(message) => return error(id, -32602, &message),
    };

    let answer = ngsi_ld_request(
        Arc::clone(&gateway),
        &endpoint,
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

    match status.is_success() {
        true => result(id, contents(uri, &payload)),
        false => result(id, refused(&refusal_text(status, &payload), &payload)),
    }
}

/// The four resource shapes this server serves.
enum Resource {
    /// `ngsi-ld://{space}/types/{type}`
    Type(String),
    /// `ngsi-ld://{space}/entities/{id}`
    Entity(String),
    /// `access://{endpointSlug}`, optionally `?format=odrl|grant-ast|permissions`
    Access(String),
    /// `schema://{endpointSlug}/v{major}/{artifact}`
    Schema { major: u64, format: String },
}

/// Names the resource a URI addresses, or `None` when this endpoint does not serve it.
///
/// The space and the slug in the URI have to be this endpoint's own: a URI naming another
/// space is not a way to read one (AG-05, SP-14).
fn parse_resource(endpoint: &Endpoint, uri: &str) -> Option<Resource> {
    if let Some(rest) = uri.strip_prefix("ngsi-ld://") {
        let (space, path) = rest.split_once('/')?;
        if space != endpoint.space {
            return None;
        }
        return match path.split_once('/')? {
            ("types", entity_type) if !entity_type.is_empty() => {
                Some(Resource::Type(entity_type.to_owned()))
            }
            ("entities", entity) if !entity.is_empty() => Some(Resource::Entity(entity.to_owned())),
            _ => None,
        };
    }
    if let Some(rest) = uri.strip_prefix("access://") {
        let (slug, format) = match rest.split_once("?format=") {
            Some((slug, format)) => (slug, format),
            None => (rest, "permissions"),
        };
        return (slug == endpoint.slug && ACCESS_FORMATS.contains(&format))
            .then(|| Resource::Access(format.to_owned()));
    }
    if let Some(rest) = uri.strip_prefix("schema://") {
        let (slug, path) = rest.split_once('/')?;
        if slug != endpoint.slug {
            return None;
        }
        let (version, artifact) = path.split_once('/')?;
        let major = version.strip_prefix('v')?.parse().ok()?;
        return matches!(artifact, "json-schema" | "context").then(|| Resource::Schema {
            major,
            format: artifact.to_owned(),
        });
    }
    None
}

/// The words `describe_access` and the `access://` resource answer in (EP-56, EP-57, EP-58).
const ACCESS_FORMATS: [&str; 3] = ["permissions", "odrl", "grant-ast"];

/// The caller's grants in one of [`ACCESS_FORMATS`], computed by the very functions the HTTP
/// access surface uses, so MCP and HTTP answer the same document (EP-60, T-0425).
fn access_document(
    gateway: &Gateway,
    subject: &Subject,
    endpoint: &Endpoint,
    format: &str,
) -> Value {
    let now = crate::pdp::now();
    match format {
        "odrl" => crate::handlers::access_odrl::policy(
            subject,
            endpoint,
            now,
            gateway.base_url(),
            crate::app::sha256_hex,
        ),
        "grant-ast" => crate::handlers::access_ucast::grant_ast(subject, endpoint, now),
        _ => access::permissions(subject, endpoint, now),
    }
}

/// One resource, in the envelope `resources/read` answers with.
fn contents(uri: &str, payload: &Value) -> Value {
    json!({
        "contents": [{
            "uri": uri,
            "mimeType": "application/json",
            "text": serde_json::to_string(payload).unwrap_or_else(|_| "null".to_owned()),
        }],
    })
}

/// A tool result an agent can both read and parse.
///
/// The structured half is an object matching the tool's output schema, never the broker's
/// bare list: a client that reads `structuredContent` by name reads nothing from a list, and
/// MCP defines the field as an object (T-0946). `restricted` says that the policy removed
/// something, never what (AG-13, R20); unlike the REST header it is not asked for, because a
/// tool result is read by a model, which has no request header to ask with.
fn answered(payload: &Value, result_key: &str, restricted: bool, sources: &[String]) -> Value {
    let mut structured = Map::new();
    structured.insert(result_key.to_owned(), payload.clone());
    if restricted {
        structured.insert("restricted".to_owned(), Value::Bool(true));
    }
    // EP-71: a tool answer is read by a model, which has no other way to attribute it. What
    // the platform can say truthfully is which registrations this answer is a union over,
    // by name and never by address; the broker merges without marking each entity, so this
    // is the answer's provenance and not one entity's.
    if !sources.is_empty() {
        structured.insert("jc:source".to_owned(), json!(sources));
    }
    let structured = Value::Object(structured);
    json!({
        "isError": false,
        "content": [{
            "type": "text",
            "text": serde_json::to_string(payload).unwrap_or_else(|_| "null".to_owned()),
        }],
        "structuredContent": structured,
    })
}

/// A tool error: what was refused, in the agent's own channel for it.
///
/// The problem document rides along when there is one; nothing does when the refusal is the
/// gateway's own words, because `structuredContent` is an object or it is absent.
fn refused(text: &str, payload: &Value) -> Value {
    let mut result = json!({
        "isError": true,
        "content": [{ "type": "text", "text": text }],
    });
    if let Value::Object(document) = payload {
        result["structuredContent"] = Value::Object(document.clone());
    }
    result
}

/// What a tool's `structuredContent` looks like, published beside its input schema so a
/// client can validate the half it parses (MCP `outputSchema`).
///
/// The payload's own shape is the data model's, not MCP's — a schema here would be a second
/// copy of it that drifts — so the output schema names what the object carries and leaves the
/// value to `describe_schema`.
fn output_schema(tool: &Tool) -> Value {
    json!({
        "type": "object",
        "properties": {
            tool.result_key: { "description": tool.description },
            "restricted": {
                "type": "boolean",
                "description": "Present when the policy narrowed this answer (AG-13, R22)",
            },
            "jc:source": {
                "type": "array",
                "items": { "type": "string" },
                "description": "The registrations this answer is a union over, by name (EP-71)",
            },
        },
        "required": [tool.result_key],
    })
}

/// The artifact one `format` name renders, for the five formalisms that are text rather than
/// JSON. The REST route names them by file name or path segment; here the name is the format.
fn text_formalism(format: &str) -> Option<schema::Artifact> {
    match format {
        "linkml" => Some(schema::Artifact::LinkMl),
        "shacl" => Some(schema::Artifact::Shacl),
        "owl" => Some(schema::Artifact::Owl),
        "rdf" => Some(schema::Artifact::Rdf),
        "markdown" => Some(schema::Artifact::Markdown),
        _ => None,
    }
}

/// The data model, in the formalism asked for and narrowed to the caller's grant (EP-47).
///
/// Every formalism the REST schema surface renders is rendered here from the same projected
/// JSON Schema, so an agent reads exactly what a browser reads for the same token (EP-46,
/// EP-52, T-0845); the text ones come back as `{format, mediaType, document}`.
fn describe_schema(
    endpoint: &Endpoint,
    subject: &Subject,
    arguments: &Map<String, Value>,
) -> Result<Value, String> {
    let mut visible = schema::visible(subject, endpoint, crate::pdp::now());
    if let Some(wanted) = arguments.get("entityType").and_then(Value::as_str) {
        visible = visible.only(wanted).ok_or_else(|| {
            format!("`{wanted}` is not an entity type this endpoint describes for you")
        })?;
    }
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
        // The five text formalisms, rendered from the projected schema the way the REST route
        // renders them; `Accept` plays no part here, the name of the format decides.
        other => match text_formalism(other) {
            Some(artifact) => Ok(json!({
                "format": other,
                "mediaType": artifact.media_type(),
                "document": schema::render(&models, artifact, &visible),
            })),
            None => Err(format!(
                "`{other}` is not a formalism this endpoint renders: it serves summary, \
                 json-schema, context, linkml, shacl, owl, rdf and markdown"
            )),
        },
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
            for key in ["q", "scopeQ", "georel", "geometry", "coordinates"] {
                if let Some(value) = text(key) {
                    add(key, &value);
                }
            }
            if let Some(attrs) = list("attrs") {
                add("attrs", &attrs);
            }
            for (key, wire) in [("limit", "limit"), ("cursor", "offset")] {
                if let Some(number) = arguments.get(key).and_then(Value::as_u64) {
                    add(wire, &number.to_string());
                }
            }
            Ok((Method::GET, "/entities".to_owned(), query.join("&"), None))
        }
        "list_types" | "list_attributes" => {
            if arguments.get("details") == Some(&Value::Bool(true)) {
                add("details", "true");
            }
            let path = match tool {
                "list_types" => "/types",
                _ => "/attributes",
            };
            Ok((Method::GET, path.to_owned(), query.join("&"), None))
        }
        "list_subscriptions" => {
            if let Some(limit) = arguments.get("limit").and_then(Value::as_u64) {
                add("limit", &limit.to_string());
            }
            Ok((
                Method::GET,
                "/subscriptions".to_owned(),
                query.join("&"),
                None,
            ))
        }
        "create_subscription" => {
            let subscription = arguments
                .get("subscription")
                .ok_or("`subscription` is required")?;
            let body = serde_json::to_vec(subscription)
                .map_err(|_| "`subscription` is not JSON".to_owned())?;
            Ok((
                Method::POST,
                "/subscriptions".to_owned(),
                String::new(),
                Some(body),
            ))
        }
        "batch_query" => {
            // CIM 009 clause 5.6.9: the selector travels in the body, the paging in the
            // query string. Ids and a type are both selectors, and either alone is enough.
            let mut selector = Map::new();
            let entities: Vec<Value> = match arguments.get("ids").and_then(Value::as_array) {
                Some(ids) => ids
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|entity| json!({ "id": entity }))
                    .collect(),
                None => vec![json!({ "type": text("type").ok_or("`ids` or `type` is required")? })],
            };
            if entities.is_empty() {
                return Err("`ids` must name at least one entity".to_owned());
            }
            selector.insert("entities".to_owned(), Value::Array(entities));
            if let Some(filter) = text("q") {
                selector.insert("q".to_owned(), Value::String(filter));
            }
            if let Some(attrs) = arguments.get("attrs").cloned() {
                selector.insert("attrs".to_owned(), attrs);
            }
            if let Some(limit) = arguments.get("limit").and_then(Value::as_u64) {
                add("limit", &limit.to_string());
            }
            let body = serde_json::to_vec(&Value::Object(selector))
                .map_err(|_| "the batch query does not serialize".to_owned())?;
            Ok((
                Method::POST,
                "/entityOperations/query".to_owned(),
                query.join("&"),
                Some(body),
            ))
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
        "query_temporal" | "retrieve_temporal" => {
            // AG-30: the temporal grammar is forwarded as written, so history is neither a
            // second query language nor a second authorization path.
            for key in ["timerel", "timeAt"] {
                add(key, &text(key).ok_or(format!("`{key}` is required"))?);
            }
            for key in [
                "endTimeAt",
                "timeproperty",
                "type",
                "q",
                "aggrPeriodDuration",
            ] {
                if let Some(value) = text(key) {
                    add(key, &value);
                }
            }
            for key in ["attrs", "aggrMethods"] {
                if let Some(values) = list(key) {
                    add(key, &values);
                }
            }
            for key in ["lastN", "limit"] {
                if let Some(number) = arguments.get(key).and_then(Value::as_u64) {
                    add(key, &number.to_string());
                }
            }
            // The two tools are the two CIM 009 operations, so the path is decided by
            // which tool was called and never by whether an argument happens to be there.
            let path = match tool {
                "retrieve_temporal" => format!(
                    "/temporal/entities/{}",
                    percent_encode(&text("id").ok_or("`id` is required")?)
                ),
                _ => "/temporal/entities".to_owned(),
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

#[cfg(test)]
mod tests {
    use super::{Tool, TOOLS};
    use jc_core::kinds::Operation;

    /// T-1066, AG-07, AG-08: `read_only` decides whether a person is asked before the call
    /// proceeds, so it is derived from the operations rather than set beside them. The two
    /// writing tools and every reading one are named here, because a tool added on the wrong
    /// side of this line is a write nobody confirms.
    #[test]
    fn a_tool_that_writes_at_all_is_not_read_only() {
        let writing: Vec<&str> = TOOLS
            .iter()
            .filter(|tool| !tool.read_only())
            .map(|tool| tool.name)
            .collect();
        assert_eq!(writing, vec!["upsert_entity", "create_subscription"]);

        for tool in TOOLS {
            let writes = tool.operations.iter().any(Operation::is_write);
            assert_eq!(
                tool.read_only(),
                !writes,
                "{} is on the wrong side of the elicitation gate",
                tool.name
            );
        }
    }

    /// A tool that stands for no operation describes the endpoint rather than its data, and
    /// describing is reading (EP-55).
    #[test]
    fn a_tool_with_no_operation_of_its_own_reads() {
        for tool in TOOLS.iter().filter(|tool| tool.operations.is_empty()) {
            assert!(tool.read_only(), "{}", tool.name);
        }
    }

    /// The rule the task proposed — read-only when *any* operation reads — would have let a
    /// mixed tool through the gate. This is the case that tells the two rules apart.
    #[test]
    fn a_tool_that_both_reads_and_writes_is_not_read_only() {
        let mixed = Tool {
            name: "read_and_write",
            operations: &[Operation::QueryEntity, Operation::UpsertBatch],
            description: "",
            schema: || serde_json::json!({}),
            result_key: "entities",
        };
        assert!(!mixed.read_only());
    }
}
