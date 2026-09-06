//! Manifest kind for the connection of one external feed (T-0290, MF-35, PL-39).
//!
//! A `DataSource` says where a feed is and how to authenticate to it, and stops there: no
//! mapping, no schedule, no target. It moves nothing on its own; a [`PipelineSpec`] references
//! one and the reconciler renders it into that pipeline's Bento input (Architecture/08 §6).
//!
//! Every credential is a [`SecretRef`]. That is not a convention here, it is the shape of the
//! type: there is no `password`, `token` or `apiKey` member anywhere below, so a plaintext
//! credential is a parse error rather than a review finding (CC-06, PL-14).
//!
//! [`PipelineSpec`]: crate::kinds::PipelineSpec

use crate::envelope::{Kind, ObjectMeta, Scope, SecretRef};
use crate::error::{Error, Result};
use crate::names;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Which kind of feed a [`DataSourceSpec`] connects to (MF-35).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum DataSourceType {
    /// An MQTT broker the runner subscribes to.
    Mqtt,
    /// An HTTP resource the runner polls.
    Http,
    /// A WebSocket the runner keeps open.
    // Spelled out rather than left to `kebab-case`, which would make it `web-socket`. The
    // documented wire value is one word (`Architecture/08 §6`) and the documentation is the
    // contract (CC-11), so the rename lives here and the other three variants are unaffected.
    // A plain comment, not a doc comment: this paragraph is about the code and would otherwise
    // be published as the variant's description in `schemas/kinds/DataSource.json`.
    #[serde(rename = "websocket")]
    WebSocket,
    /// A GTFS-realtime protobuf feed, polled over HTTP and decoded by the runner.
    GtfsRt,
}

impl DataSourceType {
    /// The wire name, as written in `spec.type`.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Mqtt => "mqtt",
            Self::Http => "http",
            Self::WebSocket => "websocket",
            Self::GtfsRt => "gtfs-rt",
        }
    }
}

impl fmt::Display for DataSourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// An MQTT connection (Architecture/08 §6).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MqttConnection {
    /// Broker URLs, `tcp://host:1883` or `tls://host:8883`; at least one.
    pub urls: Vec<String>,
    /// Topic filters to subscribe to; at least one.
    pub topics: Vec<String>,
    /// Quality of service, 0, 1 or 2. Absent leaves Bento's default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qos: Option<u8>,
    /// Whether the broker forgets the subscription between connections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clean_session: Option<bool>,
    /// The user the runner authenticates as; the password is a reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Where the password comes from (CC-06).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_ref: Option<SecretRef>,
}

/// An HTTP resource the runner polls (Architecture/08 §6).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HttpConnection {
    /// The URL to fetch, `http://` or `https://`.
    pub url: String,
    /// HTTP method, `GET` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verb: Option<String>,
    /// Static request headers. A header carrying a credential belongs in `authorization`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    /// The `Authorization` header, built from a secret (CC-06).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Authorization>,
    /// Request timeout as a Bento duration, `10s`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
}

/// A WebSocket the runner keeps open (Architecture/08 §6).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WebSocketConnection {
    /// The socket URL, `ws://` or `wss://`.
    pub url: String,
    /// A message sent once the socket opens, usually a subscription request.
    ///
    /// A socket that needs a credential authenticates inside this message: Bento's websocket
    /// input sends no `Authorization` header, and a field the renderer cannot honour would be
    /// a promise the runner breaks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_message: Option<String>,
}

/// A GTFS-realtime feed (Architecture/08 §6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GtfsRtConnection {
    /// The protobuf feed URL, `http://` or `https://`.
    pub url: String,
    /// Which of the three GTFS-realtime feeds this URL serves.
    pub feed: GtfsFeed,
}

/// The three feeds GTFS-realtime defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum GtfsFeed {
    /// Where the vehicles are.
    VehiclePositions,
    /// How the trips are running against the timetable.
    TripUpdates,
    /// Service alerts.
    Alerts,
}

impl GtfsFeed {
    /// The camelCase wire name, as written in `spec.gtfsRt.feed`.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::VehiclePositions => "vehiclePositions",
            Self::TripUpdates => "tripUpdates",
            Self::Alerts => "alerts",
        }
    }
}

/// An `Authorization` header whose value is assembled from a secret (CC-06).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Authorization {
    /// The scheme written before the secret, `Bearer` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    /// Where the credential comes from.
    pub header_ref: SecretRef,
}

/// How the runner trusts the feed's certificate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TlsSettings {
    /// Kept so a manifest can state the choice; only `false` is accepted (see [`DataSourceSpec::validate`]).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub insecure_skip_verify: bool,
    /// A private certificate authority the feed's certificate chains to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_cert_ref: Option<SecretRef>,
}

/// Desired state of a `DataSource`: one connection and its credentials (MF-35).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DataSourceSpec {
    /// Which connection block below is the live one.
    #[serde(rename = "type")]
    pub source_type: DataSourceType,
    /// The MQTT connection, present when `type` is `mqtt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mqtt: Option<MqttConnection>,
    /// The HTTP connection, present when `type` is `http`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpConnection>,
    /// The WebSocket connection, present when `type` is `websocket`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web_socket: Option<WebSocketConnection>,
    /// The GTFS-realtime connection, present when `type` is `gtfs-rt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gtfs_rt: Option<GtfsRtConnection>,
    /// Transport security for the connection above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsSettings>,
}

impl Kind for DataSourceSpec {
    const KIND: &'static str = "DataSource";
    const PLURAL: &'static str = "datasources";
    const SCOPE: Scope = Scope::Project;
    const PATH_TEMPLATE: &'static str = "projects/{project}/datasources/{name}.yaml";

    fn validate_spec(&self, meta: &ObjectMeta) -> Result<()> {
        names::validate_dns1123_label(&meta.name)?;
        self.validate()
    }
}

/// The URL schemes each connection type may reach, so a manifest cannot point an MQTT
/// subscription at a file or an HTTP poll at a broker.
const MQTT_SCHEMES: &[&str] = &["tcp://", "tls://", "ws://", "wss://"];
const HTTP_SCHEMES: &[&str] = &["http://", "https://"];
const WS_SCHEMES: &[&str] = &["ws://", "wss://"];

impl DataSourceSpec {
    /// Validates that exactly the declared connection is present and reachable as written.
    pub fn validate(&self) -> Result<()> {
        let present: Vec<&'static str> = [
            self.mqtt.is_some().then_some("mqtt"),
            self.http.is_some().then_some("http"),
            self.web_socket.is_some().then_some("webSocket"),
            self.gtfs_rt.is_some().then_some("gtfsRt"),
        ]
        .into_iter()
        .flatten()
        .collect();

        let expected = match self.source_type {
            DataSourceType::Mqtt => "mqtt",
            DataSourceType::Http => "http",
            DataSourceType::WebSocket => "webSocket",
            DataSourceType::GtfsRt => "gtfsRt",
        };
        if present != [expected] {
            return Err(Error::Name {
                field: "spec",
                value: present.join(", "),
                reason: "exactly the connection block named by `type` is present (MF-35)",
            });
        }

        if let Some(tls) = &self.tls {
            if tls.insecure_skip_verify {
                return Err(Error::Name {
                    field: "spec.tls.insecureSkipVerify",
                    value: "true".to_owned(),
                    reason: "a feed's certificate is always verified; use `caCertRef` for a private authority",
                });
            }
        }

        match self.source_type {
            DataSourceType::Mqtt => self.validate_mqtt(),
            DataSourceType::Http => {
                let http = self.http.as_ref().expect("checked above");
                url(&http.url, HTTP_SCHEMES, "spec.http.url")?;
                verb(http.verb.as_deref())
            }
            DataSourceType::WebSocket => url(
                &self.web_socket.as_ref().expect("checked above").url,
                WS_SCHEMES,
                "spec.webSocket.url",
            ),
            DataSourceType::GtfsRt => url(
                &self.gtfs_rt.as_ref().expect("checked above").url,
                HTTP_SCHEMES,
                "spec.gtfsRt.url",
            ),
        }
    }

    fn validate_mqtt(&self) -> Result<()> {
        let mqtt = self.mqtt.as_ref().expect("checked by the caller");
        if mqtt.urls.is_empty() {
            return Err(Error::Name {
                field: "spec.mqtt.urls",
                value: String::new(),
                reason: "an MQTT connection needs at least one broker URL",
            });
        }
        if mqtt.topics.is_empty() {
            return Err(Error::Name {
                field: "spec.mqtt.topics",
                value: String::new(),
                reason: "an MQTT connection needs at least one topic filter",
            });
        }
        for broker in &mqtt.urls {
            url(broker, MQTT_SCHEMES, "spec.mqtt.urls")?;
        }
        if let Some(qos) = mqtt.qos {
            if qos > 2 {
                return Err(Error::Name {
                    field: "spec.mqtt.qos",
                    value: qos.to_string(),
                    reason: "MQTT quality of service is 0, 1 or 2",
                });
            }
        }
        Ok(())
    }

    /// The connection's secret references, in the order the runner needs them injected.
    ///
    /// The reconciler resolves these and nothing else: a secret nobody references is never
    /// read, and a credential is never carried in the manifest itself (PL-15).
    pub fn secret_refs(&self) -> Vec<&SecretRef> {
        let credential = match self.source_type {
            DataSourceType::Mqtt => self.mqtt.as_ref().and_then(|m| m.password_ref.as_ref()),
            DataSourceType::Http => self
                .http
                .as_ref()
                .and_then(|h| h.authorization.as_ref())
                .map(|a| &a.header_ref),
            DataSourceType::WebSocket => None,
            DataSourceType::GtfsRt => None,
        };
        let mut refs: Vec<&SecretRef> = credential.into_iter().collect();
        refs.extend(self.tls.as_ref().and_then(|t| t.ca_cert_ref.as_ref()));
        refs
    }
}

/// The environment variable a secret reference is injected as (PL-15, PL-16).
///
/// `envVar` wins where the manifest states one, so a `bento.yaml` that already expects a name
/// keeps working; otherwise the name is derived from the source and the key and cannot collide
/// with another source's in the same runner.
pub fn env_var_of(source_name: &str, reference: &SecretRef) -> String {
    if let Some(explicit) = &reference.env_var {
        return explicit.clone();
    }
    let part = |s: &str| {
        s.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_uppercase()
                } else {
                    '_'
                }
            })
            .collect::<String>()
    };
    match &reference.key {
        Some(key) => format!("DS_{}_{}", part(source_name), part(key)),
        None => format!("DS_{}", part(source_name)),
    }
}

fn url(value: &str, schemes: &'static [&'static str], field: &'static str) -> Result<()> {
    if schemes.iter().any(|s| value.starts_with(s)) && value.len() > 8 {
        return Ok(());
    }
    Err(Error::Name {
        field,
        value: value.to_owned(),
        reason: "the URL scheme is not one this connection type speaks",
    })
}

fn verb(value: Option<&str>) -> Result<()> {
    match value {
        None | Some("GET") | Some("POST") => Ok(()),
        Some(other) => Err(Error::Name {
            field: "spec.http.verb",
            value: other.to_owned(),
            reason: "a polled feed is read with GET or POST",
        }),
    }
}
