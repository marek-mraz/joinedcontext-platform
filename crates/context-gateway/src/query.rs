//! The query string, in and out (T-0005, GW2, GW10, GW11).
//!
//! NGSI-LD spreads one geo query over three parameters and one temporal query over three
//! more, while a `Policy` writes each of them as a single string. This module is the
//! translation in both directions, plus the rule that decides which of the caller's own
//! parameters survive: a fixed allow list, so a parameter nobody thought about cannot
//! reach the broker unexamined.

use crate::pdp::evaluator::{Constraints, Request};
use std::collections::BTreeSet;

/// Parameters the caller controls and the gateway forwards unchanged: they shape the
/// answer without widening it.
const PASSTHROUGH: &[&str] = &[
    "aggrMethods",
    "aggrPeriodDuration",
    "containedBy",
    "count",
    "csf",
    "datasetId",
    "details",
    "entityMap",
    "format",
    "id",
    "idPattern",
    "join",
    "joinLevel",
    "lang",
    "lastN",
    "limit",
    "local",
    "offset",
    "omit",
    "options",
    "scopeQ",
    "pick",
    "timeproperty",
    "via",
];

/// The decoded `name=value` pairs of a query string, in the order they were sent.
pub fn parse(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((name, value)) => (decode(name), decode(value)),
            None => (decode(pair), String::new()),
        })
        .collect()
}

/// The first value of a parameter, if the caller sent one that is not empty.
pub fn first<'a>(params: &'a [(String, String)], name: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(key, value)| key == name && !value.is_empty())
        .map(|(_, value)| value.as_str())
}

/// What the caller asked for, in the dimensions a grant can narrow (GW11).
pub fn requested(params: &[(String, String)]) -> Request {
    Request {
        types: split_list(first(params, "type")),
        attrs: split_list(first(params, "attrs")),
        q: first(params, "q").map(str::to_owned),
        scope_q: first(params, "scopeQ").map(str::to_owned),
        geo_q: joined(params, &["georel", "geometry", "coordinates"]),
        temporal_q: joined(params, &["timerel", "timeAt", "endTimeAt"]),
    }
}

/// The query string of a write: the caller's harmless parameters and nothing else.
///
/// A write is bounded by the write guard, which reads the payload; narrowing parameters
/// would say nothing about what the body contains and only confuse the broker.
pub fn passthrough(params: &[(String, String)]) -> String {
    render(&kept(params))
}

/// The query string sent upstream: the caller's harmless parameters, plus the constraint
/// set, which replaces every dimension a grant can narrow (GW2).
pub fn upstream(params: &[(String, String)], constraints: &Constraints) -> String {
    let mut out = kept(params);

    if !constraints.types.is_empty() {
        out.push(("type".to_owned(), join_list(&constraints.types)));
    }
    if !constraints.attrs.is_empty() {
        out.push(("attrs".to_owned(), join_list(&constraints.attrs)));
    }
    // The grants' scopes are not a `scopeQ` any more: each policy carries its own, folded
    // into its own `q` term, so no expression can pair one policy's filter with another
    // policy's scope (R12, R13). The caller's own `scopeQ` rides through untouched and the
    // broker ANDs it, which can only narrow.
    if let Some(q) = &constraints.q {
        out.push(("q".to_owned(), q.clone()));
    }
    for compound in [&constraints.geo_q, &constraints.temporal_q]
        .into_iter()
        .flatten()
    {
        out.extend(split_compound(compound));
    }

    render(&out)
}

/// The caller's own parameters that survive, in the order they were sent.
fn kept(params: &[(String, String)]) -> Vec<(String, String)> {
    params
        .iter()
        .filter(|(name, _)| PASSTHROUGH.contains(&name.as_str()))
        .cloned()
        .collect()
}

fn render(params: &[(String, String)]) -> String {
    params
        .iter()
        .map(|(name, value)| format!("{}={}", encode(name), encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Rebuilds a `Policy`'s single-string form from the parameters that carry it on the wire.
fn joined(params: &[(String, String)], names: &[&str]) -> Option<String> {
    let parts: Vec<String> = names
        .iter()
        .filter_map(|name| first(params, name).map(|value| format!("{name}={value}")))
        .collect();
    (!parts.is_empty()).then(|| parts.join(";"))
}

/// The parameters a compound geo or temporal filter is made of, and the only names a `;`
/// may introduce inside one (CIM 009 clauses 4.10 and 4.11).
const COMPOUND_MEMBERS: &[&str] = &[
    "georel",
    "geometry",
    "coordinates",
    "geoproperty",
    "timerel",
    "timeAt",
    "endTimeAt",
    "timeproperty",
];

/// Splits a `Policy`'s single-string form back into the wire parameters.
///
/// A `;` separates parameters only when a parameter name follows it. `georel` carries its
/// own `;` inside its value — `near;maxDistance==2000` is one value, clause 4.10 — and
/// splitting on every `;` sent `maxDistance` upstream as a query parameter of its own,
/// which the broker rightly refused, so no `near` geoquery ever passed the gateway.
fn split_compound(compound: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = compound;
    while !rest.is_empty() {
        let end = rest
            .match_indices(';')
            .map(|(at, _)| at)
            .find(|&at| {
                let after = &rest[at + 1..];
                COMPOUND_MEMBERS.iter().any(|name| {
                    after
                        .strip_prefix(name)
                        .is_some_and(|tail| tail.starts_with('='))
                })
            })
            .unwrap_or(rest.len());
        if let Some((name, value)) = rest[..end].split_once('=') {
            out.push((name.trim().to_owned(), value.trim().to_owned()));
        }
        rest = rest.get(end + 1..).unwrap_or_default();
    }
    out
}

fn split_list(value: Option<&str>) -> BTreeSet<String> {
    value
        .into_iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

fn join_list(items: &BTreeSet<String>) -> String {
    items.iter().cloned().collect::<Vec<_>>().join(",")
}

/// Percent-encodes everything but the unreserved set of RFC 3986, which is always safe in
/// a query value and never needs a table of exceptions per parameter.
fn encode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Reverses the percent-encoding, and `+` for the form encoding some clients still send.
///
/// Public because the enforcement point has to decode the entity identifier out of the
/// request path before it can check which organization and space it belongs to.
pub fn decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                match u8::from_str_radix(&raw[i + 1..i + 3], 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    // Not an escape after all: a literal `%` is what the caller sent.
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_query_round_trips_through_encoding() {
        let raw = "q=pm10%3E%3D0&type=AirQualityObserved&limit=10";
        let params = parse(raw);
        assert_eq!(first(&params, "q"), Some("pm10>=0"));
        assert_eq!(first(&params, "limit"), Some("10"));
        assert_eq!(encode("pm10>=0"), "pm10%3E%3D0");
        assert_eq!(decode("100%25%20done"), "100% done");
        assert_eq!(decode("a%zz"), "a%zz", "a stray percent is not an escape");
    }

    #[test]
    fn the_three_geo_parameters_are_one_policy_string() {
        let params = parse("georel=within&geometry=Polygon&coordinates=%5B%5B0%2C0%5D%5D&limit=5");
        let request = requested(&params);
        assert_eq!(
            request.geo_q.as_deref(),
            Some("georel=within;geometry=Polygon;coordinates=[[0,0]]")
        );

        let constraints = Constraints {
            geo_q: request.geo_q.clone(),
            ..Constraints::default()
        };
        let upstream = parse(&upstream(&params, &constraints));
        assert_eq!(first(&upstream, "georel"), Some("within"));
        assert_eq!(first(&upstream, "geometry"), Some("Polygon"));
        assert_eq!(first(&upstream, "coordinates"), Some("[[0,0]]"));
        assert_eq!(
            first(&upstream, "limit"),
            Some("5"),
            "the caller's paging survives"
        );
    }

    /// GW2: the caller's own filters never reach the broker as they were sent; the
    /// constraint set replaces every dimension a grant can narrow.
    ///
    /// `scopeQ` is the exception and it is not a widening: the grants' scopes travel
    /// inside `q` now (R13), and the caller's own `scopeQ` is a filter the broker ANDs on
    /// top, which can only narrow.
    #[test]
    fn a_governed_parameter_is_replaced_and_an_unknown_one_is_dropped() {
        let params =
            parse("q=1%3D1&type=Secret&attrs=everything&scopeQ=%2Fgeo%2FSK&danger=drop%20table");
        let constraints = Constraints {
            types: BTreeSet::from(["AirQualityObserved".to_owned()]),
            attrs: BTreeSet::from(["pm10".to_owned()]),
            q: Some("(1=1);((pm10>=0))".to_owned()),
            granted_scopes: Some("/geo/SK/BB".to_owned()),
            ..Constraints::default()
        };
        let sent = parse(&upstream(&params, &constraints));

        assert_eq!(first(&sent, "type"), Some("AirQualityObserved"));
        assert_eq!(first(&sent, "attrs"), Some("pm10"));
        assert_eq!(first(&sent, "q"), Some("(1=1);((pm10>=0))"));
        assert_eq!(
            first(&sent, "scopeQ"),
            Some("/geo/SK"),
            "the caller's own scope filter rides through; the grants' are inside q"
        );
        assert_eq!(
            first(&sent, "danger"),
            None,
            "an unlisted parameter is dropped"
        );
    }

    /// T-0271, CIM 009 clause 4.10: `georel=near;maxDistance==2000` is one value with a `;`
    /// inside it. It has to leave as one `georel` parameter, or the broker refuses the
    /// `maxDistance` it was never meant to see and no `near` query passes the gateway.
    #[test]
    fn a_near_georel_keeps_its_distance_inside_the_value() {
        let params = parse(
            "georel=near%3BmaxDistance%3D%3D2000&geometry=Point&coordinates=%5B19.15%2C48.74%5D",
        );
        assert_eq!(
            requested(&params).geo_q.as_deref(),
            Some("georel=near;maxDistance==2000;geometry=Point;coordinates=[19.15,48.74]")
        );

        let constraints = Constraints {
            geo_q: requested(&params).geo_q,
            ..Constraints::default()
        };
        let sent = parse(&upstream(&params, &constraints));
        assert_eq!(first(&sent, "georel"), Some("near;maxDistance==2000"));
        assert_eq!(first(&sent, "geometry"), Some("Point"));
        assert_eq!(first(&sent, "coordinates"), Some("[19.15,48.74]"));
        assert_eq!(
            first(&sent, "maxDistance"),
            None,
            "the distance is part of georel, never a parameter of its own"
        );
        assert_eq!(sent.len(), 3);

        // The grant's form is the same string and splits the same way.
        assert_eq!(
            split_compound("georel=within;geometry=Polygon;coordinates=[[[0,0],[1,0],[1,1],[0,0]]];timerel=after;timeAt=P-1D"),
            vec![
                ("georel".to_owned(), "within".to_owned()),
                ("geometry".to_owned(), "Polygon".to_owned()),
                ("coordinates".to_owned(), "[[[0,0],[1,0],[1,1],[0,0]]]".to_owned()),
                ("timerel".to_owned(), "after".to_owned()),
                ("timeAt".to_owned(), "P-1D".to_owned()),
            ]
        );
    }
}
