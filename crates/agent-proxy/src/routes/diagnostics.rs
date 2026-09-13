//! The diagnostics door (AG-57): what a run may read about a resource of its own project when
//! a step failed, fetched by the Portal and redacted before the workspace sees it (AG-56).

use crate::audit::{log_request, AuditEntry};
use crate::auth::authenticate;
use crate::ProxyState;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use std::sync::LazyLock;
use std::time::Instant;

/// The components the door knows; anything else is refused before a request leaves the proxy.
const COMPONENTS: [&str; 2] = ["pipeline", "change"];

/// A resource name (DNS-1123) or a change id (`chg-` and eight hex digits).
fn is_name(id: &str) -> bool {
    let dns = id.len() <= 63
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !id.starts_with('-')
        && !id.ends_with('-');
    let change =
        id.len() == 12 && id.starts_with("chg-") && id[4..].bytes().all(|b| b.is_ascii_hexdigit());
    !id.is_empty() && (dns || change)
}

/// What a body must not carry to the workspace (AG-40, AG-56): a bearer, a token-shaped
/// header value, a named secret's value, the credentials of a connection URI, and a JWT.
static SECRETS: LazyLock<Vec<(regex::Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        (
            regex::Regex::new(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}").expect("a literal pattern"),
            "Bearer [REDACTED]",
        ),
        (
            regex::Regex::new(r#"(?i)\b(authorization|cookie|set-cookie)(\\?["']?\s*[:=]\s*\\?["']?)[^"'\r\n\\]+"#)
                .expect("a literal pattern"),
            "$1$2[REDACTED]",
        ),
        (
            regex::Regex::new(
                r#"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)(\\?["']?\s*[:=]\s*\\?["']?)[^"'\s,;&\\]+"#,
            )
            .expect("a literal pattern"),
            "$1$2[REDACTED]",
        ),
        (
            regex::Regex::new(r#"([a-z][a-z0-9+.-]*://[^\s/:@"']+:)[^\s@"']+@"#).expect("a literal pattern"),
            "$1[REDACTED]@",
        ),
        (
            regex::Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
                .expect("a literal pattern"),
            "[REDACTED]",
        ),
    ]
});

/// The text with every secret-shaped run replaced; the shape of the document stays.
pub fn redact(text: &str) -> String {
    SECRETS
        .iter()
        .fold(text.to_owned(), |acc, (pattern, replacement)| {
            pattern.replace_all(&acc, *replacement).into_owned()
        })
}

pub async fn handler(
    State(state): State<ProxyState>,
    headers: HeaderMap,
    Path((component, id)): Path<(String, String)>,
) -> Response {
    let start = Instant::now();
    let run = match authenticate(&headers, &state.runs, &state.config).await {
        Ok(r) => r,
        Err(p) => return (*p).into_response(),
    };

    if !COMPONENTS.contains(&component.as_str()) {
        return jc_core::ProblemDetails::new(
            400,
            "bad-request",
            format!("the diagnostics door knows no component '{component}'"),
        )
        .into_response();
    }
    if !is_name(&id) {
        return jc_core::ProblemDetails::new(
            400,
            "bad-request",
            "a diagnostics id is a resource name or a change id",
        )
        .into_response();
    }

    if let Err(msg) = state
        .limits
        .check_rpm(&run.id, run.requests_per_minute)
        .await
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            jc_core::ProblemDetails::new(429, "too-many-requests", msg),
        )
            .into_response();
    }

    let path = format!(
        "internal/agent-runs/{}/diagnostics/{component}/{id}",
        run.id
    );
    let mut url = state.config.portal_base.clone();
    url.set_path(&path);

    let resp = state
        .http
        .get(url)
        .bearer_auth(state.credentials.get_proxy_token())
        .send()
        .await;

    let (status, body) = match resp {
        Ok(r) => {
            let s = StatusCode::from_u16(r.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let text = r.text().await.unwrap_or_default();
            // The profile's response cap holds here as on every other door (AG-41).
            let cut = text
                .char_indices()
                .nth(run.max_response_bytes)
                .map_or(text.len(), |(i, _)| i);
            (s, redact(&text[..cut]))
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, redact(&e.to_string())),
    };

    log_request(&AuditEntry {
        run_id: &run.id,
        user: &run.created_by,
        upstream: "portal",
        method: "GET",
        path: &path,
        status: status.as_u16(),
        bytes: body.len(),
        duration_ms: start.elapsed().as_millis(),
    });

    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

#[cfg(test)]
mod tests {
    use super::{is_name, redact};

    #[test]
    fn names_and_change_ids_pass_and_paths_do_not() {
        for ok in ["hsl-bikes", "a", "chg-0000000a", "x9"] {
            assert!(is_name(ok), "{ok}");
        }
        for bad in [
            "",
            "../x",
            "a/b",
            "Hsl",
            "-a",
            "a-",
            "chg-xyz",
            "chg-0000000A0",
            "a b",
        ] {
            assert!(!is_name(bad), "{bad}");
        }
    }

    #[test]
    fn a_bearer_a_named_secret_a_uri_credential_and_a_jwt_are_redacted() {
        let body = concat!(
            r#"{"authorization":"Bearer abcdefghijklmnop.qrstuvwxyz","error":"connect postgresql://jc:s3cr3t-pw@db:5432/jc failed","#,
            r#""apiKey":"sk-live-0123456789","password": "hunter2","token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop", "received": 42}"#
        );
        let out = redact(body);
        assert!(!out.contains("abcdefghijklmnop.qrstuvwxyz"), "{out}");
        assert!(!out.contains("s3cr3t-pw"), "{out}");
        assert!(!out.contains("sk-live-0123456789"), "{out}");
        assert!(!out.contains("hunter2"), "{out}");
        assert!(!out.contains("eyJhbGciOiJIUzI1NiJ9"), "{out}");
        assert!(
            out.contains("postgresql://jc:[REDACTED]@db:5432/jc"),
            "{out}"
        );
        assert!(
            out.contains(r#""received": 42"#),
            "the shape of the document stays: {out}"
        );
    }

    #[test]
    fn plain_counters_pass_untouched() {
        let body = r#"{"pipeline":"hsl-bikes","received":1200,"sent":1190,"errors":10}"#;
        assert_eq!(redact(body), body);
    }
}
