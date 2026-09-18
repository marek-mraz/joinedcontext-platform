pub mod body;
pub mod data;
pub mod diagnostics;
pub mod events;
pub mod fetch;
pub mod forge;
pub mod inbox;
pub mod llm;
pub mod mcp;
pub mod packages;

/// Whether a path a workspace sends would leave the base it is appended to once the outbound URL
/// is parsed. axum has decoded the path once; the URL parser follows WHATWG, which reads `%2e%2e`
/// as a `..` segment and a backslash as a slash in an http(s) URL, so nothing still encoded, no
/// backslash, no dot segment and no empty segment gets through (T-0817, T-1300, T-1301). A
/// trailing slash, a directory listing, stays allowed.
pub(crate) fn escapes(path: &str) -> bool {
    path.contains('%')
        || path.contains('\\')
        || path.starts_with('/')
        || path.contains("//")
        || path.split('/').any(|segment| matches!(segment, "." | ".."))
}

#[cfg(test)]
mod tests {
    use super::escapes;

    #[test]
    fn a_path_that_would_leave_its_base_is_refused_and_an_ordinary_one_is_not() {
        for path in [
            "..",
            "../admin",
            "ngsi-ld/v1/../../x",
            "%2e%2e/x",
            "%252e%252e/x",
            "a/%2Fb",
            "a\\..\\b",
            "/etc/passwd",
            "a//b",
            "./x",
        ] {
            assert!(escapes(path), "{path}");
        }
        for path in [
            "ngsi-ld/v1/entities",
            "ngsi-ld/v1/entities/urn:ngsi-ld:Bike:hel.fi:helsinki:a..b",
            "mcp",
            "api/v1/crates/serde/1.0.0/download",
            "projects/helsinki/apps/bikes/",
            "",
        ] {
            assert!(!escapes(path), "{path}");
        }
    }
}
