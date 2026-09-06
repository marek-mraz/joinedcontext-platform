mod common;

use common::*;
use jcctl::apisix::{render, Settings, END_MARKER};
use serde_json::Value;

fn settings() -> Settings {
    Settings::new("city.example.com", "prod", "prod")
}

fn rendered(dir: &std::path::Path) -> String {
    render(&load(dir), &settings())
}

fn parsed(yaml: &str) -> Value {
    serde_norway::from_str(yaml).expect("the rendered configuration is valid YAML")
}

const SERVICE_APP: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: App
metadata:
  name: air-quality-today
  namespace: ovzdusie
spec:
  kind: service
  source:
    path: apps/air-quality-today
  build: {}
  visibility: internal
"#;

const STATIC_APP: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: App
metadata:
  name: air-quality-map
  namespace: ovzdusie
spec:
  kind: static
  source:
    path: apps/air-quality-map
  build: {}
  visibility: public
"#;

/// Without the terminal marker APISIX commits nothing and keeps serving the previous
/// routing table, silently (stack verdict S7).
#[test]
fn the_last_line_is_the_literal_end_marker() {
    let dir = demo_repo("apisix-end");
    let config = rendered(&dir);

    assert!(config.ends_with("\n#END\n"), "{config}");
    assert_eq!(
        config.lines().last(),
        Some(END_MARKER),
        "the marker must be the final line"
    );
    assert_eq!(
        config.matches("\n#END").count(),
        1,
        "exactly one marker, at the end"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// APISIX refuses the whole file if it does not parse, so the renderer's output has to be
/// YAML even with the Lua header-stripping function inside it.
#[test]
fn the_rendered_configuration_is_valid_yaml_with_the_documented_sections() {
    let dir = demo_repo("apisix-yaml");
    let config = rendered(&dir);
    let document = parsed(config.trim_end_matches("#END\n"));

    for section in ["routes", "upstreams", "plugin_configs"] {
        assert!(
            document[section].is_array(),
            "{section} is missing from the rendered configuration"
        );
    }

    let gateway = document["upstreams"]
        .as_array()
        .expect("upstreams")
        .iter()
        .find(|u| u["id"] == "upstream-context-gateway")
        .expect("the gateway upstream");
    assert!(gateway["nodes"]["context-gateway.prod.svc.cluster.local:8080"] == 1);
    assert_eq!(gateway["timeout"]["read"], 300);

    let _ = std::fs::remove_dir_all(&dir);
}

/// The endpoint surface must sit above the context space surface, and both above the
/// catch-all that serves the Portal UI (Deployment/10 section 3).
#[test]
fn route_priorities_put_the_specific_surfaces_above_the_catch_all() {
    let dir = demo_repo("apisix-priority");
    let document = parsed(rendered(&dir).trim_end_matches("#END\n"));
    let routes = document["routes"].as_array().expect("routes").clone();

    let priority = |id: &str| {
        routes
            .iter()
            .find(|r| r["id"] == id)
            .unwrap_or_else(|| panic!("route {id}"))["priority"]
            .as_u64()
            .expect("a numeric priority")
    };

    assert_eq!(priority("portal-ui"), 1);
    assert!(priority("context-space") > priority("portal-api"));
    assert!(priority("context-endpoint") > priority("context-space"));
    assert!(priority("apps-surface") > priority("context-endpoint"));

    let endpoint = routes
        .iter()
        .find(|r| r["id"] == "context-endpoint")
        .expect("the endpoint route");
    assert_eq!(endpoint["uri"], "/api/endpoint/*");
    assert_eq!(endpoint["upstream_id"], "upstream-context-gateway");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A `service` app is routed to its own oauth2-proxy sidecar; a `static` app is served
/// from the Portal's shared surface and gets no route of its own (AP-26).
#[test]
fn only_service_and_fullstack_apps_get_their_own_route() {
    let dir = demo_repo("apisix-apps");
    write(
        &dir,
        "projects/ovzdusie/apps/air-quality-today/app.yaml",
        SERVICE_APP,
    );
    write(
        &dir,
        "projects/ovzdusie/apps/air-quality-map/app.yaml",
        STATIC_APP,
    );

    let document = parsed(rendered(&dir).trim_end_matches("#END\n"));
    let routes = document["routes"].as_array().expect("routes");

    let app_route = routes
        .iter()
        .find(|r| r["id"] == "app-air-quality-today")
        .expect("the service app is routed");
    assert_eq!(app_route["uri"], "/apps/air-quality-today/*");
    assert!(
        app_route["priority"].as_u64()
            > routes
                .iter()
                .find(|r| r["id"] == "apps-surface")
                .expect("the shared surface")["priority"]
                .as_u64()
    );

    assert!(
        !routes.iter().any(|r| r["id"] == "app-air-quality-map"),
        "a static app is served from /apps/*, not its own route"
    );

    let sidecar = document["upstreams"]
        .as_array()
        .expect("upstreams")
        .iter()
        .find(|u| u["id"] == "upstream-app-air-quality-today")
        .expect("the app upstream");
    assert!(sidecar["nodes"]["app-air-quality-today.prod.svc.cluster.local:4180"] == 1);

    let _ = std::fs::remove_dir_all(&dir);
}

/// Every header a caller could use to forge a tenant or an authorization claim is cleared
/// before the request reaches the gateway (Deployment/10 section 4).
#[test]
fn the_context_surfaces_strip_every_forgeable_header() {
    let dir = demo_repo("apisix-headers");
    let document = parsed(rendered(&dir).trim_end_matches("#END\n"));
    let configs = document["plugin_configs"]
        .as_array()
        .expect("plugin_configs");

    for id in ["pc-context-firewall", "pc-endpoint-surface"] {
        let plugins = &configs
            .iter()
            .find(|c| c["id"] == id)
            .unwrap_or_else(|| panic!("{id}"))["plugins"];
        let lua = plugins["serverless-pre-function"]["functions"][0]
            .as_str()
            .expect("the stripping function");

        for header in [
            "NGSILD-Tenant",
            "X-Userinfo",
            "X-Access-Token",
            "X-Allowed-Scope-Ids",
            "X-Endpoint-Slug",
            "X-Consumer-Identity",
        ] {
            assert!(lua.contains(header), "{id} does not clear {header}");
        }
        assert_eq!(plugins["serverless-pre-function"]["phase"], "rewrite");
    }

    // The public surface lets an anonymous caller through to the gateway's own PEP; the
    // tenant surface never does.
    let firewall = configs
        .iter()
        .find(|c| c["id"] == "pc-context-firewall")
        .expect("firewall");
    let surface = configs
        .iter()
        .find(|c| c["id"] == "pc-endpoint-surface")
        .expect("surface");
    assert_eq!(firewall["plugins"]["openid-connect"]["bearer_only"], true);
    assert_eq!(surface["plugins"]["openid-connect"]["bearer_only"], false);
    assert_eq!(
        surface["plugins"]["openid-connect"]["unauth_action"],
        "pass"
    );
    assert_eq!(surface["plugins"]["openid-connect"]["ssl_verify"], true);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_same_repository_renders_byte_identical_output() {
    let dir = demo_repo("apisix-deterministic");
    write(
        &dir,
        "projects/ovzdusie/apps/air-quality-today/app.yaml",
        SERVICE_APP,
    );

    assert_eq!(rendered(&dir), rendered(&dir));

    let _ = std::fs::remove_dir_all(&dir);
}
