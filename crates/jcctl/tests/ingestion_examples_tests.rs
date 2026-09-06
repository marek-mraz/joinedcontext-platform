//! The shipped ingestion examples, checked against the code that has to run them
//! (T-0294…T-0297, PL-01, PL-03, PL-22, PL-26, PL-27, PL-39, MF-35, CC-06).
//!
//! `bento test` proves the transformations; these tests prove the half Bento cannot see. An
//! example is documentation people copy, so a manifest that no longer parses, a reference that
//! points at nothing, a cadence that would land in the wrong runtime or a credential written
//! as a value is a defect in the same sense as a broken function.

use std::fs;
use std::path::{Path, PathBuf};

use jc_core::envelope::ResourceEnvelope;
use jc_core::kinds::{DataSourceSpec, DataSourceType, Pipeline};
use jcctl::bento::{render, InputContext};
use jcctl::pipelines::{runtime_of, Runtime};

/// Every example folder, and the connection type it is there to demonstrate.
const EXAMPLES: [(&str, DataSourceType); 4] = [
    ("hsl-hfp-mqtt", DataSourceType::Mqtt),
    ("http-json-poll", DataSourceType::Http),
    ("csv-fetch", DataSourceType::Http),
    ("gtfs-rt", DataSourceType::GtfsRt),
];

fn examples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/ingestion")
}

fn read(example: &str, file: &str) -> String {
    let path = examples_dir().join(example).join(file);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn data_source(example: &str) -> ResourceEnvelope<DataSourceSpec> {
    let parsed = ResourceEnvelope::<DataSourceSpec>::from_yaml(&read(example, "datasource.yaml"))
        .unwrap_or_else(|e| panic!("{example}/datasource.yaml: {e}"));
    parsed
        .validate()
        .unwrap_or_else(|e| panic!("{example}/datasource.yaml: {e}"));
    parsed
}

fn pipeline(example: &str) -> Pipeline {
    let parsed = Pipeline::from_yaml(&read(example, "pipeline.yaml"))
        .unwrap_or_else(|e| panic!("{example}/pipeline.yaml: {e}"));
    parsed
        .validate()
        .unwrap_or_else(|e| panic!("{example}/pipeline.yaml: {e}"));
    parsed
}

/// MF-35, PL-39: both manifests parse, validate and agree with each other.
#[test]
fn every_example_is_a_valid_pair_of_manifests() {
    for (example, expected_type) in EXAMPLES {
        let source = data_source(example);
        assert_eq!(
            source.spec.source_type, expected_type,
            "{example} demonstrates a different connection than it claims"
        );

        let pipeline = pipeline(example);
        let reference = pipeline
            .spec
            .source
            .as_ref()
            .and_then(|source| source.data_source_ref.as_ref())
            .unwrap_or_else(|| panic!("{example}: the pipeline references no DataSource"));
        assert_eq!(
            reference.name(),
            source.metadata.name,
            "{example}: the reference names a source that is not in this folder"
        );
        assert_eq!(reference.kind(), Some("DataSource"), "{example}");
        assert_eq!(
            pipeline.metadata.namespace, source.metadata.namespace,
            "{example}: a pipeline resolves its source inside its own project"
        );
    }
}

/// PL-26, PL-27: the cadence each example declares is the one the reader is told it has.
#[test]
fn each_example_lands_in_the_runtime_its_comment_promises() {
    // Push-based: no period at all, so the thirty-second rule leaves it resident.
    assert_eq!(
        runtime_of(&pipeline("hsl-hfp-mqtt").spec),
        Runtime::Resident
    );
    // Fifteen seconds is inside the rule.
    assert_eq!(runtime_of(&pipeline("gtfs-rt").spec), Runtime::Resident);

    let Runtime::Scheduled(five_minutes) = runtime_of(&pipeline("http-json-poll").spec) else {
        panic!("five minutes is past the thirty-second rule");
    };
    assert_eq!(five_minutes.concurrency_policy, "Forbid");

    // PL-27, the one-minute cron floor: forty-five seconds runs every minute and fetches once.
    let Runtime::Scheduled(forty_five) = runtime_of(&pipeline("csv-fetch").spec) else {
        panic!("forty-five seconds is past the thirty-second rule");
    };
    assert_eq!(forty_five.schedule, "* * * * *");
    assert_eq!(forty_five.interval.as_deref(), Some("45s"));
    assert_eq!(forty_five.count, 1);
}

/// PL-39: the rendered config is the author's file with the connection's input in front of it.
#[test]
fn every_example_renders_the_input_the_reader_never_wrote() {
    for (example, _) in EXAMPLES {
        let source = data_source(example);
        let authored = read(example, "bento.yaml");
        assert!(
            !authored.contains("\ninput:"),
            "{example}: the input is the reconciler's, not the author's"
        );

        let pipeline = pipeline(example);
        let context = InputContext {
            source: &source.metadata.name,
            project: pipeline.metadata.namespace.as_deref().unwrap_or_default(),
            pipeline: &pipeline.metadata.name,
        };
        let rendered =
            render(&authored, &source.spec, &context).unwrap_or_else(|e| panic!("{example}: {e}"));
        assert!(rendered.starts_with("input:"), "{example}:\n{rendered}");

        let expected_input = match source.spec.source_type {
            DataSourceType::Mqtt => "  mqtt:",
            DataSourceType::WebSocket => "  websocket:",
            DataSourceType::Http | DataSourceType::GtfsRt => "  http_client:",
        };
        assert!(
            rendered.contains(expected_input),
            "{example} did not render {expected_input}:\n{rendered}"
        );
    }
}

/// The GTFS-realtime decoder the example's `tests/decoder.yaml` mirrors is the one the
/// reconciler actually prepends; the copy in the folder exists only so the test can run
/// without the runner image.
#[test]
fn the_gtfs_example_mirrors_the_decoder_the_reconciler_prepends() {
    let source = data_source("gtfs-rt");
    let pipeline = pipeline("gtfs-rt");
    let rendered = render(
        &read("gtfs-rt", "bento.yaml"),
        &source.spec,
        &InputContext {
            source: &source.metadata.name,
            project: pipeline.metadata.namespace.as_deref().unwrap_or_default(),
            pipeline: &pipeline.metadata.name,
        },
    )
    .expect("renders");

    let config: serde_norway::Value = serde_norway::from_str(&rendered).expect("parses");
    let first = config
        .get("pipeline")
        .and_then(|p| p.get("processors"))
        .and_then(|p| p.as_sequence())
        .and_then(|p| p.first())
        .and_then(|p| p.get("protobuf"))
        .expect("the decoder runs first");
    assert_eq!(
        first.get("message").and_then(|m| m.as_str()),
        Some("transit_realtime.FeedMessage")
    );

    let mirror = read("gtfs-rt", "tests/decoder.yaml");
    assert!(
        mirror.contains("transit_realtime.FeedMessage") && mirror.contains("to_json"),
        "tests/decoder.yaml no longer mirrors the rendered decoder"
    );
    assert!(
        read("gtfs-rt", "proto/gtfs-realtime.proto").contains("package transit_realtime;"),
        "the vendored descriptors are what the decoder names"
    );
}

/// CC-06, PL-16: a credential appears in an example as a reference and in the rendered config
/// as an interpolation. Never as a value, not even a placeholder one somebody might copy.
#[test]
fn no_example_carries_a_credential() {
    for (example, _) in EXAMPLES {
        let source = data_source(example);
        let pipeline = pipeline(example);
        let rendered = render(
            &read(example, "bento.yaml"),
            &source.spec,
            &InputContext {
                source: &source.metadata.name,
                project: pipeline.metadata.namespace.as_deref().unwrap_or_default(),
                pipeline: &pipeline.metadata.name,
            },
        )
        .expect("renders");

        for (file, text) in [
            ("datasource.yaml", read(example, "datasource.yaml")),
            ("pipeline.yaml", read(example, "pipeline.yaml")),
            ("bento.yaml", read(example, "bento.yaml")),
            ("<rendered>", rendered),
        ] {
            for line in text.lines() {
                let lower = line.to_ascii_lowercase();
                let names_a_credential = ["password", "token", "secret", "authorization"]
                    .iter()
                    .any(|needle| lower.contains(needle));
                if !names_a_credential {
                    continue;
                }
                let value = line.split_once(':').map(|(_, v)| v.trim()).unwrap_or("");
                let is_reference = value.is_empty()
                    || value.starts_with('{')
                    || value.starts_with("Bearer ${")
                    || value.starts_with("${")
                    || lower.contains("ref:")
                    || line.trim_start().starts_with('#');
                assert!(
                    is_reference,
                    "{example}/{file} writes a credential as a value: {line}"
                );
            }
        }
    }
}
