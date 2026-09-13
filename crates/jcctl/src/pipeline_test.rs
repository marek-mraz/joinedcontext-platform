//! Testing a candidate pipeline before it is proposed (T-0590, PL-43, MF-38, Architecture/08 §7).
//!
//! A mapping is tested where it will run: as an ephemeral stream on the project's Bento runner,
//! never as a subprocess of the Portal. This module is the pure half of that: the harness the
//! runner is handed, and the trace read back from what the harness sent to the capture route.
//! The `DataSource` input becomes a `generate` input emitting the sample once (or an
//! `http_client` input for a sample URL, so the fetch obeys the runner's own egress policy,
//! PL-23), the author's processors stay what they are, and the output becomes an `http_client`
//! POST of one envelope per message: the input the message was, what the mapping made of it,
//! and the error when a processor failed. Nothing here resolves a `secretRef` or reaches the
//! target endpoint (MF-38).

use jc_core::kinds::{ComputeKind, PipelineSpec};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// How many messages one test may produce: enough to see every column, small enough to read.
pub const MAX_MESSAGES: usize = 20;
/// The largest inline sample (API/01 §7a).
pub const MAX_SAMPLE_BYTES: usize = 5 * 1024 * 1024;
/// The stream id prefix on the runner: `pipeline-test-{id}`.
pub const STREAM_PREFIX: &str = "pipeline-test-";

/// What the sample is, so the harness knows how to split it into messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SampleFormat {
    /// One message as it is, bytes untouched.
    #[default]
    Text,
    /// A header row and one message per data row, every cell a string.
    Csv,
    /// A JSON document; an array becomes one message per element.
    Json,
}

/// The sample of one test: inline text, or a URL the runner fetches itself.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    /// The sample inline, at most `MAX_SAMPLE_BYTES`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// An http(s) URL the runner fetches the sample from instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// How the sample is split into messages.
    #[serde(default)]
    pub format: SampleFormat,
}

/// Why a harness cannot be built from this manifest and sample.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HarnessError {
    /// Neither `text` nor `url` was given.
    #[error("sample: give either text or url")]
    NoSample,
    /// Both `text` and `url` were given.
    #[error("sample: text and url together; give one")]
    TwoSamples,
    /// The inline sample is past `MAX_SAMPLE_BYTES`.
    #[error("sample: {0} bytes is over the {MAX_SAMPLE_BYTES} byte limit")]
    TooLarge(usize),
    /// The sample URL is not http or https.
    #[error("sample: url '{0}' is not http or https")]
    BadUrl(String),
    /// The pipeline's compute stage is not a Bento processor this harness can run.
    #[error("compute kind {0} is not tested as a Bento processor")]
    NotABentoProcessor(ComputeKind),
}

/// The Bento stream config that tests `spec` on `sample`, posting every message to `capture_url`.
pub fn harness(
    spec: &PipelineSpec,
    sample: &Sample,
    capture_url: &str,
) -> Result<Value, HarnessError> {
    let input = match (&sample.text, &sample.url) {
        (Some(_), Some(_)) => return Err(HarnessError::TwoSamples),
        (None, None) => return Err(HarnessError::NoSample),
        (Some(text), None) => {
            if text.len() > MAX_SAMPLE_BYTES {
                return Err(HarnessError::TooLarge(text.len()));
            }
            // Base64 keeps every byte of the sample out of Bloblang's own string syntax.
            let encoded = base64_encode(text.as_bytes());
            json!({ "generate": {
                "count": 1,
                "interval": "",
                "mapping": format!("root = \"{encoded}\".decode(\"base64\")"),
            }})
        }
        (None, Some(url)) => {
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(HarnessError::BadUrl(url.clone()));
            }
            json!({ "http_client": { "url": url, "verb": "GET", "timeout": "3s", "retries": 0 } })
        }
    };

    let mut processors = Vec::new();
    match sample.format {
        SampleFormat::Text => {}
        SampleFormat::Csv | SampleFormat::Json => {
            let parse = match sample.format {
                SampleFormat::Csv => "content().string().parse_csv()",
                _ => "content().parse_json()",
            };
            processors.push(json!({ "mapping": format!(
                "let rows = {parse}\nroot = if $rows.type() == \"array\" {{ $rows.slice(0, {MAX_MESSAGES}) }} else {{ [$rows] }}"
            )}));
            processors.push(json!({ "unarchive": { "format": "json_array" } }));
        }
    }
    processors.push(json!({ "mapping": "meta jc_input = content().string()" }));
    if let Some(compute) = &spec.compute {
        match compute.kind {
            ComputeKind::Bloblang => {
                if let Some(mapping) = &compute.bloblang {
                    processors.push(json!({ "mapping": mapping }));
                }
            }
            kind => return Err(HarnessError::NotABentoProcessor(kind)),
        }
    }
    processors.push(json!({ "mapping": concat!(
        "let failed = errored()\n",
        "let out = this\n",
        "root = {}\n",
        "root.input = meta(\"jc_input\")\n",
        "root.output = if $failed { null } else { $out }\n",
        "root.error = if $failed { error() } else { null }"
    )}));
    // The envelope replaces the failed message, so the flag must not follow it to the output.
    processors.push(json!({ "catch": [] }));
    // A mapping that yields an array is one entity per element (PL-48), the same split the
    // reconciler renders for a live stream (PL-47); capped so a feed of thousands answers in
    // the same three seconds. A failed message has no array and passes through whole.
    processors.push(json!({ "mapping": format!(concat!(
        "root = if this.output.type() == \"array\" {{ ",
        "this.output.slice(0, {}).map_each(o -> {{ \"input\": this.input, \"output\": o, \"error\": null }}) ",
        "}} else {{ [this] }}"
    ), MAX_MESSAGES) }));
    processors.push(json!({ "unarchive": { "format": "json_array" } }));

    Ok(json!({
        "input": input,
        "pipeline": { "processors": processors },
        "output": { "http_client": {
            "url": capture_url,
            "verb": "POST",
            "timeout": "3s",
            "retries": 0,
            "max_in_flight": 1,
        }},
    }))
}

/// One captured message, as the harness posted it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Captured {
    /// The raw input message, as text.
    #[serde(default)]
    pub input: Option<String>,
    /// What the mapping produced, when it succeeded.
    #[serde(default)]
    pub output: Option<Value>,
    /// The processor error, when it failed.
    #[serde(default)]
    pub error: Option<String>,
}

/// The input stage of the trace: what the runner read and the first message as data.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct InputStage {
    /// Messages the runner read from the sample.
    pub events: usize,
    /// Their size in bytes, summed.
    pub bytes: usize,
    /// The first message as data, or as text when it is not JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample: Option<Value>,
}

/// Whether one mapped message is an NGSI-LD entity the platform would accept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validation {
    /// Which mapped message, in capture order.
    pub index: usize,
    /// Whether the message is an entity the platform would accept.
    pub ok: bool,
    /// Why not, one line each.
    pub problems: Vec<String>,
}

/// One thing that went wrong, at the stage it went wrong.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestError {
    /// `lint` (the runner refused the harness), `mapping` (a processor failed) or `runner`.
    pub stage: String,
    /// The Bloblang line the runner named, when it named one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// The runner's message, as it wrote it.
    pub message: String,
}

/// The trace of one test (Architecture/08 §7).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TestTrace {
    /// What the runner read.
    pub input: InputStage,
    /// Every mapped message, in capture order.
    pub mapping: Vec<Value>,
    /// One verdict per mapped message.
    pub validation: Vec<Validation>,
    /// What went wrong, at the stage it went wrong.
    pub errors: Vec<TestError>,
}

/// The trace of what the harness sent back.
pub fn trace(captured: &[Captured]) -> TestTrace {
    let mut trace = TestTrace::default();
    trace.input.events = captured.len();
    for (index, message) in captured.iter().enumerate() {
        let input = message.input.as_deref().unwrap_or_default();
        trace.input.bytes += input.len();
        if index == 0 {
            trace.input.sample = Some(
                serde_json::from_str(input).unwrap_or_else(|_| Value::String(input.to_owned())),
            );
        }
        if let Some(error) = &message.error {
            trace.errors.push(TestError {
                stage: "mapping".into(),
                line: line_of(error),
                message: error.clone(),
            });
            continue;
        }
        let output = message.output.clone().unwrap_or(Value::Null);
        let problems = problems_of(&output);
        trace.validation.push(Validation {
            index: trace.mapping.len(),
            ok: problems.is_empty(),
            problems,
        });
        trace.mapping.push(output);
    }
    trace
}

/// The runner's refusal of the harness as lint errors, one per line that names a problem.
pub fn lint_errors(refusal: &str) -> Vec<TestError> {
    let lines: Vec<&str> = refusal
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if lines.is_empty() {
        return vec![TestError {
            stage: "lint".into(),
            line: None,
            message: "the runner refused the harness".into(),
        }];
    }
    lines
        .into_iter()
        .map(|line| TestError {
            stage: "lint".into(),
            line: line_of(line),
            message: line.to_owned(),
        })
        .collect()
}

/// The line a Bento error names (`line 3 char 7`, `(line 3)`, `:3:7:`), when it names one.
///
/// A harness line is a mapping line plus nothing: the author's mapping is its own processor,
/// so the number Bento reports is the number in the editor.
pub fn line_of(message: &str) -> Option<u32> {
    let after = message.find("line ")? + "line ".len();
    let digits: String = message[after..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// What keeps `value` from being an NGSI-LD entity the gateway would take (PF-42).
pub fn problems_of(value: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    let Some(object) = value.as_object() else {
        problems.push("the mapping did not produce an object".into());
        return problems;
    };
    let entity_type = object
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if entity_type.is_empty() {
        problems.push("no 'type'".into());
    }
    match object.get("id").and_then(Value::as_str) {
        None => problems.push("no 'id'".into()),
        Some(id) if !id.starts_with("urn:ngsi-ld:") => {
            problems.push(format!("id '{id}' does not start with urn:ngsi-ld:"));
        }
        Some(id)
            if !entity_type.is_empty()
                && !id.starts_with(&format!("urn:ngsi-ld:{entity_type}:")) =>
        {
            problems.push(format!("id '{id}' does not name the type '{entity_type}'"));
        }
        Some(_) => {}
    }
    problems
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(bloblang: Option<&str>) -> PipelineSpec {
        let mut value = json!({
            "class": "resident",
            "source": { "dataSourceRef": { "kind": "DataSource", "name": "shmu-csv" } },
            "targetEndpoint": "urn:ngsi-ld:Endpoint:hel.fi:helsinki:helsinki-all"
        });
        if let Some(mapping) = bloblang {
            value["compute"] = json!({ "kind": "bloblang", "bloblang": mapping });
        }
        serde_json::from_value(value).expect("a pipeline spec")
    }

    #[test]
    fn a_csv_sample_is_generated_once_split_by_row_and_posted_to_the_capture_route() {
        let sample = Sample {
            text: Some("station_id,pm10\n01,18.2\n".into()),
            url: None,
            format: SampleFormat::Csv,
        };
        let config = harness(
            &spec(Some("root.id = this.station_id")),
            &sample,
            "http://portal:9090/internal/pipeline-tests/abc",
        )
        .expect("a harness");
        assert_eq!(config["input"]["generate"]["count"], 1);
        assert!(config["input"]["generate"]["mapping"]
            .as_str()
            .is_some_and(|m| m.ends_with(".decode(\"base64\")") && !m.contains("station_id")));
        let processors = config["pipeline"]["processors"]
            .as_array()
            .expect("processors");
        assert!(processors[0]["mapping"]
            .as_str()
            .is_some_and(|m| m.contains("parse_csv")));
        assert_eq!(processors[1]["unarchive"]["format"], "json_array");
        assert_eq!(processors[3]["mapping"], "root.id = this.station_id");
        let n = processors.len();
        assert_eq!(processors[n - 3]["catch"], json!([]));
        assert!(processors[n - 2]["mapping"].as_str().is_some_and(|m| m
            .contains("this.output.type() == \"array\"")
            && m.contains("slice(0, 20)")));
        assert_eq!(processors[n - 1]["unarchive"]["format"], "json_array");
        assert_eq!(
            config["output"]["http_client"]["url"],
            "http://portal:9090/internal/pipeline-tests/abc"
        );
        assert_eq!(config["output"]["http_client"]["verb"], "POST");
        assert!(
            config.get("resources").is_none(),
            "no secret, no resource: MF-38"
        );
    }

    #[test]
    fn a_url_sample_is_fetched_by_the_runner_and_text_is_one_message() {
        let sample = Sample {
            text: None,
            url: Some("https://feeds.example/air.json".into()),
            format: SampleFormat::Text,
        };
        let config = harness(&spec(None), &sample, "http://portal/c").expect("a harness");
        assert_eq!(
            config["input"]["http_client"]["url"],
            "https://feeds.example/air.json"
        );
        let processors = config["pipeline"]["processors"]
            .as_array()
            .expect("processors");
        assert_eq!(
            processors.len(),
            5,
            "capture, envelope, catch, the array split and its unarchive: nothing else (PL-48)"
        );
    }

    #[test]
    fn what_cannot_be_a_harness_is_refused_with_the_reason() {
        let none = Sample::default();
        assert_eq!(
            harness(&spec(None), &none, "http://p").unwrap_err(),
            HarnessError::NoSample
        );
        let both = Sample {
            text: Some("x".into()),
            url: Some("http://a".into()),
            format: SampleFormat::Text,
        };
        assert_eq!(
            harness(&spec(None), &both, "http://p").unwrap_err(),
            HarnessError::TwoSamples
        );
        let ftp = Sample {
            text: None,
            url: Some("ftp://a".into()),
            format: SampleFormat::Text,
        };
        assert!(matches!(
            harness(&spec(None), &ftp, "http://p").unwrap_err(),
            HarnessError::BadUrl(_)
        ));
        let big = Sample {
            text: Some("x".repeat(MAX_SAMPLE_BYTES + 1)),
            url: None,
            format: SampleFormat::Text,
        };
        assert!(matches!(
            harness(&spec(None), &big, "http://p").unwrap_err(),
            HarnessError::TooLarge(_)
        ));
        let wasm: PipelineSpec = serde_json::from_value(json!({
            "class": "resident",
            "compute": { "kind": "wasm", "module": "m", "function": "f" },
            "targetEndpoint": "urn:ngsi-ld:Endpoint:hel.fi:helsinki:helsinki-all"
        }))
        .expect("spec");
        let text = Sample {
            text: Some("x".into()),
            url: None,
            format: SampleFormat::Text,
        };
        assert!(matches!(
            harness(&wasm, &text, "http://p").unwrap_err(),
            HarnessError::NotABentoProcessor(ComputeKind::Wasm)
        ));
    }

    #[test]
    fn the_trace_reads_input_mapping_validation_and_errors_from_what_came_back() {
        let captured = vec![
            Captured {
                input: Some(r#"{"station_id":"01","pm10":"18.2"}"#.into()),
                output: Some(
                    json!({ "id": "urn:ngsi-ld:AirQualityObserved:hel.fi:aq:01", "type": "AirQualityObserved" }),
                ),
                error: None,
            },
            Captured {
                input: Some(r#"{"station_id":"02"}"#.into()),
                output: Some(json!({ "id": "station-02", "type": "AirQualityObserved" })),
                error: None,
            },
            Captured {
                input: Some("garbage".into()),
                output: None,
                error: Some("failed assignment (line 2): expected number, got string".into()),
            },
        ];
        let trace = trace(&captured);
        assert_eq!(trace.input.events, 3);
        let expected: usize = captured
            .iter()
            .map(|c| c.input.as_deref().unwrap_or_default().len())
            .sum();
        assert_eq!(trace.input.bytes, expected);
        assert_eq!(
            trace.input.sample,
            Some(json!({ "station_id": "01", "pm10": "18.2" }))
        );
        assert_eq!(trace.mapping.len(), 2);
        assert_eq!(
            trace.validation[0],
            Validation {
                index: 0,
                ok: true,
                problems: vec![]
            }
        );
        assert!(!trace.validation[1].ok);
        assert!(trace.validation[1].problems[0].contains("urn:ngsi-ld:"));
        assert_eq!(
            trace.errors,
            vec![TestError {
                stage: "mapping".into(),
                line: Some(2),
                message: "failed assignment (line 2): expected number, got string".into()
            }]
        );
    }

    #[test]
    fn a_refusal_becomes_lint_errors_with_their_lines() {
        let errors = lint_errors("stream 'pipeline-test-x' failed to create:\n  line 12 char 3: expected string, got number\n");
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[1].line, Some(12));
        assert_eq!(errors[1].stage, "lint");
        assert_eq!(lint_errors("")[0].line, None);
        assert_eq!(line_of("no number here"), None);
    }

    #[test]
    fn an_entity_needs_a_type_and_an_id_that_names_it() {
        assert!(
            problems_of(&json!({ "id": "urn:ngsi-ld:Bike:hel.fi:b:1", "type": "Bike" })).is_empty()
        );
        assert_eq!(
            problems_of(&json!({ "id": "urn:ngsi-ld:Bike:hel.fi:b:1" })),
            vec!["no 'type'"]
        );
        assert_eq!(problems_of(&json!({ "type": "Bike" })), vec!["no 'id'"]);
        assert!(
            problems_of(&json!({ "id": "urn:ngsi-ld:Car:x:y:1", "type": "Bike" }))[0]
                .contains("does not name the type")
        );
        assert_eq!(
            problems_of(&json!([1])),
            vec!["the mapping did not produce an object"]
        );
    }
}
