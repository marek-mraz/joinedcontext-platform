//! `jcctl`, the reconciler and repository CLI (API/03).
//!
//! `validate`, `plan`, `apply` and `schema export` are implemented. `plan` and `apply`
//! need a live platform; until the Context Gateway serves the configuration API, only the
//! in-process implementation of [`jcctl::platform::Platform`] exists, so the CLI runs them
//! against an empty platform, which is what a fresh installation looks like.

use jcctl::commands;
use jcctl::loader::Repository;
use jcctl::platform::InMemory;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "usage: jcctl validate --repo-dir <path>\n       jcctl plan --repo-dir <path> [--json]\n       jcctl apply --repo-dir <path> [--prune] [--confirm-deletions]\n       jcctl export --space <id> --out-dir <path> [--project <slug>]\n       jcctl schema export [--out <dir>]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = args.iter().map(String::as_str).collect();

    match words.as_slice() {
        ["validate", "--repo-dir", dir] => validate(Path::new(dir)),
        ["plan", "--repo-dir", dir, rest @ ..] => match rest {
            [] => plan(Path::new(dir), false),
            ["--json"] => plan(Path::new(dir), true),
            _ => usage(),
        },
        ["apply", "--repo-dir", dir, rest @ ..] => match apply_options(rest) {
            Some(options) => apply(Path::new(dir), options),
            None => usage(),
        },
        ["export", rest @ ..] => match export_options(rest) {
            Some((space, out, project)) => export(&space, &out, project.as_deref()),
            None => usage(),
        },
        ["schema", "export", rest @ ..] => match out_dir(rest) {
            Some(out) => match export_schemas(&out) {
                Ok(count) => {
                    println!("{count} schemas written to {}", out.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("jcctl: {e}");
                    ExitCode::FAILURE
                }
            },
            None => {
                eprintln!("{USAGE}");
                ExitCode::FAILURE
            }
        },
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::FAILURE
}

/// Reports every invalid manifest under `dir`, one per line (API/03 section 1).
///
/// Exit code 1 covers both an invalid manifest and an unreadable repository: API/03
/// section 3 gives `validate` no separate code for a bad manifest.
fn validate(dir: &Path) -> ExitCode {
    let report = jcctl::commands::validate::run(dir);
    for finding in &report.findings {
        eprintln!("{finding}");
    }
    if report.is_valid() {
        println!("{} manifests valid", report.checked);
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "{} manifests valid, {} invalid",
            report.checked,
            report.findings.len()
        );
        ExitCode::FAILURE
    }
}

/// Reports what `apply` would do (API/03 section 2 and 3: exit 2 means pending changes).
fn plan(dir: &Path, as_json: bool) -> ExitCode {
    let repo = match Repository::load(dir) {
        Ok(repo) => repo,
        Err(err) => return fail(&err.to_string()),
    };
    let changes = match commands::plan::compute(&repo, &InMemory::new()) {
        Ok(changes) => changes,
        Err(err) => return fail(&err.to_string()),
    };

    if as_json {
        match serde_json::to_string_pretty(&changes.to_json()) {
            Ok(json) => println!("{json}"),
            Err(err) => return fail(&err.to_string()),
        }
    } else {
        print!("{}", changes.render());
    }

    if changes.is_clean() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

/// Converges the platform and prints the per-resource result (CC-18, CC-20).
fn apply(dir: &Path, options: commands::apply::Options) -> ExitCode {
    let repo = match Repository::load(dir) {
        Ok(repo) => repo,
        Err(err) => return fail(&err.to_string()),
    };
    let mut platform = InMemory::new();
    let report = match commands::apply::run(&repo, &mut platform, options) {
        Ok(report) => report,
        Err(err) => return fail(&err.to_string()),
    };

    for result in &report.results {
        println!(
            "{:<9} {} {}",
            result.action.as_str().to_lowercase(),
            result.id,
            match &result.outcome {
                commands::apply::Outcome::Applied => "applied".to_owned(),
                commands::apply::Outcome::Unchanged => "unchanged".to_owned(),
                commands::apply::Outcome::Skipped(why) => format!("skipped: {why}"),
                commands::apply::Outcome::Failed(err) => format!("failed: {err}"),
            }
        );
    }
    if let Some(revision) = &report.revision {
        println!("applied revision {revision}");
    }

    if report.is_successful() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Parses the two deletion flags, in either order; `None` on anything else (CC-19).
fn apply_options(args: &[&str]) -> Option<commands::apply::Options> {
    let mut options = commands::apply::Options::default();
    for arg in args {
        match *arg {
            "--prune" => options.prune = true,
            "--confirm-deletions" => options.confirm_deletions = true,
            _ => return None,
        }
    }
    Some(options)
}

/// Copies one context space out of the live platform as a repository (CC-22, MF-16).
///
/// Like `plan` and `apply`, this runs against the in-process platform until the Context
/// Gateway serves the configuration API, so today it exports a fresh installation: an
/// empty space. The cleaning and the redaction are what the command is for and they are
/// exercised by `commands::export` directly.
fn export(space: &str, out: &Path, project: Option<&str>) -> ExitCode {
    // A space lives in a project and the platform has no project directory to ask; the
    // usual naming has the two equal, and `--project` names them when they are not.
    let project = project.unwrap_or(space);
    let report = match commands::export::collect(&InMemory::new(), project, space) {
        Ok(report) => report,
        Err(err) => return fail(&err.to_string()),
    };
    let written = match commands::export::write(out, &report) {
        Ok(written) => written,
        Err(err) => return fail(&err.to_string()),
    };

    for redaction in &report.redactions {
        eprintln!(
            "jcctl: redacted {redaction} (MF-17: a manifest carries a secretRef, never a secret)"
        );
    }
    println!("{written} manifests written to {}", out.display());
    ExitCode::SUCCESS
}

/// Parses `--space`, `--out-dir` and the optional `--project`, in any order.
fn export_options(args: &[&str]) -> Option<(String, PathBuf, Option<String>)> {
    let (mut space, mut out, mut project) = (None, None, None);
    let mut rest = args;
    while let [flag, value, tail @ ..] = rest {
        match *flag {
            "--space" => space = Some((*value).to_owned()),
            "--out-dir" => out = Some(PathBuf::from(value)),
            "--project" => project = Some((*value).to_owned()),
            _ => return None,
        }
        rest = tail;
    }
    if !rest.is_empty() {
        return None;
    }
    Some((space?, out?, project))
}

fn fail(message: &str) -> ExitCode {
    eprintln!("jcctl: {message}");
    ExitCode::FAILURE
}

/// Parses the single `--out <dir>` option; `None` on anything else.
fn out_dir(args: &[&str]) -> Option<PathBuf> {
    match args {
        [] => Some(PathBuf::from("schemas/kinds")),
        ["--out", dir] => Some(PathBuf::from(dir)),
        _ => None,
    }
}

/// Writes the draft-07 schema of every catalogued kind to `out/{Kind}.json` (MF-09, CC-12).
fn export_schemas(out: &std::path::Path) -> std::io::Result<usize> {
    std::fs::create_dir_all(out)?;
    for info in jc_core::registry::KINDS {
        let schema =
            jc_core::registry::schema_of(info.kind).expect("every catalogued kind has a schema");
        let mut json = serde_json::to_string_pretty(&schema)?;
        json.push('\n');
        std::fs::write(out.join(format!("{}.json", info.kind)), json)?;
    }
    Ok(jc_core::registry::KINDS.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_option_parsing() {
        assert_eq!(
            export_options(&["--space", "ovzdusie", "--out-dir", "/tmp/x"]),
            Some(("ovzdusie".to_owned(), PathBuf::from("/tmp/x"), None))
        );
        assert_eq!(
            export_options(&["--out-dir", "/tmp/x", "--project", "bb", "--space", "air"]),
            Some((
                "air".to_owned(),
                PathBuf::from("/tmp/x"),
                Some("bb".to_owned())
            ))
        );
        assert_eq!(export_options(&["--space", "ovzdusie"]), None, "no out-dir");
        assert_eq!(export_options(&["--out-dir", "/tmp/x"]), None, "no space");
        assert_eq!(export_options(&["--space"]), None, "no value");
        assert_eq!(export_options(&["--repo-dir", "x", "--space", "y"]), None);
    }

    #[test]
    fn out_dir_parsing() {
        assert_eq!(out_dir(&[]), Some(PathBuf::from("schemas/kinds")));
        assert_eq!(out_dir(&["--out", "/tmp/x"]), Some(PathBuf::from("/tmp/x")));
        assert_eq!(out_dir(&["--out"]), None);
        assert_eq!(out_dir(&["--outdir", "x"]), None);
        assert_eq!(out_dir(&["--out", "a", "b"]), None);
    }

    #[test]
    fn export_writes_one_draft07_schema_per_kind() {
        let dir = std::env::temp_dir().join("jcctl-schema-export-test");
        let _ = std::fs::remove_dir_all(&dir);
        let count = export_schemas(&dir).expect("export succeeds");
        assert_eq!(count, jc_core::registry::KINDS.len());

        for info in jc_core::registry::KINDS {
            let text = std::fs::read_to_string(dir.join(format!("{}.json", info.kind)))
                .unwrap_or_else(|e| panic!("{}: {e}", info.kind));
            let schema: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
            assert_eq!(
                schema["$schema"],
                serde_json::json!("http://json-schema.org/draft-07/schema#"),
                "{} must be draft-07",
                info.kind
            );
        }
        std::fs::remove_dir_all(&dir).expect("clean up");
    }
}
