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

const USAGE: &str =
    "usage: jcctl validate --repo-dir <path>\n       jcctl schema export [--out <dir>]";

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
