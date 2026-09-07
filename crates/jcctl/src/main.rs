//! `jcctl`, the reconciler and repository CLI (API/03).
//!
//! `validate`, `plan`, `apply` and `schema export` are implemented. `plan` and `apply`
//! need a live platform; until the Context Gateway serves the configuration API, only the
//! in-process implementation of [`jcctl::platform::Platform`] exists, so the CLI runs them
//! against an empty platform, which is what a fresh installation looks like.

use jcctl::commands;
use jcctl::loader::Repository;
use jcctl::model;
use jcctl::platform::InMemory;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "usage: jcctl validate --repo-dir <path>\n       jcctl plan --repo-dir <path> [--json]\n       jcctl apply --repo-dir <path> [--prune] [--confirm-deletions]\n       jcctl drift --repo-dir <path> [--json] [--adopt-dir <path>]\n       jcctl export --space <id> --out-dir <path> [--project <slug>]\n       jcctl import <source> --repo-dir <path> [--namespace <slug>] [--org-domain <d>] [--conflict fail|skip|replace|rename] [--json]\n       jcctl schema export [--out <dir>]\n       jcctl roles render --repo-dir <path>\n       jcctl roles input --repo-dir <path> --base-dir <path> --changes <name-status file> --author <login> [--author-email <e>] [--groups a,b]\n       jcctl model generate|diff|validate --repo-dir <path> [--url <url>]\n       jcctl model import <dataModel.Subject/Model> --out <file> [--url <url>]\n       jcctl publish ckan --repo-dir <path> --project <slug> --host <gateway host> [--organization-title <t>] [--api-token-env <VAR>] [--age-key-file <path>] [--withdraw]";

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
        ["drift", "--repo-dir", dir, rest @ ..] => match drift_options(rest) {
            Some((as_json, adopt_dir)) => drift(Path::new(dir), as_json, adopt_dir.as_deref()),
            None => usage(),
        },
        ["import", source, rest @ ..] => match bundle_options(rest) {
            Some((dir, options, as_json)) => import(Path::new(source), &dir, options, as_json),
            None => usage(),
        },
        ["export", rest @ ..] => match export_options(rest) {
            Some((space, out, project)) => export(&space, &out, project.as_deref()),
            None => usage(),
        },
        ["model", "import", id, rest @ ..] => match import_options(rest) {
            Some((out, url)) => model_import(id, &out, url),
            None => usage(),
        },
        ["model", verb, rest @ ..] => match (model_mode(verb), model_options(rest)) {
            (Some(mode), Some((dir, url))) => model(&dir, url, mode),
            _ => usage(),
        },
        ["publish", "ckan", rest @ ..] => match publish_ckan_options(rest) {
            Some(options) => publish_ckan(&options),
            None => usage(),
        },
        ["roles", "render", "--repo-dir", dir] => match jcctl::roles::render(Path::new(dir)) {
            Ok(written) => {
                for path in written {
                    println!("{}", path.display());
                }
                ExitCode::SUCCESS
            }
            Err(err) => fail(&err.to_string()),
        },
        ["roles", "input", rest @ ..] => match roles_input_options(rest) {
            Some(options) => roles_input(&options),
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

/// Reports what changed on the platform behind Git's back (API/03 section 3, CC-21).
///
/// Exit 2 means drift, the same code `plan` uses for pending changes: a scheduled run is a
/// cron job whose exit code is the alert, and an operator reads the two resolutions per
/// resource (CC-38, UI-26).
fn drift(dir: &Path, as_json: bool, adopt_dir: Option<&Path>) -> ExitCode {
    let repo = match Repository::load(dir) {
        Ok(repo) => repo,
        Err(err) => return fail(&err.to_string()),
    };
    let report = match commands::drift::detect(&repo, &InMemory::new()) {
        Ok(report) => report,
        Err(err) => return fail(&err.to_string()),
    };

    if let Some(out) = adopt_dir {
        match commands::drift::write_adoptions(out, &report) {
            Ok(written) => eprintln!(
                "jcctl: {written} adoptable manifests written to {}",
                out.display()
            ),
            Err(err) => return fail(&err.to_string()),
        }
    }
    for drifted in &report.drifted {
        for redaction in &drifted.redactions {
            eprintln!(
                "jcctl: {}/{} adopts without `{redaction}` (MF-17: a manifest carries a \
                 secretRef, never a secret)",
                drifted.id.kind, drifted.id.name
            );
        }
    }

    if as_json {
        println!("{}", json(&report.to_json()));
    } else {
        print!("{}", report.render());
    }

    if report.is_clean() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

/// Parses `--json` and the optional `--adopt-dir <path>`, in any order.
fn drift_options(args: &[&str]) -> Option<(bool, Option<PathBuf>)> {
    let (mut as_json, mut adopt_dir) = (false, None);
    let mut rest = args;
    while let Some((flag, tail)) = rest.split_first() {
        match *flag {
            "--json" => {
                as_json = true;
                rest = tail;
            }
            "--adopt-dir" => match tail.split_first() {
                Some((value, next)) => {
                    adopt_dir = Some(PathBuf::from(value));
                    rest = next;
                }
                None => return None,
            },
            _ => return None,
        }
    }
    Some((as_json, adopt_dir))
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

/// Renders every DataModel through Model Tools (API/03 section 4, DM-02, DM-19, DM-32).
///
/// `diff` exits 2 the way `plan` does: a committed artifact that no longer matches a fresh
/// rendering is a pending change, and CI reads the code rather than the log.
fn model(dir: &Path, url: Option<String>, mode: model::Mode) -> ExitCode {
    let url = match url.or_else(|| std::env::var(model::URL_ENV).ok()) {
        Some(url) => url,
        None => {
            return fail(&format!(
                "no Model Tools URL: pass --url or set {} (API/03 section 4)",
                model::URL_ENV
            ))
        }
    };
    let tools = model::ModelTools::new(url);
    let report = match model::run(dir, &tools, mode) {
        Ok(report) => report,
        Err(err) => return fail(&err.to_string()),
    };

    println!("{}", json(&report.to_json()));
    if report.failed() > 0 {
        ExitCode::FAILURE
    } else if report.stale() > 0 {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

/// Imports one Smart Data Models model as LinkML (DM-07..DM-11).
fn model_import(id: &str, out: &Path, url: Option<String>) -> ExitCode {
    let url = match url.or_else(|| std::env::var(model::URL_ENV).ok()) {
        Some(url) => url,
        None => {
            return fail(&format!(
                "no Model Tools URL: pass --url or set {} (API/03 section 4)",
                model::URL_ENV
            ))
        }
    };
    let result = match model::import(&model::ModelTools::new(url), id, out) {
        Ok(result) => result,
        Err(err) => return fail(&err.to_string()),
    };

    let failed = result["errors"].as_array().is_some_and(|e| !e.is_empty());
    println!("{}", json(&result));
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// What `jcctl publish ckan` was asked to do.
struct PublishCkanOptions {
    repo_dir: PathBuf,
    project: String,
    host: String,
    organization_title: Option<String>,
    api_token_env: Option<String>,
    age_key_file: Option<PathBuf>,
    withdraw: bool,
}

/// Parses the options of `publish ckan`, in any order; `--repo` is accepted for
/// `--repo-dir`. The host is taken without a scheme or a trailing slash, so a URL pasted
/// in place of a host still names the host.
fn publish_ckan_options(args: &[&str]) -> Option<PublishCkanOptions> {
    let mut options = PublishCkanOptions {
        repo_dir: PathBuf::new(),
        project: String::new(),
        host: String::new(),
        organization_title: None,
        api_token_env: None,
        age_key_file: None,
        withdraw: false,
    };
    let mut rest = args;
    while let Some((flag, tail)) = rest.split_first() {
        match (*flag, tail) {
            ("--repo-dir" | "--repo", [dir, tail @ ..]) => {
                options.repo_dir = PathBuf::from(dir);
                rest = tail;
            }
            ("--project", [project, tail @ ..]) => {
                options.project = (*project).to_owned();
                rest = tail;
            }
            ("--host", [host, tail @ ..]) => {
                let host = host
                    .strip_prefix("https://")
                    .or_else(|| host.strip_prefix("http://"))
                    .unwrap_or(host);
                options.host = host.trim_end_matches('/').to_owned();
                rest = tail;
            }
            ("--organization-title", [title, tail @ ..]) => {
                options.organization_title = Some((*title).to_owned());
                rest = tail;
            }
            ("--api-token-env", [variable, tail @ ..]) => {
                options.api_token_env = Some((*variable).to_owned());
                rest = tail;
            }
            ("--age-key-file", [path, tail @ ..]) => {
                options.age_key_file = Some(PathBuf::from(path));
                rest = tail;
            }
            ("--withdraw", tail) => {
                options.withdraw = true;
                rest = tail;
            }
            _ => return None,
        }
    }
    let complete = options.repo_dir.as_os_str().is_empty()
        || options.project.is_empty()
        || options.host.is_empty();
    (!complete).then_some(options)
}

/// Publishes every Endpoint of one project that declares `spec.publish.ckan` (T-0487,
/// EP-62…EP-67, CC-18).
///
/// One line per Endpoint; an Endpoint that fails is reported on stderr and the run goes
/// on to the next, so one unreachable record does not hold the other datasets back. Exit
/// 1 when any Endpoint failed. A second run over an unchanged repository prints
/// `unchanged` for every dataset and writes nothing (CC-18).
fn publish_ckan(options: &PublishCkanOptions) -> ExitCode {
    use jcctl::commands::publish_ckan::{self as command, TokenSource};
    use jcctl::publish::ckan::Settings;
    use jcctl::publish::ckan_http::HttpCkan;

    let repo = match Repository::load(&options.repo_dir) {
        Ok(repo) => repo,
        Err(err) => return fail(&err.to_string()),
    };
    let targets = match command::targets(&repo, &options.project) {
        Ok(targets) => targets,
        Err(err) => return fail(&err.to_string()),
    };
    if targets.is_empty() {
        println!(
            "no endpoint of project {} declares spec.publish.ckan",
            options.project
        );
        return ExitCode::SUCCESS;
    }
    let mut settings = Settings::new(options.host.clone());
    if let Some(title) = &options.organization_title {
        settings = settings.titled(title.clone());
    }
    let source = TokenSource {
        env: options.api_token_env.as_deref(),
        age_key_file: options.age_key_file.as_deref(),
    };

    // One client per instance, built when the first Endpoint of that instance comes up;
    // an instance whose token cannot be read fails every Endpoint that names it.
    let mut clients: std::collections::BTreeMap<String, Result<HttpCkan, String>> =
        std::collections::BTreeMap::new();
    let mut failed = 0usize;
    for target in &targets {
        let client = clients
            .entry(target.instance_name.clone())
            .or_insert_with(|| {
                command::token(&target.instance, repo.root(), source)
                    .map_err(|e| e.to_string())
                    .and_then(|token| {
                        HttpCkan::new(target.instance.base_url(), token).map_err(|e| e.to_string())
                    })
            });
        let api = match client {
            Ok(api) => api,
            Err(message) => {
                eprintln!("{}: {message}", target.id);
                failed += 1;
                continue;
            }
        };
        let line = if options.withdraw {
            command::withdraw_one(api, target)
        } else {
            command::record(target, &settings).and_then(|record| {
                let rows = command::rows(target, &settings)?;
                command::publish_one(api, target, &record, rows.as_deref(), &settings)
            })
        };
        match line {
            Ok(line) => println!("{line}"),
            Err(err) => {
                eprintln!("{}: {err}", target.id);
                failed += 1;
            }
        }
    }
    if failed > 0 {
        eprintln!(
            "{failed} of {} endpoints failed; the others are as reported",
            targets.len()
        );
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// The verb after `model`, or `None` for anything else.
fn model_mode(verb: &str) -> Option<model::Mode> {
    match verb {
        "generate" => Some(model::Mode::Generate),
        "diff" => Some(model::Mode::Diff),
        "validate" => Some(model::Mode::Validate),
        _ => None,
    }
}

/// Parses `--repo-dir` and the optional `--url`, in any order.
fn model_options(args: &[&str]) -> Option<(PathBuf, Option<String>)> {
    let (mut dir, mut url) = (None, None);
    let mut rest = args;
    while let [flag, value, tail @ ..] = rest {
        match *flag {
            "--repo-dir" => dir = Some(PathBuf::from(value)),
            "--url" => url = Some((*value).to_owned()),
            _ => return None,
        }
        rest = tail;
    }
    if rest.is_empty() {
        dir.map(|dir| (dir, url))
    } else {
        None
    }
}

/// Parses `--out` and the optional `--url`, in any order.
fn import_options(args: &[&str]) -> Option<(PathBuf, Option<String>)> {
    let (mut out, mut url) = (None, None);
    let mut rest = args;
    while let [flag, value, tail @ ..] = rest {
        match *flag {
            "--out" => out = Some(PathBuf::from(value)),
            "--url" => url = Some((*value).to_owned()),
            _ => return None,
        }
        rest = tail;
    }
    if rest.is_empty() {
        out.map(|out| (out, url))
    } else {
        None
    }
}

/// One JSON document per run, so a CI step reads the result instead of the log.
fn json(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
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

/// Imports a bundle into the repository, rewritten for this project (MF-20…MF-24, PF-22).
///
/// Exit 1 on any rejection, and nothing is written then: MF-24 is a gate, so half an import
/// is not a smaller import, it is a repository that no longer validates.
fn import(
    source: &Path,
    repo_dir: &Path,
    options: commands::import::Options,
    as_json: bool,
) -> ExitCode {
    let report = match commands::import::collect(source, repo_dir, &options) {
        Ok(report) => report,
        Err(err) => return fail(&err.to_string()),
    };

    for rejection in &report.rejections {
        eprintln!("jcctl: {rejection}");
    }
    if !report.is_acceptable() {
        eprintln!(
            "jcctl: {} of the bundle refused, nothing written",
            report.rejections.len()
        );
        if as_json {
            println!("{}", json(&report.to_json()));
        }
        return ExitCode::FAILURE;
    }

    let written = match commands::import::write(repo_dir, &report) {
        Ok(written) => written,
        Err(err) => return fail(&err.to_string()),
    };

    if as_json {
        println!("{}", json(&report.to_json()));
    } else {
        for resource in &report.imported {
            println!(
                "{:<9} {}",
                resource.outcome.as_str().to_lowercase(),
                resource.path.display()
            );
        }
        println!("{written} manifests written to {}", repo_dir.display());
    }
    ExitCode::SUCCESS
}

/// Parses `--repo-dir`, `--namespace`, `--org-domain`, `--conflict` and `--json`, in any order.
fn bundle_options(args: &[&str]) -> Option<(PathBuf, commands::import::Options, bool)> {
    let mut dir = None;
    let mut options = commands::import::Options::default();
    let mut as_json = false;
    let mut rest = args;
    while let Some((flag, tail)) = rest.split_first() {
        if *flag == "--json" {
            as_json = true;
            rest = tail;
            continue;
        }
        let (value, next) = tail.split_first()?;
        match *flag {
            "--repo-dir" => dir = Some(PathBuf::from(value)),
            "--namespace" => options.namespace = Some((*value).to_owned()),
            "--org-domain" => options.org_domain = Some((*value).to_owned()),
            "--conflict" => options.conflict = commands::import::Conflict::parse(value)?,
            _ => return None,
        }
        rest = next;
    }
    dir.map(|dir| (dir, options, as_json))
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

struct RolesInputOptions {
    repo_dir: PathBuf,
    base_dir: PathBuf,
    changes: PathBuf,
    author: String,
    author_email: Option<String>,
    groups: Vec<String>,
}

fn roles_input_options(args: &[&str]) -> Option<RolesInputOptions> {
    let mut repo_dir = None;
    let mut base_dir = None;
    let mut changes = None;
    let mut author = None;
    let mut author_email = None;
    let mut groups = Vec::new();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it.next()?;
        match *flag {
            "--repo-dir" => repo_dir = Some(PathBuf::from(value)),
            "--base-dir" => base_dir = Some(PathBuf::from(value)),
            "--changes" => changes = Some(PathBuf::from(value)),
            "--author" => author = Some((*value).to_owned()),
            "--author-email" => author_email = Some((*value).to_owned()).filter(|e| !e.is_empty()),
            "--groups" => {
                groups = value
                    .split(',')
                    .filter(|g| !g.is_empty())
                    .map(str::to_owned)
                    .collect()
            }
            _ => return None,
        }
    }
    Some(RolesInputOptions {
        repo_dir: repo_dir?,
        base_dir: base_dir?,
        changes: changes?,
        author: author?,
        author_email,
        groups,
    })
}

/// Prints the document `policies/roles.rego` evaluates (PF-52).
fn roles_input(options: &RolesInputOptions) -> ExitCode {
    let listing = match std::fs::read_to_string(&options.changes) {
        Ok(listing) => listing,
        Err(err) => return fail(&format!("{}: {err}", options.changes.display())),
    };
    match jcctl::roles::input(
        &options.repo_dir,
        &options.base_dir,
        &listing,
        &options.author,
        options.author_email.as_deref(),
        &options.groups,
    ) {
        Ok(input) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&input).expect("input serializes")
            );
            ExitCode::SUCCESS
        }
        Err(err) => fail(&err.to_string()),
    }
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
