//! A peer's schema surface mirrored as read-only foreign DataModels (T-0176, DM-48, DM-49).
//!
//! DM-48 gives this work to the reconciler, and that is where it lives. The Context Gateway is
//! the enforcement point on the public network and has no write path into the configuration
//! repository; giving it one so that it could commit a peer's schema would widen the gateway's
//! reach far past what mirroring needs. So the fetch happens here, in the reconciler, and the
//! gateway's half of DM-49 is a single exclusion: a mirrored model is not part of an
//! endpoint's or a space's own schema surface.
//!
//! Like the CKAN publisher and the registration reconciler next door, this module opens no
//! socket. It is handed a [`SchemaApi`] and the base URL of the peer's surface, because the
//! reconciler is the one that knows how a `SharedSpaceReference` or a
//! `ContextSourceRegistration` resolves to an address.
//!
//! Everything the peer says is treated as what it is: input from another organisation. The
//! base URL has to be `https://`, a model name that is not a DNS-1123 label never reaches the
//! filesystem, and a document whose digest does not match the peer's own `index.json` is
//! refused rather than written. A peer that publishes no schema surface at all is flagged and
//! the reference stands without a model, which is what DM-48 asks for.
//!
//! Nothing is written by [`mirror`]: it is the whole judgement and [`write`] is the
//! consequence, so a caller can print the plan and stop. A model whose digest changed comes
//! back as [`Outcome::Changed`] carrying the digest the repository pinned and the local
//! Mappings that read the model; DM-49 wants that change reviewed, so the caller puts it on a
//! branch rather than on `main`.

use crate::loader::{RawManifest, RawMetadata, Repository};
use jc_core::kinds::{DataModelSpec, MappingSpec};
use jc_core::{names, registry, API_VERSION};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The catalogue every schema surface publishes, relative to the peer's base (EP-46).
pub const INDEX: &str = "schema/index.json";

/// The authoring source; the document a mirror pins its `sha256` to (DM-48).
pub const LINKML: &str = "model.linkml.yaml";

/// The JSON-LD `@context` of the model (DM-48).
pub const CONTEXT: &str = "context.jsonld";

/// The peer's example entity, which is not one of the seven documents an endpoint has to
/// publish, so a surface without it is mirrored without it (DM-48, EP-46).
pub const EXAMPLE: &str = "example.jsonld";

/// The part of a peer's schema surface a mirror reads.
///
/// The implementation carries whatever the hop needs — a partner's API key, a proxy, a
/// timeout — and nothing built here holds a credential (CC-06).
pub trait SchemaApi {
    /// `GET url`. `Ok(None)` is the peer answering `404`.
    fn get(&self, url: &str) -> Result<Option<Vec<u8>>, FetchError>;
}

/// Why the peer did not answer. Carries no credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// The peer could not be reached.
    #[error("peer unavailable: {0}")]
    Unavailable(String),
    /// The peer answered and refused.
    #[error("peer refused {url}: {status}")]
    Refused {
        /// What was asked for.
        url: String,
        /// What the peer answered.
        status: u16,
    },
}

/// Why a mirror could not be built or written.
#[derive(Debug, thiserror::Error)]
pub enum MirrorError {
    /// The manifest names no peer.
    #[error("not a SharedSpaceReference or ContextSourceRegistration manifest")]
    NotAReference,
    /// The reference's spec does not parse or does not validate.
    #[error("reference spec: {0}")]
    Spec(String),
    /// A reference is mirrored into its own project, and this manifest names none.
    #[error("the reference has no namespace, so the mirror has no project to live in")]
    NoProject,
    /// The peer's surface is not `https://`. Refused before anything is requested.
    #[error("{0} is not an https:// schema surface, and a mirror is not fetched in the clear")]
    InsecureBase(String),
    /// The peer answered `schema/index.json` with something that is not a catalogue.
    #[error("the peer's schema/index.json is not a catalogue: {0}")]
    Index(String),
    /// The peer did not answer.
    #[error(transparent)]
    Fetch(#[from] FetchError),
    /// A mirror could not be written.
    #[error("{path}: {source}")]
    Io {
        /// What could not be written.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
}

/// What one model's mirror did to the repository (CC-18).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The repository held no mirror of this model and now does.
    Created,
    /// The repository's mirror already pins this digest; nothing is written.
    Unchanged,
    /// The peer publishes a different document than the repository pinned (DM-49).
    Changed,
}

impl Outcome {
    /// The name a plan prints.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Unchanged => "unchanged",
            Self::Changed => "changed",
        }
    }
}

/// One foreign DataModel, ready to be written.
#[derive(Debug, Clone, PartialEq)]
pub struct MirroredModel {
    /// The manifest, with `lifecycle: mirrored` and `source.remote` (DM-48).
    pub manifest: RawManifest,
    /// Repository path of the manifest (MF-06).
    pub path: PathBuf,
    /// The fetched documents, by the repository path each belongs at.
    pub files: BTreeMap<PathBuf, Vec<u8>>,
    /// What the repository already held.
    pub outcome: Outcome,
    /// The digest the repository's mirror pinned, when this run found a different one (DM-49).
    pub previous_sha256: Option<String>,
    /// Local Mappings reading this model, which a changed digest sends back for review (DM-49).
    pub affected_mappings: Vec<String>,
}

/// What one mirroring run produced.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Mirror {
    /// The foreign models, in the peer's catalogue order.
    pub models: Vec<MirroredModel>,
    /// What the plan has to say out loud: a peer without a schema surface, a model whose
    /// documents did not check out, a name that cannot be mirrored (DM-48).
    pub flags: Vec<String>,
}

impl Mirror {
    /// The JSON one line of a plan carries.
    pub fn to_json(&self) -> Value {
        json!({
            "summary": {
                "created": self.count(Outcome::Created),
                "changed": self.count(Outcome::Changed),
                "unchanged": self.count(Outcome::Unchanged),
                "flagged": self.flags.len(),
            },
            "models": self.models.iter().map(|model| json!({
                "name": model.manifest.metadata.name,
                "path": model.path.to_string_lossy(),
                "outcome": model.outcome.as_str(),
                "previousSha256": model.previous_sha256,
                "affectedMappings": model.affected_mappings,
            })).collect::<Vec<_>>(),
            "flags": self.flags,
        })
    }

    fn count(&self, outcome: Outcome) -> usize {
        self.models.iter().filter(|m| m.outcome == outcome).count()
    }
}

/// Where one reference's mirror lives and what it is named after.
struct Target<'a> {
    reference: &'a str,
    project: String,
    space: String,
}

/// Mirrors the peer a reference points at, without writing anything (DM-48).
///
/// `base` is the peer's surface without the trailing `schema/`, resolved by the reconciler:
/// `https://peer.example/api/endpoint/{slug}` or `https://peer.example/cs/{space}`.
/// `fetched_at` is an RFC 3339 timestamp; it goes into the manifest through the same serde
/// path that reads it back, so the repository's copy cannot drift from the one recorded here.
pub fn mirror(
    reference: &RawManifest,
    base: &str,
    fetched_at: &str,
    repo: &Repository,
    api: &impl SchemaApi,
) -> Result<Mirror, MirrorError> {
    let target = target_of(reference)?;
    let base = secure_base(base)?;

    let mut out = Mirror::default();
    let Some(body) = api.get(&format!("{base}/{INDEX}"))? else {
        out.flags.push(format!(
            "{base} publishes no {INDEX}; the reference stands without a model (DM-48)"
        ));
        return Ok(out);
    };

    let index: Value =
        serde_json::from_slice(&body).map_err(|err| MirrorError::Index(err.to_string()))?;
    let models = index
        .get("models")
        .and_then(Value::as_array)
        .ok_or_else(|| MirrorError::Index("no `models` array".to_owned()))?;

    for entry in models {
        if let Some(model) = one(&target, &base, fetched_at, entry, repo, api, &mut out.flags)? {
            out.models.push(model);
        }
    }
    Ok(out)
}

/// Writes a mirror into the repository, returning how many files it wrote.
///
/// An unchanged model is not rewritten: a reconciler that rewrote byte-identical files every
/// run would put a commit on the repository every day for nothing (CC-18).
pub fn write(repo_dir: &Path, mirror: &Mirror) -> Result<usize, MirrorError> {
    let mut written = 0;
    for model in &mirror.models {
        if model.outcome == Outcome::Unchanged {
            continue;
        }
        let yaml = serde_norway::to_string(&model.manifest).map_err(|err| MirrorError::Io {
            path: model.path.clone(),
            source: std::io::Error::other(err.to_string()),
        })?;
        put(repo_dir, &model.path, yaml.as_bytes())?;
        written += 1;
        for (path, body) in &model.files {
            put(repo_dir, path, body)?;
            written += 1;
        }
    }
    Ok(written)
}

fn put(repo_dir: &Path, relative: &Path, body: &[u8]) -> Result<(), MirrorError> {
    let path = repo_dir.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| MirrorError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    std::fs::write(&path, body).map_err(|source| MirrorError::Io {
        path: relative.to_path_buf(),
        source,
    })
}

/// The project and space a reference mirrors into.
///
/// A `SharedSpaceReference` names the remote space by its local alias, a
/// `ContextSourceRegistration` by the space it registers into; either way the mirror lives in
/// a local space of the reference's own project, never in another one (MF-06).
fn target_of(reference: &RawManifest) -> Result<Target<'_>, MirrorError> {
    let project = reference
        .metadata
        .namespace
        .clone()
        .ok_or(MirrorError::NoProject)?;
    let space = match reference.kind.as_str() {
        "SharedSpaceReference" => {
            let spec: jc_core::kinds::SharedSpaceReferenceSpec =
                serde_json::from_value(reference.spec.clone())
                    .map_err(|err| MirrorError::Spec(err.to_string()))?;
            spec.validate()
                .map_err(|e| MirrorError::Spec(e.to_string()))?;
            spec.alias
        }
        "ContextSourceRegistration" => {
            let spec: jc_core::kinds::ContextSourceRegistrationSpec =
                serde_json::from_value(reference.spec.clone())
                    .map_err(|err| MirrorError::Spec(err.to_string()))?;
            spec.validate()
                .map_err(|e| MirrorError::Spec(e.to_string()))?;
            spec.context_space_ref.name().to_owned()
        }
        _ => return Err(MirrorError::NotAReference),
    };
    Ok(Target {
        reference: &reference.metadata.name,
        project,
        space,
    })
}

/// The peer's base URL, checked before a single request is made.
fn secure_base(base: &str) -> Result<String, MirrorError> {
    let trimmed = base.trim_end_matches('/');
    if !trimmed.starts_with("https://")
        || trimmed.len() <= "https://".len()
        || trimmed.split('/').any(|segment| segment == "..")
    {
        return Err(MirrorError::InsecureBase(base.to_owned()));
    }
    Ok(trimmed.to_owned())
}

/// One catalogue entry as one foreign DataModel, or `None` with a flag saying why not.
#[allow(clippy::too_many_arguments)]
fn one(
    target: &Target<'_>,
    base: &str,
    fetched_at: &str,
    entry: &Value,
    repo: &Repository,
    api: &impl SchemaApi,
    flags: &mut Vec<String>,
) -> Result<Option<MirroredModel>, MirrorError> {
    let Some(peer_name) = entry.get("name").and_then(Value::as_str) else {
        flags.push(format!("{base} lists a model without a name; skipped"));
        return Ok(None);
    };
    // The peer's own name reaches the filesystem through the mirror's paths, so it is checked
    // before it is used for anything at all.
    if names::validate_dns1123_label(peer_name).is_err() {
        flags.push(format!(
            "{base} lists a model named `{peer_name}`, which is not a DNS-1123 label; skipped"
        ));
        return Ok(None);
    }
    let Some(semver) = entry.get("semver").and_then(Value::as_str) else {
        flags.push(format!(
            "{base} lists `{peer_name}` without a semver; skipped"
        ));
        return Ok(None);
    };
    let Some(major) = entry.get("version").and_then(Value::as_u64) else {
        flags.push(format!(
            "{base} lists `{peer_name}` without a served major version; skipped"
        ));
        return Ok(None);
    };

    let name = format!("{}-{peer_name}", target.reference);
    if names::validate_dns1123_label(&name).is_err() {
        flags.push(format!(
            "`{name}` is not a DNS-1123 label, so `{peer_name}` cannot be mirrored under \
             reference `{}`; rename the reference",
            target.reference
        ));
        return Ok(None);
    }

    let surface = format!("{base}/schema/v{major}");
    let declared = entry.get("artifacts").and_then(Value::as_object);
    let mut fetched: BTreeMap<&str, Vec<u8>> = BTreeMap::new();
    let mut pinned = String::new();
    for artifact in [LINKML, CONTEXT, EXAMPLE] {
        let Some(sha256) = declared
            .and_then(|map| map.get(artifact))
            .and_then(|d| d.get("sha256"))
            .and_then(Value::as_str)
        else {
            if artifact != EXAMPLE {
                flags.push(format!(
                    "{surface} does not publish {artifact} with a digest, so `{peer_name}` \
                     cannot be pinned; skipped"
                ));
                return Ok(None);
            }
            continue;
        };
        let url = format!("{surface}/{artifact}");
        let Some(body) = api.get(&url)? else {
            if artifact != EXAMPLE {
                flags.push(format!(
                    "{url} is in the catalogue but answers 404; skipped"
                ));
                return Ok(None);
            }
            continue;
        };
        // A document the peer's own catalogue does not vouch for is not written anywhere.
        let actual = hex(&Sha256::digest(&body));
        if actual != sha256 {
            flags.push(format!(
                "{url} does not match the digest its catalogue declares ({sha256}); `{peer_name}` skipped"
            ));
            return Ok(None);
        }
        if artifact == LINKML {
            pinned = actual;
        }
        fetched.insert(artifact, body);
    }
    let classes: Vec<&str> = entry
        .get("types")
        .and_then(Value::as_array)
        .map(|types| types.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    let mut artifacts = json!({ "context": format!("{name}/{CONTEXT}") });
    if fetched.contains_key(EXAMPLE) {
        artifacts["example"] = json!(format!("{name}/{EXAMPLE}"));
    }
    let spec = json!({
        "contextSpaceRef": target.space,
        "linkml": format!("{name}/{LINKML}"),
        "version": semver,
        "lifecycle": "mirrored",
        "classes": classes,
        "source": {
            // The URL of the document the digest is over, so a re-fetch checks the same bytes
            // this run pinned rather than a directory that may have grown a file since.
            "remote": {
                "url": format!("{surface}/{LINKML}"),
                "version": semver,
                "sha256": pinned,
                "fetchedAt": fetched_at,
            }
        },
        "artifacts": artifacts,
    });

    // Through the typed spec, so the mirror is refused by the same validation the Portal and
    // `jcctl validate` apply: https-only remote, a well-formed digest and timestamp, and the
    // DM-48 invariant that `mirrored` and `source.remote` imply each other.
    let typed: DataModelSpec = match serde_json::from_value(spec.clone()) {
        Ok(typed) => typed,
        Err(err) => {
            flags.push(format!(
                "`{peer_name}` does not mirror into a DataModel: {err}"
            ));
            return Ok(None);
        }
    };
    if let Err(err) = typed.validate() {
        flags.push(format!(
            "`{peer_name}` does not mirror into a DataModel: {err}"
        ));
        return Ok(None);
    }

    let manifest = RawManifest {
        api_version: API_VERSION.to_owned(),
        kind: "DataModel".to_owned(),
        metadata: RawMetadata {
            name: name.clone(),
            namespace: Some(target.project.clone()),
            rest: serde_json::Map::new(),
        },
        spec,
    };
    let path = PathBuf::from(
        registry::by_kind("DataModel")
            .expect("DataModel is a registered kind")
            .repo_path(&target.project, &target.space, &name),
    );
    let directory = path.parent().unwrap_or(Path::new("")).join(&name);
    let files = fetched
        .into_iter()
        .map(|(artifact, body)| (directory.join(artifact), body))
        .collect();

    let previous = pinned_sha256(repo, &target.project, &name);
    let (outcome, previous_sha256) = match previous {
        None => (Outcome::Created, None),
        Some(before) if before == pinned => (Outcome::Unchanged, None),
        Some(before) => (Outcome::Changed, Some(before)),
    };
    let affected_mappings = match outcome {
        Outcome::Changed => mappings_reading(repo, &target.project, &name, major),
        _ => Vec::new(),
    };

    Ok(Some(MirroredModel {
        manifest,
        path,
        files,
        outcome,
        previous_sha256,
        affected_mappings,
    }))
}

/// The digest the repository's mirror of this model pins, when it holds one.
fn pinned_sha256(repo: &Repository, project: &str, name: &str) -> Option<String> {
    let (_, resource) = repo.iter().find(|(id, _)| {
        id.kind == "DataModel" && id.name == name && id.namespace.as_deref() == Some(project)
    })?;
    resource
        .manifest
        .spec
        .get("source")?
        .get("remote")?
        .get("sha256")?
        .as_str()
        .map(str::to_owned)
}

/// The local Mappings that read this model version, which DM-49 sends a changed digest to.
fn mappings_reading(repo: &Repository, project: &str, name: &str, major: u64) -> Vec<String> {
    let major = major.to_string();
    repo.iter()
        .filter(|(id, _)| id.kind == "Mapping" && id.namespace.as_deref() == Some(project))
        .filter(|(_, resource)| {
            serde_json::from_value::<MappingSpec>(resource.manifest.spec.clone()).is_ok_and(
                |spec| {
                    [&spec.source, &spec.target]
                        .iter()
                        .any(|reference| reference.name == name && reference.version == major)
                },
            )
        })
        .map(|(id, _)| id.name.clone())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
