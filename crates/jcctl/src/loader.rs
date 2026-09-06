//! Repository walker and manifest loader (T-0124, CC-08, CC-09, CC-10, MF-05, MF-06).

use jc_core::registry;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// One manifest loaded from the repository, kept untyped (CC-09, MF-05).
#[derive(Debug, Clone, PartialEq)]
pub struct LoadedResource {
    /// Repository-relative path of the file it came from (MF-06).
    pub path: PathBuf,
    /// 1-based index of the YAML document inside that file (MF-05).
    pub document: usize,
    /// 1-based line in the file where this document starts, for diagnostics.
    pub line: usize,
    /// `apiVersion`, `kind`, `metadata` and `spec` exactly as written (MF-01).
    pub manifest: RawManifest,
}

/// The four envelope members every manifest carries (MF-01).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RawManifest {
    /// Canonical API version string (MF-01).
    pub api_version: String,
    /// Manifest kind name (MF-01).
    pub kind: String,
    /// Manifest metadata block (MF-02).
    pub metadata: RawMetadata,
    /// Manifest specification payload, unparsed for untyped handling (MF-03).
    #[serde(default)]
    pub spec: serde_json::Value,
}

/// The metadata members the loader needs to build an identity (MF-02, MF-06).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawMetadata {
    /// Resource DNS-1123 name (MF-02).
    pub name: String,
    /// Resource namespace (project slug or `org`), if present (MF-02).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Remaining metadata attributes preserved for fidelity (MF-02).
    #[serde(flatten)]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

/// `(group, kind, namespace, name)`, the identity a resource is indexed by (MF-06).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceId {
    /// The API group segment before `/` in `apiVersion` (MF-06).
    pub group: String,
    /// Manifest kind name (MF-06).
    pub kind: String,
    /// Resource namespace, absent for organization-level resources (MF-06).
    pub namespace: Option<String>,
    /// Resource name (MF-06).
    pub name: String,
}

impl ResourceId {
    /// Creates a new resource identifier from individual components (MF-06).
    pub fn new(
        group: impl Into<String>,
        kind: impl Into<String>,
        namespace: Option<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            group: group.into(),
            kind: kind.into(),
            namespace,
            name: name.into(),
        }
    }

    /// Derives a resource identifier from a loaded raw manifest envelope (MF-06).
    pub fn from_manifest(manifest: &RawManifest) -> Self {
        let group = match manifest.api_version.split_once('/') {
            Some((g, _)) => g.to_string(),
            None => manifest.api_version.clone(),
        };
        Self {
            group,
            kind: manifest.kind.clone(),
            namespace: manifest.metadata.namespace.clone(),
            name: manifest.metadata.name.clone(),
        }
    }
}

impl fmt::Display for ResourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.namespace {
            Some(ns) => write!(f, "{}/{}/{}", self.kind, ns, self.name),
            None => write!(f, "{}/{}", self.kind, self.name),
        }
    }
}

/// Errors that can occur when loading an organization repository (CC-08, MF-06).
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// File path or symlink target escapes repository root (CC-08).
    #[error("path escapes repository root: {path}")]
    PathEscapesRepository {
        /// Relative path that escapes repository root.
        path: PathBuf,
    },

    /// Manifest apiVersion does not match the canonical API version (MF-01).
    #[error("manifest in {path} (document {document}) has invalid apiVersion `{got}`, expected `{expected}`")]
    ApiVersion {
        /// Repository-relative file path where the error occurred.
        path: PathBuf,
        /// 1-based index of YAML document in file.
        document: usize,
        /// Expected API version string.
        expected: &'static str,
        /// Actual API version encountered.
        got: String,
    },

    /// Manifest kind is not recognized by the kind registry (MF-09).
    #[error("manifest in {path} (document {document}) has unknown kind `{kind}`")]
    UnknownKind {
        /// Repository-relative file path where the error occurred.
        path: PathBuf,
        /// 1-based index of YAML document in file.
        document: usize,
        /// Unknown kind name encountered.
        kind: String,
    },

    /// Two manifests share the same resource identity (MF-06).
    #[error("duplicate resource identity {id}: first declared in {first}, duplicate in {second}")]
    DuplicateIdentity {
        /// Conflicting resource identity, boxed to keep `LoadError` small.
        id: Box<ResourceId>,
        /// Repository-relative path of the first declaration.
        first: PathBuf,
        /// Repository-relative path of the duplicate declaration.
        second: PathBuf,
    },

    /// Underlying I/O error occurred while reading the repository (CC-08).
    #[error("I/O error reading {path}: {source}")]
    Io {
        /// Path where the I/O error occurred.
        path: PathBuf,
        /// Underlying I/O error source.
        #[source]
        source: std::io::Error,
    },

    /// Manifest document failed YAML parsing (MF-05).
    #[error("failed to parse YAML in {path} (document {document}, line {line}): {message}")]
    Parse {
        /// Repository-relative file path where the error occurred.
        path: PathBuf,
        /// 1-based index of YAML document in file.
        document: usize,
        /// 1-based line number where the document starts.
        line: usize,
        /// Parser error message.
        message: String,
    },
}

/// In-memory indexed repository of loaded manifests (CC-08, MF-06).
#[derive(Debug, Clone, PartialEq)]
pub struct Repository {
    root: PathBuf,
    resources: BTreeMap<ResourceId, LoadedResource>,
}

impl Repository {
    /// Loads and indexes an organization repository from a directory path (CC-08, MF-06).
    pub fn load(root: &Path) -> Result<Self, LoadError> {
        let canonical_root = root.canonicalize().map_err(|source| LoadError::Io {
            path: root.to_path_buf(),
            source,
        })?;

        let mut entries = Vec::new();
        let mut it = WalkDir::new(root).follow_links(false).into_iter();

        loop {
            let entry = match it.next() {
                None => break,
                Some(Ok(entry)) => entry,
                Some(Err(err)) => {
                    return Err(LoadError::Io {
                        path: err.path().unwrap_or(root).to_path_buf(),
                        source: err.into(),
                    });
                }
            };

            if entry.depth() == 0 {
                continue;
            }

            if entry.file_type().is_dir()
                && entry
                    .file_name()
                    .to_str()
                    .is_some_and(|s| s.starts_with('.'))
            {
                it.skip_current_dir();
                continue;
            }

            entries.push(entry);
        }

        entries.sort_by(|a, b| a.path().cmp(b.path()));

        let mut resources: BTreeMap<ResourceId, LoadedResource> = BTreeMap::new();

        for entry in entries {
            let rel_path = entry
                .path()
                .strip_prefix(root)
                .unwrap_or(entry.path())
                .to_path_buf();

            if entry.path_is_symlink() {
                match entry.path().canonicalize() {
                    Ok(canonical) => {
                        if !canonical.starts_with(&canonical_root) {
                            return Err(LoadError::PathEscapesRepository { path: rel_path });
                        }
                    }
                    Err(_) => {
                        return Err(LoadError::PathEscapesRepository { path: rel_path });
                    }
                }
                if !entry.file_type().is_file() {
                    continue;
                }
            } else {
                let canonical = entry
                    .path()
                    .canonicalize()
                    .map_err(|source| LoadError::Io {
                        path: rel_path.clone(),
                        source,
                    })?;
                if !canonical.starts_with(&canonical_root) {
                    return Err(LoadError::PathEscapesRepository { path: rel_path });
                }
                if !entry.file_type().is_file() {
                    continue;
                }
            }

            let file_name = match entry.file_name().to_str() {
                Some(s) => s,
                None => continue,
            };

            if !file_name.ends_with(".yaml") && !file_name.ends_with(".yml") {
                continue;
            }

            if file_name.ends_with(".linkml.yaml") || file_name == "bento.yaml" {
                continue;
            }

            let content =
                std::fs::read_to_string(entry.path()).map_err(|source| LoadError::Io {
                    path: rel_path.clone(),
                    source,
                })?;

            let chunks = parse_yaml_documents(&content);
            for chunk in chunks {
                if is_empty_doc(&chunk.content) {
                    continue;
                }

                let manifest: RawManifest = match serde_norway::from_str(&chunk.content) {
                    Ok(m) => m,
                    Err(e) => {
                        return Err(LoadError::Parse {
                            path: rel_path,
                            document: chunk.document_index,
                            line: chunk.start_line,
                            message: e.to_string(),
                        });
                    }
                };

                if manifest.api_version != jc_core::API_VERSION {
                    return Err(LoadError::ApiVersion {
                        path: rel_path,
                        document: chunk.document_index,
                        expected: jc_core::API_VERSION,
                        got: manifest.api_version,
                    });
                }

                if registry::by_kind(&manifest.kind).is_none() {
                    return Err(LoadError::UnknownKind {
                        path: rel_path,
                        document: chunk.document_index,
                        kind: manifest.kind,
                    });
                }

                let id = ResourceId::from_manifest(&manifest);
                if let Some(existing) = resources.get(&id) {
                    return Err(LoadError::DuplicateIdentity {
                        id: Box::new(id),
                        first: existing.path.clone(),
                        second: rel_path,
                    });
                }

                resources.insert(
                    id,
                    LoadedResource {
                        path: rel_path.clone(),
                        document: chunk.document_index,
                        line: chunk.start_line,
                        manifest,
                    },
                );
            }
        }

        Ok(Self {
            root: root.to_path_buf(),
            resources,
        })
    }

    /// Looks up a loaded resource by its identity (MF-06).
    pub fn get(&self, id: &ResourceId) -> Option<&LoadedResource> {
        self.resources.get(id)
    }

    /// Iterates over all loaded resources in deterministic `ResourceId` sorted order (CC-18).
    pub fn iter(&self) -> impl Iterator<Item = (&ResourceId, &LoadedResource)> {
        self.resources.iter()
    }

    /// Returns the total count of loaded resources in the repository.
    pub fn len(&self) -> usize {
        self.resources.len()
    }

    /// Returns `true` if the repository contains no loaded resources.
    pub fn is_empty(&self) -> bool {
        self.resources.is_empty()
    }

    /// Returns the root path of the organization repository (CC-08).
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Computes the expected repository path for a resource based on its kind template (MF-06).
    pub fn expected_path(&self, id: &ResourceId) -> Option<String> {
        let loaded = self.resources.get(id)?;
        let kind_info = registry::by_kind(&id.kind)?;
        let project = id.namespace.as_deref().unwrap_or("");
        let space = extract_space(&loaded.manifest.spec);
        Some(kind_info.repo_path(project, space, &id.name))
    }

    /// Lists resources whose repository path differs from their canonical path template (MF-06).
    pub fn misplaced(&self) -> Vec<(ResourceId, PathBuf, String)> {
        let mut result = Vec::new();
        for (id, loaded) in &self.resources {
            if let Some(expected) = self.expected_path(id) {
                if loaded.path != Path::new(&expected) {
                    result.push((id.clone(), loaded.path.clone(), expected));
                }
            }
        }
        result
    }
}

/// The `{space}` placeholder of a path template: every space-scoped kind names it
/// `contextSpaceRef` (Architecture/06 section 2).
fn extract_space(spec: &serde_json::Value) -> &str {
    spec.get("contextSpaceRef")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
}

fn is_empty_doc(s: &str) -> bool {
    s.lines().all(|line| {
        let t = line.trim();
        t.is_empty() || t.starts_with('#') || t == "..."
    })
}

struct DocChunk {
    document_index: usize,
    start_line: usize,
    content: String,
}

/// A line that starts a YAML document: `---` at column 0. An indented `---` belongs to
/// a block scalar (a `linkml:` payload, say) and must not split the file.
fn is_doc_separator(line: &str) -> bool {
    let line = line.trim_end();
    line == "---"
        || line
            .strip_prefix("---")
            .is_some_and(|r| r.starts_with([' ', '\t']))
}

/// Splits a file into its YAML documents, keeping the 1-based document index and start
/// line of each for diagnostics. Empty documents count towards the index, as they do in
/// the YAML stream, so `document 3` means the third `---` block a reader sees.
fn parse_yaml_documents(text: &str) -> Vec<DocChunk> {
    let mut chunks: Vec<DocChunk> = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    let mut start_line = 1;

    for (i, line) in text.lines().enumerate() {
        if !is_doc_separator(line) {
            current.push(line);
            continue;
        }
        // A leading `---` opens the first document rather than closing an empty one.
        let file_start = chunks.is_empty() && current.iter().all(|l| is_empty_doc(l));
        if !file_start {
            chunks.push(DocChunk {
                document_index: chunks.len() + 1,
                start_line,
                content: current.join("\n"),
            });
        }
        current.clear();
        start_line = i + 1;
    }

    if !current.is_empty() {
        chunks.push(DocChunk {
            document_index: chunks.len() + 1,
            start_line,
            content: current.join("\n"),
        });
    }

    chunks
}
