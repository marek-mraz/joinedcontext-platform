//! Error types and Result alias for `jc-core`.

/// Specific failure reason when constructing or parsing an entity URN.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum UrnError {
    /// URN prefix is missing or does not match `urn:ngsi-ld:` (case-insensitive).
    #[error("missing or invalid prefix, expected `urn:ngsi-ld:`")]
    InvalidPrefix,
    /// Colon-separated segment count after prefix is not exactly 4.
    #[error("expected exactly 4 colon-separated segments, got {got}")]
    InvalidSegmentCount {
        /// Number of segments found.
        got: usize,
    },
    /// A segment at the given index is empty.
    #[error("empty segment at index {index}")]
    EmptySegment {
        /// Zero-based segment index.
        index: usize,
    },
    /// The entity type segment failed validation.
    #[error("invalid entity type segment `{segment}`: {reason}")]
    InvalidEntityType {
        /// Offending segment text.
        segment: String,
        /// Reason for failure.
        reason: &'static str,
    },
    /// The organization domain segment failed validation.
    #[error("invalid orgDomain segment `{segment}`: {reason}")]
    InvalidOrgDomain {
        /// Offending segment text.
        segment: String,
        /// Reason for failure.
        reason: &'static str,
    },
    /// The space segment failed validation.
    #[error("invalid space segment `{segment}`: {reason}")]
    InvalidSpace {
        /// Offending segment text.
        segment: String,
        /// Reason for failure.
        reason: &'static str,
    },
    /// The local identifier segment failed validation.
    #[error("invalid localId segment `{segment}`: {reason}")]
    InvalidLocalId {
        /// Offending segment text.
        segment: String,
        /// Reason for failure.
        reason: &'static str,
    },
}

/// Primary error enum for `jc-core`.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum Error {
    /// An entity URN is invalid.
    #[error("invalid URN `{urn}`: {reason}")]
    Urn {
        /// The raw URN string.
        urn: String,
        /// Specific failure reason.
        reason: UrnError,
    },
    /// An identifier or field value failed validation.
    #[error("invalid {field} `{value}`: {reason}")]
    Name {
        /// Name of the field that failed validation.
        field: &'static str,
        /// The invalid value.
        value: String,
        /// Human-readable explanation.
        reason: &'static str,
    },
    /// The manifest apiVersion does not match joinedcontext.com/v1alpha1.
    #[error("apiVersion must be `joinedcontext.com/v1alpha1`, got `{0}`")]
    ApiVersion(String),
    /// The manifest kind does not match the expected kind for the struct.
    #[error("kind must be `{expected}`, got `{got}`")]
    Kind {
        /// Expected kind name.
        expected: &'static str,
        /// Actual kind encountered.
        got: String,
    },
    /// A language code is not an ISO 639-1 two-letter code.
    #[error("locale `{0}` is not an ISO 639-1 two-letter code")]
    Locale(String),
    /// The designated fallback locale has no translation in the map.
    #[error("no value for the fallback locale `{0}`")]
    MissingFallbackLocale(String),
}

/// Result type alias for operations in `jc-core`.
pub type Result<T> = std::result::Result<T, Error>;
