//! Serving one space as somebody else's model (T-0175, EP-54, DM-51, DM-52).
//!
//! An Endpoint with `spec.viewMappingRef` publishes the *target* model of a Mapping. The
//! broker knows only the source model, so the gateway stands in the middle and runs the
//! Mapping's compiled IR in both directions: the caller's query is inverted on the way out,
//! and every entity is rebuilt on the way back.
//!
//! The IR is the JSON artifact Model Tools compiles from the same specification as the
//! Bloblang Bento runs, and DM-39's golden tests run against both, so the two executors
//! cannot answer differently. Nothing here parses LinkML-Map: this module only interprets an
//! IR that was already reduced to the invertible subset DM-51 allows.
//!
//! A view is read only. A mapping is invertible per slot, not per entity — a required source
//! slot no target slot derives has no value to reconstruct, and a constant or an `expr` slot
//! has none at all — so a write in the target model is refused rather than half-inverted.

use jc_core::ProblemDetails;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// The IR schema version this interpreter understands (DM-52).
pub const IR_VERSION: u64 = 1;

/// The members of an entity that belong to NGSI-LD rather than to a model, and travel
/// through a view untouched. `type` is not one of them: a view answers with the target class.
const STRUCTURAL: &[&str] = &["id", "@id", "@context", "scope"];

/// The members the broker generates, which a view keeps for the same reason a projection does
/// (EP-71): they say when the data was written and who answered, not what it contains.
const SYSTEM: &[&str] = &["createdAt", "modifiedAt", "deletedAt", "expiresAt"];

/// Why an IR document is not one this gateway can run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidIr {
    /// The document is not the JSON object an IR is.
    #[error("the mapping IR is not an object")]
    Malformed,
    /// A version this interpreter does not know, which is a Model Tools newer than this build.
    #[error("the mapping IR is version {0}, and this gateway interprets version {IR_VERSION}")]
    Version(u64),
    /// A slot entry the interpreter cannot make sense of.
    #[error("mapping IR slot {index}: {reason}")]
    Slot {
        /// Which entry.
        index: usize,
        /// What is wrong with it.
        reason: String,
    },
}

/// What one target slot is made of.
#[derive(Debug, Clone, PartialEq)]
pub enum Derivation {
    /// The target slot is the source slot under another name.
    Rename,
    /// A linear conversion of the source value: `value * factor + offset`.
    UnitConversion {
        /// The multiplier, source to target.
        factor: f64,
        /// The offset, added after the multiplication.
        offset: f64,
    },
    /// A finite value table with both directions precomputed.
    ValueMappings {
        /// Source value to target value.
        forward: BTreeMap<String, Value>,
        /// Target value back to source value; the compiler refuses a table without one.
        inverse: BTreeMap<String, Value>,
    },
    /// The source value read as another type.
    Cast(Cast),
    /// A value that depends on no source slot at all.
    Constant(Value),
    /// A computed slot. The IR carries no expression, so live translation neither produces
    /// nor filters it (DM-51).
    Expr,
}

/// The casts the IR uses, matching the reference engine exactly (DM-39).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cast {
    /// Python `int()`: truncates towards zero, refuses a non-integer literal.
    Integer,
    /// Python `float()`.
    Float,
    /// Python `str()`.
    String,
}

/// One target slot of the mapping.
#[derive(Debug, Clone, PartialEq)]
pub struct Slot {
    /// The name the view serves.
    pub target: String,
    /// The name the broker knows, absent for a slot that derives from no source slot.
    pub source: Option<String>,
    /// How the value is derived.
    pub derivation: Derivation,
    /// Whether a filter may name this slot, which is whether the derivation has an inverse.
    pub filterable: bool,
}

/// A compiled Mapping, ready to run in both directions.
#[derive(Debug, Clone, PartialEq)]
pub struct ViewMapping {
    /// The class the broker holds.
    pub source_class: String,
    /// The class the view serves.
    pub target_class: String,
    slots: Vec<Slot>,
}

impl ViewMapping {
    /// Reads one compiled mapping IR document (DM-52).
    pub fn parse(document: &Value) -> Result<Self, InvalidIr> {
        let members = document.as_object().ok_or(InvalidIr::Malformed)?;
        let version = members
            .get("version")
            .and_then(Value::as_u64)
            .ok_or(InvalidIr::Malformed)?;
        if version != IR_VERSION {
            return Err(InvalidIr::Version(version));
        }

        let slots = members
            .get("slots")
            .and_then(Value::as_array)
            .ok_or(InvalidIr::Malformed)?
            .iter()
            .enumerate()
            .map(|(index, entry)| slot(index, entry))
            .collect::<Result<Vec<Slot>, InvalidIr>>()?;

        Ok(Self {
            source_class: text(members.get("sourceClass")).unwrap_or_default(),
            target_class: text(members.get("targetClass")).unwrap_or_default(),
            slots,
        })
    }

    /// The slot a target name refers to.
    pub fn by_target(&self, name: &str) -> Option<&Slot> {
        self.slots.iter().find(|slot| slot.target == name)
    }

    /// The source name a target name reads, when the derivation has one.
    pub fn source_of(&self, target: &str) -> Option<&str> {
        self.by_target(target)?.source.as_deref()
    }

    /// Rebuilds one entity, or a whole answer, in the target model (EP-54).
    pub fn translate(&self, body: &mut Value) {
        match body {
            Value::Array(entities) => {
                for entity in entities {
                    self.translate_entity(entity);
                }
            }
            entity => self.translate_entity(entity),
        }
    }

    /// Rebuilds one entity in the target model.
    ///
    /// Everything the mapping does not derive is dropped: a view serves the target model, and
    /// an attribute that leaks through under its source name is one no target schema
    /// describes.
    pub fn translate_entity(&self, entity: &mut Value) {
        let Some(members) = entity.as_object() else {
            return;
        };
        // Not an entity: a problem document, a type list, an attribute list.
        if !members.contains_key("id") && !members.contains_key("@id") {
            return;
        }

        let mut translated = Map::new();
        for name in STRUCTURAL.iter().chain(SYSTEM.iter()) {
            if let Some(value) = members.get(*name) {
                translated.insert((*name).to_owned(), value.clone());
            }
        }
        translated.insert("type".to_owned(), Value::String(self.target_class.clone()));

        for slot in &self.slots {
            if let Derivation::Constant(value) = &slot.derivation {
                translated.insert(slot.target.clone(), value.clone());
                continue;
            }
            let Some(source) = slot.source.as_deref() else {
                // An `expr` slot: the IR carries no expression, so nothing can be computed
                // for it here (DM-51).
                continue;
            };
            let Some(attribute) = members.get(source) else {
                continue;
            };
            translated.insert(slot.target.clone(), forward(&slot.derivation, attribute));
        }
        *entity = Value::Object(translated);
    }

    /// The `attrs` a caller asked for, in the source model's names (DM-51).
    ///
    /// A name the mapping does not define is a bad request rather than a silent omission: the
    /// caller asked for something this view does not serve, and answering as if they had not
    /// asked is how a client concludes the data is missing.
    pub fn invert_attrs(&self, attrs: &str) -> Result<String, Box<ProblemDetails>> {
        let mut sources = Vec::new();
        for asked in attrs.split(',').map(str::trim).filter(|a| !a.is_empty()) {
            let Some(slot) = self.by_target(asked) else {
                return Err(Box::new(unknown(asked)));
            };
            // A constant or an `expr` is produced here, so the broker is not asked for it.
            if let Some(source) = &slot.source {
                sources.push(source.clone());
            }
        }
        Ok(sources.join(","))
    }

    /// The `geoproperty` a caller named, in the source model's name.
    pub fn invert_geo_property(&self, name: &str) -> Result<String, Box<ProblemDetails>> {
        match self.by_target(name) {
            Some(slot) if slot.filterable => {
                Ok(slot.source.clone().unwrap_or_else(|| slot.target.clone()))
            }
            Some(_) => Err(Box::new(not_filterable(name))),
            None => Err(Box::new(unknown(name))),
        }
    }

    /// The caller's `q`, rewritten into the source model (DM-51).
    ///
    /// Attribute names become source names and a compared value goes back through the slot's
    /// own inverse, so a filter written in the target model reaches the broker as a filter
    /// the broker's own data satisfies.
    pub fn invert_q(&self, filter: &str) -> Result<String, Box<ProblemDetails>> {
        let mut out = String::with_capacity(filter.len());
        let mut term = String::new();
        for character in filter.chars() {
            match character {
                ';' | '|' | '(' | ')' => {
                    out.push_str(&self.invert_term(&term)?);
                    term.clear();
                    out.push(character);
                }
                _ => term.push(character),
            }
        }
        out.push_str(&self.invert_term(&term)?);
        Ok(out)
    }

    /// One comparison of a `q`, or one bare attribute name (an existence check).
    fn invert_term(&self, term: &str) -> Result<String, Box<ProblemDetails>> {
        if term.trim().is_empty() {
            return Ok(term.to_owned());
        }
        let (name, operator, value) = match split_comparison(term) {
            Some(split) => split,
            None => (term, "", ""),
        };
        let attribute = name.trim();
        // A negated existence check is `!attribute`, and the `!` belongs to the term rather
        // than to the name.
        let (prefix, attribute) = match attribute.strip_prefix('!') {
            Some(rest) => ("!", rest.trim()),
            None => ("", attribute),
        };

        let Some(slot) = self.by_target(attribute) else {
            return Err(Box::new(unknown(attribute)));
        };
        if !slot.filterable {
            return Err(Box::new(not_filterable(attribute)));
        }
        let source = slot.source.as_deref().unwrap_or(&slot.target);
        if operator.is_empty() {
            return Ok(format!("{prefix}{source}"));
        }
        let inverted = value
            .split(',')
            .map(|one| invert_value(&slot.derivation, one))
            .collect::<Vec<_>>()
            .join(",");
        Ok(format!("{prefix}{source}{operator}{inverted}"))
    }
}

/// The comparison operators of the NGSI-LD query language, longest first so `>=` is never
/// read as `>` (CIM 009 clause 4.9).
const OPERATORS: &[&str] = &["==", "!=", ">=", "<=", "~=", ">", "<"];

/// Splits one term into its attribute, its operator and its value.
fn split_comparison(term: &str) -> Option<(&str, &str, &str)> {
    OPERATORS
        .iter()
        .filter_map(|operator| term.find(operator).map(|at| (at, *operator)))
        .min_by_key(|(at, _)| *at)
        .map(|(at, operator)| (&term[..at], operator, &term[at + operator.len()..]))
}

/// The source value a target value in a filter stands for.
fn invert_value(derivation: &Derivation, value: &str) -> String {
    let trimmed = value.trim();
    let (quote, bare) = match trimmed.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        Some(bare) => ("\"", bare),
        None => ("", trimmed),
    };
    match derivation {
        Derivation::ValueMappings { inverse, .. } => match inverse.get(bare) {
            Some(source) => format!("{quote}{}{quote}", plain(source)),
            // A value the table does not name matches nothing on either side, so it is sent
            // as it stands and the broker answers with nothing, which is the truth.
            None => value.to_owned(),
        },
        Derivation::UnitConversion { factor, offset } if *factor != 0.0 => {
            match bare.parse::<f64>() {
                Ok(number) => render((number - offset) / factor),
                Err(_) => value.to_owned(),
            }
        }
        _ => value.to_owned(),
    }
}

/// The target value one source value becomes.
fn forward(derivation: &Derivation, attribute: &Value) -> Value {
    match derivation {
        Derivation::Rename | Derivation::Expr | Derivation::Constant(_) => attribute.clone(),
        Derivation::UnitConversion { factor, offset } => {
            map_value(attribute, |value| match value.as_f64() {
                Some(source) => number_value(source * factor + offset),
                None => value.clone(),
            })
        }
        Derivation::ValueMappings { forward, .. } => {
            map_value(attribute, |value| match forward.get(&plain(value)) {
                Some(target) => target.clone(),
                None => value.clone(),
            })
        }
        Derivation::Cast(cast) => map_value(attribute, |value| cast_value(*cast, value)),
    }
}

/// Applies `transform` to an attribute's value, whatever NGSI-LD shape it is in.
///
/// A normalized attribute carries its value under `value` or `object`; a key-value one is the
/// value itself. Both forms reach a view, because the representation is the caller's choice.
fn map_value(attribute: &Value, transform: impl Fn(&Value) -> Value) -> Value {
    let Some(members) = attribute.as_object() else {
        return transform(attribute);
    };
    let Some(key) = ["value", "object"]
        .into_iter()
        .find(|key| members.contains_key(*key))
    else {
        return attribute.clone();
    };
    let mut translated = members.clone();
    translated.insert(key.to_owned(), transform(&members[key]));
    Value::Object(translated)
}

/// One cast, matching the reference engine (DM-39): a value the cast cannot make is left as
/// it is rather than becoming null, because a view must not invent data.
fn cast_value(cast: Cast, value: &Value) -> Value {
    match cast {
        Cast::String => Value::String(plain(value)),
        Cast::Float => match value.as_f64() {
            Some(number) => number_value(number),
            None => plain(value)
                .parse::<f64>()
                .map_or_else(|_| value.clone(), number_value),
        },
        Cast::Integer => match value.as_f64() {
            // Python `int()` truncates towards zero: -4.7 is -4, not -5.
            Some(float) => Value::from(float.trunc() as i64),
            None => plain(value)
                .parse::<i64>()
                .map_or_else(|_| value.clone(), Value::from),
        },
    }
}

/// A JSON number, or a string when the value is not finite: JSON has no NaN.
fn number_value(value: f64) -> Value {
    serde_json::Number::from_f64(value).map_or_else(|| Value::Null, Value::Number)
}

/// A JSON value as the plain text a mapping table and a `q` are written with.
fn plain(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// A number as the shortest text that round-trips, so an inverted filter reads like one a
/// person would have written.
fn render(value: f64) -> String {
    let rounded = (value * 1e9).round() / 1e9;
    if rounded.fract() == 0.0 && rounded.abs() < 1e15 {
        return format!("{}", rounded as i64);
    }
    format!("{rounded}")
}

fn text(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(str::to_owned)
}

/// One slot entry of the IR.
fn slot(index: usize, entry: &Value) -> Result<Slot, InvalidIr> {
    let refuse = |reason: &str| InvalidIr::Slot {
        index,
        reason: reason.to_owned(),
    };
    let members = entry.as_object().ok_or_else(|| refuse("not an object"))?;
    let target = text(members.get("target")).ok_or_else(|| refuse("names no target slot"))?;
    let source = text(members.get("source"));
    let kind = text(members.get("kind")).ok_or_else(|| refuse("names no kind"))?;

    let derivation = match kind.as_str() {
        "rename" => Derivation::Rename,
        "expr" => Derivation::Expr,
        "constant" => Derivation::Constant(
            members
                .get("value")
                .cloned()
                .ok_or_else(|| refuse("a constant carries no value"))?,
        ),
        "unitConversion" => Derivation::UnitConversion {
            factor: members
                .get("factor")
                .and_then(Value::as_f64)
                .ok_or_else(|| refuse("a unit conversion carries no factor"))?,
            offset: members
                .get("offset")
                .and_then(Value::as_f64)
                .unwrap_or_default(),
        },
        "valueMappings" => Derivation::ValueMappings {
            forward: table(members.get("forward")).ok_or_else(|| refuse("no forward table"))?,
            inverse: table(members.get("inverse")).ok_or_else(|| refuse("no inverse table"))?,
        },
        "cast" => Derivation::Cast(match text(members.get("range")).as_deref() {
            Some("integer") => Cast::Integer,
            Some("float") => Cast::Float,
            Some("string") => Cast::String,
            other => {
                return Err(refuse(&format!(
                    "cast to `{}` is not one this gateway performs",
                    other.unwrap_or("?")
                )))
            }
        }),
        other => {
            return Err(refuse(&format!(
                "kind `{other}` is not one this gateway runs"
            )))
        }
    };

    if source.is_none() && !matches!(derivation, Derivation::Constant(_) | Derivation::Expr) {
        return Err(refuse("names no source slot"));
    }
    Ok(Slot {
        target,
        source,
        // The compiler decides this, and a slot with no inverse must not become filterable
        // because this interpreter thinks it could manage.
        filterable: members
            .get("filterable")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        derivation,
    })
}

fn table(value: Option<&Value>) -> Option<BTreeMap<String, Value>> {
    Some(
        value?
            .as_object()?
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    )
}

/// The refusal for a target attribute this view does not serve.
fn unknown(name: &str) -> ProblemDetails {
    ProblemDetails::bad_request().with_detail(format!(
        "`{name}` is not an attribute of the model this endpoint serves"
    ))
}

/// The refusal for a slot the mapping cannot invert (DM-51).
fn not_filterable(name: &str) -> ProblemDetails {
    ProblemDetails::bad_request().with_detail(format!(
        "`{name}` is computed by the view and has no source attribute to filter on, so it \
         cannot appear in a query"
    ))
}

/// The refusal every write to a view endpoint answers with (EP-54).
pub fn read_only() -> ProblemDetails {
    ProblemDetails::new(405, "read-only-view", "Method Not Allowed").with_detail(
        "this endpoint serves a mapped view of another model, which is read only: a mapping \
         is invertible per attribute, not per entity, so a write has no source entity to \
         reconstruct",
    )
}
