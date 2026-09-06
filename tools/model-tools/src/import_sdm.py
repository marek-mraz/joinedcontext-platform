"""Smart Data Models → LinkML (T-0171, DM-07…DM-11, DM-18).

The wizard hands over a catalogue identifier, `dataModel.Environment/AirQualityObserved`, and
gets a LinkML model back. Two halves, deliberately separate:

* `fetch` is the only code in Model Tools that opens a socket. It builds every URL itself from
  a validated identifier and refuses anything that does not land on the Smart Data Models
  organisation, so no caller can steer the fetch (DM-10).
* `convert` is a pure function over the three fetched documents. It is what the tests drive,
  and what CI re-runs to prove an import is reproducible from the recorded commit (DM-08).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

import requests
import yaml

from common import UPSTREAM_ANNOTATION

SDM_ORG = "smart-data-models"
SDM_NAMESPACE = "https://smartdatamodels.org/"
RAW_BASE = f"https://raw.githubusercontent.com/{SDM_ORG}/"
API_BASE = f"https://api.github.com/repos/{SDM_ORG}/"

#: Every URL Model Tools may open. A URL that does not start with one of these is refused
#: before a socket exists, whatever produced it (DM-10, DM-18).
ALLOWED_PREFIXES = (RAW_BASE, API_BASE)

#: The documents an import needs, at the paths the catalogue publishes them under. The schema
#: and the example are per model; the `@context` is **one per subject repository, at its
#: root**, because every model of a subject shares the same term definitions. Fetching it as
#: `{model}/context.jsonld` answers 404 for every model in the catalogue.
SCHEMA_FILE = "schema.json"
CONTEXT_FILE = "context.jsonld"
EXAMPLE_FILE = "examples/example-normalized.jsonld"

#: A catalogue identifier: `dataModel.<Subject>/<Model>`. The Portal already refuses anything
#: else (API/01 §11); Model Tools does not trust that it is the only caller.
IDENTIFIER = re.compile(r"^(?!\.)[A-Za-z0-9._-]{1,128}/(?!\.)[A-Za-z0-9._-]{1,128}$")

#: One path segment of a catalogue URL: a repository name, a model name or a ref. No slash and
#: no leading dot, so a segment can neither add a path of its own nor start a traversal.
SEGMENT = re.compile(r"^(?!\.)[A-Za-z0-9._-]{1,128}$")

#: Attributes that belong to every NGSI-LD entity and therefore to the shared import, not to
#: the imported model (DM-09).
CORE_SLOTS = ("id", "type", "location", "observedAt")

#: Everything `linkml:types` defines, which is every range an imported model may name without
#: declaring it. LinkML refuses to load a schema whose slot has an unrecognized range, so a
#: range outside this set has to be an enum or a class the document itself carries.
LINKML_TYPES = frozenset(
    {
        "boolean", "curie", "date", "date_or_datetime", "datetime", "decimal", "double",
        "float", "integer", "jsonpath", "jsonpointer", "ncname", "nodeidentifier",
        "objectidentifier", "sparqlpath", "string", "time", "uri", "uriorcurie",
    }
)

REQUEST_TIMEOUT = 20


class ImportError_(Exception):
    """An import that cannot proceed. The message reaches the person running the wizard."""


def split_identifier(model: str) -> tuple[str, str]:
    """`dataModel.Environment/AirQualityObserved` → (subject repository, model name)."""
    if not IDENTIFIER.match(model):
        raise ImportError_(
            f"'{model}' is not a Smart Data Models identifier "
            "(expected 'dataModel.<Subject>/<Model>'); a URL is never accepted"
        )
    subject, name = model.split("/", 1)
    return subject, name


def _segment(value: str, what: str) -> str:
    """One URL path segment, checked before it is put into a URL."""
    if not SEGMENT.match(value):
        raise ImportError_(f"'{value}' is not a usable {what} for a Smart Data Models URL")
    return value


def _get(url: str) -> requests.Response:
    """One HTTP GET, and only to the Smart Data Models organisation (DM-10).

    The prefix alone is not the check: `…/smart-data-models/../other-org/x` starts with the
    allowed prefix and still leaves the organisation once a server normalises it, so a URL
    carrying a traversal is refused as well.
    """
    if not url.startswith(ALLOWED_PREFIXES) or ".." in url:
        raise ImportError_(f"refusing to fetch outside the Smart Data Models allowlist: {url}")
    response = requests.get(url, timeout=REQUEST_TIMEOUT)
    if response.status_code != 200:
        raise ImportError_(f"{url} answered {response.status_code}")
    return response


def resolve_commit(subject: str, ref: str = "master") -> str:
    """The commit an import is pinned to, so a re-import is reproducible (DM-08).

    A ref is one segment: the catalogue's branches are plain names, and accepting a slash here
    would let a ref carry a path of its own.
    """
    url = f"{API_BASE}{_segment(subject, 'repository')}/commits/{_segment(ref, 'ref')}"
    return _get(url).json()["sha"]


def fetch(model: str, ref: str = "master") -> dict[str, Any]:
    """Fetch the documents one import needs, pinned to a commit."""
    subject, name = split_identifier(model)
    commit = resolve_commit(subject, ref)

    def document(filename: str, *, of_the_model: bool = True) -> Any:
        under = f"{name}/" if of_the_model else ""
        return _get(f"{RAW_BASE}{subject}/{commit}/{under}{filename}").json()

    return {
        "schema": document(SCHEMA_FILE),
        "context": document(CONTEXT_FILE, of_the_model=False),
        # A model without a published example is still importable; the example only seeds the
        # editor's preview and the golden test of a later Mapping.
        "example": _example(subject, name, commit),
        "provenance": {
            "repository": f"https://github.com/{SDM_ORG}/{subject}",
            "path": f"{name}/{SCHEMA_FILE}",
            "commit": commit,
        },
    }


def _example(subject: str, name: str, commit: str) -> Any | None:
    try:
        return _get(f"{RAW_BASE}{subject}/{commit}/{name}/{EXAMPLE_FILE}").json()
    except ImportError_:
        return None


def _term_kind(term: Any) -> str | None:
    """The NGSI-LD kind a `@context` term implies (DM-05).

    Smart Data Models does not annotate kinds, but its `@context` already says what a value
    is: an `@id` type is a relationship, a language container is a language map.
    """
    if not isinstance(term, dict):
        return None
    if term.get("@type") == "@id":
        return "Relationship"
    if term.get("@container") == "@language":
        return "LanguageProperty"
    return None


def _kind_of(slot_name: str, definition: dict[str, Any], context: dict[str, Any]) -> str:
    from_context = _term_kind(context.get(slot_name))
    if from_context:
        return from_context
    if slot_name == "location" or (definition.get("format") or "") == "geojson":
        return "GeoProperty"
    if definition.get("type") == "object":
        return "JsonProperty"
    if definition.get("type") == "array":
        return "ListProperty"
    return "Property"


#: JSON Schema string formats whose LinkML range schema-automator leaves at the default.
#: A timestamp typed as a string is a timestamp nothing can filter on (DM-20).
FORMAT_RANGES = {"date-time": "datetime", "date": "date", "time": "time", "uri": "uriorcurie"}


def _range_of(definition: dict[str, Any], imported: dict[str, Any]) -> str | None:
    return imported.get("range") or FORMAT_RANGES.get(definition.get("format") or "")


def _iri(slot_name: str, context: dict[str, Any]) -> str | None:
    """The canonical Smart Data Models IRI of a term, from the upstream `@context` (DM-09)."""
    term = context.get(slot_name)
    if isinstance(term, str):
        return term
    if isinstance(term, dict) and isinstance(term.get("@id"), str):
        return term["@id"]
    return None


def _composed(schema_json: dict[str, Any], key: str) -> dict[str, Any] | list[Any]:
    """`properties` or `required` of a catalogue schema, whichever branch declares them.

    A Smart Data Models schema declares almost nothing at its top level: it is an `allOf` of
    the shared commons, by `$ref`, and one inline branch carrying the model's own attributes.
    Reading only the top level imports a model with no slots at all.

    The `$ref`ed commons are not merged here. They live on `smart-data-models.github.io`,
    which the DM-10 allowlist does not cover, so importing them is a decision about the
    allowlist and not a line of code (T-0405).
    """
    merged: dict[str, Any] = {}
    order: list[Any] = []
    for branch in [*(schema_json.get("allOf") or []), schema_json]:
        if not isinstance(branch, dict):
            continue
        value = branch.get(key)
        if isinstance(value, dict):
            merged.update(value)
        elif isinstance(value, list):
            order.extend(item for item in value if item not in order)
    return order if key == "required" else merged


def _flattened(schema_json: dict[str, Any]) -> dict[str, Any]:
    """The catalogue schema as one object, with the `allOf` branches merged into the top.

    schema-automator derives the ranges and the enums, and it reads the top level too, so a
    schema handed over unflattened produces a model with no slots, no ranges and no enums.
    """
    flat = {key: value for key, value in schema_json.items() if key != "allOf"}
    flat["properties"] = _composed(schema_json, "properties")
    flat["required"] = _composed(schema_json, "required")
    return flat


def _automator_schema(schema_json: dict[str, Any], name: str) -> dict[str, Any]:
    """schema-automator's LinkML output for one JSON Schema, as plain data (DM-09)."""
    from linkml_runtime.dumpers import yaml_dumper
    from schema_automator.importers.jsonschema_import_engine import JsonSchemaImportEngine

    with NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
        json.dump(schema_json, handle)
        path = handle.name
    try:
        schema = JsonSchemaImportEngine().load(path, name=name, format="json")
    finally:
        Path(path).unlink(missing_ok=True)
    return yaml.safe_load(yaml_dumper.dumps(schema))


def convert(
    model: str,
    schema_json: dict[str, Any],
    context_jsonld: dict[str, Any],
    example: Any | None,
    provenance: dict[str, str],
) -> dict[str, Any]:
    """Turn the fetched documents into one LinkML model.

    Every upstream slot is kept (DM-11): a slot nobody uses locally is still what a federation
    partner sends, and a model that quietly drops it starts rejecting valid payloads.
    """
    _, name = split_identifier(model)
    context = context_jsonld.get("@context", {}) if isinstance(context_jsonld, dict) else {}
    if not isinstance(context, dict):
        raise ImportError_("the fetched context.jsonld has no object under @context")
    flat = _flattened(schema_json) if isinstance(schema_json, dict) else {}
    automator = _automator_schema(flat, name)
    properties = flat.get("properties") or {}
    required = flat.get("required") or []
    upstream = f"{provenance['repository']}@{provenance['commit']}"

    slots: dict[str, Any] = {}
    for slot_name, definition in properties.items():
        if slot_name in CORE_SLOTS:
            # Declared once in ngsi-ld-core and inherited, so every model agrees on them.
            continue
        imported = (automator.get("slots") or {}).get(slot_name, {})
        slot: dict[str, Any] = {
            "description": definition.get("description") or imported.get("description"),
            "range": _range_of(definition, imported),
            "required": slot_name in required,
            "annotations": {
                "ngsi_ld_kind": _kind_of(slot_name, definition, context),
                # The IRI below is upstream's; this is the citation that says so (DM-04).
                UPSTREAM_ANNOTATION: upstream,
            },
        }
        iri = _iri(slot_name, context)
        if iri:
            slot["slot_uri"] = iri
        slots[slot_name] = {k: v for k, v in slot.items() if v is not None and v is not False}

    # Enums schema-automator derived for a core slot (`type`) have no slot left to serve.
    referenced = {slot.get("range") for slot in slots.values()}
    enums = {k: v for k, v in (automator.get("enums") or {}).items() if k in referenced}

    # schema-automator names a nested object as a range (`address: Address`) and then defines
    # no such class, and LinkML refuses to load a schema with an unrecognized range, so the
    # whole import would compile to nothing. The attribute is kept and falls back to the
    # document's default range; what it loses is the shape of the nested object (T-0405).
    resolvable = LINKML_TYPES | set(enums) | {name}
    for slot in slots.values():
        if slot.get("range") and slot["range"] not in resolvable:
            del slot["range"]

    # Without a prefix every IRI is written out in full and every generator warns about it;
    # the upstream namespaces are known here, so they are declared once.
    prefixes = {"linkml": "https://w3id.org/linkml/"}
    if any(str(slot.get("slot_uri", "")).startswith(SDM_NAMESPACE) for slot in slots.values()):
        prefixes["sdm"] = SDM_NAMESPACE

    model_iri = _iri(name, context) or f"{provenance['repository']}#{name}"
    document: dict[str, Any] = {
        "id": f"{provenance['repository']}/{name}",
        "name": name,
        "title": schema_json.get("title") or name,
        "description": schema_json.get("description"),
        "prefixes": prefixes,
        "default_range": "string",
        "imports": ["linkml:types", "ngsi-ld-core"],
        "annotations": {
            "spec.source.repository": provenance["repository"],
            "spec.source.path": provenance["path"],
            "spec.source.commit": provenance["commit"],
        },
        "classes": {
            name: {
                "class_uri": model_iri,
                "description": schema_json.get("description"),
                "is_a": "Entity",
                "slots": sorted(slots),
                "annotations": {UPSTREAM_ANNOTATION: upstream},
            }
        },
        "slots": slots,
        # The enums schema-automator derived from `enum` keywords carry the permissible
        # values the gateway validates against, so they travel with the model.
        "enums": enums,
    }
    if example is not None:
        document["annotations"]["spec.source.example"] = json.dumps(example, sort_keys=True)
    return {k: v for k, v in document.items() if v not in (None, {}, [])}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("model", help="catalogue identifier, dataModel.Environment/AirQualityObserved")
    parser.add_argument("--ref", default="master", help="upstream branch or tag to pin from")
    parser.add_argument("-o", "--output", help="write here instead of stdout")
    args = parser.parse_args(argv)

    try:
        fetched = fetch(args.model, args.ref)
        document = convert(
            args.model,
            fetched["schema"],
            fetched["context"],
            fetched["example"],
            fetched["provenance"],
        )
    except (ImportError_, requests.RequestException) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    text = yaml.safe_dump(document, sort_keys=False, allow_unicode=True)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
