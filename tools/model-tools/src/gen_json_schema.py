"""LinkML → JSON Schema draft-07 (T-0168, DM-02, DM-03, DM-18, TS-18).

`gen-json-schema` renders 2019-09. The gateway validates every write against these schemas
with a draft-07 validator (CC-12, stack verdict S4), and a 2019-09 keyword there is not a
validation error but a silently ignored constraint, so the dialect is converted here rather
than hoped for.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from linkml.generators.jsonschemagen import JsonSchemaGenerator
from linkml_runtime import SchemaView

from common import ModelError, generator_version, load, ngsi_ld_kind, slots_of, unit_of

DRAFT_07 = "http://json-schema.org/schema#"
DRAFT_07_ID = "http://json-schema.org/draft-07/schema#"

#: 2019-09 and 2020-12 keywords that have no draft-07 equivalent. Dropping them is the honest
#: move: keeping a keyword the validator ignores would claim a constraint nothing enforces.
UNSUPPORTED = (
    "unevaluatedProperties",
    "unevaluatedItems",
    "$anchor",
    "$recursiveRef",
    "$recursiveAnchor",
    "$dynamicRef",
    "$dynamicAnchor",
    "$vocabulary",
    "prefixItems",
    "minContains",
    "maxContains",
    "deprecated",
)

#: Keywords 2019-09 split out of draft-07's `dependencies`, which draft-07 spells as one.
DEPENDENCY_KEYWORDS = ("dependentRequired", "dependentSchemas")


def _to_draft_07(node: Any) -> Any:
    """Rewrite one JSON Schema node from 2019-09 into draft-07."""
    if isinstance(node, list):
        return [_to_draft_07(item) for item in node]
    if not isinstance(node, dict):
        return node

    out: dict[str, Any] = {}
    for key, value in node.items():
        if key in UNSUPPORTED:
            continue
        if key == "$defs":
            out["definitions"] = _to_draft_07(value)
        elif key in DEPENDENCY_KEYWORDS:
            # Both collapse into draft-07 `dependencies`, which takes a list or a schema per
            # property; merging keeps whichever the source produced.
            out.setdefault("dependencies", {}).update(_to_draft_07(value))
        elif key == "$schema":
            out[key] = DRAFT_07_ID
        elif key == "$ref" and isinstance(value, str):
            out[key] = value.replace("#/$defs/", "#/definitions/")
        else:
            out[key] = _to_draft_07(value)
    return out


def _annotate(schema: dict[str, Any], view: SchemaView) -> dict[str, Any]:
    """Carry the NGSI-LD kind and the UN/CEFACT unit into the schema (DM-05, DM-06).

    Both are `x-` keywords: a draft-07 validator ignores unknown keywords, so the metadata
    travels with the schema without changing what it validates. Exports read the unit for the
    column header, the editor reads the kind to pick a form control (DM-20).
    """
    definitions = schema.get("definitions", {})
    for cls in view.all_classes().values():
        target = definitions.get(cls.name)
        if not isinstance(target, dict):
            continue
        properties = target.get("properties", {})
        for slot in slots_of(view, cls):
            prop = properties.get(slot.alias or slot.name)
            if not isinstance(prop, dict):
                continue
            prop["x-ngsi-ld-kind"] = ngsi_ld_kind(slot)
            unit = unit_of(slot)
            if unit:
                prop["x-unit"] = unit
    return schema


def compile_schema(source: str | Path) -> dict[str, Any]:
    """Render one LinkML document as a draft-07 JSON Schema."""
    view = load(source)
    # `not_closed=False` is DM-28's default: a payload with an undeclared attribute is refused
    # unless the class opts into an open world.
    rendered = JsonSchemaGenerator(view.schema, not_closed=False).serialize()
    schema = _to_draft_07(json.loads(rendered))
    schema["$schema"] = DRAFT_07_ID
    schema["x-generator-version"] = generator_version()
    return _annotate(schema, view)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source", help="LinkML YAML file")
    parser.add_argument("-o", "--output", help="write here instead of stdout")
    args = parser.parse_args(argv)

    try:
        schema = compile_schema(args.source)
    except ModelError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    text = json.dumps(schema, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
