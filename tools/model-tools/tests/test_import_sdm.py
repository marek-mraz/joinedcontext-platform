"""The Smart Data Models importer (T-0171, DM-07…DM-11, DM-18).

`convert` is driven with the fixture documents rather than the network: an import has to be
reproducible from the recorded commit, and a test that fetches proves nothing about that while
failing whenever GitHub is slow.
"""

from __future__ import annotations

import pytest
import yaml

from common import UPSTREAM_ANNOTATION, load
from gen_context import compile_context
from gen_json_schema import compile_schema
from import_sdm import (
    ImportError_,
    _get,
    convert,
    fetch,
    resolve,
    resolve_commit,
    split_identifier,
)

MODEL = "dataModel.Environment/AirQualityObserved"


@pytest.fixture
def imported(sdm_schema, sdm_context, sdm_provenance, sdm_commons) -> dict:
    return convert(MODEL, sdm_schema, sdm_context, None, sdm_provenance, sdm_commons)


def test_the_identifier_is_split_into_repository_and_model():
    assert split_identifier(MODEL) == ("dataModel.Environment", "AirQualityObserved")


@pytest.mark.parametrize(
    "bad",
    [
        "https://example.org/schema.json",
        "dataModel.Environment/../../etc/passwd",
        "dataModel.Environment",
        "/AirQualityObserved",
        ".hidden/AirQualityObserved",
        "dataModel.Environment/Air Quality",
    ],
)
def test_anything_that_is_not_a_catalogue_identifier_is_refused(bad):
    """DM-10: the fetch cannot be steered, so nothing that could name another host is taken."""
    with pytest.raises(ImportError_):
        split_identifier(bad)


@pytest.fixture
def no_network(monkeypatch):
    """Any request that actually leaves the process fails the test that allowed it."""

    def explode(*args, **kwargs):  # pragma: no cover - the point is that it never runs
        raise AssertionError(f"a request left the process: {args} {kwargs}")

    monkeypatch.setattr("import_sdm.requests.get", explode)


def test_a_traversal_never_reaches_a_url(no_network):
    """DM-10: `smart-data-models/../another-org` starts with the allowed prefix and still
    leaves the organisation, so the segment is refused before a URL is built."""
    with pytest.raises(ImportError_, match="repository"):
        resolve_commit("..")
    with pytest.raises(ImportError_, match="ref"):
        resolve_commit("dataModel.Environment", "../../other")


def test_a_url_outside_the_allowlist_is_refused(no_network):
    with pytest.raises(ImportError_):
        fetch("https://raw.githubusercontent.com/someone-else/model/schema.json")
    with pytest.raises(ImportError_, match="allowlist"):
        _get("https://example.org/schema.json")


def test_provenance_records_repository_path_and_commit(imported, sdm_provenance):
    annotations = imported["annotations"]
    assert annotations["spec.source.repository"] == sdm_provenance["repository"]
    assert annotations["spec.source.path"] == sdm_provenance["path"]
    assert annotations["spec.source.commit"] == sdm_provenance["commit"]


def test_every_upstream_slot_is_kept(imported, sdm_properties):
    """DM-11: a slot nobody uses locally is still what a federation partner sends."""
    core = {"id", "type", "location"}
    upstream = set(sdm_properties) - core
    assert upstream <= set(imported["slots"])


def test_core_attributes_come_from_the_shared_import(imported):
    """DM-09: `id`, `type` and `location` are declared once, in ngsi-ld-core."""
    assert "ngsi-ld-core" in imported["imports"]
    assert imported["classes"]["AirQualityObserved"]["is_a"] == "Entity"
    assert {"id", "type", "location"}.isdisjoint(imported["slots"])


def test_iris_are_bound_from_the_upstream_context(imported):
    assert imported["slots"]["temperature"]["slot_uri"] == "https://smartdatamodels.org/temperature"
    assert imported["classes"]["AirQualityObserved"]["class_uri"].startswith(
        "https://smartdatamodels.org/"
    )


def test_upstream_iris_are_cited_so_they_are_not_squatting(imported):
    for name, slot in imported["slots"].items():
        assert slot["annotations"][UPSTREAM_ANNOTATION], f"'{name}' does not say where it comes from"
    # And the model therefore compiles, where a hand-minted foreign IRI would not (DM-16).
    compile_context(yaml.safe_dump(imported))


def test_the_context_decides_the_ngsi_ld_kind(imported):
    """The upstream `@context` already says what a value is; the importer reads it (DM-05)."""
    assert imported["slots"]["refDevice"]["annotations"]["ngsi_ld_kind"] == "Relationship"
    assert imported["slots"]["temperature"]["annotations"]["ngsi_ld_kind"] == "Property"


def test_a_formatted_string_gets_the_range_that_makes_it_filterable(imported):
    """A timestamp left as a string is a timestamp no temporal filter can use (DM-20)."""
    assert imported["slots"]["dateObserved"]["range"] == "datetime"


def test_enums_are_carried_and_dead_ones_dropped(imported):
    assert "reliability_options" in imported["enums"]
    # `type` moved to the shared import, so the enum schema-automator derived for it has no
    # slot left to constrain.
    assert "type_options" not in imported["enums"]


def test_descriptions_survive_the_conversion(imported, sdm_properties):
    assert imported["slots"]["temperature"]["description"] == (
        sdm_properties["temperature"]["description"]
    )


def test_the_imported_model_is_a_model_the_generators_accept(imported):
    """The importer's output is the editor's input, so it has to compile end to end."""
    source = yaml.safe_dump(imported)
    view = load(source)
    assert "AirQualityObserved" in view.all_classes()

    schema = compile_schema(source)
    properties = schema["definitions"]["AirQualityObserved"]["properties"]
    assert properties["refDevice"]["x-ngsi-ld-kind"] == "Relationship"
    # Inherited from ngsi-ld-core rather than redeclared.
    assert properties["location"]["x-ngsi-ld-kind"] == "GeoProperty"


def test_the_context_is_fetched_from_the_repository_root(monkeypatch, sdm_schema, sdm_context):
    """The catalogue publishes one `@context` per subject repository, at its root; the schema
    and the example are per model. Fetching the context under the model answers 404 for every
    model in the catalogue, which is why the layout is pinned by a test and not by memory."""
    commit = "8c4f2b1a9e6d0f3c5b7a1d2e4f6a8b0c2d4e6f80"
    asked: list[str] = []

    class Answer:
        status_code = 200

        def __init__(self, url: str) -> None:
            self.url = url

        def json(self):
            if "/commits/" in self.url:
                return {"sha": commit}
            if self.url.endswith("schema.json"):
                return sdm_schema
            return sdm_context

    def get(url: str, timeout: int | None = None):
        asked.append(url)
        assert not url.endswith("AirQualityObserved/context.jsonld"), url
        return Answer(url)

    monkeypatch.setattr("import_sdm.requests.get", get)
    fetched = fetch(MODEL)

    base = f"https://raw.githubusercontent.com/smart-data-models/dataModel.Environment/{commit}"
    assert f"{base}/context.jsonld" in asked
    assert f"{base}/AirQualityObserved/schema.json" in asked
    assert f"{base}/AirQualityObserved/examples/example-normalized.jsonld" in asked
    assert fetched["provenance"]["path"] == "AirQualityObserved/schema.json"


def test_the_shared_commons_are_imported(imported, sdm_commons):
    """DM-11: `name`, `owner`, `dataProvider` and the rest of GSMA-Commons are what a
    federation partner sends. A catalogue schema `$ref`s them instead of spelling them out,
    so an import that reads only the inline branch drops every one of them."""
    commons = set(sdm_commons["definitions"]["GSMA-Commons"]["properties"]) - {"id"}
    assert commons <= set(imported["slots"]), sorted(commons - set(imported["slots"]))
    assert imported["slots"]["dateCreated"]["range"] == "datetime"
    assert imported["slots"]["owner"]["annotations"]["ngsi_ld_kind"] == "ListProperty"


def test_the_commons_come_from_the_allowlisted_repository(monkeypatch, sdm_schema, sdm_context, sdm_commons):
    """The catalogue writes that `$ref` against `smart-data-models.github.io`, a host the
    DM-10 allowlist does not cover. The same document is in the `data-models` repository,
    which it does, so the fix is a URL and not a second host in the allowlist."""
    commit = "8c4f2b1a9e6d0f3c5b7a1d2e4f6a8b0c2d4e6f80"
    asked: list[str] = []

    class Answer:
        status_code = 200

        def __init__(self, url: str) -> None:
            self.url = url

        def json(self):
            if "/commits/" in self.url:
                return {"sha": commit}
            if self.url.endswith("common-schema.json"):
                return sdm_commons
            if self.url.endswith("schema.json"):
                return sdm_schema
            return sdm_context

    def get(url: str, timeout: int | None = None):
        asked.append(url)
        assert "github.io" not in url, url
        return Answer(url)

    monkeypatch.setattr("import_sdm.requests.get", get)
    fetched = fetch(MODEL)

    assert (
        f"https://raw.githubusercontent.com/smart-data-models/data-models/{commit}/common-schema.json"
        in asked
    )
    assert fetched["commons"] == sdm_commons
    # DM-08 pins every fetched artifact, and the commons are a document of their own in a
    # repository of their own: an import whose commons are whatever master held that
    # afternoon is not reproducible.
    assert commit in fetched["provenance"]["commons"]

    document = convert(MODEL, sdm_schema, sdm_context, None, fetched["provenance"], sdm_commons)
    assert commit in document["annotations"]["spec.source.commons"]


def test_a_reference_to_anything_but_the_commons_is_left_alone():
    """`resolve` is a resolver for one known document, not a general one. A `$ref` naming
    something else stays a `$ref` — it must never turn into a fetch."""
    elsewhere = {"$ref": "https://example.invalid/other.json#/definitions/Thing"}
    assert resolve({"properties": {"x": elsewhere}}, {"definitions": {}}) == {
        "properties": {"x": elsewhere}
    }


def test_a_reference_that_points_at_itself_terminates():
    """A malformed commons document must cost an error message, never a hung import."""
    commons = {
        "definitions": {
            "Loop": {"$ref": "https://x/data-models/common-schema.json#/definitions/Loop"}
        }
    }
    resolved = resolve(
        {"$ref": "https://x/data-models/common-schema.json#/definitions/Loop"}, commons
    )
    assert isinstance(resolved, dict)


def test_a_nested_object_keeps_its_shape(imported):
    """schema-automator names a range for a nested object and defines no class for it, so the
    range had to be dropped and the shape went with it. The shape is in the JSON Schema."""
    assert imported["slots"]["address"]["range"] == "Address"
    address = imported["classes"]["Address"]
    assert set(address["attributes"]) == {
        "streetAddress", "addressLocality", "addressCountry", "areaServed",
    }
    assert address["attributes"]["streetAddress"]["required"] is True
    # Nested inside nested: the object under `areaServed` becomes a class of its own.
    assert address["attributes"]["areaServed"]["range"] == "AreaServed"
    assert set(imported["classes"]["AreaServed"]["attributes"]) == {"name"}


def test_a_nested_attribute_cites_its_upstream_like_every_other_term(imported):
    """DM-04/DM-16: without the citation the generator refuses the model for minting
    `streetAddress` under the catalogue's own namespace."""
    attribute = imported["classes"]["Address"]["attributes"]["streetAddress"]
    assert attribute["annotations"][UPSTREAM_ANNOTATION]
    compile_context(yaml.safe_dump(imported))


def test_a_reference_is_read_from_the_description_where_the_catalogue_writes_it(imported):
    """DM-05: Smart Data Models annotates no kinds and its `@context` is a flat term-to-IRI
    map, so a reference the context does not type imports as a Property — a `@context` binding
    a consumer cannot follow. The catalogue writes the kind as the first word of the
    description, and that is where it is read from."""
    assert imported["slots"]["refWeatherObserved"]["annotations"]["ngsi_ld_kind"] == "Relationship"


def test_a_description_with_no_kind_in_front_stays_a_property(imported):
    """Reading a kind out of prose is a heuristic, so it fails safe: no recognised word and a
    full stop, no change."""
    assert imported["slots"]["airQualityLevel"]["annotations"]["ngsi_ld_kind"] == "Property"


def test_the_shape_outranks_the_description(imported):
    """The catalogue describes `address` as "Property." and it is an object. The description is
    the only source that can be wrong, so it is consulted last and only where the shape says
    nothing."""
    assert imported["slots"]["address"]["annotations"]["ngsi_ld_kind"] == "JsonProperty"
