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
    resolve_commit,
    split_identifier,
)

MODEL = "dataModel.Environment/AirQualityObserved"


@pytest.fixture
def imported(sdm_schema, sdm_context, sdm_provenance) -> dict:
    return convert(MODEL, sdm_schema, sdm_context, None, sdm_provenance)


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
