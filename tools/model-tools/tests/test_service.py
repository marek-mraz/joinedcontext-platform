"""The HTTP face of Model Tools (T-0377, DM-10, DM-12, DM-17, DM-18, DM-19).

The service is driven as a WSGI application rather than over a socket: what has to hold is the
contract in API/01 §11, and a test that binds a port proves the same thing more slowly and
fails when a runner is busy. Nothing here reaches the network; the one test that would is the
one asserting that it does not.
"""

from __future__ import annotations

import io
import json
import re
from pathlib import Path
from wsgiref.util import setup_testing_defaults

import pytest

import service
from service import Catalogue, application

PACKAGE = Path(__file__).resolve().parents[1]

#: Exactly the fields the Portal's `Artifacts` struct deserialises (API/01 §11). A rename on
#: either side is an empty preview in the editor with nothing in a log to say why, so the two
#: lists are kept identical by this test and by the Portal's own serialisation test.
ARTIFACT_FIELDS = {
    "linkml",
    "jsonSchema",
    "context",
    "shacl",
    "owl",
    "example",
    "generatorVersion",
    "errors",
}

#: One subject of the catalogue index, shaped as the Smart Data Models organisation publishes
#: it. The details document is the one that carries URLs, so it also proves the index drops
#: them: a browser must never be handed a fetchable address (DM-10).
OFFICIAL_LIST = {
    "officialList": [
        {
            "repoName": "dataModel.Environment",
            "repoLink": "https://github.com/smart-data-models/dataModel.Environment.git",
            "dataModels": ["AirQualityObserved", "WaterQualityObserved"],
            "domains": ["SmartCities"],
        }
    ]
}
MODEL_DETAILS = [
    {
        "subject": "dataModel.Environment",
        "dataModel": "AirQualityObserved",
        "title": "Smart Data Models - Air quality observed schema",
        "description": "An observation of air quality conditions at a certain place and time.",
        "jsonSchemaUrl": "https://raw.githubusercontent.com/smart-data-models/x/schema.json",
    }
]


def call(method: str, path: str, body: object = None, query: str = "") -> tuple[int, dict]:
    """One request through the WSGI app, answered as (status code, parsed JSON)."""
    raw = b"" if body is None else json.dumps(body).encode("utf-8")
    environ: dict[str, object] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query,
        "CONTENT_LENGTH": str(len(raw)),
        "wsgi.input": io.BytesIO(raw),
    }
    setup_testing_defaults(environ)
    captured: dict[str, str] = {}

    def start_response(status: str, headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = dict(headers)

    chunks = application(environ, start_response)
    assert captured["headers"]["Content-Type"] == "application/json"
    return int(captured["status"].split()[0]), json.loads(b"".join(chunks))


@pytest.fixture
def no_network(monkeypatch):
    """Any request that actually leaves the process fails the test that allowed it."""

    def explode(*args, **kwargs):  # pragma: no cover - the point is that it never runs
        raise AssertionError(f"a request left the process: {args} {kwargs}")

    monkeypatch.setattr("import_sdm.requests.get", explode)


@pytest.fixture(autouse=True)
def empty_cache(monkeypatch):
    """Every test starts with a cold catalogue, so none of them depends on the order."""
    monkeypatch.setattr(service, "CATALOGUE", Catalogue())


def test_a_model_that_compiles_answers_every_artifact(senzor):
    status, body = call("POST", "/generate", {"source": Path(senzor).read_text()})

    assert status == 200
    assert body["errors"] == []
    assert body["jsonSchema"]["$schema"] == "http://json-schema.org/draft-07/schema#"
    assert "temperature" in body["context"]["@context"]
    assert "http://www.w3.org/ns/shacl#" in body["shacl"]
    assert "owl:Ontology" in body["owl"] or "owl#Ontology" in body["owl"]
    assert body["generatorVersion"].startswith("linkml-")


def test_a_model_that_does_not_compile_is_two_hundred_with_one_reason():
    """API/01 §11: a half-written model is the editor's normal state, not a server error."""
    status, body = call("POST", "/generate", {"source": "classes: [not a mapping\n"})

    assert status == 200
    assert len(body["errors"]) == 1, body["errors"]
    assert not ARTIFACT_FIELDS.intersection(body) - {"generatorVersion", "errors"}
    assert "/tmp" not in json.dumps(body), "the spooled path is not the editor's business"


def test_the_answer_carries_only_fields_the_portal_reads(senzor):
    """A field the Portal's `Artifacts` struct does not know is a silent empty preview."""
    _, body = call("POST", "/generate", {"source": Path(senzor).read_text()})

    assert set(body) <= ARTIFACT_FIELDS, set(body) - ARTIFACT_FIELDS
    # `generate` is given a source and does not echo one back; an import does (API/01 §11).
    assert "linkml" not in body


def test_generate_without_a_source_is_a_bad_request():
    for body in [{}, {"source": ""}, {"source": 17}]:
        status, answer = call("POST", "/generate", body)
        assert status == 400, body
        assert answer["errors"]


def test_an_identifier_that_is_not_a_catalogue_id_is_refused_without_a_socket(no_network):
    """DM-10: the fetch cannot be steered, and the refusal happens before a URL exists."""
    for steered in [
        "https://example.org/schema.json",
        "http://169.254.169.254/latest/meta-data",
        "dataModel.Environment/../../etc/passwd",
        "dataModel.Environment",
        "",
    ]:
        status, body = call("POST", "/import-sdm", {"model": steered})
        assert status == 400, steered
        assert body["errors"], steered

    status, body = call("POST", "/import-sdm", {"model": None})
    assert status == 400


def test_an_import_answers_the_linkml_it_produced(
    monkeypatch, no_network, sdm_schema, sdm_context, sdm_provenance
):
    """DM-08: the editor gets the document it will edit, provenance and all."""
    example = {"id": "urn:ngsi-ld:AirQualityObserved:hel.fi:air-quality:s1"}
    monkeypatch.setattr(
        service,
        "fetch",
        lambda model, *a, **k: {
            "schema": sdm_schema,
            "context": sdm_context,
            "example": example,
            "provenance": sdm_provenance,
        },
    )

    status, body = call(
        "POST", "/import-sdm", {"model": "dataModel.Environment/AirQualityObserved"}
    )

    assert status == 200
    assert body["errors"] == []
    assert f"spec.source.commit: {sdm_provenance['commit']}" in body["linkml"]
    assert body["example"] == example
    assert body["jsonSchema"] and body["context"] and body["shacl"] and body["owl"]


def test_an_import_that_cannot_reach_the_catalogue_says_so_in_errors(monkeypatch, no_network):
    """The reason has to reach the wizard; a status the Portal can only read as unreachable
    turns 'GitHub is down' into 'the compiler is broken'."""

    def unavailable(*args, **kwargs):
        raise service.ImportError_("dataModel.Environment answered 503")

    monkeypatch.setattr(service, "fetch", unavailable)

    status, body = call(
        "POST", "/import-sdm", {"model": "dataModel.Environment/AirQualityObserved"}
    )

    assert status == 200
    assert body["errors"] == ["dataModel.Environment answered 503"]
    assert "jsonSchema" not in body


def test_a_body_past_the_cap_is_refused_before_it_is_read():
    """DM-18: Model Tools is shared, so it caps the payload itself."""
    environ: dict[str, object] = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": "/generate",
        "CONTENT_LENGTH": str(service.MAX_BODY_BYTES + 1),
        # A stream that would fail the test if the app read it rather than refusing first.
        "wsgi.input": io.BytesIO(b""),
    }
    setup_testing_defaults(environ)
    captured: dict[str, str] = {}
    application(environ, lambda status, headers: captured.setdefault("status", status))

    assert captured["status"].startswith("413")


def test_an_unknown_route_is_json_and_not_a_stack_trace():
    status, body = call("GET", "/nope")
    assert status == 404
    assert body["errors"]


def test_healthz_names_the_generator_this_image_carries():
    status, body = call("GET", "/healthz")
    assert status == 200
    assert body == {"status": "ok", "generatorVersion": service.generator_version()}


# --- the catalogue index (DM-12) -------------------------------------------------------


@pytest.fixture
def catalogue_documents(monkeypatch):
    """The two upstream documents, and a count of how often they were fetched."""
    calls: list[str] = []

    def document(url: str):
        calls.append(url)
        return OFFICIAL_LIST if url == service.CATALOGUE_URL else MODEL_DETAILS

    monkeypatch.setattr(service, "_document", document)
    return calls


def test_the_index_is_subjects_models_and_descriptions(catalogue_documents):
    status, body = call("GET", "/catalog")

    assert status == 200
    assert body["stale"] is False
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", body["refreshedAt"])
    subject = body["subjects"][0]
    assert subject["name"] == "dataModel.Environment"
    assert subject["title"] == "Environment"
    assert subject["models"][0] == {
        "id": "dataModel.Environment/AirQualityObserved",
        "name": "AirQualityObserved",
        "description": MODEL_DETAILS[0]["description"],
    }
    # A model the details document does not describe is still in the index.
    assert subject["models"][1]["id"] == "dataModel.Environment/WaterQualityObserved"


def test_the_index_hands_the_browser_no_fetchable_address(catalogue_documents):
    """DM-10: a model is named by its catalogue identifier; fetching one is `import-sdm`.

    The upstream details document is a list of URLs with a description attached, and the index
    is the other way round. Descriptions are upstream prose and some of them cite a standard by
    URL, so the property asserted is the shape: no field of the index is an address.
    """
    _, body = call("GET", "/catalog")

    for subject in body["subjects"]:
        assert set(subject) == {"name", "title", "models"}
        for model in subject["models"]:
            assert set(model) <= {"id", "name", "description"}
            assert "http" not in json.dumps({k: v for k, v in model.items() if k != "description"})


def test_the_index_is_cached_and_refreshed_only_when_asked(catalogue_documents):
    call("GET", "/catalog")
    fetched_once = len(catalogue_documents)
    call("GET", "/catalog")
    assert len(catalogue_documents) == fetched_once, "the second reader used the cache"

    call("GET", "/catalog", query="refresh=true")
    assert len(catalogue_documents) > fetched_once, "refresh=true refills now (DM-12)"


def test_a_catalogue_that_cannot_be_refreshed_degrades_to_the_cached_index(
    monkeypatch, catalogue_documents
):
    """DM-12: unavailability degrades to the cache, it never blocks editing."""
    _, filled = call("GET", "/catalog")

    def unavailable(url: str):
        raise service.ImportError_(f"{url} answered 503")

    monkeypatch.setattr(service, "_document", unavailable)
    status, body = call("GET", "/catalog", query="refresh=true")

    assert status == 200
    assert body["stale"] is True
    assert body["subjects"] == filled["subjects"]
    assert body["refreshedAt"] == filled["refreshedAt"], "it says when the data is from"


def test_a_catalogue_that_was_never_reached_answers_an_empty_index(monkeypatch):
    """Nothing cached and upstream down: an editor waiting on GitHub is what DM-12 rules out."""

    def unavailable(url: str):
        raise service.ImportError_(f"{url} answered 503")

    monkeypatch.setattr(service, "_document", unavailable)
    status, body = call("GET", "/catalog")

    assert status == 200
    assert body == {"subjects": [], "refreshedAt": None, "stale": True}


def test_an_oversized_catalogue_document_is_refused(monkeypatch):
    """A mirror answering gigabytes must not fill the replica's 256 MiB."""

    class Huge:
        content = b"x" * 16
        status_code = 200

    monkeypatch.setattr(service, "MAX_CATALOGUE_BYTES", 8)
    monkeypatch.setattr(service, "_get", lambda url: Huge())

    with pytest.raises(service.ImportError_, match="past the cap"):
        service._document(service.CATALOGUE_URL)


# --- the image (DM-19) -----------------------------------------------------------------


def test_the_pinned_generator_is_the_version_recorded_in_every_artifact():
    """DM-19: CI and the preview run one version, and the artifacts say which."""
    pinned = re.search(r'"linkml==([^"]+)"', (PACKAGE / "pyproject.toml").read_text())
    assert pinned, "pyproject.toml no longer pins linkml exactly"
    assert service.generator_version() == f"linkml-{pinned.group(1)}"


def test_the_image_installs_this_package_and_serves_the_service():
    """The image is the artifact DM-19 pins, so it may not drift from this dependency set."""
    dockerfile = (PACKAGE / "Dockerfile").read_text()
    assert "pyproject.toml" in dockerfile, "the image must install the pinned dependencies"
    assert "service" in dockerfile, "the image must start the HTTP face"
    assert "USER" in dockerfile, "the container does not run as root"
