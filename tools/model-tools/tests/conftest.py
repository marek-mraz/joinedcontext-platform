"""Fixtures shared by the Model Tools suites."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def senzor() -> str:
    """A model with every NGSI-LD kind the generators treat specially."""
    return str(FIXTURES / "senzor.linkml.yaml")


@pytest.fixture
def squatted() -> str:
    """A model minting a term under a namespace the organisation does not own."""
    return str(FIXTURES / "squatted.linkml.yaml")


@pytest.fixture
def sdm_schema() -> dict:
    return json.loads((FIXTURES / "sdm-airqualityobserved.schema.json").read_text())


@pytest.fixture
def sdm_properties(sdm_schema) -> dict:
    """The attributes the fixture schema declares, read the way the importer reads them.

    A catalogue schema is an `allOf` of the shared commons and one inline branch, so the
    attributes are never at the top level. Tests compose them the same way the importer does,
    rather than each knowing the layout.
    """
    from import_sdm import _composed

    return _composed(sdm_schema, "properties")


@pytest.fixture
def sdm_context() -> dict:
    return json.loads((FIXTURES / "sdm-airqualityobserved.context.jsonld").read_text())


@pytest.fixture
def sdm_provenance() -> dict:
    return {
        "repository": "https://github.com/smart-data-models/dataModel.Environment",
        "path": "AirQualityObserved/schema.json",
        "commit": "8c4f2b1a9e6d0f3c5b7a1d2e4f6a8b0c2d4e6f80",
    }
