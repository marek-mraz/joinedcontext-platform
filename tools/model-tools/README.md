# Model Tools

The one non-Rust runtime component (Architecture/11 §6.5). LinkML and schema-automator are
Python, so the generators live here; everything with state or authority stays in Rust.

Model Tools is a pure function: it reads a LinkML document and writes artifacts. It holds no
credentials, reads no platform state and opens no socket except `import_sdm`, which reaches
the Smart Data Models organisation and nothing else (DM-10, DM-18).

| Script | Renders | Requirements |
|---|---|---|
| `src/gen_json_schema.py` | JSON Schema draft-07, with the NGSI-LD kind and the UN/CEFACT unit per slot | DM-02, DM-03, DM-05, DM-06 |
| `src/gen_context.py` | JSON-LD `@context` with bound IRIs, `@type: @id` for Relationships, `@container: @language` for LanguageProperties | DM-04, DM-05, DM-16 |
| `src/gen_rdf_artifacts.py` | closed SHACL shapes and the OWL ontology, both Turtle | DM-28, DM-43, DM-46 |
| `src/import_sdm.py` | a LinkML model from a Smart Data Models catalogue identifier, with provenance | DM-07…DM-11 |

`models/ngsi-ld-core.linkml.yaml` is the shared import: a model writes `imports:
[ngsi-ld-core]` and `is_a: Entity`, and inherits `id`, `type`, `location` and `observedAt`
(DM-09). Imports are merged when a model is loaded, so every artifact is self-contained and
resolvable without a network.

```bash
python3 src/gen_json_schema.py model.linkml.yaml -o json-schema/model.v1.json
python3 src/gen_context.py model.linkml.yaml -o context/model.v1.jsonld
python3 src/gen_rdf_artifacts.py model.linkml.yaml --artifact shacl -o shapes/model.v1.ttl
python3 src/import_sdm.py dataModel.Environment/AirQualityObserved -o model.linkml.yaml
pytest
```
