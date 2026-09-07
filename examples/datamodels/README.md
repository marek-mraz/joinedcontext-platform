# A configuration repository with one data model

The smallest repository `jcctl model` has something to do in: one organization, one project,
one Context Space and one `DataModel` with its LinkML source and the artifacts DM-02 commits
beside it.

CI regenerates those artifacts on every pull request and fails when a committed one no longer
matches (`jcctl model diff --repo-dir examples/datamodels`). That is the lane, and this is its
subject: an edit to `air-quality-observed.linkml.yaml` without a regeneration goes red, and so
does a generator whose output changes without the pin in `platform-settings.yaml` changing.

```bash
# Model Tools, the version platform-settings.yaml pins
pip install ./tools/model-tools && python3 tools/model-tools/src/service.py --port 8080 &

jcctl model diff     --repo-dir examples/datamodels --url http://127.0.0.1:8080   # exit 2 when stale
jcctl model generate --repo-dir examples/datamodels --url http://127.0.0.1:8080   # writes them
```

`spec.artifacts` declares the two artifacts Model Tools renders today. DM-02 commits four; the
documentation and the validated example arrive with the `gen-doc` and example renderers
(T-0415), and this manifest declares them in the same commit — a declared artifact the service
does not render fails the run rather than being written empty.

The names are the demo story's (`DEMO.md`): organization `hel.fi`, project `helsinki`, space
`air-quality`. It is a demonstration built on the city's open data and is not affiliated with
the City of Helsinki.
