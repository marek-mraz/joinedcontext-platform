# Ingestion examples

Seven pipelines that read the outside world and write NGSI-LD entities through an Endpoint. Each
folder is what a `projects/{project}/pipelines/{name}/` folder looks like in an organization
repository (PL-01), plus the `DataSource` the pipeline reads from (MF-35).

| Folder | Reads | Cadence | Produces |
|---|---|---|---|
| `hsl-hfp-mqtt/` | HSL high-frequency positioning over MQTT | push-based, resident | `Vehicle`, capped at 30 buses |
| `http-json-poll/` | a JSON array over HTTPS, bearer token | 5 min, CronJob | `AirQualityObserved` |
| `csv-fetch/` | a CSV export over HTTPS | 45 s, CronJob every minute | `OffStreetParking` |
| `gtfs-rt/` | a GTFS-realtime protobuf feed | 15 s, resident | `Vehicle` and `Trip` |
| `helsinki-city-bikes/` | the HSL city bike GBFS station status feed | 60 s, CronJob | `BikeHireDockingStation` |
| `helsinki-hsy-air/` | HSY's open air quality WFS | 5 min, CronJob | `AirQualityObserved` |
| `helsinki-digitraffic-tms/` | Fintraffic's TMS counters | 60 s, CronJob | `TrafficFlowObserved`, one per direction |

All seven write into the documented demonstration instance: organization `hel.fi`, project
`helsinki`, spaces `air-quality`, `transport`, `bikes` and `traffic`. The MQTT and the
GTFS-realtime recipe are two views of the same fleet and mint the same ids, so a deployment runs
one of them, not both.

The last three are the Helsinki open-data set, and they carry two files the first four do not:
`endpoint.yaml` is the Endpoint the pipeline writes into and the public reads from, and its
`spec.publish.ckan` block is the dataset it becomes in the catalogue named once for the whole
tree in `ckan-instance.yaml` (EP-01, EP-62). The catalogue's API token is a reference; the
schema has no field a token could be written into (EP-67, CC-06).

## What is in a folder

`datasource.yaml` is the connection: where the data comes from and, when the feed needs one,
the name and key of the credential. A credential is never a value here. The reconciler resolves
the reference and hands the runner an environment variable, `${DS_AQ_OPENDATA_TOKEN}` for a
`token` key of a source named `aq-opendata` (CC-06, PL-16).

`pipeline.yaml` is the envelope: the execution class, the cadence, the endpoint the entities are
written to, and `spec.source.dataSourceRef` naming the connection (PL-39).

`bento.yaml` is native Bento and nothing else (PL-03). It has **no `input`**. The reconciler
renders the input from the referenced `DataSource` and puts it in front of these processors, so
what you read here is the transformation and the write, which is the part a reviewer cares
about. For a `gtfs-rt` source the reconciler also prepends the protobuf decoder, which is why
the GTFS mapping starts from plain JSON.

Every example mints its entity ids from `env("JC_ORG_DOMAIN")` rather than from a domain written
into the file. The reconciler resolves that variable from the project's Organization and injects it
into the runner, so a project moved to another Organization mints under the new domain without an
edit and no pipeline can claim a domain that is not its own (PF-44, PF-42). The golden tests supply
the variable themselves: every case that asserts a whole URN carries an `environment:` block with
the demonstration instance's `hel.fi`.

## Running the tests

```bash
bento lint ./examples/ingestion/*/bento.yaml ./examples/ingestion/gtfs-rt/tests/decoder.yaml
bento test ./examples/ingestion/...
cargo test -p jcctl --test ingestion_examples_tests
```

Bento pairs a test file with the config of the same name in the same folder, so the golden tests
live in `bento_bento_test.yaml` beside `bento.yaml` rather than in a `tests/` subfolder. `bento
lint` resolves `${SERVICE_ACCOUNT_TOKEN}`, so export any value before running it.

The `cargo` test is the other half: it parses both manifests through `jc-core`, checks that the
cadence lands in the runtime the comments promise, renders the input the same way the reconciler
will, and fails if any example ever writes a credential as a value.

## The GTFS-realtime descriptors

`gtfs-rt/proto/gtfs-realtime.proto` is the upstream GTFS Realtime protocol definition
(<https://github.com/google/transit>, Apache License 2.0, unmodified). The pipeline runner image
carries the same descriptors at `/opt/bento/gtfs-realtime`, so no pipeline ships a copy; this one
is here only so `tests/decoder.yaml` can decode the binary fixture without the image.

## Related

- [Architecture/08 §6](https://github.com/marek-mraz/joinedcontext-docs/blob/main/Architecture/08-pipelines.md) — the `DataSource` kind and what each type becomes in Bento.
- [Development/06a-ingestion-examples.md](https://github.com/marek-mraz/joinedcontext-docs/blob/main/Development/06a-ingestion-examples.md) — the same four recipes end to end, with the curls that verify them.
