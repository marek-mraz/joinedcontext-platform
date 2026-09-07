# The executable cases of PF-52: `conftest verify -p policies` runs them in CI.
package main

import rego.v1

roles := {
	"pipeline-developer": {"rules": [
		{"kinds": ["Pipeline", "DataSource", "Mapping"], "verbs": ["propose"]},
		{"kinds": ["Endpoint"], "verbs": ["propose"], "constraints": [{"field": "spec.audience", "notIn": ["public"]}]},
	]},
	"org-admin": {"rules": [{"kinds": ["Endpoint", "Pipeline", "Role", "RoleBinding"], "verbs": ["propose", "approve", "delete"]}]},
}

bindings := [
	{"name": "ovzdusie-developers", "subjects": [{"group": "air-quality-team"}, {"user": "jana.kovacova@banskabystrica.sk"}], "role": "pipeline-developer", "scope": {"project": "ovzdusie"}},
	{"name": "admins", "subjects": [{"user": "admin"}], "role": "org-admin", "scope": {"organization": "banskabystrica"}},
]

pipeline_change := {"path": "projects/ovzdusie/pipelines/aq/pipeline.yaml", "action": "propose", "kind": "Pipeline", "name": "aq", "project": "ovzdusie", "manifest": {"kind": "Pipeline", "spec": {"class": "resident"}}}

endpoint_change(audience) := {"path": "projects/ovzdusie/spaces/ovzdusie/endpoints/air.yaml", "action": "propose", "kind": "Endpoint", "name": "air", "project": "ovzdusie", "manifest": {"kind": "Endpoint", "spec": {"contextSpaceRef": "ovzdusie", "audience": audience}}}

test_a_viewer_cannot_propose if {
	count(deny) == 1 with input as {"author": "viewer", "groups": [], "changes": [pipeline_change]}
		with data.roles as roles
		with data.bindings as bindings
}

test_a_developer_proposes_a_pipeline_by_group if {
	count(deny) == 0 with input as {"author": "jana", "groups": ["air-quality-team"], "changes": [pipeline_change]}
		with data.roles as roles
		with data.bindings as bindings
}

test_a_developer_proposes_a_pipeline_by_email if {
	count(deny) == 0 with input as {"author": "jana", "author_email": "jana.kovacova@banskabystrica.sk", "groups": [], "changes": [pipeline_change]}
		with data.roles as roles
		with data.bindings as bindings
}

test_a_developer_cannot_publish_a_public_endpoint if {
	count(deny) == 1 with input as {"author": "jana", "groups": ["air-quality-team"], "changes": [endpoint_change("public")]}
		with data.roles as roles
		with data.bindings as bindings
}

test_a_developer_proposes_an_organization_endpoint if {
	count(deny) == 0 with input as {"author": "jana", "groups": ["air-quality-team"], "changes": [endpoint_change("organization")]}
		with data.roles as roles
		with data.bindings as bindings
}

test_deletion_needs_delete if {
	deleted := object.union(pipeline_change, {"action": "delete"})
	count(deny) == 1 with input as {"author": "jana", "groups": ["air-quality-team"], "changes": [deleted]}
		with data.roles as roles
		with data.bindings as bindings
	count(deny) == 0 with input as {"author": "admin", "groups": [], "changes": [deleted]}
		with data.roles as roles
		with data.bindings as bindings
}

test_a_project_binding_stops_at_its_project if {
	other := object.union(pipeline_change, {"project": "doprava", "path": "projects/doprava/pipelines/aq/pipeline.yaml"})
	count(deny) == 1 with input as {"author": "jana", "groups": ["air-quality-team"], "changes": [other]}
		with data.roles as roles
		with data.bindings as bindings
}

test_organization_scope_covers_every_project if {
	other := object.union(pipeline_change, {"project": "doprava"})
	count(deny) == 0 with input as {"author": "admin", "groups": [], "changes": [other]}
		with data.roles as roles
		with data.bindings as bindings
}
