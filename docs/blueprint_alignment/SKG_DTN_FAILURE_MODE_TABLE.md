# SKG/DTN Failure Mode Table

Draft status: BLUEPRINT-SKGDTN-ALIGN-01 proposed alignment material only.

| Failure Code | Description | Source Layer | Expected Downstream Handling | Evidence Required | Phase19A Fixture Needed |
| --- | --- | --- | --- | --- | --- |
| EIE_MALFORMED | Required EIE fields are missing or structurally invalid. | EIE | fail closed; deny ingress; preserve evidence | EIE validation record | true |
| EIE_UNBOUND | EIE lacks request/source binding. | EIE | fail closed; deny ingress; preserve evidence | request binding check | true |
| EIE_STALE | EIE timestamp/freshness fails policy. | EIE | fail closed or escalate freshness review | freshness metadata | true |
| SKG_UNAVAILABLE | SKG readiness package absent. | SKG | fail closed or mark runtime proof pending | missing package evidence | true |
| SKG_AUTHORITY_CONFLICT | Authority hierarchy or legitimacy conflict unresolved. | SKG | escalate; deny ingress until resolved | conflict signals | true |
| SKG_LEGITIMACY_FAIL | Declared authority or source legitimacy fails. | SKG | fail closed; deny ingress | legitimacy signal | true |
| SKG_PROCEDURAL_REQUIREMENT_UNRESOLVED | Procedural obligation cannot be resolved. | SKG | escalate; preserve evidence | obligation signal | true |
| DTN_UNAVAILABLE | DTN readiness package absent. | DTN | fail closed or mark runtime proof pending | missing package evidence | true |
| DTN_CONTEXT_CONFLICT | Operational context contradicts request or SKG constraints. | DTN | escalate or deny ingress | context contradiction signal | true |
| DTN_FEASIBILITY_FAIL | Pathway is infeasible. | DTN | fail closed; deny ingress | feasibility signal | true |
| DTN_ENVIRONMENT_MISMATCH | Deployment environment does not match declared context. | DTN | fail closed or escalate | environment signal | true |
| DTN_DEPENDENCY_FAIL | Dependency state blocks safe execution. | DTN | fail closed | dependency signal | true |
| PRE_CONTEXT_SIGNAL_INVALID | Composed package fails schema. | Pre-context | deny ingress | package validation record | true |
| PRE_CONTEXT_SIGNAL_STALE | Composed package freshness fails. | Pre-context | deny ingress or escalate freshness review | timestamp/freshness record | true |
| PRE_CONTEXT_SIGNAL_SIGNATURE_FAIL | Package signature fails. | Pre-context | fail closed; deny ingress | signature verification record | true |
| PRE_CONTEXT_SIGNAL_DIGEST_FAIL | Package digest mismatch. | Pre-context | fail closed; deny ingress | digest verification record | true |
