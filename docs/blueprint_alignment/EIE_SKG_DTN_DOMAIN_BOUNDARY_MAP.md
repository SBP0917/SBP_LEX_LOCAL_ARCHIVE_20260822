# EIE / SKG / DTN / Domain Boundary Map

Draft status: BLUEPRINT-SKGDTN-ALIGN-01 proposed alignment material only.

| Layer | Role | May Do | Must Not Do | Output | Enters Control Plane? |
| --- | --- | --- | --- | --- | --- |
| Native System | Source of request or event. | emit native request/protocol payload | govern or execute through SBP-LEX | native payload | no |
| Adapter Translation | Translate native input into repository-readable request shape. | record source/protocol/translation metadata | bypass EIE or Hard Entry Gate | adapter translation record | no |
| EIE | Normalise execution intent before SKG/DTN readiness. | bind request, source, intent, target, context, and digest readiness | govern, license, execute, or bypass later layers | Execution Intent Envelope | not by itself |
| SKG | Verify truth foundations of EIE. | evaluate authority, jurisdiction, legitimacy, rule lineage, policy conflict, precedence | execute, govern, issue runtime ALLOW/DENY/ESCALATE, be overridden by DTN | SKG readiness signal package | only as validated signal |
| DTN | Corroborate contextual and operational feasibility under SKG constraints. | evaluate feasibility, dependency, environment, capability reality, contextual contradiction | override SKG, govern, execute, issue runtime ALLOW/DENY/ESCALATE | DTN readiness signal package | only as validated signal |
| Pre-context Composer | Package validated EIE/SKG/DTN readiness signals. | bind digest, signature, timestamp, nonce, request binding | import raw substrates or create authority | pre-context signal package | yes, after validation |
| Hard Entry Gate | Admit or reject package for internal state construction. | validate schema, freshness, digest, signature, request binding | accept raw SKG/DTN substrates or bypass failure modes | ingress result/evidence | yes |
| Domain | Enforce admissibility constraints after Governance/GRC. | convert verified truth into non-bypassable constraints | re-simulate, re-detect, infer intent, compute risk models, or absorb SKG/DTN intelligence | domain constraints/result | yes |
