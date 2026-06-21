# External SKG/DTN Substrate Demo

Phase 15.6A provides a read-only external signal-package demonstration:

```powershell
python -m external_substrates.demo.build_demo_pre_context_package
```

The command writes `external_substrates/demo/sample_pre_context_package.json`.
It reads declared sample inputs, builds an external SKG package, constrains DTN
with that package, and composes a signed pre-context package.

The demo does not call the Desktop V1 API, mutate runtime state, create a
governed state, bypass validation, or issue ALLOW, DENY, ESCALATE, final
admissibility, or execution permission. Submission to the existing Hard Entry
Gate is deliberately outside this demo.

