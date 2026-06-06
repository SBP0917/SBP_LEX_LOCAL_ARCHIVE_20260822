# SBP-LEX V1 Deployment Security Notes

## Local-first default

The runtime binds to localhost by default and is intended for local/runtime testing before public exposure.

## Private API mode

For Railway or any non-local deployment, set:

```text
SBP_LEX_API_SECURITY_MODE=private
SBP_LEX_REQUIRE_API_TOKEN=1
SBP_LEX_API_TOKEN=<strong bearer token>
SBP_LEX_SIGNING_SECRET=<strong signing secret>
```

## Do not expose without token mode

Do not use `SBP_LEX_API_SECURITY_MODE=disabled` except isolated test harnesses.

## Runtime authority

The APK remains observational/orchestration only. Execution authority remains inside the canonical runtime.
