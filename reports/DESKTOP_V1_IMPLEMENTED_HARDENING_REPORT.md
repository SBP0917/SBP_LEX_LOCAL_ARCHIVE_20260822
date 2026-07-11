# Desktop V1 Implemented Hardening Report

## Work package: H1A and H1B

Implemented strict enumeration of `local`, `private`, and `disabled` API modes. Unknown and empty values now fail closed. API startup resolves security configuration before socket binding. Request-time configuration faults return a denied 503 decision rather than falling through.

`disabled` is now accepted only when both an active pytest test marker and `SBP_LEX_ALLOW_INSECURE_TEST_MODE=1` are present. A normal runtime process cannot start unauthenticated.

## Files and tests

Changed `sbp_lex/api/access_control.py`, `sbp_lex/api/server.py`, `sbp_lex/config/environment.py`, `DEPLOYMENT_SECURITY.md`, and added `tests/test_api_security_mode_hardening.py`.

Eight tests cover unknown, empty, malformed and case/whitespace-mutated values; startup-before-bind rejection; disabled-mode rejection; pytest-only containment; and preservation of local/private access behavior.

## Verification

- `python -m compileall -q .`: PASS
- Targeted pytest: 8 passed
- Full pytest after commit: 716 passed, 11 local-trust/capstone failures caused
  by the sealed evidence chain correctly reporting six changed artifacts
  against its prior baseline. The baseline was not silently rebuilt.
- Runtime: ALLOW, EXECUTE, MODE_2_SPLIT_VALIDATOR, convergence matched
- Replay: 2/2 matched, zero mismatches
- `git diff --check`: PASS before reporting

The targeted tests, runtime, replay, compilation and ordinary regression suite
pass. Refreshing the protected evidence-chain baseline is the remaining
validation step and was not folded into this security change. No architectural
authority moved, no traversal changed, and no push was performed.
