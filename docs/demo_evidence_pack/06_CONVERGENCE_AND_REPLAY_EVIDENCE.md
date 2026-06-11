# Convergence and Replay Evidence

## Dual pipeline presentation

Desktop V1 presents Dual Adaptive Deterministic Pipelines as Pipeline A and
Pipeline B. Pipeline A can show retained stage trace information. Pipeline B
shows the retained deterministic validator summary when available. The
dashboard does not change pipeline behavior.

## Convergence

A matched convergence result means the compared deterministic pipeline outputs
agree for the current traversal under the existing runtime comparison. A
mismatched result means the compared outputs differ and the interface must
present that controlled outcome.

Convergence evidence may include the current pipeline mode, parity status,
convergence status, and a convergence hash when supplied by the runtime.

## Replay

A matched replay means the replayed record agrees with the expected recorded
result under the existing replay process. A mismatch indicates a difference
that requires review.

Zero mismatches in a local verification run means no differences were detected
in that specific local test context. It does not prove that every possible
input, environment, or future release will produce zero mismatches.

Replay evidence matters because it supports a replay-verifiable record: a
reviewer can compare recorded and replayed outcomes without rewriting replay
lineage. Audit, chronology, and replay behavior remain owned by the runtime.
