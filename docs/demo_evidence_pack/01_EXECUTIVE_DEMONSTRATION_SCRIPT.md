# Executive Demonstration Script

## Opening

SBP-LEX Desktop V1 is a local governance observability console backed by the
canonical SBP-LEX runtime. It gives an operator a readable view of runtime
health, deterministic traversal, decision state, convergence, execution
admissibility, audit continuity, and replay comparison.

The console is observational. It does not become the authority for governance
or execution. Runtime logic remains responsible for evaluating the fixed
demonstration request, applying existing controls, producing the decision,
gating execution, recording audit evidence, and supporting replay.

## Demonstration sequence

1. Open the dashboard and identify the local/private posture, runtime health,
   current decision state, pipeline mode, traversal reference, and audit
   reference.
2. Explain that the runtime integrity panel summarizes existing runtime and
   environment checks. The panel reports values; it does not set them.
3. Run the fixed **Run Approved Demo Traversal** action.
4. Observe Pipeline A and Pipeline B under **Dual Adaptive Deterministic
   Pipelines**. The display reflects retained runtime payload values.
5. Review the convergence proof. Matched convergence means the compared
   deterministic outputs agree for that traversal. A mismatch would be shown
   as a control outcome rather than concealed.
6. Review execution admissibility. This presents the runtime decision,
   execution result, gate verification, admissibility, and token failure
   information where available.
7. Review audit continuity. The console exposes the controlled runtime record,
   audit reference, replay ledger availability, exports, and event count.
8. Review replay comparison. This shows whether the available replay
   comparison matched and identifies the relevant ledger information.
9. Explain the visual language: PASS is successful verification, ESCALATE
   indicates controlled review, DENY indicates a governed rejection, FAIL
   indicates a failed check, ACTIVE indicates traversal activity, and IDLE
   indicates no active traversal.

The interface places the reason above the outcome so a reviewer sees the basis
before the status label.

## Deliberate V1 boundaries

Desktop V1 does not include cloud deployment, distributed runtime topology,
nodes, autonomous external execution, APK delivery, V2/V3 work, real external
knowledge-graph deployment, or formal certification. It is a local,
operator-facing demonstration and evidence surface backed by the existing
canonical runtime.
