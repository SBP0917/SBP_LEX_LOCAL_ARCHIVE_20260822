# Screenshot Capture Guide

Automated screenshot capture was not available in the Phase 15 execution
environment. Use these steps to create presentation evidence manually.

## Prepare the dashboard

1. Extract the release and open the folder containing `main.py`.
2. Start the local runtime:

   ```text
   python main.py server 8000
   ```

3. Open `http://127.0.0.1:8000/dashboard`.
4. Maximize the browser and use a readable zoom level.
5. Run **Run Approved Demo Traversal** once where a populated state is needed.
6. Do not edit the HTML, runtime payload, or exported evidence for the capture.

## Suggested captures

Save captures under `docs/demo_evidence_pack/screenshots/` with these names:

1. `01_dashboard_landing.png`
2. `02_runtime_integrity.png`
3. `03_dual_pipeline_timeline.png`
4. `04_convergence_proof.png`
5. `05_execution_admissibility.png`
6. `06_audit_continuity.png`
7. `07_replay_comparison.png`
8. `08_controlled_actions.png`

For each image:

- include the panel heading
- include the reason and outcome where present
- avoid cropping away runtime mode or local/private context when relevant
- exclude unrelated desktop notifications or personal information
- capture only values actually displayed by the current local runtime

## Evidence handling

Record the repository commit, capture date, browser, and operating system in
the review notes. Screenshots demonstrate presentation state only. Retain the
test output, endpoint responses, and JSON exports as the primary technical
evidence.

Stop the runtime with `Ctrl+C` after capture.
