# Auditor and Reviewer Walkthrough

## Start the release

1. Download the release ZIP from `main`.
2. Extract it before running any command.
3. Open a command window in the extracted folder containing `main.py`.
4. If needed, install dependencies:

   ```text
   python -m pip install -r requirements.txt
   ```

5. Start the local runtime:

   ```text
   python main.py server 8000
   ```

6. Open `http://127.0.0.1:8000/dashboard`.

Keep the command window open throughout the review.

## Review sequence

1. Open `http://127.0.0.1:8000/health`.
   Expected: a healthy JSON response with allowed local access.
2. Open `http://127.0.0.1:8000/runtime/integrity`.
   Expected: a valid runtime status contract and local environment posture.
3. Return to the dashboard and select **Run Approved Demo Traversal**.
   Expected: a fixed demonstration traversal, not an editable request.
4. Observe Pipeline A and Pipeline B.
   Expected: available stage or validator information drawn from the runtime
   payload. Unavailable values are identified as unavailable.
5. Observe convergence proof.
   Expected: matched or mismatched status, available mode/hash information,
   and a reason above the outcome.
6. Observe execution admissibility.
   Expected: runtime-produced decision, execution result, and available gate,
   admissibility, and token information.
7. Observe audit continuity.
   Expected: audit availability/reference and controlled record indicators.
8. Observe replay comparison.
   Expected: replay comparison status and available ledger information.
9. Select **Export Latest Result**.
   Expected: a local JSON download of the latest controlled runtime snapshot.
10. Select **Export Replay Ledger**.
    Expected: a local JSON download of the available replay ledger.
11. Select **Export Events**.
    Expected: a local JSON download of traversal trace events.

Exact hashes, references, event counts, and traversal identifiers are generated
by the current local run and must not be predicted in advance.

## Stop

Return to the command window and press `Ctrl+C`.
