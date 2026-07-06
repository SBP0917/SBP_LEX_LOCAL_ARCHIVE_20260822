# Start Here: Desktop V1 Operator Release

This repository contains the SBP-LEX Desktop V1 local operator release.

## Beginner launch method

1. Download the ZIP from the repository `main` branch.
2. Extract the ZIP before running anything. Do not run from inside the compressed ZIP.
3. Open the extracted folder that contains `main.py`.
4. Click the File Explorer address bar.
5. Type `cmd` and press Enter. A black command window opens in the correct folder.
6. Install dependencies if required:

   ```text
   python -m pip install -r requirements.txt
   ```

   The requirements include `cryptography>=49.0.0`, which provides the tested
   `cryptography.mldsa` ML-DSA provider used by the PQC provider contract.
   If that provider is unavailable, PQC signature operations fail closed.

7. Start the runtime:

   ```text
   python main.py server 8000
   ```

8. Open this address in a browser:

   ```text
   http://127.0.0.1:8000/dashboard
   ```

Keep the black command window open while using the dashboard. Closing it stops
the runtime. To stop cleanly, return to the command window and press `Ctrl+C`.

## Optional Windows script

You may alternatively run:

```text
scripts\run_desktop_runtime.bat
```

The recommended direct beginner method remains:

```text
python main.py server 8000
```

See `DESKTOP_V1_OPERATOR_RELEASE_LOCK.md` for the full operator guide and
`LOCAL_OPERATOR_GUIDE.md` for troubleshooting.

## PQC Note

The runtime uses the `NIST_FIPS_203_204_205` PQC policy: ML-DSA is the active
signature algorithm, SLH-DSA is a reserved backup signature policy, and ML-KEM
is the KEM basis for future session/key-establishment work. This is a provider
contract, not a claim of production certification.
