# Start Here

This repository contains the SBP-LEX V1 local-first desktop runtime baseline.

## Setup

1. Install Python 3.10 or newer.
2. Install dependencies:

   ```text
   python -m pip install -r requirements.txt
   ```

3. Run the verification suite:

   ```text
   scripts\run_tests.bat
   ```

4. Start the local desktop runtime:

   ```text
   scripts\run_desktop_runtime.bat
   ```

The default dashboard is available only on the loopback interface at
`http://127.0.0.1:8000/dashboard`.

See `LOCAL_OPERATOR_GUIDE.md` for runtime and security guidance.
