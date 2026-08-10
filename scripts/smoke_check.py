from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


ROOT_DIR = Path(__file__).resolve().parents[1]
LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1"}
REQUIRED_INTEGRITY_FIELDS = (
    "chronology_valid",
    "event_bus_valid",
    "replay_ledger_valid",
    "connector_recovery_valid",
    "persistence_valid",
)


class SmokeCheckError(RuntimeError):
    pass


def is_loopback_host(host: str | None) -> bool:
    if not host:
        return False
    if host.lower() in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def require_loopback_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme != "http":
        raise SmokeCheckError("Smoke checks require an http:// loopback URL.")
    if not is_loopback_host(parsed.hostname):
        raise SmokeCheckError(
            f"Refusing non-loopback target: {parsed.hostname or '<missing host>'}"
        )
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        raise SmokeCheckError("Base URL must not include a path, query, or fragment.")
    return base_url.rstrip("/")


def request_headers(token: str | None, *, json_body: bool = False) -> dict[str, str]:
    headers = {"Accept": "application/json"}
    if json_body:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def get_json(base_url: str, path: str, token: str | None) -> dict[str, Any]:
    request = Request(
        f"{base_url}{path}",
        headers=request_headers(token),
        method="GET",
    )
    try:
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise SmokeCheckError(f"GET {path} failed: {exc}") from exc
    if not isinstance(payload, dict):
        raise SmokeCheckError(f"GET {path} did not return a JSON object.")
    return payload


def get_text(base_url: str, path: str, token: str | None) -> str:
    request = Request(
        f"{base_url}{path}",
        headers=request_headers(token),
        method="GET",
    )
    try:
        with urlopen(request, timeout=5) as response:
            return response.read().decode("utf-8")
    except (HTTPError, URLError, TimeoutError, UnicodeDecodeError) as exc:
        raise SmokeCheckError(f"GET {path} failed: {exc}") from exc


def post_json(
    base_url: str,
    path: str,
    payload: dict[str, Any],
    token: str | None,
) -> dict[str, Any]:
    request = Request(
        f"{base_url}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers=request_headers(token, json_body=True),
        method="POST",
    )
    try:
        with urlopen(request, timeout=30) as response:
            result = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise SmokeCheckError(f"POST {path} failed: {exc}") from exc
    if not isinstance(result, dict):
        raise SmokeCheckError(f"POST {path} did not return a JSON object.")
    return result


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SmokeCheckError(message)


def run_smoke_check(
    base_url: str,
    *,
    expected_mode: str,
    token: str | None,
    video_url: str | None = None,
) -> None:
    base_url = require_loopback_url(base_url)

    health = get_json(base_url, "/health", token)
    access = health.get("access", {})
    require(health.get("ok") is True, "Health endpoint did not report ok=true.")
    require(access.get("mode") == expected_mode, "Health access mode mismatch.")
    require(
        is_loopback_host(str(access.get("client_host", ""))),
        "Health endpoint did not identify a loopback client.",
    )
    print(f"[PASS] Health endpoint: {base_url}/health")

    sys.path.insert(0, str(ROOT_DIR))
    from main import sample_request

    traversal = post_json(
        base_url,
        "/runtime/traverse",
        {
            "request_id": "local-smoke-check",
            "request": sample_request(),
        },
        token,
    )
    state = traversal.get("state", {})
    require(
        traversal.get("runtime") == "SBP_LEX_V1_CANONICAL_RUNTIME",
        "Traversal did not use the canonical runtime.",
    )
    require(state.get("decision") == "ALLOW", "Smoke traversal was not allowed.")
    require(state.get("execution_result") == "EXECUTE", "Smoke traversal did not execute.")
    require(
        state.get("pipeline_convergence", {}).get("matched") is True,
        "Dual pipeline convergence did not match.",
    )
    print("[PASS] Canonical traversal and dual pipeline convergence")

    status = get_json(base_url, "/runtime/status", token)
    require(
        status.get("runtime_id") == "SBP_LEX_V1_CANONICAL_RUNTIME",
        "Unexpected runtime identity.",
    )
    require(
        status.get("api_security_mode") == expected_mode,
        "Runtime security mode mismatch.",
    )
    for field in REQUIRED_INTEGRITY_FIELDS:
        require(status.get(field) is True, f"Runtime status failed: {field}")
    print(f"[PASS] Runtime mode confirmed: {expected_mode}")
    print(f"[PASS] Runtime status: {base_url}/runtime/status")

    integrity = get_json(base_url, "/runtime/integrity", token)
    environment = integrity.get("environment_security", {})
    require(
        integrity.get("status_contract_valid") is True,
        "Runtime status contract is invalid.",
    )
    require(environment.get("mode") == expected_mode, "Environment mode mismatch.")
    require(environment.get("valid") is True, "Environment security report is invalid.")
    print("[PASS] Runtime integrity and environment security")

    dashboard = get_text(base_url, "/dashboard", token).lower()
    require(
        "sbp-lex v1 desktop runtime dashboard" in dashboard,
        "Dashboard title was not found.",
    )
    require(
        "dual adaptive deterministic pipelines" in dashboard,
        "Dashboard dual pipeline label was not found.",
    )
    print(f"[PASS] Dashboard: {base_url}/dashboard")
    studio = get_text(base_url, "/desktop/video-studio", token).lower()
    require("sbp video studio" in studio, "Video Studio page title was not found.")
    require("constructed scenario mode" in studio, "Video Studio Cockpit layers were not found.")
    require("/runtime/traverse" not in studio, "Video Studio must not expose runtime execution controls.")
    print(f"[PASS] Video Studio UI: {base_url}/desktop/video-studio")
    if video_url is not None:
        video_health = get_json(video_url, "/health", None)
        require(video_health.get("ok") is True, "Video Studio companion did not report ok=true.")
        require(video_health.get("runtime_authority") == "NONE", "Video Studio reported runtime authority.")
        require(video_health.get("canonical_runtime_mutation") is False, "Video Studio mutation boundary failed.")
        print(f"[PASS] Video Studio companion: {video_url}/health")
    print("[PASS] Smoke check passed.")


def wait_for_server(
    base_url: str,
    *,
    token: str | None,
    process: subprocess.Popen[Any],
    timeout_seconds: float,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise SmokeCheckError(
                f"Runtime server exited early with code {process.returncode}."
            )
        try:
            get_json(base_url, "/health", token)
            return
        except SmokeCheckError:
            time.sleep(0.25)
    raise SmokeCheckError(
        f"Runtime server did not become healthy within {timeout_seconds:g} seconds."
    )


def stop_process(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify the local SBP-LEX V1 desktop runtime workflow."
    )
    parser.add_argument(
        "--base-url",
        help="Existing loopback runtime URL, for example http://127.0.0.1:8000.",
    )
    parser.add_argument(
        "--launch",
        action="store_true",
        help="Launch and manage main.py server before running checks.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--video-port", type=int, default=8765)
    parser.add_argument(
        "--expected-mode",
        choices=("local", "private"),
        default=os.environ.get("SBP_LEX_API_SECURITY_MODE", "local").strip().lower(),
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("SBP_LEX_API_TOKEN"),
        help="Bearer token for an existing private-mode loopback runtime.",
    )
    parser.add_argument(
        "--startup-timeout",
        type=float,
        default=20,
    )
    parser.add_argument(
        "--exit-after-check",
        action="store_true",
        help="Stop a launched server after a successful check.",
    )
    args = parser.parse_args()
    if args.launch and args.base_url:
        parser.error("Use either --launch or --base-url, not both.")
    if not args.launch and not args.base_url:
        args.base_url = f"http://{args.host}:{args.port}"
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535.")
    if not 1 <= args.video_port <= 65535:
        parser.error("--video-port must be between 1 and 65535.")
    if args.launch and args.video_port == args.port:
        parser.error("--video-port must differ from --port.")
    return args


def main() -> int:
    args = parse_args()
    process: subprocess.Popen[Any] | None = None
    video_process: subprocess.Popen[Any] | None = None
    try:
        if args.launch:
            if not is_loopback_host(args.host):
                raise SmokeCheckError(
                    f"Refusing to launch on non-loopback host: {args.host}"
                )
            base_url = require_loopback_url(f"http://{args.host}:{args.port}")
            video_url = require_loopback_url(f"http://{args.host}:{args.video_port}")
            environment = os.environ.copy()
            environment["SBP_LEX_API_SECURITY_MODE"] = args.expected_mode
            environment["SBP_LEX_REQUIRE_API_TOKEN"] = (
                "1" if args.expected_mode == "private" else "0"
            )
            environment["PYTHONUNBUFFERED"] = "1"
            environment["SBP_VIDEO_PORT"] = str(args.video_port)
            if args.expected_mode == "private" and not args.token:
                raise SmokeCheckError("Private mode requires SBP_LEX_API_TOKEN.")
            print(f"[INFO] Local/private mode: {args.expected_mode}")
            print(f"[INFO] Bind address: {args.host} only")
            print(f"[INFO] Dashboard URL: {base_url}/dashboard")
            print(f"[INFO] Video Studio URL: {base_url}/desktop/video-studio")
            print(f"[INFO] Runtime health URL: {base_url}/health")
            video_process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "sbp_video",
                    "service",
                    "--host",
                    args.host,
                    "--port",
                    str(args.video_port),
                ],
                cwd=ROOT_DIR,
                env=environment,
            )
            wait_for_server(
                video_url,
                token=None,
                process=video_process,
                timeout_seconds=args.startup_timeout,
            )
            process = subprocess.Popen(
                [sys.executable, str(ROOT_DIR / "main.py"), "server", str(args.port)],
                cwd=ROOT_DIR,
                env=environment,
            )
            wait_for_server(
                base_url,
                token=args.token,
                process=process,
                timeout_seconds=args.startup_timeout,
            )
        else:
            base_url = require_loopback_url(args.base_url)
            video_url = None

        run_smoke_check(
            base_url,
            expected_mode=args.expected_mode,
            token=args.token,
            video_url=video_url,
        )

        if process is not None and not args.exit_after_check:
            print("[INFO] Runtime is active. Press Ctrl+C to stop it.")
            while process.poll() is None and (video_process is None or video_process.poll() is None):
                time.sleep(0.5)
            if video_process is not None and video_process.poll() is not None:
                raise SmokeCheckError(
                    f"Video Studio companion exited with code {video_process.returncode}."
                )
            raise SmokeCheckError(
                f"Runtime server exited with code {process.returncode}."
            )
        return 0
    except KeyboardInterrupt:
        print("\n[INFO] Shutdown requested.")
        return 0
    except SmokeCheckError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    finally:
        if process is not None:
            stop_process(process)
            print("[INFO] Local runtime stopped.")
        if video_process is not None:
            stop_process(video_process)
            print("[INFO] Video Studio companion stopped.")


if __name__ == "__main__":
    raise SystemExit(main())
