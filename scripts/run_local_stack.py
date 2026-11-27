"""Run the full backend + frontend stack locally (for environments without Docker)."""

from __future__ import annotations

import base64
import os
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT / "backend"
FRONTEND_DIR = ROOT / "frontend"


def wait_for_http(url: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2.0) as resp:
                if resp.status == 200:
                    return
        except Exception:
            time.sleep(0.4)
    raise TimeoutError(f"Service did not become healthy at {url} within {timeout}s")


def _kill_proc_tree(proc: subprocess.Popen[bytes] | subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="aegisvault_local_", ignore_cleanup_errors=True) as tmpdir:
        db_path = Path(tmpdir) / "local_e2e.db"
        demo_pw = os.environ.get("DEMO_USER_PASSWORD", "ThreatDemo!2026")

        env = os.environ.copy()
        env.update(
            {
                "ENVIRONMENT": "development",
                "DATABASE_URL": f"sqlite:///{db_path.as_posix()}",
                "STREAM_MODE": "memory",
                "JWT_SECRET_KEY": env.get("JWT_SECRET_KEY") or secrets.token_hex(32),
                "VAULT_MASTER_KEY_B64": env.get("VAULT_MASTER_KEY_B64")
                or base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
                "INITIAL_HMAC_KEY_HEX": env.get("INITIAL_HMAC_KEY_HEX") or secrets.token_hex(32),
                "SEED_DEMO_DATA": "true",
                "DEMO_USER_PASSWORD": demo_pw,
                "RATE_LIMIT_ENABLED": "true",
                "CORS_ORIGINS": "http://localhost:5173,http://127.0.0.1:5173",
            }
        )

        py_exe = str(BACKEND_DIR / ".venv" / "Scripts" / "python.exe")
        if not Path(py_exe).exists():
            py_exe = sys.executable

        # Run Alembic migrations cleanly before launching uvicorn
        subprocess.run(
            [py_exe, "-m", "alembic", "upgrade", "head"],
            cwd=str(BACKEND_DIR),
            env=env,
            check=True,
        )

        backend_proc = subprocess.Popen(
            [py_exe, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"],
            cwd=str(BACKEND_DIR),
            env=env,
        )
        npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
        frontend_proc = subprocess.Popen(
            [npm_cmd, "run", "dev", "--", "--host", "127.0.0.1", "--port", "5173"],
            cwd=str(FRONTEND_DIR),
            env=env,
        )

        def _cleanup(*_args) -> None:
            _kill_proc_tree(frontend_proc)
            _kill_proc_tree(backend_proc)

        signal.signal(signal.SIGINT, _cleanup)
        signal.signal(signal.SIGTERM, _cleanup)

        try:
            wait_for_http("http://127.0.0.1:8000/health", timeout=30.0)
            wait_for_http("http://127.0.0.1:5173", timeout=30.0)
            print("Local stack ready: Frontend=http://127.0.0.1:5173 Backend=http://127.0.0.1:8000")

            if "--e2e" in sys.argv:
                npx_cmd = "npx.cmd" if os.name == "nt" else "npx"
                res = subprocess.run(
                    [npx_cmd, "playwright", "test"],
                    cwd=str(FRONTEND_DIR),
                    env=env,
                )
                return res.returncode

            while backend_proc.poll() is None and frontend_proc.poll() is None:
                time.sleep(1.0)
            return 1
        finally:
            _cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
