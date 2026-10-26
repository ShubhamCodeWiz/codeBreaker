"""Boot a target FastAPI app as a real subprocess for HTTP probing."""

import contextlib
import socket
import subprocess
import sys
import time
from collections.abc import Iterator

import httpx

READY_PATH = "/openapi.json"
STARTUP_TIMEOUT = 10.0
POLL_INTERVAL = 0.05
SHUTDOWN_TIMEOUT = 5.0


class TargetServer(str):
    """The base URL as a plain string, with the process behind it on `.process`."""

    process: subprocess.Popen[bytes]

    def __new__(cls, base_url: str, process: subprocess.Popen[bytes]) -> "TargetServer":
        instance = super().__new__(cls, base_url)
        instance.process = process
        return instance


def _free_port() -> int:
    """Ask the OS for an unused TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_until_ready(base_url: str, process: subprocess.Popen[bytes]) -> None:
    """Poll the OpenAPI schema until the app answers, or fail with a clear error."""
    deadline = time.monotonic() + STARTUP_TIMEOUT
    with httpx.Client(timeout=0.5) as client:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(
                    f"target exited during startup with code {process.returncode}"
                )
            try:
                if client.get(f"{base_url}{READY_PATH}").status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(POLL_INTERVAL)
    raise RuntimeError(
        f"target at {base_url} was not ready within {STARTUP_TIMEOUT}s"
    )


@contextlib.contextmanager
def run_target(
    app_dir: str = ".", app_module: str = "target_app.main:app"
) -> Iterator[TargetServer]:
    """Run the target app on a free port, yield its base URL, and always shut it down."""
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", app_module, "--port", str(port)],
        cwd=app_dir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_until_ready(base_url, process)
        yield TargetServer(base_url, process)
    finally:
        process.terminate()
        try:
            process.wait(timeout=SHUTDOWN_TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
