"""
PhishGuard AI V6.2 — Deep Scan Sandbox Controller
=================================================
Controls the lifecycle of an isolated browser sandbox for deep URL analysis.

Security Architecture:
  Windows Host (Flask Backend)
       ↓
  Docker Daemon (Disposable Container)
       ↓
  Restricted Container (Playwright Chromium)
       ↓
  Target Website

Core Security Principles:
  1. The target website executes ONLY inside the disposable Docker container.
  2. The sandbox NEVER uses host browser profiles, credentials, or cookies.
  3. The sandbox NEVER mounts host filesystems (no C:\\, Users\\, or project mounts).
  4. If Docker is unavailable or not running, Deep Scan returns UNAVAILABLE.
     It NEVER falls back to opening suspicious URLs in the Windows host browser.
  5. In-container SSRF guard blocks all requests and redirects to private/cloud metadata IPs.
  6. Disposable container lifecycle: created per scan, auto-removed (--rm), and memory-capped.
  7. Container rootfs is read-only (--read-only) with memory-only temporary scratchpad (--tmpfs).
"""

import os
import sys
import shutil
import subprocess
import time
import json
import uuid
from typing import Any

# ── Sandbox Configuration ───────────────────────────────────────────────────
SANDBOX_CONFIG = {
    "PAGE_LOAD_TIMEOUT_MS": 10000,
    "TOTAL_SCAN_TIMEOUT_SEC": 20,
    "MAX_REDIRECTS": 5,
    "DOCKER_IMAGE": "phishguard-sandbox:latest",
    "CONTAINER_MEMORY": "768m",
    "CONTAINER_CPUS": "1.5",
    "CONTAINER_NETWORK": "bridge",
}

# ── Dynamic Availability Telemetry ──────────────────────────────────────────
_DOCKER_INSTALLED = False
_DOCKER_RUNNING = False
_DOCKER_VERSION: str | None = None
_SANDBOX_IMAGE_AVAILABLE = False
_SANDBOX_AVAILABLE = False
_UNAVAILABILITY_REASON: str | None = "Not audited yet"


def _check_docker_cli() -> tuple[bool, str | None, str | None]:
    """
    Check if docker binary exists in PATH and query docker --version.
    Returns: (installed, version_str, reason)
    """
    docker_path = shutil.which("docker")
    if not docker_path:
        return False, None, "Docker binary not found in PATH"

    try:
        proc = subprocess.run(
            ["docker", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if proc.returncode == 0:
            version_str = proc.stdout.strip()
            return True, version_str, None
        return True, None, f"docker --version returned non-zero exit code: {proc.stderr[:100]}"
    except (subprocess.TimeoutExpired, OSError) as e:
        return True, None, f"docker --version check error: {str(e)}"


def _check_docker_daemon() -> tuple[bool, str | None]:
    """
    Check if Docker Engine/daemon is actively running via docker info.
    Returns: (running, reason)
    """
    try:
        proc = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if proc.returncode == 0:
            return True, "Docker daemon is running"
        return False, "Docker daemon is not running (is Docker Desktop started?)"
    except subprocess.TimeoutExpired:
        return False, "Docker daemon check timed out after 5s (daemon unresponsive)"
    except (OSError, FileNotFoundError) as e:
        return False, f"Docker daemon query failed: {str(e)}"


def _check_sandbox_image(image_name: str) -> bool:
    """
    Check if the dedicated sandbox Docker image exists locally.
    """
    try:
        proc = subprocess.run(
            ["docker", "image", "inspect", image_name],
            capture_output=True,
            timeout=4
        )
        return proc.returncode == 0
    except Exception:
        return False


def check_sandbox_availability() -> dict:
    """
    Perform a complete audit of the Docker sandbox capability.
    Updates cached availability flags and returns the status dictionary.
    """
    global _DOCKER_INSTALLED, _DOCKER_RUNNING, _DOCKER_VERSION
    global _SANDBOX_IMAGE_AVAILABLE, _SANDBOX_AVAILABLE, _UNAVAILABILITY_REASON

    installed, version_str, install_reason = _check_docker_cli()
    _DOCKER_INSTALLED = installed
    _DOCKER_VERSION = version_str

    if not _DOCKER_INSTALLED:
        _DOCKER_RUNNING = False
        _SANDBOX_IMAGE_AVAILABLE = False
        _SANDBOX_AVAILABLE = False
        _UNAVAILABILITY_REASON = "Docker is not installed on this machine (Docker binary not found in PATH). Docker Desktop with WSL2 backend is required for isolated Deep Scan."
    else:
        running, daemon_reason = _check_docker_daemon()
        _DOCKER_RUNNING = running

        if not _DOCKER_RUNNING:
            _SANDBOX_IMAGE_AVAILABLE = False
            _SANDBOX_AVAILABLE = False
            _UNAVAILABILITY_REASON = f"Docker is installed ({_DOCKER_VERSION or 'unknown'}), but Docker Engine is not running. Please start Docker Desktop."
        else:
            image_ok = _check_sandbox_image(SANDBOX_CONFIG["DOCKER_IMAGE"])
            _SANDBOX_IMAGE_AVAILABLE = image_ok

            if not _SANDBOX_IMAGE_AVAILABLE:
                _SANDBOX_AVAILABLE = False
                _UNAVAILABILITY_REASON = (
                    f"Docker Engine is running, but the dedicated PhishGuard sandbox image "
                    f"('{SANDBOX_CONFIG['DOCKER_IMAGE']}') is not built. "
                    f"Run: docker build -t {SANDBOX_CONFIG['DOCKER_IMAGE']} -f backend/deep_scan/Dockerfile backend/deep_scan"
                )
            else:
                _SANDBOX_AVAILABLE = True
                _UNAVAILABILITY_REASON = None

    return get_sandbox_status()


def get_sandbox_status() -> dict:
    """Return the current audited sandbox status dictionary."""
    return {
        "sandbox_available": _SANDBOX_AVAILABLE,
        "docker_installed": _DOCKER_INSTALLED,
        "docker_running": _DOCKER_RUNNING,
        "docker_version": _DOCKER_VERSION,
        "sandbox_image_available": _SANDBOX_IMAGE_AVAILABLE,
        "playwright_available": _SANDBOX_IMAGE_AVAILABLE,
        "chromium_available": _SANDBOX_IMAGE_AVAILABLE,
        "unavailability_reason": _UNAVAILABILITY_REASON,
    }


def run_deep_scan(url: str) -> dict:
    """
    Execute a Deep Scan inside an isolated disposable Docker container.

    CRITICAL SAFETY GUARANTEE:
    If the Docker sandbox is not operational, returns UNAVAILABLE immediately.
    NEVER falls back to launching the URL in the host browser.
    """
    t0 = time.perf_counter()

    # Refresh availability status dynamically
    status = check_sandbox_availability()

    if not status["sandbox_available"]:
        return {
            "available": False,
            "success": False,
            "error": f"Deep Scan unavailable: {status.get('unavailability_reason')}. Quick Scan AI & heuristics are fully active.",
            "redirect_chain": [],
            "final_url": url,
            "page_title": None,
            "html_raw": None,
            "dom_snapshot": None,
            "screenshot_path": None,
            "forms": [],
            "password_fields": [],
            "email_fields": [],
            "otp_fields": [],
            "payment_fields": [],
            "external_resources": [],
            "redirect_count": 0,
            "load_time_ms": 0.0,
            "scan_time_ms": round((time.perf_counter() - t0) * 1000, 1),
            "security_warnings": ["Deep Scan disabled — host browser fallback is prohibited."],
        }

    # Execute isolated container
    return _execute_disposable_container(url, t0)


def _execute_disposable_container(url: str, t0: float) -> dict:
    """
    Launch a disposable Docker container, pipe structured output, and enforce cleanup.
    """
    cfg = SANDBOX_CONFIG
    timeout_sec = cfg["TOTAL_SCAN_TIMEOUT_SEC"]
    container_id = f"phishguard-sandbox-{uuid.uuid4().hex[:12]}"

    # Security arguments:
    # --rm: Automatically remove container on exit
    # --read-only: Read-only root filesystem prevents container modification
    # --tmpfs: Writable scratchpad exists only in container RAM (100MB max)
    # --security-opt no-new-privileges:true: Blocks privilege escalation
    # --cap-drop=ALL: Drops all Linux capabilities
    # NO volume mounts (-v) to host filesystem!
    docker_cmd = [
        "docker", "run",
        "--rm",
        "--name", container_id,
        "--network", cfg["CONTAINER_NETWORK"],
        "--memory", cfg["CONTAINER_MEMORY"],
        "--cpus", cfg["CONTAINER_CPUS"],
        "--read-only",
        "--tmpfs", "/tmp:rw,size=100m,noexec,nosuid",
        "--security-opt", "no-new-privileges:true",
        "--cap-drop=ALL",
        cfg["DOCKER_IMAGE"],
        url
    ]

    try:
        proc = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec
        )

        # Parse container output
        stdout_text = proc.stdout.strip()
        result_dict = {}

        if stdout_text:
            # Find JSON payload in stdout lines
            for line in reversed(stdout_text.splitlines()):
                line = line.strip()
                if line.startswith("{") and line.endswith("}"):
                    try:
                        result_dict = json.loads(line)
                        break
                    except json.JSONDecodeError:
                        continue

        if not result_dict and proc.returncode != 0:
            err_msg = proc.stderr[:300] if proc.stderr else f"Sandbox container exited with code {proc.returncode}"
            return {
                "available": True,
                "success": False,
                "error": f"Sandbox execution error: {err_msg}",
                "final_url": url,
                "redirect_chain": [],
                "redirect_count": 0,
                "page_title": None,
                "html_raw": None,
                "dom_snapshot": None,
                "screenshot_path": None,
                "forms": [],
                "password_fields": [],
                "email_fields": [],
                "otp_fields": [],
                "payment_fields": [],
                "external_resources": [],
                "load_time_ms": 0.0,
                "scan_time_ms": round((time.perf_counter() - t0) * 1000, 1),
                "security_warnings": ["Container non-zero exit code"],
            }

        result_dict["available"] = True
        result_dict["scan_time_ms"] = round((time.perf_counter() - t0) * 1000, 1)

        # Handle base64 screenshot if present
        screenshot_b64 = result_dict.get("screenshot_b64")
        if screenshot_b64:
            try:
                import tempfile
                temp_dir = tempfile.gettempdir()
                scr_file = os.path.join(temp_dir, f"phishguard_scr_{uuid.uuid4().hex[:8]}.png")
                with open(scr_file, "wb") as f:
                    f.write(base64.b64decode(screenshot_b64))
                result_dict["screenshot_path"] = scr_file
            except Exception:
                result_dict["screenshot_path"] = None

        return result_dict

    except subprocess.TimeoutExpired:
        # Guarantee container kill and cleanup on timeout
        try:
            subprocess.run(["docker", "rm", "-f", container_id], capture_output=True, timeout=5)
        except Exception:
            pass

        return {
            "available": True,
            "success": False,
            "error": f"Sandbox scan timed out after {timeout_sec}s",
            "final_url": url,
            "redirect_chain": [],
            "redirect_count": 0,
            "page_title": None,
            "html_raw": None,
            "dom_snapshot": None,
            "screenshot_path": None,
            "forms": [],
            "password_fields": [],
            "email_fields": [],
            "otp_fields": [],
            "payment_fields": [],
            "external_resources": [],
            "load_time_ms": 0.0,
            "scan_time_ms": round((time.perf_counter() - t0) * 1000, 1),
            "security_warnings": ["Scan timeout: target page did not respond within limit."],
        }
    except Exception as e:
        return {
            "available": True,
            "success": False,
            "error": f"Container supervisor exception: {str(e)}",
            "final_url": url,
            "redirect_chain": [],
            "redirect_count": 0,
            "page_title": None,
            "html_raw": None,
            "dom_snapshot": None,
            "screenshot_path": None,
            "forms": [],
            "password_fields": [],
            "email_fields": [],
            "otp_fields": [],
            "payment_fields": [],
            "external_resources": [],
            "load_time_ms": 0.0,
            "scan_time_ms": round((time.perf_counter() - t0) * 1000, 1),
            "security_warnings": [f"Supervisor exception: {str(e)}"],
        }
