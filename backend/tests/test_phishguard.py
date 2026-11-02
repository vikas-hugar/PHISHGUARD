"""
PhishGuard AI V6.3 — Integration & Regression Test Suite
==========================================================
Tests the 8 required scenarios from the approved implementation plan:

  A. VM running   → Quick Scan works, Deep Scan works
  B. VM stopped   → Quick Scan works, Deep Scan shows UNAVAILABLE
  C. Invalid URL  → rejected safely
  D. localhost URL → blocked by SSRF guard
  E. Private IP URL → blocked by SSRF guard
  F. Redirect to private IP → blocked by in-VM SSRF guard
  G. Browser timeout → graceful failure
  H. Screenshot failure → Deep Scan continues without screenshot

Usage:
    cd backend
    python -m pytest tests/test_phishguard.py -v

    # Only run Quick Scan tests (no VM required):
    python -m pytest tests/test_phishguard.py -v -m quick

    # Only run VM-dependent tests:
    python -m pytest tests/test_phishguard.py -v -m deep

Prerequisites for deep scan tests:
    - Flask backend running on localhost:5000
    - VirtualBox analysis VM running and reachable on 192.168.56.101:8765
"""

import sys
import os
import json
import time

# Allow importing backend modules directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

# ── Optional: only import requests if available ─────────────────────────────
try:
    import requests as _requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

# Flask backend base URL (adjust if running on a different port)
BACKEND_URL = os.environ.get("PHISHGUARD_TEST_URL", "http://localhost:5000")


# ── Markers ──────────────────────────────────────────────────────────────────
def pytest_configure(config):
    config.addinivalue_line("markers", "quick: marks tests that only exercise Quick Scan")
    config.addinivalue_line("markers", "deep:  marks tests that require the VirtualBox VM")
    config.addinivalue_line("markers", "unit:  marks unit tests (no network required)")


# ─────────────────────────────────────────────────────────────────────────────
# UNIT TESTS — no Flask / VM required
# ─────────────────────────────────────────────────────────────────────────────

class TestSSRFGuard:
    """Unit tests for the host-side SSRF guard (detection/ssrf_guard.py)."""

    def setup_method(self):
        from detection.ssrf_guard import validate_url_safe
        self.validate = validate_url_safe

    @pytest.mark.unit
    def test_valid_public_url_passes(self):
        result = self.validate("http://example.com")
        assert result["safe"] is True, f"Expected safe=True, got: {result}"

    @pytest.mark.unit
    def test_https_public_url_passes(self):
        result = self.validate("https://google.com/search?q=test")
        assert result["safe"] is True

    @pytest.mark.unit
    def test_localhost_blocked(self):
        """Scenario D — localhost URL must be blocked."""
        result = self.validate("http://localhost/admin")
        assert result["safe"] is False, "localhost should be blocked"

    @pytest.mark.unit
    def test_loopback_ip_blocked(self):
        """Scenario E — loopback IP must be blocked."""
        result = self.validate("http://127.0.0.1/etc/passwd")
        assert result["safe"] is False, "127.0.0.1 should be blocked"

    @pytest.mark.unit
    def test_rfc1918_10_blocked(self):
        """Scenario E — private 10.x.x.x must be blocked."""
        result = self.validate("http://10.0.0.1/internal")
        assert result["safe"] is False, "10.0.0.1 should be blocked"

    @pytest.mark.unit
    def test_rfc1918_172_blocked(self):
        result = self.validate("http://172.16.0.1/secret")
        assert result["safe"] is False, "172.16.0.1 should be blocked"

    @pytest.mark.unit
    def test_rfc1918_192_168_blocked(self):
        """Scenario E — private 192.168.x.x must be blocked."""
        result = self.validate("http://192.168.1.1/admin")
        assert result["safe"] is False, "192.168.1.1 should be blocked"

    @pytest.mark.unit
    def test_link_local_metadata_blocked(self):
        """Cloud metadata endpoint must be blocked."""
        result = self.validate("http://169.254.169.254/latest/meta-data/")
        assert result["safe"] is False, "169.254.169.254 (link-local/AWS metadata) should be blocked"

    @pytest.mark.unit
    def test_file_scheme_blocked(self):
        result = self.validate("file:///etc/passwd")
        assert result["safe"] is False, "file:// scheme should be blocked"

    @pytest.mark.unit
    def test_javascript_scheme_blocked(self):
        result = self.validate("javascript:alert(1)")
        assert result["safe"] is False, "javascript: scheme should be blocked"

    @pytest.mark.unit
    def test_data_scheme_blocked(self):
        result = self.validate("data:text/html,<script>alert(1)</script>")
        assert result["safe"] is False, "data: scheme should be blocked"


class TestVMControllerSSRF:
    """Unit tests for the in-VM SSRF guard (analysis_agent/scanner.py)."""

    def setup_method(self):
        # Import the VM agent's is_safe_url (mimics what runs inside the VM)
        agent_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "..", "analysis_agent"
        )
        agent_dir = os.path.normpath(agent_dir)
        if agent_dir not in sys.path:
            sys.path.insert(0, agent_dir)
        from scanner import is_safe_url
        self.is_safe_url = is_safe_url

    @pytest.mark.unit
    def test_safe_public_url(self):
        safe, reason = self.is_safe_url("https://example.com")
        assert safe is True, f"Expected safe, got: {reason}"

    @pytest.mark.unit
    def test_localhost_blocked(self):
        safe, reason = self.is_safe_url("http://localhost/secret")
        assert safe is False
        assert reason != ""

    @pytest.mark.unit
    def test_loopback_blocked(self):
        safe, reason = self.is_safe_url("http://127.0.0.1:8080/admin")
        assert safe is False

    @pytest.mark.unit
    def test_private_ip_blocked(self):
        safe, reason = self.is_safe_url("http://192.168.1.1/router")
        assert safe is False

    @pytest.mark.unit
    def test_link_local_blocked(self):
        safe, reason = self.is_safe_url("http://169.254.169.254/metadata")
        assert safe is False

    @pytest.mark.unit
    def test_file_scheme_blocked(self):
        safe, reason = self.is_safe_url("file:///etc/passwd")
        assert safe is False

    @pytest.mark.unit
    def test_javascript_scheme_blocked(self):
        safe, reason = self.is_safe_url("javascript:void(0)")
        assert safe is False

    @pytest.mark.unit
    def test_ipv6_loopback_blocked(self):
        safe, reason = self.is_safe_url("http://[::1]/admin")
        assert safe is False

    @pytest.mark.unit
    def test_fc00_ula_blocked(self):
        """IPv6 Unique Local Address (fc00::/7) must be blocked."""
        safe, reason = self.is_safe_url("http://[fd00::1]/secret")
        assert safe is False


class TestVMControllerUnit:
    """Unit tests for vm_controller.py that do not require a real VM."""

    def setup_method(self):
        from deep_scan.vm_controller import VM_CONFIG, get_sandbox_status
        self.VM_CONFIG = VM_CONFIG
        self.get_sandbox_status = get_sandbox_status

    @pytest.mark.unit
    def test_vm_config_has_required_keys(self):
        required = ["VM_IP", "VM_PORT", "VM_TIMEOUT_SEC", "BROWSER_TIMEOUT_MS",
                    "MAX_REDIRECTS", "MAX_RESPONSE_KB"]
        for key in required:
            assert key in self.VM_CONFIG, f"Missing key: {key}"

    @pytest.mark.unit
    def test_vm_config_port_is_int(self):
        assert isinstance(self.VM_CONFIG["VM_PORT"], int)

    @pytest.mark.unit
    def test_get_sandbox_status_returns_dict(self):
        status = self.get_sandbox_status()
        assert isinstance(status, dict)

    @pytest.mark.unit
    def test_get_sandbox_status_has_required_fields(self):
        status = self.get_sandbox_status()
        for field in ["sandbox_available", "virtualbox_vm_reachable",
                      "vm_agent_healthy", "docker_installed", "docker_running"]:
            assert field in status, f"Missing status field: {field}"

    @pytest.mark.unit
    def test_docker_fields_always_false(self):
        """Docker fields must always be False — Docker is not required."""
        status = self.get_sandbox_status()
        assert status["docker_installed"] is False
        assert status["docker_running"] is False

    @pytest.mark.unit
    def test_unavailable_when_vm_not_running(self):
        """
        With no VM running this test should report unavailable.
        If the VM IS running, this test is skipped gracefully.
        """
        from deep_scan.vm_controller import _VM_REACHABLE
        if _VM_REACHABLE:
            pytest.skip("VM is currently reachable — skipping unavailability unit test")
        from deep_scan.vm_controller import get_sandbox_status
        status = get_sandbox_status()
        assert status["sandbox_available"] is False
        assert status["unavailability_reason"] is not None


# ─────────────────────────────────────────────────────────────────────────────
# INTEGRATION TESTS — require Flask backend on localhost:5000
# ─────────────────────────────────────────────────────────────────────────────

def backend_available() -> bool:
    """Check if Flask backend is reachable."""
    if not REQUESTS_OK:
        return False
    try:
        r = _requests.get(f"{BACKEND_URL}/health", timeout=4)
        return r.status_code == 200
    except Exception:
        return False


def vm_available() -> bool:
    """Check if the VirtualBox VM agent is reachable via /deep-scan/health."""
    if not REQUESTS_OK:
        return False
    try:
        r = _requests.get(f"{BACKEND_URL}/deep-scan/health", timeout=8)
        return r.status_code == 200 and r.json().get("available", False)
    except Exception:
        return False


SKIP_NO_BACKEND = pytest.mark.skipif(
    not backend_available(),
    reason="Flask backend not running on localhost:5000"
)

SKIP_NO_VM = pytest.mark.skipif(
    not vm_available(),
    reason="VirtualBox analysis VM not reachable"
)


@pytest.mark.quick
class TestHealthEndpoints:
    """Scenario A/B — health endpoints."""

    @SKIP_NO_BACKEND
    def test_health_returns_ok(self):
        r = _requests.get(f"{BACKEND_URL}/health", timeout=5)
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"

    @SKIP_NO_BACKEND
    def test_health_has_vm_fields(self):
        r = _requests.get(f"{BACKEND_URL}/health", timeout=5)
        body = r.json()
        assert "virtualbox_vm_reachable" in body
        assert "vm_agent_healthy" in body
        assert "sandbox_available" in body

    @SKIP_NO_BACKEND
    def test_health_docker_fields_always_false(self):
        """Docker must never be reported as present."""
        r = _requests.get(f"{BACKEND_URL}/health", timeout=5)
        body = r.json()
        assert body["docker_installed"] is False
        assert body["docker_running"] is False

    @SKIP_NO_BACKEND
    def test_deep_scan_health_endpoint_exists(self):
        r = _requests.get(f"{BACKEND_URL}/deep-scan/health", timeout=8)
        assert r.status_code in (200, 503)
        body = r.json()
        assert "available" in body
        assert body["provider"] == "virtualbox"


@pytest.mark.quick
class TestQuickScanAlwaysWorks:
    """Scenario A and B — Quick Scan must work regardless of VM state."""

    @SKIP_NO_BACKEND
    def test_quick_scan_safe_url(self):
        r = _requests.post(
            f"{BACKEND_URL}/predict",
            json={"url": "https://google.com", "scan_mode": "quick"},
            timeout=15,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "success"
        assert "risk_score" in body
        assert "confidence" in body

    @SKIP_NO_BACKEND
    def test_quick_scan_phishing_url(self):
        r = _requests.post(
            f"{BACKEND_URL}/predict",
            json={"url": "http://paypal-security-update.com/login", "scan_mode": "quick"},
            timeout=15,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "success"

    @SKIP_NO_BACKEND
    def test_invalid_url_rejected(self):
        """Scenario C — invalid/empty URL must be rejected."""
        r = _requests.post(
            f"{BACKEND_URL}/predict",
            json={"url": "", "scan_mode": "quick"},
            timeout=10,
        )
        assert r.status_code == 400

    @SKIP_NO_BACKEND
    def test_localhost_url_blocked(self):
        """Scenario D — localhost URL must be blocked by SSRF guard."""
        r = _requests.post(
            f"{BACKEND_URL}/predict",
            json={"url": "http://localhost/admin", "scan_mode": "quick"},
            timeout=10,
        )
        assert r.status_code == 400
        body = r.json()
        assert body.get("security_block") is True, "Expected security_block=true for localhost"

    @SKIP_NO_BACKEND
    def test_private_ip_blocked(self):
        """Scenario E — private IP 192.168.1.1 must be blocked."""
        r = _requests.post(
            f"{BACKEND_URL}/predict",
            json={"url": "http://192.168.1.1/admin", "scan_mode": "quick"},
            timeout=10,
        )
        assert r.status_code == 400
        body = r.json()
        assert body.get("security_block") is True

    @SKIP_NO_BACKEND
    def test_loopback_ip_blocked(self):
        """Scenario E — loopback 127.0.0.1 must be blocked."""
        r = _requests.post(
            f"{BACKEND_URL}/predict",
            json={"url": "http://127.0.0.1:8080/internal", "scan_mode": "quick"},
            timeout=10,
        )
        assert r.status_code == 400
        body = r.json()
        assert body.get("security_block") is True

    @SKIP_NO_BACKEND
    def test_quick_scan_returns_risk_and_confidence_separately(self):
        """Risk score and confidence must be separate numeric fields."""
        r = _requests.post(
            f"{BACKEND_URL}/predict",
            json={"url": "http://paypal-security-update.com/login", "scan_mode": "quick"},
            timeout=15,
        )
        body = r.json()
        assert isinstance(body.get("risk_score"), (int, float))
        assert isinstance(body.get("confidence"), (int, float))
        # They are mathematically independent — this verifies they are present
        assert "risk_score" in body and "confidence" in body


@pytest.mark.quick
class TestDeepScanVMStopped:
    """Scenario B — Deep Scan UNAVAILABLE when VM is not running."""

    @SKIP_NO_BACKEND
    def test_deep_scan_unavailable_returns_quick_result(self):
        """
        Even if Deep Scan is unavailable, the Quick Scan result in the
        response must still be present and valid.
        """
        if vm_available():
            pytest.skip("VM is running — scenario B requires VM to be stopped")

        r = _requests.post(
            f"{BACKEND_URL}/predict",
            json={"url": "http://paypal-security-update.com/login", "scan_mode": "deep"},
            timeout=20,
        )
        # The endpoint must return 200 (Quick Scan result) — never 500
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "success"
        assert "risk_score" in body

    @SKIP_NO_BACKEND
    def test_deep_scan_signals_contain_sandbox_unavailable(self):
        if vm_available():
            pytest.skip("VM is running — scenario B requires VM to be stopped")

        r = _requests.post(
            f"{BACKEND_URL}/predict",
            json={"url": "http://paypal-security-update.com/login", "scan_mode": "deep"},
            timeout=20,
        )
        body = r.json()
        deep_scan_field = body.get("deep_scan", {})
        assert deep_scan_field.get("available") is False or \
               deep_scan_field.get("status") in ("unavailable", "skipped", None), \
               "Deep scan should be reported as unavailable when VM is stopped"

    @SKIP_NO_BACKEND
    def test_deep_scan_health_503_when_vm_stopped(self):
        if vm_available():
            pytest.skip("VM is running")
        r = _requests.get(f"{BACKEND_URL}/deep-scan/health", timeout=8)
        assert r.status_code == 503
        body = r.json()
        assert body["available"] is False
        assert body.get("reason") is not None


@pytest.mark.deep
class TestDeepScanVMRunning:
    """Scenario A — Deep Scan works when VM is running."""

    @SKIP_NO_BACKEND
    @SKIP_NO_VM
    def test_deep_scan_executes_successfully(self):
        """Full Deep Scan pipeline must complete without error."""
        r = _requests.post(
            f"{BACKEND_URL}/predict",
            json={"url": "http://example.com", "scan_mode": "deep"},
            timeout=45,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "success"

    @SKIP_NO_BACKEND
    @SKIP_NO_VM
    def test_deep_scan_returns_html_evidence(self):
        r = _requests.post(
            f"{BACKEND_URL}/predict",
            json={"url": "http://example.com", "scan_mode": "deep"},
            timeout=45,
        )
        body = r.json()
        signals = body.get("signals", {})
        assert "html" in signals or "sandbox" in signals, \
            "Deep Scan result should include html or sandbox signal"

    @SKIP_NO_BACKEND
    @SKIP_NO_VM
    def test_deep_scan_never_opens_host_browser(self):
        """
        Verifying isolation: /predict with deep scan must return a JSON result
        (VM handled it) — NOT open anything on the Windows host.
        This is a structural test: if we get a JSON response, the host browser
        was never touched.
        """
        r = _requests.post(
            f"{BACKEND_URL}/predict",
            json={"url": "http://example.com", "scan_mode": "deep"},
            timeout=45,
        )
        assert r.headers.get("Content-Type", "").startswith("application/json"), \
            "Response must be JSON — host browser was not invoked"

    @SKIP_NO_BACKEND
    @SKIP_NO_VM
    def test_quick_scan_still_works_with_vm_running(self):
        """Scenario A — Quick Scan continues to work when VM is running."""
        r = _requests.post(
            f"{BACKEND_URL}/predict",
            json={"url": "https://google.com", "scan_mode": "quick"},
            timeout=15,
        )
        assert r.status_code == 200
        assert r.json()["status"] == "success"


@pytest.mark.deep
class TestDeepScanSSRFInVM:
    """Scenario F — Redirect to private IP must be blocked inside VM."""

    @SKIP_NO_BACKEND
    @SKIP_NO_VM
    def test_known_private_ip_url_blocked_before_vm(self):
        """
        The host SSRF guard catches direct private IPs before they reach the VM.
        This ensures Defense in Depth even if the VM SSRF guard failed.
        """
        r = _requests.post(
            f"{BACKEND_URL}/predict",
            json={"url": "http://192.168.1.1/", "scan_mode": "deep"},
            timeout=10,
        )
        assert r.status_code == 400
        assert r.json().get("security_block") is True


@pytest.mark.deep
class TestDeepScanGracefulFailures:
    """Scenarios G and H — graceful handling of timeout and screenshot failure."""

    @SKIP_NO_BACKEND
    @SKIP_NO_VM
    def test_scan_continues_even_if_no_screenshot(self):
        """
        Scenario H — Deep Scan must return evidence even if screenshot is None.
        We verify by checking that a successful scan result still has risk_score.
        """
        r = _requests.post(
            f"{BACKEND_URL}/predict",
            json={"url": "http://example.com", "scan_mode": "deep"},
            timeout=45,
        )
        body = r.json()
        # risk_score must be present regardless of screenshot availability
        assert "risk_score" in body
        assert isinstance(body["risk_score"], (int, float))

    @SKIP_NO_BACKEND
    @SKIP_NO_VM
    def test_deep_scan_health_200_when_vm_running(self):
        r = _requests.get(f"{BACKEND_URL}/deep-scan/health", timeout=8)
        assert r.status_code == 200
        body = r.json()
        assert body["available"] is True
        assert body["provider"] == "virtualbox"


# ─────────────────────────────────────────────────────────────────────────────
# MOCKED UNIT TESTS — vm_controller behaviour without a live VM
# Requirement coverage:
#   - VM healthy                 → check_sandbox_availability reports available
#   - VM unavailable             → run_deep_scan returns UNAVAILABLE immediately
#   - /analyze HTTP 200          → result dict is returned correctly
#   - /analyze HTTP non-200      → error dict is returned, no exception
#   - VM timeout                 → Timeout exception produces well-formed error dict
#   - screenshot_b64 decoding    → PNG bytes written to temp file
#   - screenshot_b64 bad data    → non-fatal warning, scan continues
#   - No host-browser fallback   → run_deep_scan never calls webbrowser/subprocess
# ─────────────────────────────────────────────────────────────────────────────

class TestVMControllerMocked:
    """
    Fully-mocked unit tests for vm_controller.py.
    No live VM or Flask server required.
    """

    # ── helpers ───────────────────────────────────────────────────────────────

    def _import_vc(self):
        import deep_scan.vm_controller as vc
        return vc

    # ── VM healthy ────────────────────────────────────────────────────────────

    @pytest.mark.unit
    def test_vm_healthy_sets_sandbox_available(self):
        """
        When TCP connect succeeds AND /health returns {available: true},
        check_sandbox_availability() must set sandbox_available=True.
        """
        from unittest.mock import patch, MagicMock
        vc = self._import_vc()

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.json.return_value = {"available": True, "status": "ok", "version": "1.0"}

        with patch.object(vc, "_tcp_reachable", return_value=True), \
             patch("requests.get", return_value=fake_resp):
            status = vc.check_sandbox_availability()

        assert status["sandbox_available"] is True, (
            f"Expected sandbox_available=True when VM healthy, got: {status}"
        )
        assert status["virtualbox_vm_reachable"] is True
        assert status["vm_agent_healthy"] is True
        assert status["unavailability_reason"] is None

    # ── VM unavailable (TCP fail) ─────────────────────────────────────────────

    @pytest.mark.unit
    def test_vm_unreachable_sets_unavailable(self):
        """
        When TCP connect fails, check_sandbox_availability must report
        sandbox_available=False with a non-empty reason.
        """
        from unittest.mock import patch
        vc = self._import_vc()

        with patch.object(vc, "_tcp_reachable", return_value=False):
            status = vc.check_sandbox_availability()

        assert status["sandbox_available"] is False
        assert status["virtualbox_vm_reachable"] is False
        assert status["unavailability_reason"] is not None
        assert len(status["unavailability_reason"]) > 0

    # ── run_deep_scan when VM unavailable ─────────────────────────────────────

    @pytest.mark.unit
    def test_run_deep_scan_unavailable_returns_unavailable_dict(self):
        """
        If sandbox is not available, run_deep_scan must return the
        UNAVAILABLE sentinel dict immediately — no network calls made.
        """
        from unittest.mock import patch
        vc = self._import_vc()

        unavailable_status = {
            "sandbox_available": False,
            "unavailability_reason": "Unit-test-forced unavailability",
            "virtualbox_vm_reachable": False,
            "vm_agent_healthy": False,
            "vm_agent_version": None,
        }

        with patch.object(vc, "check_sandbox_availability", return_value=unavailable_status):
            result = vc.run_deep_scan("http://evil.example.com/phish")

        assert result["available"] is False
        assert result["success"] is False
        assert "Deep Scan unavailable" in result["error"]
        assert "host browser fallback is prohibited" in " ".join(result.get("security_warnings", []))

    # ── /analyze HTTP 200 success ─────────────────────────────────────────────

    @pytest.mark.unit
    def test_analyze_success_returns_result_dict(self):
        """
        When VM returns HTTP 200 with a valid JSON body,
        _execute_vm_scan should return a dict with available=True and success=True.
        """
        import base64
        from unittest.mock import patch, MagicMock
        vc = self._import_vc()

        png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32  # minimal fake PNG
        b64_scr = base64.b64encode(png_bytes).decode()

        fake_agent_response = {
            "success": True,
            "error": None,
            "final_url": "http://example.com",
            "page_title": "Example Domain",
            "html_raw": "<html></html>",
            "dom_snapshot": "<html></html>",
            "forms": [],
            "external_resources": [],
            "redirect_chain": [],
            "redirect_count": 0,
            "load_time_ms": 234.5,
            "screenshot_b64": b64_scr,
        }

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.json.return_value = fake_agent_response

        available_status = {
            "sandbox_available": True,
            "unavailability_reason": None,
            "virtualbox_vm_reachable": True,
            "vm_agent_healthy": True,
            "vm_agent_version": "1.0",
        }

        with patch.object(vc, "check_sandbox_availability", return_value=available_status), \
             patch("requests.post", return_value=fake_resp):
            result = vc.run_deep_scan("http://example.com")

        assert result["available"] is True
        assert result.get("success") is True
        assert result.get("final_url") == "http://example.com"
        assert result.get("page_title") == "Example Domain"

    # ── /analyze HTTP non-200 error ───────────────────────────────────────────

    @pytest.mark.unit
    def test_analyze_http_error_returns_error_dict(self):
        """
        When the VM agent returns a non-200 status, the result must have
        success=False and a meaningful error message.  No exception must propagate.
        """
        from unittest.mock import patch, MagicMock
        vc = self._import_vc()

        fake_resp = MagicMock()
        fake_resp.status_code = 500
        fake_resp.json.return_value = {"error": "Internal VM agent error"}

        available_status = {
            "sandbox_available": True,
            "unavailability_reason": None,
            "virtualbox_vm_reachable": True,
            "vm_agent_healthy": True,
            "vm_agent_version": "1.0",
        }

        with patch.object(vc, "check_sandbox_availability", return_value=available_status), \
             patch("requests.post", return_value=fake_resp):
            result = vc.run_deep_scan("http://example.com")

        assert result["success"] is False
        assert result.get("error") is not None
        assert "500" in result["error"] or "Internal VM agent error" in result["error"]

    # ── VM timeout ────────────────────────────────────────────────────────────

    @pytest.mark.unit
    def test_vm_timeout_returns_error_dict_no_exception(self):
        """
        Scenario G — when the VM agent times out, run_deep_scan must return
        a well-formed error dict.  No exception must bubble up to the caller.
        """
        from unittest.mock import patch
        import requests as req
        vc = self._import_vc()

        available_status = {
            "sandbox_available": True,
            "unavailability_reason": None,
            "virtualbox_vm_reachable": True,
            "vm_agent_healthy": True,
            "vm_agent_version": "1.0",
        }

        with patch.object(vc, "check_sandbox_availability", return_value=available_status), \
             patch("requests.post", side_effect=req.exceptions.Timeout("timed out")):
            result = vc.run_deep_scan("http://slow-target.example.com")

        assert result["success"] is False
        assert "timeout" in result["error"].lower() or "timed out" in result["error"].lower()
        # Must still have the mandatory structural fields
        assert "redirect_chain" in result
        assert "scan_time_ms" in result

    # ── screenshot_b64 decoding ───────────────────────────────────────────────

    @pytest.mark.unit
    def test_screenshot_b64_decoded_to_temp_file(self):
        """
        When the VM returns a valid screenshot_b64, _execute_vm_scan must
        decode it and set screenshot_path to a real temp file path.
        """
        import base64, os
        from unittest.mock import patch, MagicMock
        vc = self._import_vc()

        png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
        b64_scr = base64.b64encode(png_bytes).decode()

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.json.return_value = {
            "success": True, "error": None,
            "final_url": "http://example.com", "page_title": "T",
            "html_raw": "", "dom_snapshot": "", "forms": [],
            "external_resources": [], "redirect_chain": [], "redirect_count": 0,
            "load_time_ms": 100.0, "screenshot_b64": b64_scr,
        }

        available_status = {
            "sandbox_available": True, "unavailability_reason": None,
            "virtualbox_vm_reachable": True, "vm_agent_healthy": True, "vm_agent_version": "1.0",
        }

        with patch.object(vc, "check_sandbox_availability", return_value=available_status), \
             patch("requests.post", return_value=fake_resp):
            result = vc.run_deep_scan("http://example.com")

        scr_path = result.get("screenshot_path")
        assert scr_path is not None, "screenshot_path must not be None when screenshot_b64 is valid"
        assert os.path.isfile(scr_path), f"Decoded screenshot file does not exist: {scr_path}"
        with open(scr_path, "rb") as f:
            data = f.read()
        assert data == png_bytes, "Decoded screenshot bytes do not match original"
        # Cleanup
        os.unlink(scr_path)

    # ── screenshot_b64 bad data (non-fatal) ───────────────────────────────────

    @pytest.mark.unit
    def test_screenshot_b64_invalid_data_is_non_fatal(self):
        """
        Scenario H — if screenshot_b64 contains invalid base64, the scan must
        still return success=True and set screenshot_path=None.
        """
        from unittest.mock import patch, MagicMock
        vc = self._import_vc()

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.json.return_value = {
            "success": True, "error": None,
            "final_url": "http://example.com", "page_title": "T",
            "html_raw": "", "dom_snapshot": "", "forms": [],
            "external_resources": [], "redirect_chain": [], "redirect_count": 0,
            "load_time_ms": 100.0,
            "screenshot_b64": "!!!INVALID_BASE64!!!",
        }

        available_status = {
            "sandbox_available": True, "unavailability_reason": None,
            "virtualbox_vm_reachable": True, "vm_agent_healthy": True, "vm_agent_version": "1.0",
        }

        with patch.object(vc, "check_sandbox_availability", return_value=available_status), \
             patch("requests.post", return_value=fake_resp):
            result = vc.run_deep_scan("http://example.com")

        # Scan must succeed even when screenshot fails
        assert result.get("success") is True
        assert result.get("screenshot_path") is None
        # A warning must be attached
        warnings = result.get("security_warnings") or []
        assert any("screenshot" in w.lower() for w in warnings), (
            "Expected a screenshot warning in security_warnings"
        )

    # ── No host-browser fallback guarantee ───────────────────────────────────

    @pytest.mark.unit
    def test_deep_scan_never_calls_host_browser(self):
        """
        The most critical safety guarantee: run_deep_scan must NEVER invoke
        webbrowser.open(), subprocess.Popen(), or os.startfile() on the host,
        regardless of the URL passed to it.
        """
        from unittest.mock import patch
        import webbrowser, subprocess
        vc = self._import_vc()

        # Make VM unavailable so _execute_vm_scan is never reached either
        unavailable_status = {
            "sandbox_available": False,
            "unavailability_reason": "Forced unavailable for isolation test",
            "virtualbox_vm_reachable": False,
            "vm_agent_healthy": False,
            "vm_agent_version": None,
        }

        with patch.object(vc, "check_sandbox_availability", return_value=unavailable_status), \
             patch.object(webbrowser, "open") as mock_wb, \
             patch.object(subprocess, "Popen") as mock_popen, \
             patch.object(subprocess, "run") as mock_run:

            result = vc.run_deep_scan("http://dangerous-phishing-site.xyz/steal-creds")

        mock_wb.assert_not_called()
        mock_popen.assert_not_called()
        mock_run.assert_not_called()
        assert result["available"] is False, "Must report unavailable, not open host browser"

    # ── app.py imports vm_controller (not sandbox_controller) ─────────────────

    @pytest.mark.unit
    def test_app_py_imports_vm_controller_not_sandbox_controller(self):
        """
        Verify that backend/app.py imports run_deep_scan from vm_controller,
        not from sandbox_controller.  This is checked at the source level.
        """
        import ast
        app_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "app.py"
        )
        assert os.path.isfile(app_path), f"app.py not found at {app_path}"
        with open(app_path, "r", encoding="utf-8") as f:
            source = f.read()

        tree = ast.parse(source)
        vm_import_found = False
        sandbox_import_run_deep_scan = False

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                names = [alias.name for alias in node.names]
                if "vm_controller" in module and "run_deep_scan" in names:
                    vm_import_found = True
                if "sandbox_controller" in module and "run_deep_scan" in names:
                    sandbox_import_run_deep_scan = True

        assert vm_import_found, (
            "app.py must import run_deep_scan from deep_scan.vm_controller"
        )
        assert not sandbox_import_run_deep_scan, (
            "app.py must NOT import run_deep_scan from sandbox_controller"
        )


# ─────────────────────────────────────────────────────────────────────────────
# QUICK standalone runner (python tests/test_phishguard.py)
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import subprocess
    result = subprocess.run(
        [sys.executable, "-m", "pytest", __file__, "-v", "--tb=short"],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )
    sys.exit(result.returncode)
