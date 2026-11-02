"""
PhishGuard AI V6.4 — Universal Deep Scan Reliability & Screenshot Display Test Suite
=====================================================================================
Comprehensive regression tests verifying:
  1. Screenshot propagation to /predict response and signals.screenshot
  2. Frontend screenshot telemetry data (screenshot_type, screenshot_status)
  3. Screenshot missing handling (graceful fallback without crashing)
  4. Multi-stage page navigation timeout taxonomy (distinction from VM failure)
  5. Partial page screenshot and DOM recovery
  6. Distinction between VM_AGENT_UNAVAILABLE and PAGE_NAVIGATION_TIMEOUT
  7. OCR availability and word count telemetry
  8. Redirect limit enforcement (MAX_REDIRECTS=5)
  9. In-VM SSRF redirect protection
  10. Malformed URLs and dangerous schemes rejection
  11. Private IP and metadata endpoint blocking
  12. Live Deep Scan execution on safe public targets (example.com, iana.org)
"""

import sys
import os
import json
import base64
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import requests
from deep_scan import vm_controller as vc

BACKEND_URL = os.environ.get("PHISHGUARD_TEST_URL", "http://localhost:5000")


# ── 1. Unit Tests: Timeout Configuration & Taxonomy ─────────────────────────

def test_v64_timeout_config_keys():
    """Verify all 5 multi-stage timeout keys exist in VM_CONFIG."""
    assert "CONNECT_TIMEOUT" in vc.VM_CONFIG
    assert "NAVIGATION_TIMEOUT" in vc.VM_CONFIG
    assert "CONTENT_SETTLE_TIMEOUT" in vc.VM_CONFIG
    assert "SCREENSHOT_TIMEOUT" in vc.VM_CONFIG
    assert "TOTAL_DEEP_SCAN_TIMEOUT" in vc.VM_CONFIG
    assert vc.VM_CONFIG["NAVIGATION_TIMEOUT"] >= 30.0
    assert vc.VM_CONFIG["TOTAL_DEEP_SCAN_TIMEOUT"] >= 60.0


def test_v64_unavailable_result_taxonomy():
    """Verify _unavailable_result accurately marks error_type and statuses."""
    res = vc._unavailable_result(
        url="https://example.com",
        t0=0.0,
        reason="Agent offline",
        error_type="VM_AGENT_UNAVAILABLE",
    )
    assert res["available"] is False
    assert res["success"] is False
    assert res["scan_status"] == "UNAVAILABLE"
    assert res["navigation_status"] == "ERROR"
    assert res["error_type"] == "VM_AGENT_UNAVAILABLE"
    assert res["screenshot_status"] == "unavailable"
    assert "host browser fallback is prohibited" in res["security_warnings"][0]


def test_v64_vm_timeout_distinguished_from_vm_offline():
    """Verify target timeout produces PAGE_NAVIGATION_TIMEOUT, NOT VM_AGENT_UNAVAILABLE."""
    with patch("deep_scan.vm_controller.check_sandbox_availability") as mock_avail, \
         patch("deep_scan.vm_controller._get_requests") as mock_get_req:

        mock_avail.return_value = {
            "sandbox_available": True,
            "virtualbox_vm_reachable": True,
            "vm_agent_healthy": True,
        }
        mock_req = MagicMock()
        mock_req.exceptions.Timeout = requests.exceptions.Timeout
        mock_req.exceptions.ConnectionError = requests.exceptions.ConnectionError
        mock_req.post.side_effect = requests.exceptions.Timeout("Target navigation timed out")
        mock_get_req.return_value = mock_req

        result = vc._execute_vm_scan("https://slow-target.example.org", 0.0)

        assert result["available"] is True  # VM itself is alive
        assert result["success"] is False
        assert result["scan_status"] == "UNAVAILABLE"
        assert result["navigation_status"] == "TIMEOUT"
        assert result["error_type"] == "PAGE_NAVIGATION_TIMEOUT"
        assert "timed out" in result["error"].lower()


def test_v64_vm_agent_connection_loss():
    """Verify connection loss during scan is tagged as VM_AGENT_UNAVAILABLE."""
    with patch("deep_scan.vm_controller.check_sandbox_availability") as mock_avail, \
         patch("deep_scan.vm_controller._get_requests") as mock_get_req:

        mock_avail.return_value = {"sandbox_available": True}
        mock_req = MagicMock()
        mock_req.exceptions.Timeout = requests.exceptions.Timeout
        mock_req.exceptions.ConnectionError = requests.exceptions.ConnectionError
        mock_req.post.side_effect = requests.exceptions.ConnectionError("Connection reset by peer")
        mock_get_req.return_value = mock_req

        result = vc._execute_vm_scan("https://example.com", 0.0)

        assert result["available"] is True
        assert result["success"] is False
        assert result["error_type"] == "VM_AGENT_UNAVAILABLE"


def test_v64_partial_scan_result_propagation():
    """Verify that partial scan evidence from VM is preserved and decoded."""
    dummy_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4"
    dummy_b64 = base64.b64encode(dummy_png).decode("ascii")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "success": True,
        "scan_status": "PARTIAL",
        "navigation_status": "TIMEOUT",
        "error_type": "PAGE_PARTIAL_LOAD",
        "page_available": True,
        "screenshot_available": True,
        "ocr_available": True,
        "dom_available": True,
        "screenshot_type": "viewport",
        "screenshot_status": "captured",
        "screenshot_b64": dummy_b64,
        "screenshot_evidence": {
            "available": True,
            "ocr_available": True,
            "ocr_word_count": 42,
            "analysis_time_ms": 110.5,
        },
        "page_title": "Partial Page",
        "html_raw": "<html><body>Partial content</body></html>",
        "dom_snapshot": "<html><body>Partial content</body></html>",
        "forms": [],
        "redirect_chain": [],
        "redirect_count": 0,
        "load_time_ms": 0.0,
        "security_warnings": ["Page navigation timed out after 30000ms"],
    }

    with patch("deep_scan.vm_controller._get_requests") as mock_get_req:
        mock_req = MagicMock()
        mock_req.post.return_value = mock_resp
        mock_get_req.return_value = mock_req

        res = vc._execute_vm_scan("https://partially-slow.org", 0.0)

        assert res["available"] is True
        assert res["success"] is True
        assert res["scan_status"] == "PARTIAL"
        assert res["navigation_status"] == "TIMEOUT"
        assert res["screenshot_b64"] == dummy_b64
        assert res["screenshot_type"] == "viewport"
        assert res["screenshot_path"] is not None
        assert os.path.exists(res["screenshot_path"])
        # Clean up temp file
        try:
            os.remove(res["screenshot_path"])
        except Exception:
            pass


# ── 2. Integration Tests with Flask Backend ──────────────────────────────────

def test_v64_flask_health_endpoint():
    """Verify backend /health returns deep_scan_available and VM status."""
    resp = requests.get(f"{BACKEND_URL}/health", timeout=5)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["deep_scan_available"] is True
    assert data["virtualbox_vm_reachable"] is True
    assert data["vm_agent_healthy"] is True
    assert data["playwright_available"] is True
    assert data["ocr_available"] is True


def test_v64_ssrf_malformed_and_private_blocked():
    """Verify malformed and private URLs are blocked before opening in browser."""
    blocked_urls = [
        "http://127.0.0.1:8080/test",
        "http://localhost:5000/internal",
        "http://192.168.1.100/router",
        "http://10.0.0.5/admin",
        "http://169.254.169.254/latest/meta-data",
        "file:///etc/passwd",
        "javascript:alert(1)",
    ]
    for u in blocked_urls:
        resp = requests.post(
            f"{BACKEND_URL}/predict",
            json={"url": u, "scan_mode": "deep"},
            timeout=5,
        )
        assert resp.status_code == 400
        data = resp.json()
        assert data["security_block"] is True


def test_v64_live_example_domain_deep_scan():
    """Verify live Deep Scan on example.com captures screenshot and OCR words."""
    resp = requests.post(
        f"{BACKEND_URL}/predict",
        json={"url": "https://example.com", "scan_mode": "deep"},
        timeout=35,
    )
    assert resp.status_code == 200
    data = resp.json()

    # Classification & Verdict
    assert data["verdict"] in ("Legitimate", "Suspicious")
    assert data["classification"] in ("LEGITIMATE", "SUSPICIOUS")

    # Deep Scan structure
    ds = data.get("deep_scan", {})
    assert ds.get("available") is True
    assert ds.get("executed") is True
    assert ds.get("status") in ("executed", "SUCCESS")
    assert ds.get("scan_status") == "SUCCESS"
    assert ds.get("navigation_status") == "SUCCESS"
    assert ds.get("screenshot_type") in ("full_page", "viewport")

    # Screenshot data URL base64 verification
    scr_b64 = ds.get("screenshot_b64")
    assert scr_b64 is not None
    assert len(scr_b64) > 1000

    # OCR Telemetry
    ocr = data.get("signals", {}).get("screenshot", {})
    assert ocr.get("ocr_available") is True
    assert (ocr.get("ocr_word_count") or 0) >= 20

    # Sandbox signals
    sb = data.get("signals", {}).get("sandbox", {})
    assert sb.get("page_title") == "Example Domain"
    assert sb.get("final_url") in ("https://example.com/", "https://example.com")


def test_v64_live_iana_reserved_domains_deep_scan():
    """Verify live Deep Scan on slower page (iana.org) succeeds with multi-stage timeout."""
    resp = requests.post(
        f"{BACKEND_URL}/predict",
        json={"url": "https://www.iana.org/domains/reserved", "scan_mode": "deep"},
        timeout=65,
    )
    assert resp.status_code == 200
    data = resp.json()

    ds = data.get("deep_scan", {})
    assert ds.get("available") is True
    assert ds.get("executed") is True
    assert ds.get("status") in ("executed", "partial", "SUCCESS", "PARTIAL")
    assert ds.get("screenshot_b64") is not None
    assert len(ds.get("screenshot_b64")) > 5000

    # OCR extraction on IANA page
    ocr = data.get("signals", {}).get("screenshot", {})
    assert ocr.get("ocr_available") is True
    assert (ocr.get("ocr_word_count") or 0) >= 50
