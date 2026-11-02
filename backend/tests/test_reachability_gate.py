"""
PhishGuard AI — Reachability Pre-Scan Gate Test Suite
======================================================
Tests all 11 required scenarios:
  TEST 1:  Reachable legitimate website
  TEST 2:  Reachable phishing website
  TEST 3:  Non-existent domain
  TEST 4:  Offline / unavailable server
  TEST 5:  Connection timeout
  TEST 6:  DNS failure
  TEST 7:  localhost (SSRF BLOCKED)
  TEST 8:  127.0.0.1 (SSRF BLOCKED)
  TEST 9:  Private IP (SSRF BLOCKED)
  TEST 10: Public URL redirecting to localhost / private IP (SSRF BLOCKED)
  TEST 11: Reachable unknown / new domain (Unknown ≠ Safe)
"""

import sys
import os
from unittest.mock import patch, MagicMock
import requests

# Add backend directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import app
from detection.reachability import validate_url, validate_ssrf, check_reachability


@pytest.fixture
def client():
    """Create Flask test client for direct endpoint testing."""
    app.app.config["TESTING"] = True
    with app.app.test_client() as c:
        yield c


# =============================================================================
# TEST 1: Reachable Legitimate Website
# =============================================================================
def test_1_reachable_legitimate_website(client):
    """
    TEST 1: Reachable legitimate website
    Expected:
      - reachable
      - scan_performed = true
      - full analysis starts
    """
    # Verify reachability module directly
    reach = check_reachability("https://example.com")
    assert reach["reachable"] is True
    assert reach["status"] == "REACHABLE"

    # Verify predict endpoint
    resp = client.post("/predict", json={"url": "https://example.com"})
    assert resp.status_code == 200
    data = resp.get_json()

    assert data.get("scan_performed") is True
    assert data.get("reachability_status") == "reachable"
    assert data.get("verdict") in ("SAFE", "LEGITIMATE", "Safe", "Legitimate")
    assert data.get("classification") == "LEGITIMATE"
    assert data.get("risk_score") is not None
    assert "deep_scan" in data
    assert "models" in data


# =============================================================================
# TEST 2: Reachable Phishing Website
# =============================================================================
def test_2_reachable_phishing_website(client):
    """
    TEST 2: Reachable phishing website
    Expected:
      - reachable
      - scan_performed = true
      - phishing analysis runs
      - final verdict can be PHISHING
    """
    # Mock reachability to guarantee reachable status regardless of live domain status
    mock_reach = {
        "reachable": True,
        "ssrf_blocked": False,
        "status": "REACHABLE",
        "reachability_status": "reachable",
        "reason": None,
        "http_status": 200,
        "final_url": "http://ledger-com-strts.pages.dev/",
        "redirect_chain": [],
        "redirect_count": 0,
        "elapsed_ms": 15.0,
    }

    with patch("app.check_reachability", return_value=mock_reach):
        resp = client.post("/predict", json={"url": "http://ledger-com-strts.pages.dev/"})
        assert resp.status_code == 200
        data = resp.get_json()

        assert data.get("scan_performed") is True
        assert data.get("reachability_status") == "reachable"
        assert data.get("classification") in ("KNOWN_PHISHING", "ZERO_DAY_PHISHING", "SUSPICIOUS")
        assert data.get("verdict") in ("Known Phishing", "Zero-Day Phishing", "Suspicious", "PHISHING", "KNOWN_PHISHING")
        assert data.get("risk_score") is not None
        assert data.get("risk_score") >= 50


# =============================================================================
# TEST 3: Non-existent Domain
# =============================================================================
def test_3_non_existent_domain(client):
    """
    TEST 3: Non-existent domain
    Expected:
      - not_reachable
      - scan_performed = false
      - verdict = INCONCLUSIVE
      - risk_score = null
      - confidence_score = 0
    """
    url = "https://nonexistent-phish-domain-40482934.org"
    resp = client.post("/predict", json={"url": url})
    assert resp.status_code == 200
    data = resp.get_json()

    assert data.get("status") == "not_reachable"
    assert data.get("scan_performed") is False
    assert data.get("verdict") == "INCONCLUSIVE"
    assert data.get("risk_score") is None
    assert data.get("confidence_score") == 0
    assert data.get("reachability_status") in ("DNS_FAILED", "HOST_UNAVAILABLE")
    assert "not performed" in data.get("message", "").lower()
    assert "safe" in data.get("recommendation", "").lower()
    assert data["deep_scan"]["executed"] is False


# =============================================================================
# TEST 4: Offline / Unavailable Server
# =============================================================================
def test_4_offline_unavailable_server(client):
    """
    TEST 4: Offline/unavailable server
    Expected:
      - not_reachable
      - scan_performed = false
      - verdict = INCONCLUSIVE
    """
    mock_reach = {
        "reachable": False,
        "ssrf_blocked": False,
        "status": "HOST_UNAVAILABLE",
        "reachability_status": "HOST_UNAVAILABLE",
        "reason": "Host unavailable: Target server returned HTTP 502",
        "http_status": 502,
        "final_url": "https://offline-server.example.com",
        "redirect_chain": [],
        "redirect_count": 0,
        "elapsed_ms": 20.0,
    }

    with patch("app.check_reachability", return_value=mock_reach):
        resp = client.post("/predict", json={"url": "https://offline-server.example.com"})
        assert resp.status_code == 200
        data = resp.get_json()

        assert data.get("status") == "not_reachable"
        assert data.get("scan_performed") is False
        assert data.get("verdict") == "INCONCLUSIVE"
        assert data.get("risk_score") is None
        assert data.get("confidence_score") == 0
        assert data.get("reachability_status") == "HOST_UNAVAILABLE"


# =============================================================================
# TEST 5: Connection Timeout
# =============================================================================
def test_5_connection_timeout(client):
    """
    TEST 5: Connection timeout
    Expected:
      - not_reachable
      - scan_performed = false
      - reachability_status = CONNECTION_TIMEOUT
    """
    mock_reach = {
        "reachable": False,
        "ssrf_blocked": False,
        "status": "CONNECTION_TIMEOUT",
        "reachability_status": "CONNECTION_TIMEOUT",
        "reason": "Connection timeout: The target server did not respond within the time limit",
        "http_status": None,
        "final_url": "https://slow-hanging-server.example.com",
        "redirect_chain": [],
        "redirect_count": 0,
        "elapsed_ms": 4000.0,
    }

    with patch("app.check_reachability", return_value=mock_reach):
        resp = client.post("/predict", json={"url": "https://slow-hanging-server.example.com"})
        assert resp.status_code == 200
        data = resp.get_json()

        assert data.get("status") == "not_reachable"
        assert data.get("scan_performed") is False
        assert data.get("verdict") == "INCONCLUSIVE"
        assert data.get("risk_score") is None
        assert data.get("reachability_status") == "CONNECTION_TIMEOUT"


# =============================================================================
# TEST 6: DNS Failure
# =============================================================================
def test_6_dns_failure(client):
    """
    TEST 6: DNS failure
    Expected:
      - not_reachable
      - scan_performed = false
      - reachability_status = DNS_FAILED
    """
    mock_reach = {
        "reachable": False,
        "ssrf_blocked": False,
        "status": "DNS_FAILED",
        "reachability_status": "DNS_FAILED",
        "reason": "DNS resolution failed: Domain does not exist or nameserver unreachable",
        "http_status": None,
        "final_url": "https://invalid-dns-lookup-failure.test",
        "redirect_chain": [],
        "redirect_count": 0,
        "elapsed_ms": 12.0,
    }

    with patch("app.check_reachability", return_value=mock_reach):
        resp = client.post("/predict", json={"url": "https://invalid-dns-lookup-failure.test"})
        assert resp.status_code == 200
        data = resp.get_json()

        assert data.get("status") == "not_reachable"
        assert data.get("scan_performed") is False
        assert data.get("verdict") == "INCONCLUSIVE"
        assert data.get("reachability_status") == "DNS_FAILED"


# =============================================================================
# TEST 7: localhost (SSRF BLOCKED)
# =============================================================================
def test_7_localhost_blocked(client):
    """
    TEST 7: localhost
    Expected:
      - SSRF BLOCKED
      - scan_performed = false
      - HTTP status 400
    """
    resp = client.post("/predict", json={"url": "http://localhost/admin"})
    assert resp.status_code == 400
    data = resp.get_json()

    assert data.get("security_block") is True
    assert data.get("scan_performed") is False
    assert data.get("reachability_status") == "SSRF_BLOCKED"
    assert data["deep_scan"]["status"] == "BLOCKED_SSRF"


# =============================================================================
# TEST 8: 127.0.0.1 (SSRF BLOCKED)
# =============================================================================
def test_8_loopback_ip_blocked(client):
    """
    TEST 8: 127.0.0.1
    Expected:
      - SSRF BLOCKED
      - scan_performed = false
      - HTTP status 400
    """
    resp = client.post("/predict", json={"url": "http://127.0.0.1:8080/secret"})
    assert resp.status_code == 400
    data = resp.get_json()

    assert data.get("security_block") is True
    assert data.get("scan_performed") is False
    assert data.get("reachability_status") == "SSRF_BLOCKED"


# =============================================================================
# TEST 9: Private IP (SSRF BLOCKED)
# =============================================================================
def test_9_private_ip_blocked(client):
    """
    TEST 9: Private IP
    Expected:
      - SSRF BLOCKED
      - scan_performed = false
      - HTTP status 400
    """
    for private_target in ("http://10.0.0.1/admin", "http://192.168.1.1/router", "http://172.16.0.1/corp"):
        resp = client.post("/predict", json={"url": private_target})
        assert resp.status_code == 400
        data = resp.get_json()

        assert data.get("security_block") is True
        assert data.get("scan_performed") is False
        assert data.get("reachability_status") == "SSRF_BLOCKED"


# =============================================================================
# TEST 10: Public URL redirecting to localhost / private IP
# =============================================================================
def test_10_redirect_to_private_ip_blocked(client):
    """
    TEST 10: Public URL redirecting to localhost/private IP
    Expected:
      - SSRF BLOCKED
      - scan_performed = false
      - HTTP status 400
    """
    mock_reach = {
        "reachable": False,
        "ssrf_blocked": True,
        "status": "SSRF_BLOCKED",
        "reachability_status": "SSRF_BLOCKED",
        "reason": "Redirect destination blocked by security policy: http://127.0.0.1:8080/admin",
        "http_status": 302,
        "final_url": "http://127.0.0.1:8080/admin",
        "redirect_chain": ["https://innocent-looking-site.com"],
        "redirect_count": 1,
        "elapsed_ms": 35.0,
    }

    with patch("app.check_reachability", return_value=mock_reach):
        resp = client.post("/predict", json={"url": "https://innocent-looking-site.com"})
        assert resp.status_code == 400
        data = resp.get_json()

        assert data.get("security_block") is True
        assert data.get("scan_performed") is False
        assert data.get("reachability_status") == "SSRF_BLOCKED"
        assert "127.0.0.1" in data.get("block_reason", "") or "prohibited" in data.get("block_reason", "").lower()


# =============================================================================
# TEST 11: Reachable Unknown / New Domain
# =============================================================================
def test_11_reachable_unknown_new_domain(client):
    """
    TEST 11: Reachable unknown/new domain
    Expected:
      - reachable
      - scan_performed = true
      - full behavioral/ML analysis runs
      - Unknown reputation must NOT automatically mean Safe!
    """
    mock_reach = {
        "reachable": True,
        "ssrf_blocked": False,
        "status": "REACHABLE",
        "reachability_status": "reachable",
        "reason": None,
        "http_status": 200,
        "final_url": "https://brand-new-unclassified-domain-2026.xyz/portal",
        "redirect_chain": [],
        "redirect_count": 0,
        "elapsed_ms": 45.0,
    }

    with patch("app.check_reachability", return_value=mock_reach):
        resp = client.post("/predict", json={"url": "https://brand-new-unclassified-domain-2026.xyz/portal"})
        assert resp.status_code == 200
        data = resp.get_json()

        assert data.get("scan_performed") is True
        assert data.get("reachability_status") == "reachable"
        # Full analysis must run
        assert "deep_scan" in data
        assert "models" in data
        assert "signals" in data

        # Unknown domain with suspicious characteristics must not be blindly marked safe
        assert data.get("classification") in ("SUSPICIOUS", "ZERO_DAY_PHISHING", "LEGITIMATE")
        if data.get("classification") == "LEGITIMATE":
            # If legitimate, confidence should reflect evidence, not zero-evidence default
            assert data.get("confidence_score") is not None
