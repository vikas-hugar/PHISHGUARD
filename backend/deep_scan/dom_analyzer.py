"""
PhishGuard AI V6 — DOM Analyzer
=================================
Analyzes the rendered DOM snapshot from the sandbox browser.
Detects interactive elements, credential collection structures,
and UI deception patterns from the rendered page tree.

Runs offline. No external API calls.
"""

import re
from urllib.parse import urlparse
from typing import Any


def analyze_dom(dom_snapshot: str | None, page_url: str = "") -> dict:
    """
    Analyze a rendered DOM snapshot for phishing structural indicators.

    The DOM snapshot here is the page.content() from Playwright (rendered HTML).
    For a full production implementation, this should receive a proper DOM tree
    (e.g., JSON-serialized via page.evaluate()); for V6, we analyze the HTML string.

    Returns structured evidence. Does NOT return a risk score.
    """
    if not dom_snapshot:
        return {"available": False, "error": "No DOM snapshot provided"}

    dom_lower = dom_snapshot.lower()
    result: dict[str, Any] = {
        "available": True,

        # Login / authentication
        "login_form": False,
        "credential_collection_form": False,
        "password_input": False,
        "email_input": False,
        "otp_input": False,

        # Payment
        "payment_form": False,

        # External submission
        "external_form_action": False,

        # Deceptive UI elements
        "hidden_overlay": False,
        "fake_browser_dialog": False,
        "suspicious_modal": False,
        "hidden_elements_count": 0,

        # Structure signals
        "redirect_detected": False,
        "meta_refresh_detected": False,
        "iframe_form": False,

        # Brand
        "brand_logo_count": 0,
        "brand_text_count": 0,
    }

    # ── Password / Email inputs ───────────────────────────────────────────
    password_inputs = re.findall(r'<input[^>]+type\s*=\s*["\']?password["\']?[^>]*>', dom_lower)
    if password_inputs:
        result["password_input"] = True
        result["login_form"] = True

    email_inputs = re.findall(
        r'<input[^>]+(?:type\s*=\s*["\']?email["\']?|name\s*=\s*["\']?(?:email|username|user)["\']?)[^>]*>',
        dom_lower
    )
    if email_inputs:
        result["email_input"] = True

    if result["password_input"] and result["email_input"]:
        result["credential_collection_form"] = True

    # ── OTP input detection ───────────────────────────────────────────────
    otp_patterns = [
        r'name\s*=\s*["\']?otp["\']?',
        r'id\s*=\s*["\']?otp["\']?',
        r'placeholder\s*=\s*["\'].*?otp.*?["\']',
        r'placeholder\s*=\s*["\'].*?verification.*?code.*?["\']',
        r'name\s*=\s*["\']?(?:mfa|2fa|auth.?code)["\']?',
    ]
    for pat in otp_patterns:
        if re.search(pat, dom_lower):
            result["otp_input"] = True
            break

    # ── Payment fields ────────────────────────────────────────────────────
    payment_patterns = [
        r'name\s*=\s*["\']?(?:card.?number|credit.?card|cc.?number|cvv|cvc)["\']?',
        r'placeholder\s*=\s*["\'].*?card\s*number.*?["\']',
        r'class\s*=\s*["\'].*?(?:credit|card|payment).*?["\']',
    ]
    for pat in payment_patterns:
        if re.search(pat, dom_lower):
            result["payment_form"] = True
            break

    # ── External form action ──────────────────────────────────────────────
    try:
        page_host = urlparse(page_url).hostname or ""
    except Exception:
        page_host = ""

    form_actions = re.findall(r'<form[^>]+action\s*=\s*["\']([^"\']+)["\']', dom_lower)
    for action in form_actions:
        try:
            action_host = urlparse(action).hostname or ""
            if action_host and page_host and action_host.lower() != page_host.lower():
                result["external_form_action"] = True
        except Exception:
            pass

    # ── Meta refresh (redirect) ───────────────────────────────────────────
    if re.search(r'<meta[^>]+http-equiv\s*=\s*["\']?refresh["\']?', dom_lower):
        result["meta_refresh_detected"] = True
        result["redirect_detected"] = True

    # ── JS redirect patterns ──────────────────────────────────────────────
    if re.search(r'window\.location\s*(?:\.href)?\s*=', dom_lower):
        result["redirect_detected"] = True

    # ── Hidden elements (overlays, deceptive UI) ──────────────────────────
    hidden_patterns = [
        r'style\s*=\s*["\'][^"\']*display\s*:\s*none',
        r'style\s*=\s*["\'][^"\']*visibility\s*:\s*hidden',
        r'hidden\s*=\s*["\']?true["\']?',
        r'type\s*=\s*["\']?hidden["\']?',
    ]
    hidden_count = 0
    for pat in hidden_patterns:
        hidden_count += len(re.findall(pat, dom_lower))
    result["hidden_elements_count"] = hidden_count

    # ── Overlay detection (fullscreen translucent div) ────────────────────
    overlay_patterns = [
        r'position\s*:\s*fixed.*?z-index\s*:\s*\d{4,}',  # very high z-index fixed element
        r'class\s*=\s*["\'][^"\']*overlay[^"\']*["\']',
        r'class\s*=\s*["\'][^"\']*modal[^"\']*["\']',
        r'id\s*=\s*["\']?(?:overlay|modal|popup|dialog)["\']?',
    ]
    for pat in overlay_patterns:
        if re.search(pat, dom_lower):
            result["hidden_overlay"] = True
            break

    # ── Fake browser dialog detection ─────────────────────────────────────
    dialog_patterns = [
        r'class\s*=\s*["\'][^"\']*(?:fake.?browser|chrome.?bar|browser.?header)[^"\']*["\']',
        r'id\s*=\s*["\']?(?:fake.?url|address.?bar)["\']?',
    ]
    for pat in dialog_patterns:
        if re.search(pat, dom_lower):
            result["fake_browser_dialog"] = True
            break

    # ── Brand logo/image count ────────────────────────────────────────────
    # Count img tags with alt text or src containing brand names
    brand_names = ["microsoft", "apple", "google", "paypal", "amazon", "netflix",
                   "facebook", "instagram", "twitter", "linkedin", "adobe"]
    brand_logo_count = 0
    brand_text_count = 0
    for brand in brand_names:
        if re.search(rf'(?:alt|src|class|id)\s*=\s*["\'][^"\']*{brand}[^"\']*["\']', dom_lower):
            brand_logo_count += 1
        if brand in dom_lower:
            brand_text_count += 1
    result["brand_logo_count"] = brand_logo_count
    result["brand_text_count"] = brand_text_count

    return result


def analyze_dom_for_evidence(dom_snapshot: str | None, page_url: str = "") -> dict:
    """
    Alias for analyze_dom — use in fusion pipeline for consistency.
    """
    return analyze_dom(dom_snapshot, page_url)
