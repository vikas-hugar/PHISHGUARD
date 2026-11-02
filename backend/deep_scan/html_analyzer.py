"""
PhishGuard AI V6 — HTML Analyzer
=================================
Analyzes raw captured HTML from the sandbox browser for phishing indicators.
Runs offline. Does NOT send data to external services.

All analysis is purely structural/lexical — no LLM is called here.
"""

import re
from urllib.parse import urlparse
from typing import Any

# ── Suspicious JavaScript patterns ────────────────────────────────────────
SUSPICIOUS_JS_PATTERNS = [
    r'document\.cookie',
    r'window\.location\s*=',
    r'document\.write\s*\(',
    r'eval\s*\(',
    r'atob\s*\(',
    r'btoa\s*\(',
    r'fromCharCode',
    r'unescape\s*\(',
    r'decodeURIComponent.*base64',
    r'new\s+Function\s*\(',
    r'setTimeout.*eval',
    r'setInterval.*eval',
    r'\.submit\s*\(',
]

# ── Phishing context language ──────────────────────────────────────────────
PHISHING_LANGUAGE = [
    "verify your account", "update your information", "confirm your identity",
    "your account has been suspended", "your account will be closed",
    "click here to verify", "enter your password", "sign in to continue",
    "unusual activity", "security alert", "unauthorized access",
    "reset your password", "account verification required",
    "your payment failed", "billing information required",
    "one-time password", "enter the otp", "enter your pin",
    "enter your credit card", "cvv", "card number",
]

KNOWN_BRANDS_FOR_MENTIONS = [
    "microsoft", "apple", "google", "paypal", "amazon", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "dropbox", "adobe",
    "chase", "bank of america", "wells fargo", "citibank", "paypal",
    "coinbase", "binance", "metamask", "ledger", "dhl", "fedex", "ups",
    "irs", "sbi", "hdfc", "icici", "axis bank",
]


def analyze_html(html: str | None, page_url: str = "") -> dict:
    """
    Analyze raw HTML for phishing indicators.

    Returns a structured evidence dict with boolean flags and counts.
    Does NOT return a risk score — scoring is done by the fusion engine.
    """
    if not html:
        return {"available": False, "error": "No HTML provided"}

    html_lower = html.lower()
    result: dict[str, Any] = {
        "available": True,

        # Page identity
        "has_title": bool(re.search(r'<title[^>]*>(.+?)</title>', html, re.IGNORECASE | re.DOTALL)),
        "title_text": "",

        # Form analysis
        "login_form": False,
        "credential_form": False,   # has both username-like AND password field
        "password_field": False,
        "email_field": False,
        "payment_field": False,
        "otp_field": False,
        "hidden_field_count": 0,
        "form_count": 0,
        "external_form_action": False,
        "form_actions": [],

        # Brand mentions
        "brand_mentions": [],

        # Content analysis
        "login_page_detected": False,
        "phishing_language_count": 0,
        "phishing_phrases_found": [],

        # Script analysis
        "script_count": 0,
        "external_script_count": 0,
        "suspicious_script_count": 0,
        "suspicious_script_patterns": [],

        # Iframe analysis
        "iframe_count": 0,
        "external_iframe_count": 0,
        "suspicious_iframe_count": 0,

        # External resources
        "external_domain_count": 0,
    }

    # ── Title ─────────────────────────────────────────────────────────────
    title_match = re.search(r'<title[^>]*>(.+?)</title>', html, re.IGNORECASE | re.DOTALL)
    if title_match:
        result["title_text"] = re.sub(r'<[^>]+>', '', title_match.group(1)).strip()[:200]

    # ── Page domain for external link detection ───────────────────────────
    try:
        page_host = urlparse(page_url).hostname or ""
    except Exception:
        page_host = ""

    # ── Form analysis ─────────────────────────────────────────────────────
    forms = re.findall(r'<form[^>]*>.*?</form>', html, re.IGNORECASE | re.DOTALL)
    result["form_count"] = len(forms)

    for form in forms:
        form_lower = form.lower()
        # Action URL
        action_match = re.search(r'action\s*=\s*["\']?([^"\'>\s]+)', form, re.IGNORECASE)
        action_url = action_match.group(1) if action_match else ""
        if action_url:
            result["form_actions"].append(action_url[:200])
            # Check if external
            try:
                action_host = urlparse(action_url).hostname or ""
                if action_host and page_host and action_host != page_host:
                    result["external_form_action"] = True
            except Exception:
                pass

        # Input types
        inputs = re.findall(r'<input[^>]*>', form, re.IGNORECASE)
        has_password = False
        has_email_or_text = False
        for inp in inputs:
            inp_lower = inp.lower()
            type_match = re.search(r'type\s*=\s*["\']?(\w+)', inp_lower)
            itype = type_match.group(1) if type_match else "text"

            if itype == "password":
                result["password_field"] = True
                has_password = True
                result["login_form"] = True

            elif itype in ("email", "text") or "email" in inp_lower or "user" in inp_lower:
                result["email_field"] = True
                has_email_or_text = True

            elif itype == "hidden":
                result["hidden_field_count"] += 1

            # OTP detection
            if any(kw in inp_lower for kw in ["otp", "one-time", "verification-code", "auth-code", "mfa"]):
                result["otp_field"] = True

            # Payment detection
            if any(kw in inp_lower for kw in ["card", "cvv", "credit", "debit", "ccv", "expiry"]):
                result["payment_field"] = True

        if has_password and has_email_or_text:
            result["credential_form"] = True

    # ── Script analysis ───────────────────────────────────────────────────
    scripts = re.findall(r'<script[^>]*>.*?</script>', html, re.IGNORECASE | re.DOTALL)
    result["script_count"] = len(scripts)

    for script in scripts:
        # External scripts
        src_match = re.search(r'src\s*=\s*["\']([^"\']+)["\']', script, re.IGNORECASE)
        if src_match:
            result["external_script_count"] += 1

        # Suspicious patterns
        for pattern in SUSPICIOUS_JS_PATTERNS:
            if re.search(pattern, script, re.IGNORECASE):
                result["suspicious_script_count"] += 1
                result["suspicious_script_patterns"].append(pattern)
                break  # one match per script

    result["suspicious_script_patterns"] = list(set(result["suspicious_script_patterns"]))[:5]

    # ── Iframe analysis ───────────────────────────────────────────────────
    iframes = re.findall(r'<iframe[^>]*>', html, re.IGNORECASE)
    result["iframe_count"] = len(iframes)

    for iframe in iframes:
        src_match = re.search(r'src\s*=\s*["\']([^"\']+)["\']', iframe, re.IGNORECASE)
        if src_match:
            src = src_match.group(1)
            result["external_iframe_count"] += 1
            # Suspicious iframes: hidden or zero-size
            style = re.search(r'style\s*=\s*["\']([^"\']+)["\']', iframe, re.IGNORECASE)
            if style and ("display:none" in style.group(1).replace(" ", "") or
                          "width:0" in style.group(1).replace(" ", "") or
                          "height:0" in style.group(1).replace(" ", "")):
                result["suspicious_iframe_count"] += 1

    # ── Brand mentions ────────────────────────────────────────────────────
    found_brands = []
    for brand in KNOWN_BRANDS_FOR_MENTIONS:
        if brand in html_lower:
            found_brands.append(brand.title())
    result["brand_mentions"] = list(set(found_brands))[:5]

    # ── Phishing language ─────────────────────────────────────────────────
    found_phrases = []
    for phrase in PHISHING_LANGUAGE:
        if phrase in html_lower:
            found_phrases.append(phrase)
    result["phishing_phrases_found"] = found_phrases[:5]
    result["phishing_language_count"] = len(found_phrases)

    # ── Login page detection ──────────────────────────────────────────────
    login_signals = [
        result["password_field"],
        result["login_form"],
        result["phishing_language_count"] >= 2,
        "login" in html_lower or "sign in" in html_lower or "sign-in" in html_lower,
    ]
    result["login_page_detected"] = sum(login_signals) >= 2

    return result
