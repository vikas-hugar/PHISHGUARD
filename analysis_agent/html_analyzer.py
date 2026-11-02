"""
PhishGuard AI — Analysis VM Agent: HTML Analyzer
==================================================
Analyzes raw captured HTML from the VM browser for phishing indicators.
Runs offline.  No external API calls.

This is a self-contained copy of the host-side html_analyzer.py so the
VM agent does not need to reach the host filesystem.  The logic is identical
so both sides produce consistent output.
"""

import re
from urllib.parse import urlparse
from typing import Any

# ── Suspicious JavaScript patterns ────────────────────────────────────────
_SUSPICIOUS_JS_PATTERNS = [
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

# ── Phishing social-engineering language ──────────────────────────────────
_PHISHING_LANGUAGE = [
    "verify your account", "update your information", "confirm your identity",
    "your account has been suspended", "your account will be closed",
    "click here to verify", "enter your password", "sign in to continue",
    "unusual activity", "security alert", "unauthorized access",
    "reset your password", "account verification required",
    "your payment failed", "billing information required",
    "one-time password", "enter the otp", "enter your pin",
    "enter your credit card", "cvv", "card number",
]

_KNOWN_BRANDS = [
    "microsoft", "apple", "google", "paypal", "amazon", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "dropbox", "adobe",
    "chase", "bank of america", "wells fargo", "citibank",
    "coinbase", "binance", "metamask", "ledger", "dhl", "fedex", "ups",
    "irs", "sbi", "hdfc", "icici", "axis bank",
]


def analyze_html(html: str | None, page_url: str = "") -> dict:
    """
    Analyse raw HTML for phishing indicators.  Returns a structured evidence
    dict with boolean flags and counts.  Does NOT return a risk score; scoring
    is done by the host-side fusion engine.
    """
    if not html:
        return {"available": False, "error": "No HTML provided"}

    html_lower = html.lower()
    result: dict[str, Any] = {
        "available": True,

        # Form / credential collection
        "has_password_field": False,
        "has_email_field": False,
        "has_credit_card_field": False,
        "has_otp_field": False,
        "credential_form": False,
        "form_count": 0,
        "form_actions": [],

        # External form submission
        "external_form_action": False,

        # Scripts
        "suspicious_script_count": 0,
        "external_script_count": 0,

        # Page language signals
        "phishing_language_count": 0,
        "phishing_language_phrases": [],

        # Brand mentions in page text
        "brand_mentions": [],

        # Iframes
        "external_iframe": False,
        "iframe_count": 0,

        # Misc
        "login_page": False,
        "otp_field": False,
        "payment_field": False,
        "brand_logo_mismatch": False,

        # Visual overlay / fakery
        "fake_overlay_detected": False,
        "meta_refresh_detected": False,
    }

    # Password / email / payment / OTP fields
    if re.search(r'<input[^>]+type\s*=\s*["\']?password["\']?', html_lower):
        result["has_password_field"] = True
        result["login_page"] = True

    if re.search(
        r'<input[^>]+(?:type\s*=\s*["\']?email["\']?|name\s*=\s*["\']?(?:email|username|user)["\']?)',
        html_lower
    ):
        result["has_email_field"] = True

    if result["has_password_field"] and result["has_email_field"]:
        result["credential_form"] = True

    otp_pattern = re.compile(r'name\s*=\s*["\']?otp|id\s*=\s*["\']?otp|placeholder\s*=\s*["\']?otp')
    if otp_pattern.search(html_lower):
        result["has_otp_field"] = True
        result["otp_field"] = True

    card_pattern = re.compile(r'(?:card[_-]?number|cvv|cvc|exp(?:iry)?[_-]?date|cardnumber)')
    if card_pattern.search(html_lower):
        result["has_credit_card_field"] = True
        result["payment_field"] = True

    # Forms — count and check for external action targets
    form_matches = re.findall(r'<form[^>]*action\s*=\s*["\']([^"\']+)["\']', html_lower)
    result["form_count"] = len(re.findall(r'<form', html_lower))
    result["form_actions"] = form_matches[:10]

    page_host = urlparse(page_url).hostname or ""
    for action_url in form_matches:
        action_host = urlparse(action_url).hostname or ""
        if action_host and page_host and action_host != page_host:
            result["external_form_action"] = True
            break

    # Suspicious JavaScript patterns
    suspicious_count = 0
    for pattern in _SUSPICIOUS_JS_PATTERNS:
        if re.search(pattern, html_lower):
            suspicious_count += 1
    result["suspicious_script_count"] = suspicious_count

    # External scripts
    ext_scripts = re.findall(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', html_lower)
    ext_count = sum(
        1 for s in ext_scripts
        if urlparse(s).hostname not in ("", page_host)
    )
    result["external_script_count"] = ext_count

    # Phishing language
    phrases_found = [p for p in _PHISHING_LANGUAGE if p in html_lower]
    result["phishing_language_count"] = len(phrases_found)
    result["phishing_language_phrases"] = phrases_found[:5]

    # Brand mentions (mismatch signal if brand text present but wrong domain)
    brands_found = [b for b in _KNOWN_BRANDS if b in html_lower]
    result["brand_mentions"] = brands_found

    if brands_found and page_host:
        brand_in_host = any(b.replace(" ", "") in page_host for b in brands_found)
        if not brand_in_host:
            result["brand_logo_mismatch"] = True

    # Iframes
    iframe_srcs = re.findall(r'<iframe[^>]+src\s*=\s*["\']([^"\']+)["\']', html_lower)
    result["iframe_count"] = len(iframe_srcs)
    for src in iframe_srcs:
        src_host = urlparse(src).hostname or ""
        if src_host and src_host != page_host:
            result["external_iframe"] = True
            break

    # Fake overlay / UI deception
    if re.search(r'position\s*:\s*fixed|z-index\s*:\s*9{3,}', html_lower):
        result["fake_overlay_detected"] = True

    # Meta refresh redirect
    if re.search(r'<meta[^>]+http-equiv\s*=\s*["\']?refresh["\']?', html_lower):
        result["meta_refresh_detected"] = True

    return result
