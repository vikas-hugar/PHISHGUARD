"""
PhishGuard AI V6 — Screenshot Analyzer
========================================
Captures and analyzes screenshots taken inside the sandbox browser.

Important design rule:
  - We do NOT send screenshots to any cloud/external vision API.
  - If a local OCR/vision library is not installed, we report "Visual AI unavailable"
    instead of fabricating a score.
  - The architecture is designed so a local vision model can be added in V7.

Current V6 implementation:
  - Screenshot capture (inside sandbox — just saves path)
  - If pytesseract (Tesseract OCR) is available: basic text extraction
  - If pytesseract is not available: OCR unavailable
  - Logo/brand text candidate detection via OCR output (if available)
  - Login-page layout heuristic from OCR text (if available)

This module does NOT return a risk score — only evidence.
"""

import os
import time
from typing import Any

# ── Optional local OCR support ─────────────────────────────────────────────
try:
    import pytesseract
    from PIL import Image
    _OCR_AVAILABLE = True
except ImportError:
    _OCR_AVAILABLE = False

_OCR_STATUS = "available (pytesseract)" if _OCR_AVAILABLE else "unavailable (install pytesseract + Tesseract)"

KNOWN_BRANDS_FOR_OCR = [
    "microsoft", "apple", "google", "paypal", "amazon", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "adobe", "dropbox",
    "chase", "bank of america", "wells fargo", "citibank", "coinbase",
    "binance", "metamask", "ledger", "dhl", "fedex", "ups", "irs",
]

LOGIN_PAGE_OCR_KEYWORDS = [
    "sign in", "log in", "login", "password", "username", "email address",
    "forgot password", "remember me", "create account", "verify",
    "enter your", "continue", "one-time password", "otp", "authenticate", "auth"
]

CREDENTIAL_PAGE_OCR_KEYWORDS = [
    "password", "passcode", "secret", "credentials", "credit card", "debit card",
    "cvv", "security code", "social security", "pin", "ssn", "routing number",
    "account number", "billing address", "cardholder"
]


def get_ocr_status() -> dict:
    """Return the current OCR availability status (checks VM environment first)."""
    try:
        from deep_scan.vm_controller import get_sandbox_status
        sb = get_sandbox_status()
        if sb.get("ocr_available"):
            return {
                "available": True,
                "status": sb.get("ocr_status", "available (in-VM pytesseract)"),
            }
    except Exception:
        pass

    return {
        "available": _OCR_AVAILABLE,
        "status": _OCR_STATUS,
    }


def analyze_screenshot(screenshot_path: str | None) -> dict:
    """
    Analyze a screenshot captured inside the sandbox.

    Does NOT send the screenshot to any external service.
    Returns structured evidence. If OCR is unavailable, says so explicitly.

    Returns:
    {
        "available": bool,
        "ocr_available": bool,
        "ocr_text": str | None,
        "ocr_word_count": int,
        "brand_candidates": list,
        "login_page_visual": bool | None,   # None if OCR unavailable
        "visual_text_preview": str | None,
        "analysis_time_ms": float,
        "error": str | None
    }
    """
    t0 = time.perf_counter()

    result: dict[str, Any] = {
        "available": False,
        "ocr_available": _OCR_AVAILABLE,
        "ocr_text": None,
        "ocr_word_count": 0,
        "brand_candidates": [],
        "login_page_visual": None,   # None = not determined (OCR unavailable)
        "visual_text_preview": None,
        "analysis_time_ms": 0.0,
        "error": None,
    }

    if not screenshot_path:
        result["error"] = "No screenshot path provided"
        result["analysis_time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        return result

    if not os.path.exists(screenshot_path):
        result["error"] = "Screenshot file not found"
        result["analysis_time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        return result

    result["available"] = True

    # ── OCR text extraction ────────────────────────────────────────────────
    if not _OCR_AVAILABLE:
        result["error"] = "Visual AI unavailable — pytesseract/Tesseract not installed"
        result["analysis_time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        return result

    try:
        img = Image.open(screenshot_path)
        ocr_text = pytesseract.image_to_string(img, lang="eng", config="--psm 11")
        ocr_lower = ocr_text.lower()

        result["ocr_text"] = ocr_text[:5000]
        result["ocr_word_count"] = len(ocr_text.split())
        result["visual_text_preview"] = ocr_text[:500].strip()

        # ── Brand detection from OCR text ─────────────────────────────────
        found_brands = []
        for brand in KNOWN_BRANDS_FOR_OCR:
            if brand in ocr_lower:
                found_brands.append(brand.title())
        result["brand_candidates"] = list(set(found_brands))[:5]

        # ── Login page visual detection ────────────────────────────────────
        login_signal_count = sum(1 for kw in LOGIN_PAGE_OCR_KEYWORDS if kw in ocr_lower)
        result["login_page_visual"] = login_signal_count >= 2
        result["login_related_terms"] = list(set([kw for kw in LOGIN_PAGE_OCR_KEYWORDS if kw in ocr_lower]))
        result["credential_terms"] = list(set([kw for kw in CREDENTIAL_PAGE_OCR_KEYWORDS if kw in ocr_lower]))

    except Exception as e:
        result["error"] = f"OCR analysis failed: {str(e)[:200]}"
        result["ocr_text"] = None

    result["analysis_time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return result
