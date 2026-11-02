"""
PhishGuard AI — Analysis VM Agent: Screenshot Module
=====================================================
Handles screenshot capture and optional OCR inside the VM.

The screenshot is taken by scanner.py using Playwright and passed here as
raw bytes.  This module encodes it to base64 for transmission to the host
and optionally runs local OCR (pytesseract) if installed.

Runs INSIDE the VirtualBox Linux guest.  Never on the Windows host.

Design rule: we do NOT send screenshots to any external cloud or vision API.
If pytesseract is not installed, OCR is simply reported as unavailable.
"""

import time
import base64
from typing import Any

# ── Optional local OCR support ────────────────────────────────────────────
try:
    import pytesseract
    from PIL import Image
    import io
    _OCR_AVAILABLE = True
except ImportError:
    _OCR_AVAILABLE = False

_OCR_STATUS = "available (pytesseract)" if _OCR_AVAILABLE else "unavailable (install pytesseract + Tesseract)"

_LOGIN_KEYWORDS = [
    "sign in", "log in", "login", "password", "username", "email address",
    "forgot password", "remember me", "create account", "verify",
    "enter your", "continue", "one-time password", "otp", "authenticate", "auth"
]

_CREDENTIAL_KEYWORDS = [
    "password", "passcode", "secret", "credentials", "credit card", "debit card",
    "cvv", "security code", "social security", "pin", "ssn", "routing number",
    "account number", "billing address", "cardholder"
]

_KNOWN_BRANDS_OCR = [
    "microsoft", "apple", "google", "paypal", "amazon", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "adobe", "dropbox",
    "chase", "bank of america", "wells fargo", "citibank", "coinbase",
    "binance", "metamask", "ledger", "dhl", "fedex", "ups", "irs",
]


def get_ocr_status() -> dict:
    return {"available": _OCR_AVAILABLE, "status": _OCR_STATUS}


def encode_screenshot(raw_bytes: bytes | None) -> str | None:
    """Encode screenshot bytes to a base64 string for transmission."""
    if not raw_bytes:
        return None
    try:
        return base64.b64encode(raw_bytes).decode("ascii")
    except Exception:
        return None


def analyze_screenshot_bytes(raw_bytes: bytes | None) -> dict[str, Any]:
    """
    Analyse screenshot bytes for visual phishing indicators using local OCR
    inside the analysis VM. Never calls external APIs.
    """
    t0 = time.perf_counter()

    result: dict[str, Any] = {
        "available": False,
        "ocr_available": _OCR_AVAILABLE,
        "ocr_status": _OCR_STATUS,
        "ocr_text": None,
        "ocr_word_count": 0,
        "brand_candidates": [],
        "brand_logos_detected": [],
        "login_page_visual": None,
        "visual_text_preview": None,
        "analysis_time_ms": 0.0,
        "error": None,
    }

    if not raw_bytes:
        result["error"] = "No screenshot bytes provided"
        result["analysis_time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        return result

    result["available"] = True

    if not _OCR_AVAILABLE:
        result["error"] = "Visual AI unavailable — pytesseract/Tesseract not installed"
        result["analysis_time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        return result

    try:
        img = Image.open(io.BytesIO(raw_bytes))
        # Crop to upper 900px (viewport zone) where content, headers, and login controls live
        if hasattr(img, "height") and img.height > 900:
            img = img.crop((0, 0, img.width, 900))

        # Downscale for fast, robust OCR
        if hasattr(img, "size"):
            w, h = img.size
            max_dim = 900
            if w > max_dim:
                scale = max_dim / float(w)
                new_w, new_h = max(1, int(w * scale)), max(1, int(h * scale))
                img = img.resize((new_w, new_h), Image.Resampling.BILINEAR)

        ocr_text = ""
        try:
            ocr_text = pytesseract.image_to_string(img, lang="eng", config="--psm 11", timeout=10)
        except Exception as ocr_e:
            result["error"] = f"OCR timeout/warning: {str(ocr_e)[:100]}"
            ocr_text = ""

        ocr_lower = ocr_text.lower()
        result["ocr_text"] = ocr_text[:2000]
        result["ocr_word_count"] = len(ocr_text.split())
        result["visual_text_preview"] = ocr_text[:300].strip()

        # Brand detection via OCR text
        found_brands = []
        for b in _KNOWN_BRANDS_OCR:
            if b in ocr_lower:
                found_brands.append(b.title())
        result["brand_candidates"] = list(set(found_brands))[:5]
        result["brand_logos_detected"] = result["brand_candidates"]

        # Login page heuristic
        login_signal_count = sum(1 for kw in _LOGIN_KEYWORDS if kw in ocr_lower)
        result["login_page_visual"] = login_signal_count >= 2

        # Extract specific matched terms
        result["login_related_terms"] = list(set([kw for kw in _LOGIN_KEYWORDS if kw in ocr_lower]))
        result["credential_terms"] = list(set([kw for kw in _CREDENTIAL_KEYWORDS if kw in ocr_lower]))

    except Exception as exc:
        result["error"] = f"OCR analysis failed: {str(exc)[:200]}"
        result["ocr_text"] = None

    result["analysis_time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return result
