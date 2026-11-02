"""
PhishGuard AI V7.0 — Visual Phishing Analysis Engine
=====================================================
Analyzes rendered webpage screenshot, in-VM OCR text, and DOM form/input fields
to detect visual phishing cues:
  - Fake login pages
  - Credential harvesting forms
  - Payment / Credit Card collection fields
  - One-Time Password (OTP / 2FA) intercept forms
  - Security warning / Account suspension urgency impersonation
  - Visual brand impersonation (brand logos / text rendered on non-brand domains)

Operates 100% locally and safely using in-VM evidence. No external APIs.
"""

from __future__ import annotations
import re
from typing import Any
from urllib.parse import urlparse

# Keywords indicating login / authentication forms
LOGIN_KEYWORDS = [
    "sign in", "log in", "login", "password", "username", "email address",
    "forgot password", "remember me", "create account", "verify account",
    "enter your password", "continue to login", "one-time password", "otp",
    "authentication required", "security challenge"
]

# Keywords indicating credential collection
CREDENTIAL_KEYWORDS = [
    "password", "passcode", "secret", "credentials", "credit card", "debit card",
    "cvv", "security code", "social security", "pin", "ssn", "routing number",
    "account number", "billing address", "cardholder"
]

# Keywords indicating financial / payment harvesting
PAYMENT_KEYWORDS = [
    "credit card", "debit card", "card number", "expiration date", "expiry",
    "cvv", "cvc", "billing address", "cardholder name", "payment method",
    "checkout", "pay now", "bank account", "routing number", "wire transfer"
]

# Keywords indicating urgency / coercion
URGENCY_KEYWORDS = [
    "account suspended", "unauthorized access", "immediate action required",
    "verify within 24 hours", "account locked", "security alert", "unusual activity",
    "final notice", "access terminated", "action required"
]

# Common brands mapped to legitimate domain suffixes
BRAND_LEGITIMATE_DOMAINS = {
    "google": ["google.com", "google.co", "youtube.com", "gmail.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"],
    "apple": ["apple.com", "icloud.com"],
    "paypal": ["paypal.com", "paypal.me"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "aws.amazon.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "instagram": ["instagram.com"],
    "twitter": ["twitter.com", "x.com"],
    "linkedin": ["linkedin.com"],
    "adobe": ["adobe.com"],
    "dropbox": ["dropbox.com"],
    "chase": ["chase.com"],
    "bank of america": ["bankofamerica.com"],
    "wells fargo": ["wellsfargo.com"],
    "citibank": ["citi.com", "citibank.com"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com"],
    "metamask": ["metamask.io"],
}


def analyze_visual_evidence(
    ocr_evidence: dict[str, Any] | None = None,
    dom_evidence: dict[str, Any] | None = None,
    html_evidence: dict[str, Any] | None = None,
    domain: str = "",
    is_whitelisted: bool = False,
) -> dict[str, Any]:
    """
    Perform multi-modal visual phishing analysis by combining:
      1. In-VM Tesseract OCR text extraction
      2. DOM interactive inputs (passwords, emails, OTPs, payment fields)
      3. HTML form submission targets (external actions)
      4. Domain identity vs. rendered visual brand markers
    """
    ocr_data = ocr_evidence or {}
    dom_data = dom_evidence or {}
    html_data = html_evidence or {}

    ocr_available = bool(ocr_data.get("available") or ocr_data.get("ocr_available"))
    ocr_text = (ocr_data.get("ocr_text") or ocr_data.get("text") or "").lower()
    ocr_words = ocr_data.get("ocr_word_count", len(ocr_text.split()))

    indicators: list[str] = []
    detected_brands: list[str] = ocr_data.get("brand_candidates") or []

    # 1. Login Page Visual Identification
    login_keywords_found = [kw for kw in LOGIN_KEYWORDS if kw in ocr_text]
    has_dom_password = bool(dom_data.get("password_fields"))
    has_html_login = bool(html_data.get("login_page_detected"))

    is_login_page = has_dom_password or has_html_login or len(login_keywords_found) >= 2
    if is_login_page:
        indicators.append("Interactive login / authentication interface detected")

    # 2. Credential Harvesting Analysis
    has_dom_email = bool(dom_data.get("email_fields"))
    credential_terms_found = [kw for kw in CREDENTIAL_KEYWORDS if kw in ocr_text]
    has_credential_harvesting = (has_dom_password and (has_dom_email or len(credential_terms_found) >= 1)) or bool(dom_data.get("credential_collection_form"))
    if has_credential_harvesting:
        indicators.append("Credential collection fields (password + account identifier) active")

    # 3. Payment Harvesting Analysis
    has_dom_payment = bool(dom_data.get("payment_fields"))
    payment_terms_found = [kw for kw in PAYMENT_KEYWORDS if kw in ocr_text]
    has_payment_fields = has_dom_payment or (len(payment_terms_found) >= 2)
    if has_payment_fields:
        indicators.append("Financial / Payment card harvesting fields detected")

    # 4. OTP / 2FA Intercept Analysis
    has_dom_otp = bool(dom_data.get("otp_fields"))
    otp_terms_found = [kw for kw in ["one-time password", "otp", "2fa", "verification code", "sms code"] if kw in ocr_text]
    has_otp_fields = has_dom_otp or len(otp_terms_found) >= 1
    if has_otp_fields:
        indicators.append("Secondary authentication / OTP input intercept detected")

    # 5. Urgency & Coercion Language
    urgency_terms_found = [kw for kw in URGENCY_KEYWORDS if kw in ocr_text]
    urgency_detected = len(urgency_terms_found) >= 1
    if urgency_detected:
        indicators.append(f"Psychological urgency cues in page text: '{urgency_terms_found[0]}'")

    # 6. Visual Brand Impersonation Check
    brand_impersonation_visual = False
    clean_domain = domain.lower().replace("www.", "").strip()

    for brand_lower in detected_brands:
        brand_key = brand_lower.lower()
        if brand_key in BRAND_LEGITIMATE_DOMAINS:
            legit_suffixes = BRAND_LEGITIMATE_DOMAINS[brand_key]
            # Check if clean_domain matches any legitimate suffix
            is_legit_domain = any(clean_domain == s or clean_domain.endswith("." + s) for s in legit_suffixes)
            if not is_legit_domain and not is_whitelisted:
                brand_impersonation_visual = True
                indicators.append(f"Visual impersonation: Brand '{brand_lower}' rendered on unrelated domain '{clean_domain}'")
                break

    # 7. Form Action Check (Data Exfiltration)
    external_action = bool(html_data.get("external_form_action") or dom_data.get("external_form_action"))
    if external_action:
        indicators.append("Form targets external domain — possible credential exfiltration")

    # 8. Compute Visual Phishing Risk Score (0 - 100)
    visual_risk = 0.0
    if not is_whitelisted:
        if brand_impersonation_visual:
            visual_risk += 45.0
        if has_credential_harvesting:
            visual_risk += 30.0
        elif is_login_page:
            visual_risk += 15.0
        if has_payment_fields:
            visual_risk += 25.0
        if has_otp_fields:
            visual_risk += 15.0
        if urgency_detected:
            visual_risk += 15.0
        if external_action:
            visual_risk += 20.0
    else:
        # Whitelisted domains have minimal visual risk unless compromised
        visual_risk = 0.0

    visual_risk_score = round(min(visual_risk, 100.0), 1)

    return {
        "available": True,
        "executed": True,
        "is_login_page": is_login_page,
        "has_credential_harvesting": has_credential_harvesting,
        "has_payment_fields": has_payment_fields,
        "has_otp_fields": has_otp_fields,
        "urgency_detected": urgency_detected,
        "detected_brands": detected_brands,
        "brand_impersonation_visual": brand_impersonation_visual,
        "login_related_terms": login_keywords_found,
        "credential_terms": credential_terms_found,
        "payment_terms": payment_terms_found,
        "urgency_terms": urgency_terms_found,
        "visual_risk_score": visual_risk_score,
        "indicators": indicators,
    }
