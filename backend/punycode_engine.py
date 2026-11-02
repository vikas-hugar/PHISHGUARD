"""
PhishGuard AI V6 — Local Punycode & IDN Spoofing Engine
========================================================
Decodes Internationalized Domain Names (IDNs) with 'xn--' prefixes locally
using the Python standard library 'idna' codec.
Decodes Unicode homoglyphs (e.g. Cyrillic, Greek lookalikes) and compares
against global brand assets to detect invisible homograph spoofing.
"""

import re
import idna
from brand_engine import levenshtein_distance, jaro_winkler_similarity, COMPANY_NAMES, BRAND_DICT_PATH
from homoglyph_detector import decode_homoglyphs
import json
import os

_LOADED_BRANDS = None

def _get_all_brands() -> list:
    global _LOADED_BRANDS
    if _LOADED_BRANDS is not None:
        return _LOADED_BRANDS

    brands = set(COMPANY_NAMES.keys())
    if os.path.exists(BRAND_DICT_PATH):
        try:
            with open(BRAND_DICT_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                for b in data.get("brands", []):
                    b_clean = b.lower().strip()
                    if b_clean:
                        brands.add(b_clean)
        except Exception:
            pass

    _LOADED_BRANDS = sorted(list(brands))
    return _LOADED_BRANDS


def analyze_punycode(domain: str) -> dict:
    """
    Decodes punycode domains and evaluates visual and semantic proximity to known brands.
    """
    domain = domain.lower().strip()
    is_punycode = "xn--" in domain

    result = {
        "detected": False,
        "is_punycode": is_punycode,
        "raw_domain": domain,
        "decoded_domain": domain,
        "decoded_apex": "",
        "target_brand": None,
        "similarity": 0.0,
        "risk_level": "Safe",
        "reason": None
    }

    if not is_punycode:
        return result

    # Decode IDN / Punycode using standard library idna
    try:
        decoded = idna.decode(domain)
        result["decoded_domain"] = decoded
    except Exception:
        result["decoded_domain"] = domain

    decoded_domain = result["decoded_domain"]
    parts = decoded_domain.split(".")
    apex = parts[-2] if len(parts) >= 2 else decoded_domain
    result["decoded_apex"] = apex

    # Also resolve any homoglyphs in the decoded Unicode apex (e.g. Cyrillic 'а' -> Latin 'a')
    canonical_apex, _ = decode_homoglyphs(apex)

    all_brands = _get_all_brands()
    best_brand = None
    best_sim = 0.0

    # Compare decoded characters and canonical characters to known brands
    for brand in all_brands:
        if len(brand) < 3:
            continue

        # Check against decoded apex (Unicode) and canonical apex (Latin ASCII normalized)
        for cand in [canonical_apex, apex]:
            if cand == brand:
                best_sim = 1.0
                best_brand = brand
                break
            elif brand in cand or cand in brand:
                sim = len(brand) / max(len(cand), len(brand))
                if sim > best_sim:
                    best_sim = sim
                    best_brand = brand
            else:
                dist = levenshtein_distance(cand, brand)
                max_l = max(len(cand), len(brand))
                sim = 1.0 - (dist / max_l)
                jw = jaro_winkler_similarity(cand, brand)
                combined = max(sim, jw)
                if combined > best_sim:
                    best_sim = combined
                    best_brand = brand

        if best_sim >= 1.0:
            break

    result["similarity"] = round(best_sim, 4)
    result["target_brand"] = best_brand

    # If decoded similarity >= 85% (0.85), classify as High/Critical Risk
    if is_punycode and best_sim >= 0.85 and best_brand:
        result["detected"] = True
        result["risk_level"] = "Critical"
        result["confidence"] = 99.0
        result["reason"] = f"Punycode (xn--) Internationalized spoof targeting {best_brand.capitalize()} ({round(best_sim * 100)}% match)"
    elif is_punycode:
        result["detected"] = True
        result["risk_level"] = "High"
        result["confidence"] = 85.0
        result["reason"] = f"Punycode encoding detected in domain ({decoded_domain})"

    return result
