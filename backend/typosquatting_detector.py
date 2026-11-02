"""
PhishGuard AI V6.1 — Advanced Typosquatting Detector
=====================================================
Detects domain impersonation via:
  - Character repetition / omission (e.g., gooogle, gogle)
  - Transposition / swap (e.g., googel)
  - Keyboard adjacent key proximity (QWERTY layout errors)
  - Damerau-Levenshtein & Jaro-Winkler distance calibration
  - Subsequence and phonetic typosquatting patterns
"""

import re
from brand_engine import (
    levenshtein_distance,
    damerau_levenshtein_distance,
    jaro_winkler_similarity,
    longest_common_subsequence_ratio,
    extract_apex_label,
    get_all_brands,
    KEYBOARD_NEIGHBORS,
    BRAND_PHONETIC_ALIASES,
    COMPANY_NAMES,
)


def is_adjacent_keyboard_swap(str1: str, str2: str) -> bool:
    """Check if single character difference between strings is an adjacent keyboard key."""
    if len(str1) != len(str2):
        return False
    diffs = []
    for c1, c2 in zip(str1, str2):
        if c1 != c2:
            diffs.append((c1, c2))
    if len(diffs) == 1:
        c1, c2 = diffs[0]
        neighbors = KEYBOARD_NEIGHBORS.get(c2, [])
        return c1 in neighbors
    return False


def is_transposition(str1: str, str2: str) -> bool:
    """Check if two adjacent characters were swapped (e.g. googel vs google)."""
    if len(str1) != len(str2):
        return False
    diff_indices = [i for i in range(len(str1)) if str1[i] != str2[i]]
    if len(diff_indices) == 2 and diff_indices[1] == diff_indices[0] + 1:
        i, j = diff_indices
        return str1[i] == str2[j] and str1[j] == str2[i]
    return False


def detect_typosquatting(domain: str) -> dict:
    """
    Evaluates domain apex for typosquatting attacks against all loaded brands.
    """
    brands = get_all_brands()
    apex = extract_apex_label(domain)
    clean_apex = re.sub(r"[^a-z0-9]", "", apex)

    result = {
        "detected": False,
        "target_brand": None,
        "company": None,
        "similarity": 0.0,
        "technique": None,
        "confidence": 0.0,
        "reason": None
    }

    if not clean_apex:
        return result

    # Check phonetic aliases first
    if clean_apex in BRAND_PHONETIC_ALIASES:
        brand = BRAND_PHONETIC_ALIASES[clean_apex]
        company = COMPANY_NAMES.get(brand, brand.capitalize())
        result.update({
            "detected": True,
            "target_brand": brand,
            "company": company,
            "similarity": 0.94,
            "technique": "Phonetic / Alias Typosquatting",
            "confidence": 97.0,
            "reason": f"Typosquatting alias targeting {company} (via '{clean_apex}')"
        })
        return result

    best_brand = None
    best_sim = 0.0
    best_technique = None

    c_len = len(clean_apex)

    for brand in brands:
        b_len = len(brand)
        if b_len < 3:
            continue
        if clean_apex == brand:
            # Exact match is not a typosquat
            continue

        # Technique 1: Transposition (e.g. googel -> google)
        if is_transposition(clean_apex, brand):
            best_brand = brand
            best_sim = 0.96
            best_technique = "Character Transposition / Swap"
            break

        # Technique 2: Adjacent keyboard replacement (e.g. foogle -> google, paypa1)
        if is_adjacent_keyboard_swap(clean_apex, brand):
            best_brand = brand
            best_sim = 0.95
            best_technique = "Adjacent Keyboard Typo"
            break

        # Technique 3: Missing character (e.g. gogle -> google)
        if c_len == b_len - 1:
            dist = levenshtein_distance(clean_apex, brand)
            if dist == 1:
                best_brand = brand
                best_sim = round(1.0 - (1 / b_len), 3)
                best_technique = "Omitted Character"
                break

        # Technique 4: Added character / Repetition (e.g. gooogle -> google)
        if c_len == b_len + 1:
            dist = levenshtein_distance(clean_apex, brand)
            if dist == 1:
                best_brand = brand
                best_sim = round(1.0 - (1 / c_len), 3)
                best_technique = "Inserted / Repeated Character"
                break

        # Technique 5: Damerau-Levenshtein distance 1 or 2 with high similarity
        if abs(c_len - b_len) <= 2:
            d_dist = damerau_levenshtein_distance(clean_apex, brand)
            max_l = max(c_len, b_len)
            sim = 1.0 - (d_dist / max_l)
            jw = jaro_winkler_similarity(clean_apex, brand)
            comb = max(sim, jw)

            if d_dist == 1 or (b_len >= 6 and d_dist == 2 and comb >= 0.85):
                if comb > best_sim:
                    best_sim = comb
                    best_brand = brand
                    best_technique = "Damerau-Levenshtein Edit Typo"

    if best_brand and (best_sim >= 0.84 or best_technique):
        sim_pct = round(best_sim * 100, 1)
        company = COMPANY_NAMES.get(best_brand, best_brand.capitalize())
        result.update({
            "detected": True,
            "target_brand": best_brand,
            "company": company,
            "similarity": best_sim,
            "technique": best_technique or "Fuzzy Typo",
            "confidence": min(round(best_sim * 100 + 2.0, 1), 99.0),
            "reason": f"Typosquatting attack targeting {company} ({sim_pct}% match via {best_technique})"
        })

    return result
