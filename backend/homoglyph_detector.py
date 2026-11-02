"""
PhishGuard AI V5 — Homoglyph & Visual Spoofing Detector
========================================================
Detects visual character substitutions, leet-speak, Cyrillic lookalikes,
and mixed-script homoglyphs designed to deceive users.
Examples:
  - paypaI (capital I for l)
  - g00gle (0 for o)
  - micr0soft (0 for o)
  - faceb00k (0 for o)
  - Cyrillic 'а', 'о', 'е', 'р'
"""

import os
import re
import json

_BASE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.join(_BASE, "threat_repository")
HOMOGLYPH_PATH = os.path.join(_REPO, "homoglyph_map.json")

# In-memory mapping
_HOMOGLYPHS = {}
_LOADED = False

DEFAULT_HOMOGLYPHS = {
    # Numerical and symbol substitutions
    "0": "o", "1": "l", "2": "z", "3": "e", "4": "a",
    "5": "s", "6": "g", "7": "t", "8": "b", "9": "g",
    "@": "a", "$": "s", "!": "i", "|": "l", "+": "t",
    # Cyrillic lookalikes
    "\u0430": "a", "\u0441": "c", "\u0435": "e", "\u043e": "o",
    "\u0440": "p", "\u0455": "s", "\u0445": "x", "\u0443": "y",
    "\u0456": "i", "\u0458": "j", "\u0406": "i", "\u0410": "a",
    "\u0412": "b", "\u0415": "e", "\u041a": "k", "\u041c": "m",
    "\u041d": "h", "\u041e": "o", "\u0420": "p", "\u0421": "c",
    "\u0422": "t", "\u0423": "y", "\u0425": "x",
    # Greek lookalikes
    "\u03b1": "a", "\u03b2": "b", "\u03b3": "y", "\u03b5": "e",
    "\u03b9": "i", "\u03ba": "k", "\u03bf": "o", "\u03c1": "p",
    "\u03c5": "u", "\u03bd": "v", "\u03c9": "w"
}


def _load_homoglyphs():
    global _HOMOGLYPHS, _LOADED
    if _LOADED:
        return
    _HOMOGLYPHS = DEFAULT_HOMOGLYPHS.copy()
    if os.path.exists(HOMOGLYPH_PATH):
        try:
            with open(HOMOGLYPH_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                for cat in ["numbers", "symbols", "cyrillic", "greek"]:
                    if cat in data:
                        _HOMOGLYPHS.update(data[cat])
        except Exception:
            pass
    _LOADED = True


def decode_homoglyphs(text: str) -> tuple:
    """
    Decodes homoglyph characters into their standard Latin canonical equivalents.
    Returns: (canonical_text, substitutions_list)
    """
    _load_homoglyphs()
    substitutions = []
    chars = []

    for i, ch in enumerate(text):
        # Case 1: capital I or lowercase l ambiguity (e.g. paypaI)
        if ch == "I":
            chars.append("l")
            substitutions.append({"index": i, "char": ch, "canonical": "l", "type": "Latin Case Ambiguity"})
        elif ch in _HOMOGLYPHS:
            canonical = _HOMOGLYPHS[ch]
            chars.append(canonical)
            substitutions.append({"index": i, "char": ch, "canonical": canonical, "type": "Homoglyph/Leet"})
        else:
            chars.append(ch.lower())

    canonical_text = "".join(chars)
    return canonical_text, substitutions


def detect_homoglyphs(domain: str, brand_list: list = None) -> dict:
    """
    Analyzes domain for homoglyphs and compares resulting canonical string against known brands.
    """
    _load_homoglyphs()
    domain_clean = re.sub(r"^www\.", "", domain.strip())
    parts = domain_clean.split(".")
    apex = parts[-2] if len(parts) >= 2 else domain_clean

    canonical, subs = decode_homoglyphs(apex)

    has_homoglyphs = len(subs) > 0
    matched_brand = None
    similarity = 0.0

    if brand_list:
        clean_canon = re.sub(r"[^a-z0-9]", "", canonical)
        for b in brand_list:
            if clean_canon == b:
                matched_brand = b
                similarity = 1.0
                break
            elif b in clean_canon:
                matched_brand = b
                similarity = 0.95
                break

    sub_details = ", ".join(f"{s['char']} -> {s['canonical']}" for s in subs[:3]) if subs else ""
    return {
        "detected": has_homoglyphs,
        "substitution_count": len(subs),
        "substitutions": subs,
        "apex_original": apex,
        "apex_canonical": canonical,
        "matched_brand": matched_brand,
        "similarity": similarity,
        "confidence": 98.0 if (has_homoglyphs and matched_brand) else (85.0 if has_homoglyphs else 0.0),
        "reason": f"Homoglyph characters detected ({sub_details})" if has_homoglyphs else None
    }
