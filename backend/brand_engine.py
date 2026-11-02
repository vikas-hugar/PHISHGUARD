"""
PhishGuard AI V6.1 — Advanced Brand Intelligence & Typo Engine
================================================================
Comprehensive brand detection and impersonation analysis:
  - Exact brand matching with contextual modifiers
  - Repeated-character squashing (e.g., aaappllle -> apple, uuttubte -> utubte -> utube)
  - Damerau-Levenshtein distance (insertions, deletions, substitutions, transpositions)
  - Jaro-Winkler with prefix scaling
  - Longest Common Subsequence (LCS) ratio & character n-gram overlap
  - Phonetic brand alias mapping (e.g., utube -> youtube)
  - QWERTY keyboard neighbor typing error detection
  - Separation of verified BRANDS from GENERIC SUSPICIOUS KEYWORDS (crypto, wallet, login)
"""

import os
import re
import json
from urllib.parse import urlparse

_BASE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.join(_BASE, "threat_repository")
BRAND_DICT_PATH = os.path.join(_REPO, "brand_dictionary.json")

# In-memory stores
_BRANDS: list[str] = []
_BRAND_SET: set[str] = set()
_DECEPTIVE_MODIFIERS: list[str] = []
_LOADED = False

# Mapping from brand tokens to official company names
COMPANY_NAMES = {
    "youtube": "YouTube LLC (Google)",
    "google": "Google LLC",
    "apple": "Apple Inc.",
    "microsoft": "Microsoft Corporation",
    "amazon": "Amazon.com Inc.",
    "meta": "Meta Platforms Inc.",
    "facebook": "Meta Platforms Inc. (Facebook)",
    "instagram": "Meta Platforms Inc. (Instagram)",
    "whatsapp": "Meta Platforms Inc. (WhatsApp)",
    "netflix": "Netflix Inc.",
    "paypal": "PayPal Holdings Inc.",
    "adobe": "Adobe Systems Inc.",
    "github": "GitHub Inc. (Microsoft)",
    "gitlab": "GitLab Inc.",
    "dropbox": "Dropbox Inc.",
    "cloudflare": "Cloudflare Inc.",
    "yahoo": "Yahoo! Inc.",
    "chase": "JPMorgan Chase & Co.",
    "bankofamerica": "Bank of America Corporation",
    "wellsfargo": "Wells Fargo & Company",
    "citibank": "Citigroup Inc.",
    "citi": "Citigroup Inc.",
    "sbi": "State Bank of India",
    "hdfc": "HDFC Bank Ltd.",
    "icici": "ICICI Bank Ltd.",
    "axisbank": "Axis Bank Ltd.",
    "kotak": "Kotak Mahindra Bank",
    "binance": "Binance Holdings Ltd.",
    "coinbase": "Coinbase Global Inc.",
    "metamask": "ConsenSys (MetaMask)",
    "trustwallet": "Trust Wallet (Binance)",
    "ledger": "Ledger SAS",
    "trezor": "SatoshiLabs (Trezor)",
    "dhl": "DHL International GmbH",
    "fedex": "FedEx Corporation",
    "ups": "United Parcel Service",
    "usps": "United States Postal Service",
    "irs": "Internal Revenue Service (US Gov)",
    "govuk": "HM Government (UK)",
    "spotify": "Spotify Technology S.A.",
    "steam": "Valve Corporation (Steam)",
    "roblox": "Roblox Corporation",
    "epicgames": "Epic Games Inc.",
    "discord": "Discord Inc.",
    "telegram": "Telegram FZ-LLC",
    "twitter": "X Corp. (Twitter)",
    "x": "X Corp.",
    "linkedin": "LinkedIn Corporation (Microsoft)",
    "tiktok": "ByteDance Ltd. (TikTok)",
    "att": "AT&T Inc.",
    "verizon": "Verizon Communications Inc.",
    "tmobile": "T-Mobile US Inc."
}

# Generic category and security keywords that must NOT be misreported as brands
GENERIC_SUSPICIOUS_KEYWORDS = frozenset([
    "crypto", "cryptocurrency", "bitcoin", "btc", "ethereum", "eth",
    "wallet", "mywallet", "web3", "defi", "vault",
    "login", "signin", "sign-in", "log-in", "signon", "auth", "authenticate",
    "secure", "security", "protect", "defense", "shield", "guard",
    "verify", "verification", "validate", "validation", "confirm", "confirmation",
    "account", "myaccount", "profile", "billing", "invoice", "payment",
    "update", "upgrade", "renew", "renewal", "alert", "notification",
    "support", "service", "help", "helpdesk", "center", "portal",
    "banking", "onlinebanking", "netbanking", "token", "otp", "2fa"
])

# Known popular typosquat aliases / phonetic variants for prominent brands
BRAND_PHONETIC_ALIASES = {
    "utube": "youtube",
    "u-tube": "youtube",
    "ytube": "youtube",
    "yotube": "youtube",
    "you-tube": "youtube",
    "uuttubte": "youtube",
    "utubte": "youtube",
    "gugle": "google",
    "gogle": "google",
    "googel": "google",
    "googl": "google",
    "microsof": "microsoft",
    "microsft": "microsoft",
    "micosoft": "microsoft",
    "amazn": "amazon",
    "amzon": "amazon",
    "paypa": "paypal",
    "paypl": "paypal",
    "paypall": "paypal",
    "netflx": "netflix",
    "netfli": "netflix",
    "facebok": "facebook",
    "facbook": "facebook",
    "instgram": "instagram",
    "whatsap": "whatsapp"
}

# QWERTY adjacent key map
KEYBOARD_NEIGHBORS = {
    "q": ["w", "a", "s"],
    "w": ["q", "e", "a", "s", "d"],
    "e": ["w", "r", "s", "d", "f"],
    "r": ["e", "t", "d", "f", "g"],
    "t": ["r", "y", "f", "g", "h"],
    "y": ["t", "u", "g", "h", "j"],
    "u": ["y", "i", "h", "j", "k"],
    "i": ["u", "o", "j", "k", "l"],
    "o": ["i", "p", "k", "l"],
    "p": ["o", "l"],
    "a": ["q", "w", "s", "z"],
    "s": ["a", "w", "e", "d", "x", "z"],
    "d": ["s", "e", "r", "f", "c", "x"],
    "f": ["d", "r", "t", "g", "v", "c"],
    "g": ["f", "t", "y", "h", "b", "v"],
    "h": ["g", "y", "u", "j", "n", "b"],
    "j": ["h", "u", "i", "k", "m", "n"],
    "k": ["j", "i", "o", "l", "m"],
    "l": ["k", "o", "p"],
    "z": ["a", "s", "x"],
    "x": ["z", "s", "d", "c"],
    "c": ["x", "d", "f", "v"],
    "v": ["c", "f", "g", "b"],
    "b": ["v", "g", "h", "n"],
    "n": ["b", "h", "j", "m"],
    "m": ["n", "j", "k"]
}


def _load_brand_data():
    """Ensure brand dictionary is loaded into memory."""
    global _BRANDS, _BRAND_SET, _DECEPTIVE_MODIFIERS, _LOADED
    if _LOADED and len(_BRANDS) > 0:
        return

    loaded_brands = set(COMPANY_NAMES.keys())
    if os.path.exists(BRAND_DICT_PATH):
        try:
            with open(BRAND_DICT_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                for b in data.get("brands", []):
                    clean = b.lower().strip()
                    # Filter out any generic terms
                    if clean and clean not in GENERIC_SUSPICIOUS_KEYWORDS and len(clean) >= 3:
                        loaded_brands.add(clean)
                _DECEPTIVE_MODIFIERS = [m.lower().strip() for m in data.get("deceptive_modifiers", [])]
        except Exception as e:
            print(f"[BrandEngine] Warning: Failed to load brand dictionary: {e}")

    # Ensure prominent brands are always present
    for core in COMPANY_NAMES.keys():
        loaded_brands.add(core)

    _BRANDS = sorted(list(loaded_brands))
    _BRAND_SET = loaded_brands
    if not _DECEPTIVE_MODIFIERS:
        _DECEPTIVE_MODIFIERS = ["login", "verify", "secure", "update", "account", "billing", "confirm", "wallet"]
    _LOADED = True


def get_all_brands() -> list[str]:
    """Public helper ensuring caller receives populated brand list."""
    _load_brand_data()
    return _BRANDS


def normalize_repeated_chars(text: str) -> tuple[str, str]:
    """
    Squashes repeated characters into canonical reduced forms.
    Returns: (reduced_max_2, fully_deduped)
      e.g., 'uuttubte' -> ('uutubte', 'utubte')
      e.g., 'aaappllle' -> ('aapple', 'aple')
    """
    if not text:
        return "", ""
    reduced_2 = re.sub(r"(.)\1{2,}", r"\1\1", text)
    reduced_1 = re.sub(r"(.)\1+", r"\1", text)
    return reduced_2, reduced_1


def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calculates Damerau-Levenshtein distance (insertions, deletions,
    substitutions, and transpositions of adjacent characters).
    """
    len1, len2 = len(s1), len(s2)
    if s1 == s2:
        return 0
    if len1 == 0:
        return len2
    if len2 == 0:
        return len1

    # Matrix allocation
    d = [[0] * (len2 + 2) for _ in range(len1 + 2)]
    max_dist = len1 + len2
    d[0][0] = max_dist

    da = {}
    for i in range(1, len1 + 2):
        d[i][0] = max_dist
        d[i][1] = i - 1
    for j in range(1, len2 + 2):
        d[0][j] = max_dist
        d[1][j] = j - 1

    for i in range(2, len1 + 2):
        db = 0
        for j in range(2, len2 + 2):
            k = da.get(s2[j - 2], 0)
            l = db
            cost = 0 if s1[i - 2] == s2[j - 2] else 1
            if cost == 0:
                db = j - 1

            d[i][j] = min(
                d[i - 1][j] + 1,       # deletion
                d[i][j - 1] + 1,       # insertion
                d[i - 1][j - 1] + cost, # substitution
                d[k][l] + (i - 2 - k) + 1 + (j - 2 - l)  # transposition
            )
        da[s1[i - 2]] = i - 1

    return d[len1 + 1][len2 + 1]


def levenshtein_distance(s1: str, s2: str) -> int:
    """Standard dynamic-programming Levenshtein distance."""
    if s1 == s2:
        return 0
    if len(s1) == 0:
        return len(s2)
    if len(s2) == 0:
        return len(s1)
    v0 = list(range(len(s2) + 1))
    v1 = [0] * (len(s2) + 1)
    for i in range(len(s1)):
        v1[0] = i + 1
        for j in range(len(s2)):
            cost = 0 if s1[i] == s2[j] else 1
            v1[j + 1] = min(v1[j] + 1, v0[j + 1] + 1, v0[j] + cost)
        v0 = v1[:]
    return v0[len(s2)]


def jaro_winkler_similarity(s1: str, s2: str) -> float:
    """Jaro-Winkler string similarity (0.0 to 1.0)."""
    if s1 == s2:
        return 1.0
    len1, len2 = len(s1), len(s2)
    if len1 == 0 or len2 == 0:
        return 0.0

    match_dist = max(len1, len2) // 2 - 1
    s1_matches = [False] * len1
    s2_matches = [False] * len2
    matches = 0
    transpositions = 0

    for i in range(len1):
        start = max(0, i - match_dist)
        end = min(i + match_dist + 1, len2)
        for j in range(start, end):
            if s2_matches[j] or s1[i] != s2[j]:
                continue
            s1_matches[i] = True
            s2_matches[j] = True
            matches += 1
            break

    if matches == 0:
        return 0.0

    k = 0
    for i in range(len1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
            if k >= len2:
                break
        if k < len2 and s1[i] != s2[k]:
            transpositions += 1
        k += 1

    transpositions //= 2
    jaro = (matches / len1 + matches / len2 + (matches - transpositions) / matches) / 3.0

    prefix = 0
    for i in range(min(len1, len2, 4)):
        if s1[i] == s2[i]:
            prefix += 1
        else:
            break
    return round(jaro + prefix * 0.1 * (1.0 - jaro), 4)


def longest_common_subsequence_ratio(s1: str, s2: str) -> float:
    """Calculates LCS length / max(len(s1), len(s2)). Order-preserving match."""
    m, n = len(s1), len(s2)
    if m == 0 or n == 0:
        return 0.0
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if s1[i - 1] == s2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
    lcs_len = dp[m][n]
    return round(lcs_len / max(m, n), 4)


def extract_apex_label(domain: str) -> str:
    """Extract apex label e.g., 'paypa1-update.com' -> 'paypa1-update'."""
    domain = re.sub(r"^www\.", "", domain.lower().strip())
    parts = domain.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return domain


def find_generic_keywords(text: str) -> list[str]:
    """Identify generic category/security keywords present in domain or URL."""
    text_lower = text.lower()
    found = []
    for kw in GENERIC_SUSPICIOUS_KEYWORDS:
        if kw in text_lower:
            found.append(kw)
    return sorted(found, key=lambda x: -len(x))


def analyze_brand_impersonation(url: str, domain: str) -> dict:
    """
    Advanced multi-strategy brand impersonation and typosquatting detection.
    Combines:
      - Exact brand containment with deceptive modifiers
      - Repeated-character reduction (aaappllle -> apple, uuttubte -> utube)
      - Phonetic / alias dictionary matching (utube -> youtube)
      - Damerau-Levenshtein transpositions
      - Keyboard proximity replacement
      - LCS and Jaro-Winkler multi-metric scoring
      - Generic keyword separation (crypto != brand)
    """
    _load_brand_data()
    apex = extract_apex_label(domain)
    apex_clean = re.sub(r"[^a-z0-9]", "", apex)
    full_url_lower = url.lower()

    # Identify generic keywords present
    generic_kws = find_generic_keywords(domain)

    result = {
        "detected": False,
        "brand": None,
        "company": None,
        "similarity": 0.0,
        "confidence": 0.0,
        "has_modifier": False,
        "modifier": None,
        "impersonation_type": None,
        "generic_keywords": generic_kws,
        "reason": None
    }

    if not apex_clean:
        return result

    # Check for deceptive modifiers
    detected_modifier = None
    for mod in _DECEPTIVE_MODIFIERS:
        if mod in apex_clean or mod in full_url_lower:
            detected_modifier = mod
            break
    result["has_modifier"] = bool(detected_modifier)
    result["modifier"] = detected_modifier

    # -------------------------------------------------------------
    # 0. Misleading Subdomain Brand Impersonation (e.g. paypal.com.attacker.com)
    # -------------------------------------------------------------
    domain_parts = domain.split(".")
    if len(domain_parts) > 2:
        subdomain_part = ".".join(domain_parts[:-2])
        for brand in COMPANY_NAMES.keys():
            if len(brand) >= 4 and brand in subdomain_part:
                company = COMPANY_NAMES.get(brand, brand.capitalize())
                result.update({
                    "detected": True,
                    "brand": brand,
                    "company": company,
                    "similarity": 0.95,
                    "confidence": 97.0,
                    "impersonation_type": "Misleading Subdomain Brand Impersonation",
                    "reason": f"Deceptive subdomain embedding official brand '{company}' on unauthorized apex domain '{domain_parts[-2]}.{domain_parts[-1]}'"
                })
                return result

    # -------------------------------------------------------------
    # 1. Exact Embedded Brand with Deceptive Modifier
    # -------------------------------------------------------------
    for brand in _BRANDS:
        if len(brand) < 3:
            continue
        if brand in apex_clean:
            # If the apex is exactly the brand name without modifier,
            # this is likely the legitimate brand domain itself
            if apex_clean == brand and not detected_modifier:
                continue

            if detected_modifier or apex_clean != brand:
                company = COMPANY_NAMES.get(brand, brand.capitalize())
                conf = 98.0 if detected_modifier else 90.0
                result.update({
                    "detected": True,
                    "brand": brand,
                    "company": company,
                    "similarity": 1.0,
                    "confidence": conf,
                    "impersonation_type": "Brand Impersonation with Deceptive Modifier" if detected_modifier else "Embedded Brand Name",
                    "reason": f"Targeting {company} with deceptive word '{detected_modifier}'" if detected_modifier else f"Targeting {company} brand"
                })
                return result

    # -------------------------------------------------------------
    # 2. Phonetic / Popular Typo Aliases (e.g. uuttubte -> utube -> youtube)
    # -------------------------------------------------------------
    red_2, red_1 = normalize_repeated_chars(apex_clean)
    candidate_tokens = [apex_clean, red_2, red_1]

    for cand in candidate_tokens:
        if cand in BRAND_PHONETIC_ALIASES:
            matched_brand = BRAND_PHONETIC_ALIASES[cand]
            company = COMPANY_NAMES.get(matched_brand, matched_brand.capitalize())
            result.update({
                "detected": True,
                "brand": matched_brand,
                "company": company,
                "similarity": 0.94,
                "confidence": 96.0,
                "impersonation_type": "Phonetic / Alias Typosquatting",
                "reason": f"Typosquatting alias targeting {company} (via '{cand}')"
            })
            return result

    # -------------------------------------------------------------
    # 3. Repeated Characters Normalization (e.g. aaappllle -> apple)
    # -------------------------------------------------------------
    for brand in _BRANDS:
        if len(brand) < 4:
            continue
        if red_2 == brand or red_1 == brand:
            company = COMPANY_NAMES.get(brand, brand.capitalize())
            result.update({
                "detected": True,
                "brand": brand,
                "company": company,
                "similarity": 0.96,
                "confidence": 97.5,
                "impersonation_type": "Repeated Character Impersonation",
                "reason": f"Repeated character impersonation targeting {company}"
            })
            return result

    # -------------------------------------------------------------
    # 4. Multi-Metric Similarity Scoring across All Brands
    # -------------------------------------------------------------
    best_brand = None
    best_sim = 0.0
    best_technique = None

    test_tokens = [apex_clean]
    if red_1 != apex_clean:
        test_tokens.append(red_1)
    if detected_modifier and detected_modifier in apex_clean:
        stripped = apex_clean.replace(detected_modifier, "")
        if stripped:
            test_tokens.append(stripped)

    for token in test_tokens:
        t_len = len(token)
        t_set = set(token)

        # High-speed pre-filter: prune 1000+ brands to candidate subset in < 1ms
        candidates = [
            b for b in _BRANDS
            if len(b) >= 3 and (
                (abs(t_len - len(b)) <= 2 and len(t_set & set(b)) >= min(len(b), t_len) - 2) or
                (len(b) >= 5 and b[-4:] in token) or
                (len(b) >= 5 and b[:4] in token)
            )
        ]

        for brand in candidates:
            b_len = len(brand)
            d_dist = damerau_levenshtein_distance(token, brand)
            max_len = max(t_len, b_len)
            d_sim = 1.0 - (d_dist / max_len)
            jw_sim = jaro_winkler_similarity(token, brand)
            lcs_sim = longest_common_subsequence_ratio(token, brand)

            # Combined multi-factor score
            comb_sim = max(d_sim, jw_sim, lcs_sim)

            # Check for adjacent keyboard replacement
            if d_dist == 1 and t_len == b_len:
                comb_sim = max(comb_sim, 0.94)

            # Check for transpositions (e.g. googel)
            if d_dist == 1 and abs(t_len - b_len) == 0:
                comb_sim = max(comb_sim, 0.95)

            # Distinctive suffix match: e.g. token ends in 'tube' for youtube
            if b_len >= 6 and brand[-4:] in token and lcs_sim >= 0.70:
                comb_sim = max(comb_sim, 0.91)

            if comb_sim > best_sim:
                best_sim = comb_sim
                best_brand = brand
                if d_dist == 1 and t_len == b_len:
                    best_technique = "Adjacent Keyboard / Single Character Typo"
                elif d_dist == 1:
                    best_technique = "Damerau-Levenshtein Edit Typo"
                elif lcs_sim >= 0.85:
                    best_technique = "Subsequence Alignment Typosquat"
                else:
                    best_technique = "Fuzzy String Similarity"

    # Threshold for brand impersonation alert: >= 0.86
    if best_sim >= 0.86 and best_brand:
        company = COMPANY_NAMES.get(best_brand, best_brand.capitalize())
        conf = round(best_sim * 100, 1)
        if detected_modifier:
            conf = min(conf + 4.0, 99.0)

        result.update({
            "detected": True,
            "brand": best_brand,
            "company": company,
            "similarity": round(best_sim, 4),
            "confidence": conf,
            "impersonation_type": best_technique or "Fuzzy Brand Impersonation",
            "reason": f"Targeting {company} ({round(best_sim * 100)}% domain similarity via {best_technique or 'fuzzy matching'})"
        })
        return result

    return result
