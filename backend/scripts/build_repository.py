"""
PhishGuard AI V5 — Global Offline Threat Intelligence Repository Builder
=========================================================================
Run this script ONCE during setup (requires internet) to build the offline
repository. After building, the Flask backend runs 100% offline.

Usage:
    python backend/scripts/build_repository.py

Datasets:
    - OpenPhish Community Feed
    - PhishTank Recent Phishing URLs
    - URLHaus Phishing URL List
    - Phishing.Database GitHub Feed
"""

import os
import csv
import hashlib
import sqlite3
import json
import time
import re
import sys
import urllib.request
import urllib.error
from urllib.parse import urlparse, urlunparse
from datetime import datetime

# ─── Paths ─────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(SCRIPT_DIR)
REPO_DIR = os.path.join(BACKEND_DIR, "threat_repository")

KNOWN_URLS_DB    = os.path.join(REPO_DIR, "known_urls.sqlite")
KNOWN_DOMAINS_DB = os.path.join(REPO_DIR, "known_domains.sqlite")
BRAND_DICT       = os.path.join(REPO_DIR, "brand_dictionary.json")
METADATA_JSON    = os.path.join(REPO_DIR, "repository_metadata.json")
HOMOGLYPH_JSON   = os.path.join(REPO_DIR, "homoglyph_map.json")
TLD_JSON         = os.path.join(REPO_DIR, "tld_reputation.json")

os.makedirs(REPO_DIR, exist_ok=True)

# ─── Phishing Feeds ─────────────────────────────────────────────────────────
FEEDS = [
    {
        "name": "OpenPhish Community Feed",
        "url": "https://openphish.com/feed.txt",
        "format": "plaintext",
    },
    {
        "name": "PhishTank (CSV verified)",
        "url": "http://data.phishtank.com/data/online-valid.csv",
        "format": "phishtank_csv",
    },
    {
        "name": "URLHaus Phishing",
        "url": "https://urlhaus.abuse.ch/downloads/text_online/",
        "format": "plaintext_comments",
    },
    {
        "name": "Phishing.Database (GH raw)",
        "url": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
        "format": "plaintext_comments",
    },
    {
        "name": "SecureReapir Phishing DB",
        "url": "https://raw.githubusercontent.com/nicktindall/cyclon.p2p/master/test/phishingHosts.txt",
        "format": "plaintext_comments",
    },
]

# ─── Helpers ────────────────────────────────────────────────────────────────

def normalize_url(raw):
    """Canonicalize a URL for consistent lookup."""
    raw = raw.strip().lower()
    if not raw:
        return ""
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    try:
        parsed = urlparse(raw)
        host = parsed.hostname or parsed.netloc
        host = re.sub(r"^www\.", "", host)
        port = parsed.port
        if port in (80, 443):
            port = None
        netloc = host if not port else f"{host}:{port}"
        path = parsed.path.rstrip("/") or "/"
        canonical = urlunparse((
            parsed.scheme, netloc, path,
            parsed.params, parsed.query, ""
        ))
        return canonical
    except Exception:
        return raw


def sha256_of(url):
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def extract_domain(url):
    try:
        parsed = urlparse(url if "://" in url else "https://" + url)
        host = parsed.hostname or ""
        return re.sub(r"^www\.", "", host.lower())
    except Exception:
        return ""


def fetch_feed(feed):
    """Download a feed and return a list of raw URL strings."""
    print(f"  Downloading: {feed['name']} ...")
    urls = []
    try:
        req = urllib.request.Request(
            feed["url"],
            headers={"User-Agent": "PhishGuard/4.0 ThreatIntelBuilder"}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"    WARN: Failed to download {feed['name']}: {e}")
        return []

    fmt = feed.get("format", "plaintext")

    if fmt == "plaintext":
        for line in content.splitlines():
            line = line.strip()
            if line and line.startswith("http"):
                urls.append(line)

    elif fmt == "plaintext_comments":
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and line.startswith("http"):
                urls.append(line)

    elif fmt == "phishtank_csv":
        try:
            lines = content.splitlines()
            reader = csv.DictReader(lines)
            for row in reader:
                u = row.get("url", "").strip()
                if u.startswith("http"):
                    urls.append(u)
        except Exception as e2:
            print(f"    WARN: CSV parse error for {feed['name']}: {e2}")
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("http"):
                    urls.append(line)

    print(f"    OK: Got {len(urls):,} URLs from {feed['name']}")
    return urls


# ─── Fallback seed URLs ───────────────────────────────────────────────────
SEED_URLS = [
    "http://paypal-security-update.com/login",
    "http://paypal-account-verify.xyz/secure",
    "http://netflix-billing-verify.xyz/account",
    "http://amazon-refund-processing.top/claim",
    "http://appleid-account-recovery.live/verify",
    "http://microsoft-verify-security.com/auth",
    "http://google-account-alerts.xyz/signin",
    "http://sbi-net-banking-update.xyz/login",
    "http://hdfc-bank-kyc-update.top/verify",
    "http://icici-secure-login.xyz/banking",
    "http://paytm-kyc-verify.live/account",
    "http://phonepe-secure-payment.xyz/upi",
    "http://192.168.1.1/admin-verify",
    "http://apple-support-icloud.biz/session",
    "http://secure-bank-token-auth.info",
    "http://facebook-login-verify.xyz",
    "http://instagram-security-alert.top",
    "http://whatsapp-verification-center.live",
    "http://linkedin-account-suspended.com",
    "http://amazon-prime-refund.xyz/billing",
    "http://netflix-account-suspended.top",
    "http://googleaccount-recovery.xyz",
    "http://microsoft-office365-verify.live",
    "http://steam-community-verify.com/trade",
    "http://discord-nitro-free-gift.xyz",
    "http://coinbase-wallet-verify.top",
    "http://binance-security-alert.live",
    "http://paypa1-secure.com/login",
    "http://amaz0n-account.net/verify",
    "http://secure-hdfc-kyc.xyz/update",
    "http://iphish-apple.live/id",
    "http://axisbank-netbanking.xyz/otp",
    "http://union-bank-verify.top/login",
    "http://jio-recharge-offer.xyz",
    "http://airtel-thanks-reward.top",
    "http://flipkart-deal-claim.xyz/refund",
    "http://irctc-booking-verify.live/ticket",
    "http://uidai-aadhaar-update.xyz/kyc",
    "http://incometax-refund-2024.top/claim",
    "http://zerodha-trading-verify.xyz",
    "http://groww-investment-claim.live",
]


# ─── Main Build ─────────────────────────────────────────────────────────────

def build():
    print("=" * 65)
    print(" PhishGuard AI V4 — Global Threat Intelligence Repository Builder")
    print("=" * 65)
    print(f" Output directory: {REPO_DIR}\n")

    start = time.time()
    all_raw_urls = []

    # 1. Collect from all feeds
    print("[1/5] Downloading phishing feeds...")
    for feed in FEEDS:
        urls = fetch_feed(feed)
        all_raw_urls.extend(urls)

    if not all_raw_urls:
        print("\nWARN: No URLs downloaded. Using seed dataset...")
        all_raw_urls = SEED_URLS

    print(f"\n  Total raw URLs collected: {len(all_raw_urls):,}")

    # 2. Normalize, deduplicate
    print("\n[2/5] Normalizing and deduplicating...")
    normalized_set = set()
    domains_set = set()
    good_urls = []

    for raw in all_raw_urls:
        norm = normalize_url(raw)
        if not norm or len(norm) < 10:
            continue
        if norm not in normalized_set:
            normalized_set.add(norm)
            domain = extract_domain(norm)
            if domain:
                domains_set.add(domain)
            good_urls.append((norm, domain))

    print(f"  Unique normalized URLs: {len(good_urls):,}")
    print(f"  Unique malicious domains: {len(domains_set):,}")

    # 3. Write known_urls.csv
    print("\n[3/5] Writing known_urls.csv...")
    with open(KNOWN_URLS_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "domain", "sha256"])
        for (norm, domain) in good_urls:
            writer.writerow([norm, domain, sha256_of(norm)])
    print(f"  OK: Saved {len(good_urls):,} entries")

    # 4. Write malicious_domains.csv
    print("\n[4/5] Writing malicious_domains.csv...")
    with open(DOMAINS_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["domain"])
        for domain in sorted(domains_set):
            writer.writerow([domain])
    print(f"  OK: Saved {len(domains_set):,} domains")

    # 5. Build SQLite with hash + domain indexes
    print("\n[5/5] Building SQLite index database...")
    if os.path.exists(SQLITE_DB):
        os.remove(SQLITE_DB)

    conn = sqlite3.connect(SQLITE_DB)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE url_hashes (
            sha256 TEXT PRIMARY KEY,
            url TEXT,
            domain TEXT
        )
    """)
    cur.execute("CREATE INDEX idx_domain ON url_hashes(domain)")

    batch = []
    BATCH_SIZE = 5000
    for (norm, domain) in good_urls:
        batch.append((sha256_of(norm), norm, domain))
        if len(batch) >= BATCH_SIZE:
            cur.executemany("INSERT OR IGNORE INTO url_hashes VALUES (?,?,?)", batch)
            conn.commit()
            batch = []
    if batch:
        cur.executemany("INSERT OR IGNORE INTO url_hashes VALUES (?,?,?)", batch)
        conn.commit()

    count = cur.execute("SELECT COUNT(*) FROM url_hashes").fetchone()[0]
    conn.close()
    print(f"  OK: SQLite built with {count:,} indexed entries")

    # 6. Write metadata.json
    elapsed = round(time.time() - start, 2)
    metadata = {
        "known_urls": len(good_urls),
        "domains": len(domains_set),
        "generated_on": datetime.utcnow().strftime("%Y-%m-%d"),
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "build_time_seconds": elapsed,
        "version": "Global Threat Repository V4",
        "feeds_used": [f["name"] for f in FEEDS],
    }
    with open(METADATA_JSON, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"\n{'='*65}")
    print(f"  Build complete in {elapsed}s")
    print(f"  Known URLs  : {len(good_urls):,}")
    print(f"  Domains     : {len(domains_set):,}")
    print(f"  Generated   : {metadata['generated_on']}")
    print(f"{'='*65}")


if __name__ == "__main__":
    build()
