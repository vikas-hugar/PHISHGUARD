"""
PhishGuard AI V7 — Safe Web View: Complete Page Discovery Engine
==================================================================
Implements universal, bounded same-origin crawling, DOM link discovery,
sitemap analysis, URL normalization, SSRF protection, and page tree construction.

Requirements Addressed:
  1. Strict Same-Origin Crawling with External Link Cataloguing
  2. Complete Rendered DOM Link Extraction (<a href>, <area href>, SPA routing, canonical)
  3. Universal URL Normalization (fragment stripping, query sanitization, slash normalization)
  4. Destructive Action Blocking (logout, delete, purchase, pay, cancel, wipe)
  5. Pre-Crawl SSRF Verification for Discovered URLs
  6. XML Sitemap Discovery (/sitemap.xml and sitemap indexes)
  7. Hierarchical Page Tree Construction (parent_page_id and path hierarchy)
"""

from __future__ import annotations

import os
import re
import html
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, urljoin, urldefrag, parse_qs, urlencode
from typing import Any, Optional

from detection.ssrf_guard import validate_url_safe


# Excluded file extensions (binary/static resources that are not browsable web pages)
_STATIC_EXTENSIONS = frozenset([
    ".pdf", ".exe", ".zip", ".tar", ".gz", ".7z", ".rar", ".msi", ".dmg", ".apk",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp", ".tiff",
    ".css", ".js", ".mjs", ".json", ".xml", ".csv", ".tsv",
    ".mp4", ".mp3", ".avi", ".mov", ".wav", ".webm", ".mkv", ".ogg",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
])

# High-priority security and functional path keywords
_AUTH_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "auth", "authenticate",
    "verify", "verification", "checkpoint", "account", "security",
    "portal", "password", "reset", "recover", "admin", "billing",
    "update", "confirm", "wallet", "oauth", "mfa", "2fa", "otp",
]

_INFO_KEYWORDS = [
    "about", "contact", "support", "help", "faq", "terms", "privacy",
    "signup", "register", "documentation", "docs", "pricing", "services",
    "products", "features", "solutions", "team", "company", "legal",
    "blog", "articles", "news",
]

# Destructive action keywords — MUST NEVER BE VISITED (Requirement 5 & 30)
_BLOCKED_ACTION_KEYWORDS = [
    "logout", "signout", "log-out", "sign-out", "logoff", "signoff", "exit",
    "delete", "remove", "destroy", "drop", "wipe", "terminate", "kill",
    "purchase", "checkout", "buy", "pay", "payment", "order", "subscribe",
    "cancel", "unsubscribe", "revoke", "reset-db", "clear-all",
]

# Query parameters to ignore during deduplication (analytics, tracking, cache-busters)
_IGNORED_QUERY_PARAMS = frozenset([
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "gclsrc", "dclid", "msclkid", "_ga", "_gl",
    "ref", "source", "affiliate", "sessionid", "sid", "timestamp", "ts", "_",
])


class PageDiscoveryEngine:
    """Discovers, normalizes, filters, prioritizes, and structures internal site pages."""

    def __init__(
        self,
        max_pages: int = 50,
        max_depth: int = 4,
    ) -> None:
        self.max_pages = int(os.environ.get("PHISHGUARD_CRAWL_MAX_PAGES", str(max_pages)))
        self.max_depth = int(os.environ.get("PHISHGUARD_CRAWL_MAX_DEPTH", str(max_depth)))

    def discover_from_dom(
        self,
        html_content: str,
        current_url: str,
        target_origin_url: Optional[str] = None,
        depth: int = 0,
        browser_links: Optional[list[Any]] = None,
        parent_page_id: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """
        Comprehensive link extraction from rendered DOM and post-JavaScript HTML.
        Returns candidate internal pages list.
        """
        result = self.extract_all_links(
            html_content=html_content,
            current_url=current_url,
            target_origin_url=target_origin_url or current_url,
            current_depth=depth,
            browser_links=browser_links,
            parent_page_id=parent_page_id,
        )
        return result["candidates"]

    def extract_internal_links(
        self,
        html_content: str,
        current_url: str,
        target_origin_url: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Backwards-compatible helper returning candidate internal pages."""
        result = self.extract_all_links(
            html_content=html_content,
            current_url=current_url,
            target_origin_url=target_origin_url or current_url,
            current_depth=0,
        )
        return result["candidates"]

    def extract_all_links(
        self,
        html_content: str,
        current_url: str,
        target_origin_url: str,
        current_depth: int = 0,
        browser_links: Optional[list[Any]] = None,
        parent_page_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Extracts links from DOM, enforces same-origin policy, verifies SSRF,
        detects destructive actions, normalizes URLs, and catalogues external domains.
        """
        try:
            parsed_origin = urlparse(target_origin_url)
            origin_scheme = (parsed_origin.scheme or "http").lower()
            origin_netloc = (parsed_origin.netloc or "").lower()
            origin_hostname = (parsed_origin.hostname or "").lower()
            if not origin_hostname:
                return {"candidates": [], "blocked_actions": [], "external_domains": [], "external_links": []}
        except Exception:
            return {"candidates": [], "blocked_actions": [], "external_domains": [], "external_links": []}

        try:
            parsed_curr = urlparse(current_url)
            curr_hostname = (parsed_curr.hostname or "").lower()
        except Exception:
            curr_hostname = origin_hostname

        def is_same_site(host: str) -> bool:
            if not host:
                return False
            # Direct match to origin or current redirected host
            if host in (origin_hostname, curr_hostname):
                return True
            # www. vs non-www variations
            for base in (origin_hostname, curr_hostname):
                if not base:
                    continue
                if host == f"www.{base}" or f"www.{host}" == base:
                    return True
                clean_base = base[4:] if base.startswith("www.") else base
                if "." in clean_base and host.endswith(f".{clean_base}"):
                    return True
            return False

        # Raw links collection: (href, context_text)
        raw_links: list[tuple[str, str]] = []

        # 1. Incorporate live browser-discovered links (from Chromium DOM evaluation)
        if browser_links:
            for item in browser_links:
                if isinstance(item, dict):
                    href = item.get("href") or item.get("raw_href") or ""
                    txt = item.get("text") or "DOM Link"
                    if href:
                        raw_links.append((href, txt))
                elif isinstance(item, str) and item.strip():
                    raw_links.append((item.strip(), "DOM Link"))

        # 2. Extract from rendered HTML (Requirement 8 & 13)
        if html_content:
            # Anchor tags with text: <a ... href="..." ...>Text</a>
            for m in re.finditer(r'''<\s*a\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>(.*?)<\s*/\s*a\s*>''', html_content, flags=re.IGNORECASE | re.DOTALL):
                href, inner_text = m.group(1), m.group(2)
                clean_text = re.sub(r'<[^>]+>', '', inner_text).strip()
                raw_links.append((href, clean_text[:60] if clean_text else "Navigation Link"))

            # Fallback anchor match (unquoted or single-quoted or complex tag)
            for m in re.finditer(r'''<\s*a\b[^>]*\bhref\s*=\s*(?:["']([^"']+)["']|([^\s>]+))''', html_content, flags=re.IGNORECASE):
                href = m.group(1) or m.group(2)
                if href:
                    raw_links.append((href, "Anchor Link"))

            # <area href="..."> and <link rel="canonical" href="...">
            for m in re.finditer(r'''<\s*(?:area|link)\b[^>]*\bhref\s*=\s*["']([^"']+)["']''', html_content, flags=re.IGNORECASE):
                raw_links.append((m.group(1), "Document Link"))

            # SPA & Client-Side routing attributes: data-href, data-to, to, routerlink, data-url, data-route
            for m in re.finditer(r'''\b(?:data-href|data-to|routerlink|data-url|data-route)\s*=\s*["']([^"']+)["']''', html_content, flags=re.IGNORECASE):
                raw_links.append((m.group(1), "SPA Router Route"))

            # Form actions: <form action="..."> (INSPECTED ONLY, NEVER SUBMITTED)
            for m in re.finditer(r'''<\s*form\b[^>]*\baction\s*=\s*["']([^"']+)["']''', html_content, flags=re.IGNORECASE):
                raw_links.append((m.group(1), "Form Action Destination"))

            # Client-Side router patterns in scripts: history.pushState(..., '/path') or router.push('/path')
            for m in re.finditer(r'''(?:pushState|replaceState|router\.push|navigate)\s*\(\s*[^,)]*,\s*[^,)]*,\s*["'](/[\w\d\-_/]+)["']''', html_content, flags=re.IGNORECASE):
                raw_links.append((m.group(1), "Client-Side Route"))

            # Common SPA path strings: path: "/about", to: "/products"
            for m in re.finditer(r'''\b(?:path|route|to|url)\s*:\s*["'](/[\w\d\-_/]+)["']''', html_content, flags=re.IGNORECASE):
                raw_links.append((m.group(1), "SPA Route Config"))

        candidates: list[dict[str, Any]] = []
        blocked_actions: list[dict[str, Any]] = []
        external_domains: set[str] = set()
        external_links: list[dict[str, str]] = []
        seen_normalized: set[str] = set()

        # Always include root path / as base candidate
        root_url = f"{origin_scheme}://{origin_netloc}/"
        root_clean = self._normalize_candidate_url(root_url)
        if root_clean:
            seen_normalized.add(root_clean)
            candidates.append({
                "url": root_url,
                "canonical_url": root_url,
                "path": "/",
                "title": "Homepage / Root",
                "depth": 0,
                "priority": 100,
                "reason": "Root landing page",
                "is_root": True,
                "parent_page_id": None,
                "discovered_from": None,
            })

        for raw_link, link_context in raw_links:
            raw_link = html.unescape(raw_link.strip())
            if not raw_link or raw_link.startswith("#"):
                continue

            # Strip non-navigable protocols
            lower_raw = raw_link.lower()
            if any(lower_raw.startswith(p) for p in ("javascript:", "mailto:", "tel:", "data:", "file:", "blob:", "about:", "chrome:", "android-app:", "ios-app:")):
                continue

            # Resolve relative URLs against the currently inspected page (Requirement 8)
            try:
                resolved = urljoin(current_url, raw_link)
                resolved, _ = urldefrag(resolved)  # Strip #fragment completely (Requirement 9)
            except Exception:
                continue

            try:
                parsed_res = urlparse(resolved)
            except Exception:
                continue

            res_scheme = (parsed_res.scheme or "").lower()
            if res_scheme not in ("http", "https"):
                continue

            res_host = (parsed_res.hostname or "").lower()

            # Same-Origin Policy (Requirement 10 & 36)
            if not is_same_site(res_host):
                if res_host:
                    external_domains.add(res_host)
                    if len(external_links) < 100:
                        external_links.append({
                            "url": resolved[:300],
                            "host": res_host,
                            "context": link_context,
                        })
                continue  # Never add external URLs to the internal crawl queue

            # Path verification
            path = parsed_res.path or "/"
            lower_path = path.lower()

            # Exclude static binary assets (.pdf, .jpg, .css, .js, .zip, etc.)
            if any(lower_path.endswith(ext) for ext in _STATIC_EXTENSIONS):
                continue

            # Anti-Trap / Recursive Loop Detection (Requirement 45 & 46)
            if self._is_path_trap(path):
                continue

            # URL Normalization (Requirement 9)
            norm_url = self._normalize_candidate_url(resolved)
            if not norm_url or norm_url in seen_normalized:
                continue
            seen_normalized.add(norm_url)

            clean_path = re.sub(r"/+", "/", parsed_res.path or "/")
            if clean_path != "/" and clean_path.endswith("/"):
                clean_path = clean_path[:-1]

            # Destructive Action Check (Requirement 30)
            is_destructive, block_reason = self._check_destructive_action(lower_path, parsed_res.query.lower())
            if is_destructive:
                blocked_actions.append({
                    "url": norm_url,
                    "path": clean_path,
                    "reason": block_reason,
                    "context": link_context,
                })
                continue

            # SSRF Protection on every discovered link (Requirement 11)
            ssrf = validate_url_safe(norm_url)
            if not ssrf.get("safe", True):
                continue

            # Priority & Classification
            priority = self._calculate_priority(clean_path)
            title = self._derive_title(clean_path, link_context)

            candidates.append({
                "url": norm_url,
                "canonical_url": norm_url,
                "path": clean_path,
                "title": title,
                "depth": current_depth + 1,
                "priority": priority,
                "reason": self._get_priority_reason(clean_path),
                "is_root": False,
                "parent_page_id": parent_page_id or "p_root",
                "discovered_from": current_url,
            })

        # Sort candidates descending by security priority score
        candidates.sort(key=lambda c: (c.get("depth", 0), -c.get("priority", 0)))

        return {
            "candidates": candidates[: self.max_pages],
            "blocked_actions": blocked_actions,
            "external_domains": sorted(list(external_domains)),
            "external_links": external_links,
        }

    def fetch_sitemap(self, origin_url: str) -> list[dict[str, Any]]:
        """
        Safely inspects /sitemap.xml and extracts valid same-origin candidate URLs (Requirement 34).
        Every sitemap entry is validated against same-origin policy and SSRF protection.
        """
        try:
            parsed = urlparse(origin_url)
            sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"

            # SSRF pre-check
            ssrf = validate_url_safe(sitemap_url)
            if not ssrf.get("safe", True):
                return []

            req = urllib.request.Request(
                sitemap_url,
                headers={"User-Agent": "PhishGuard-SafeView-Crawler/7.0 (Isolated Analysis)"},
            )
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                if resp.status != 200:
                    return []
                content_type = (resp.headers.get("Content-Type") or "").lower()
                if "html" in content_type and "xml" not in content_type:
                    return []  # Avoid HTML 404 pages returned as 200
                raw_xml = resp.read(256 * 1024)  # Limit to 256KB to prevent XML bombs

            # Parse XML safely without external entity expansion
            root = ET.fromstring(raw_xml)
            candidates: list[dict[str, Any]] = []

            # Handle both standard sitemap and sitemap index
            for loc in root.iter():
                if loc.tag.endswith("loc") and loc.text:
                    url = loc.text.strip()
                    if not url.startswith("http"):
                        continue
                    norm_url = self._normalize_candidate_url(url)
                    if not norm_url:
                        continue
                    p = urlparse(norm_url)
                    if p.netloc.lower() != parsed.netloc.lower():
                        continue
                    if any(p.path.lower().endswith(ext) for ext in _STATIC_EXTENSIONS):
                        continue
                    if self._is_path_trap(p.path):
                        continue

                    # SSRF check
                    if not validate_url_safe(norm_url).get("safe", True):
                        continue

                    clean_path = re.sub(r"/+", "/", p.path or "/")
                    if clean_path != "/" and clean_path.endswith("/"):
                        clean_path = clean_path[:-1]

                    candidates.append({
                        "url": norm_url,
                        "canonical_url": norm_url,
                        "path": clean_path,
                        "title": self._derive_title(clean_path, "Sitemap XML Entry"),
                        "depth": 1,
                        "priority": self._calculate_priority(clean_path),
                        "reason": "Discovered via /sitemap.xml",
                        "is_root": clean_path == "/",
                        "parent_page_id": "p_root",
                        "discovered_from": sitemap_url,
                    })

                    if len(candidates) >= 30:
                        break

            return candidates
        except Exception:
            return []

    def build_page_tree(self, pages: list[dict[str, Any]], root_page_id: str = "p_root") -> dict[str, Any]:
        """
        Builds a real hierarchical page tree from discovered pages (Requirement 19 & 28).
        Preserves true parent-child discovery relationships and path hierarchy.
        """
        if not pages:
            return {
                "page_id": "p_root",
                "title": "Home",
                "path": "/",
                "url": "",
                "depth": 0,
                "status": "AVAILABLE",
                "children": [],
            }

        # Index all pages by page_id and path
        by_id: dict[str, dict[str, Any]] = {}
        by_path: dict[str, str] = {}
        root_node = None

        for p in pages:
            pid = p.get("page_id", "")
            node = {
                "page_id": pid,
                "representation_id": p.get("representation_id") or pid,
                "url": p.get("url", ""),
                "path": p.get("path", "/"),
                "title": p.get("title") or p.get("path", "/"),
                "depth": p.get("depth", 0),
                "status": p.get("status", "AVAILABLE"),
                "http_status": p.get("http_status", 200),
                "risk_level": p.get("risk_level", "LOW"),
                "has_credentials": p.get("has_credentials", False),
                "forms_count": p.get("forms_count", 0),
                "is_root": p.get("is_root", False) or pid == root_page_id,
                "parent_page_id": p.get("parent_page_id"),
                "children": [],
            }
            by_id[pid] = node
            by_path[node["path"]] = pid

            if node["is_root"] or pid == root_page_id:
                root_node = node

        if not root_node:
            root_node = next(iter(by_id.values()))

        # Connect children to their respective parents
        attached_ids: set[str] = {root_node["page_id"]}

        for pid, node in by_id.items():
            if pid == root_node["page_id"]:
                continue

            parent_id = node.get("parent_page_id")
            parent = by_id.get(parent_id) if parent_id else None

            # Fallback: infer parent from path segments
            if not parent:
                path = node["path"].strip("/")
                if "/" in path:
                    parent_path = "/" + "/".join(path.split("/")[:-1])
                    if parent_path in by_path and by_path[parent_path] in by_id:
                        parent = by_id[by_path[parent_path]]

            if not parent or parent["page_id"] == pid:
                parent = root_node

            parent["children"].append(node)
            attached_ids.add(pid)

        # Sort children by depth and path
        def _sort_tree(n: dict[str, Any]):
            n["children"].sort(key=lambda x: (x.get("depth", 0), x.get("path", "")))
            for child in n["children"]:
                _sort_tree(child)

        _sort_tree(root_node)
        return root_node

    def _is_path_trap(self, path: str) -> bool:
        """
        Detects recursive path traps, repetitive segments, and calendar explosions (Requirement 45).
        """
        segments = [s for s in path.strip("/").split("/") if s]
        if len(segments) > 7:
            return True  # Too deep, likely infinite crawler trap

        # Detect consecutive repeated segments: e.g. /product/product
        for i in range(len(segments) - 1):
            if segments[i].lower() == segments[i + 1].lower():
                return True

        # Detect alternating loops: e.g. /category/12/category/12
        if len(segments) >= 4:
            s_lower = [s.lower() for s in segments]
            if s_lower[-4:-2] == s_lower[-2:]:
                return True

        # Detect date/calendar traps: e.g. /calendar/2026/10/25/...
        if any(seg in ("calendar", "events", "archive", "date") for seg in segments):
            digits = sum(1 for seg in segments if seg.isdigit())
            if digits >= 3:
                return True

        return False

    def _check_destructive_action(self, lower_path: str, lower_query: str) -> tuple[bool, str]:
        """Classifies endpoints that perform state changes, payment, logout, or deletion."""
        for kw in _BLOCKED_ACTION_KEYWORDS:
            if kw in lower_path or kw in lower_query:
                return True, f"Blocked potentially destructive action endpoint ('{kw}')"
        return False, ""

    def _normalize_candidate_url(self, raw_url: str) -> Optional[str]:
        """
        Normalizes URL for strict deduplication, removing tracking queries and trailing slashes (Requirement 9).
        """
        try:
            parsed = urlparse(raw_url)
            scheme = (parsed.scheme or "http").lower()
            host = (parsed.hostname or "").lower().rstrip(".")
            port = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""

            # Normalize multiple slashes to single
            path = re.sub(r"/+", "/", parsed.path or "/")
            if path != "/" and path.endswith("/"):
                path = path[:-1]

            # Filter query parameters — strip tracking tokens (utm_*, fbclid, etc.)
            clean_query = ""
            if parsed.query:
                qs = parse_qs(parsed.query, keep_blank_values=False)
                filtered_qs = {k: v for k, v in qs.items() if k.lower() not in _IGNORED_QUERY_PARAMS}
                if filtered_qs:
                    clean_query = "?" + urlencode(filtered_qs, doseq=True)

            return f"{scheme}://{host}{port}{path}{clean_query}"
        except Exception:
            return None

    def _calculate_priority(self, path: str) -> int:
        """Assigns priority weight based on security significance."""
        p_lower = path.lower()
        if p_lower == "/" or p_lower == "":
            return 100
        if any(k in p_lower for k in _AUTH_KEYWORDS):
            return 80  # Highest priority — credential/login surfaces
        if any(k in p_lower for k in _INFO_KEYWORDS):
            return 50  # High priority — institutional/about/contact surfaces
        depth = len([seg for seg in path.split("/") if seg])
        if depth <= 1:
            return 40
        if depth <= 2:
            return 25
        return 10

    def _get_priority_reason(self, path: str) -> str:
        p_lower = path.lower()
        if any(k in p_lower for k in _AUTH_KEYWORDS):
            return "Authentication / Credential harvesting target"
        if any(k in p_lower for k in _INFO_KEYWORDS):
            return "Informational / Brand support surface"
        return "Internal same-site navigation link"

    def _derive_title(self, path: str, link_context: str) -> str:
        """Derives a human-readable title for discovered pages."""
        if link_context and link_context not in ("Navigation Link", "Document Link", "Anchor Link", "DOM Link", "SPA Router Route", "Form Action Destination", "Client-Side Route", "SPA Route Config", "Sitemap XML Entry"):
            return link_context[:45]

        clean_path = path.strip("/")
        if not clean_path:
            return "Home"

        # e.g. /verify/account -> "Verify - Account"
        segments = [s.replace("-", " ").replace("_", " ").title() for s in clean_path.split("/") if s]
        return " - ".join(segments[:2])


# Global page discovery engine singleton
page_discovery_engine = PageDiscoveryEngine()
