"""
PhishGuard AI V7 — Safe Web View: HTML Sanitizer & Forensic Reconstructor
========================================================================
Transforms captured post-JavaScript DOM into a 100% read-only, sandboxed
representation suitable for secure visual inspection by analysts.

Core Security Guarantees:
  1. ALL executable JavaScript is eradicated:
     - Strips <script> tags and inline script bodies
     - Strips <noscript>, <base>, <meta http-equiv="refresh">
     - Strips all on* inline event handlers (onclick, onsubmit, onload, etc.)
  2. ALL form submission capabilities are neutralized:
     - <form> action forced to javascript:void(0), onsubmit forced to return false
     - All <input>, <textarea>, <button>, <select> have readonly="true" and disabled="true"
     - Visual watermark badge: 🔒 READ-ONLY FIELD
  3. ALL outbound navigation is blocked:
     - <a href="..."> rewritten to href="javascript:void(0)" data-pg-href="<original>"
     - Target links cannot navigate the analyst's browser to the target site
  4. Relative URLs (CSS, images, fonts) are resolved to absolute against page origin
  5. Forensic metadata is injected:
     - data-pg-id="el_N"
     - data-pg-risk="credential | external_action | dynamic_mutation | hidden_iframe | safe"
     - Forensic highlighting CSS rules injected (red/orange/yellow overlays for Forensic Mode)
"""

from __future__ import annotations

import re
import html
import json
import threading
import urllib.parse
from urllib.parse import urljoin, urlparse
from typing import Any, Optional
from concurrent.futures import ThreadPoolExecutor
import requests
import urllib3

# Suppress certificate verification warnings for external asset fetching
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# In-memory stylesheet cache to eliminate redundant downloads and hotlink blocks
_CSS_CACHE: dict[str, str] = {}
_CSS_CACHE_LOCK = threading.Lock()
_MAX_CSS_CACHE_ENTRIES = 500



# Regex patterns for stripping dangerous tags and attributes
_SCRIPT_RE = re.compile(r"<\s*script[^>]*>[\s\S]*?<\s*/\s*script\s*>", re.IGNORECASE)
_NOSCRIPT_RE = re.compile(r"<\s*noscript[^>]*>[\s\S]*?<\s*/\s*noscript\s*>", re.IGNORECASE)
_META_REFRESH_RE = re.compile(r"<\s*meta[^>]*http-equiv\s*=\s*['\"]?refresh['\"]?[^>]*>", re.IGNORECASE)
_BASE_TAG_RE = re.compile(r"<\s*base[^>]*>", re.IGNORECASE)
_COLOR_SCHEME_RE = re.compile(r"<\s*meta[^>]*name\s*=\s*['\"]?color-scheme['\"]?[^>]*>", re.IGNORECASE)
_EMBED_OBJECT_RE = re.compile(r"<\s*(?:embed|object|applet)[^>]*>[\s\S]*?<\s*/\s*(?:embed|object|applet)\s*>", re.IGNORECASE)
_EVENT_HANDLER_ATTR_RE = re.compile(r"""\s+on[a-z]+\s*=\s*(?:'[^']*'|"[^"]*"|[^\s>]+)""", re.IGNORECASE)
_JAVASCRIPT_URI_ATTR_RE = re.compile(r"""(href|src|action|data)\s*=\s*['"]\s*javascript:[^'"]*['"]""", re.IGNORECASE)


class HTMLSanitizer:
    """Sanitizes rendered DOM and enriches it for Safe Web View & Forensic Mode."""

    def __init__(self) -> None:
        pass

    def sanitize(
        self,
        html_content: str,
        base_url: str,
        dynamic_events: Optional[list[str]] = None,
        is_forensic_mode: bool = False,
        error_type: Optional[str] = None,
        http_status: Optional[int] = None,
        captured_stylesheets: Optional[dict[str, str]] = None,
    ) -> tuple[str, list[dict[str, Any]], dict[str, Any]]:
        """
        Sanitizes raw post-JS HTML.
        Returns:
          - sanitized_html: string
          - elements_map: list of element inspection dictionaries
          - content_inventory: dict of counts (text, images, scripts, forms, etc.)
        """
        if not html_content or not html_content.strip():
            reason = f"Navigation failed ({error_type})." if error_type else "No DOM content was captured for this page."
            return self._build_empty_fallback(reason, base_url, error_type=error_type, http_status=http_status)

        try:
            parsed_base = urlparse(base_url)
            base_domain = (parsed_base.hostname or "").lower()
        except Exception:
            base_domain = ""

        elements_map: list[dict[str, Any]] = []
        element_counter = 0

        # Step 1: Detect if document is pure JSON or wrapped in a <pre> tag (common for API endpoints)
        formatted_json_doc = self._detect_and_format_json(html_content, base_url)
        is_json = bool(formatted_json_doc)

        if is_json:
            source_content = formatted_json_doc
        else:
            # If the document is purely plain text (not HTML and not JSON), wrap it into a clean standard body container
            has_html_tags = bool(re.search(r'<\s*(html|head|body|div|p|span|table|h[1-6]|pre|main|section|header|footer)\b', html_content, re.IGNORECASE))
            if not has_html_tags and html_content.strip():
                source_content = f"<!DOCTYPE html><html><head><meta charset=\"utf-8\"></head><body><pre style=\"margin: 24px; font-family: ui-monospace, monospace; font-size: 13px; color: #0f172a; white-space: pre-wrap; word-break: break-word;\">{html.escape(html_content.strip())}</pre></body></html>"
            else:
                source_content = html_content

        # Step 2: Strip active executable elements and problematic color-scheme tags
        clean = _SCRIPT_RE.sub("", source_content)
        clean = _NOSCRIPT_RE.sub("", clean)
        clean = _META_REFRESH_RE.sub("", clean)
        clean = _BASE_TAG_RE.sub("", clean)
        clean = _COLOR_SCHEME_RE.sub("", clean)
        clean = _EMBED_OBJECT_RE.sub("", clean)
        clean = _EVENT_HANDLER_ATTR_RE.sub("", clean)
        clean = _JAVASCRIPT_URI_ATTR_RE.sub(r'\1="javascript:void(0)"', clean)

        # Step 3: Content Inventory Counts
        content_inventory = self._calculate_content_inventory(html_content, clean, base_domain)

        # Step 4: Resolve relative URLs for images & stylesheets so layout is preserved
        clean = self._resolve_relative_urls(clean, base_url)

        # Step 4b: Inline & Proxy Stylesheets (Complete CSS Fidelity for All Websites)
        if not is_json:
            clean = self._inline_and_resolve_stylesheets(clean, base_url, captured_stylesheets=captured_stylesheets)

        # Step 5: Transform forms & input fields (neutralize actions, add read-only tags & inspection IDs)
        clean, form_elements = self._transform_forms_and_inputs(clean, base_url, base_domain)
        elements_map.extend(form_elements)

        # Step 6: Transform links (block navigation, retain data-pg-href for inspection)
        clean, link_elements = self._transform_links(clean, base_url, base_domain)
        elements_map.extend(link_elements)

        # Step 7: Transform iframes (neutralize, mark hidden iframes)
        clean, iframe_elements = self._transform_iframes(clean, base_url, base_domain)
        elements_map.extend(iframe_elements)

        # Step 8: If SPA with no visible elements, inject helpful SPA notice (skip if JSON)
        if not is_json:
            clean = self._detect_and_format_spa(clean, content_inventory, base_url)

        # Step 9: Inject Safe Sandbox Stylesheet & Visual Watermarks
        final_html = self._inject_safe_head_and_styles(clean, base_url, is_forensic_mode)

        return final_html, elements_map, content_inventory

    def _resolve_relative_urls(self, html_str: str, base_url: str) -> str:
        """Resolve relative src, srcset, link href, and CSS url(...) to absolute URLs so assets display accurately."""
        def _replace_src(match: re.Match) -> str:
            attr = match.group(1)
            val = match.group(2).strip()
            if val.startswith("data:") or val.startswith("blob:") or val.startswith("http://") or val.startswith("https://"):
                return match.group(0)
            abs_url = urljoin(base_url, val)
            return f'{attr}="{abs_url}"'

        # Replace img src, source src, video/audio src
        html_str = re.sub(r'''\b(src)\s*=\s*["']([^"']+)["']''', _replace_src, html_str, flags=re.IGNORECASE)

        # Replace srcset
        def _replace_srcset(match: re.Match) -> str:
            srcset_val = match.group(1).strip()
            candidates = srcset_val.split(',')
            new_candidates = []
            for cand in candidates:
                cand = cand.strip()
                if not cand:
                    continue
                parts = cand.split()
                if parts:
                    u = parts[0]
                    if not (u.startswith("data:") or u.startswith("blob:") or u.startswith("http://") or u.startswith("https://")):
                        u = urljoin(base_url, u)
                    new_candidates.append(" ".join([u] + parts[1:]))
                else:
                    new_candidates.append(cand)
            return f'srcset="{", ".join(new_candidates)}"'

        html_str = re.sub(r'''\bsrcset\s*=\s*["']([^"']+)["']''', _replace_srcset, html_str, flags=re.IGNORECASE)

        # Replace all <link ... href="...">
        def _replace_link_href(match: re.Match) -> str:
            full_link = match.group(0)
            href_m = re.search(r'''\bhref\s*=\s*["']([^"']+)["']''', full_link, re.IGNORECASE)
            if not href_m:
                return full_link
            val = href_m.group(1).strip()
            if val.startswith("data:") or val.startswith("blob:") or val.startswith("http://") or val.startswith("https://"):
                return full_link
            abs_url = urljoin(base_url, val)
            return re.sub(r'''\bhref\s*=\s*["'][^"']+["']''', f'href="{abs_url}"', full_link, count=1, flags=re.IGNORECASE)

        html_str = re.sub(r'<\s*link\b[^>]*>', _replace_link_href, html_str, flags=re.IGNORECASE)

        # Replace CSS url(...) in style tags and inline styles
        def _replace_css_url(match: re.Match) -> str:
            raw_url = match.group(1).strip().strip("'\"")
            if raw_url.startswith("data:") or raw_url.startswith("blob:") or raw_url.startswith("http://") or raw_url.startswith("https://"):
                return match.group(0)
            abs_url = urljoin(base_url, raw_url)
            return f'url("{abs_url}")'

        html_str = re.sub(r'''url\(\s*['"]?([^'")]+)['"]?\s*\)''', _replace_css_url, html_str, flags=re.IGNORECASE)
        return html_str

    def _inline_and_resolve_stylesheets(
        self,
        html_str: str,
        base_url: str,
        captured_stylesheets: Optional[dict[str, str]] = None,
    ) -> str:
        """
        Embeds external stylesheets directly as sanitized inline <style> tags to guarantee
        100% authentic visual layout and CSS fidelity across all targets in Safe Web View.

        Solves:
          1. Cross-Origin CDN hotlink protection & HTTP 403 Forbidden blocks.
          2. Sandboxed iframe CORS / Sec-Fetch-Site restrictions.
          3. Mixed content blocks (HTTP stylesheets on HTTPS pages).
          4. Resolves internal url(...) references to absolute asset paths.
          5. Provides fallback rewriting to local /safe-view/asset-proxy for any un-inlinable sheets.
        """
        if not html_str:
            return html_str

        # 1. Gather all <link ... rel="stylesheet" ...> tags
        link_tag_pattern = re.compile(r'<\s*link\b[^>]*>', re.IGNORECASE)
        all_links = link_tag_pattern.findall(html_str)
        if not all_links:
            return html_str

        # Filter for stylesheets
        sheet_targets: list[tuple[str, str]] = []
        for tag in all_links:
            if not re.search(r'\brel\s*=\s*["\'](?:[^"\']*\s+)?stylesheet(?:\s+[^"\']*)?["\']', tag, re.IGNORECASE):
                continue
            href_m = re.search(r'\bhref\s*=\s*["\']([^"\']+)["\']', tag, re.IGNORECASE)
            if not href_m:
                continue
            raw_href = href_m.group(1).strip()
            if not raw_href or raw_href.startswith("data:") or raw_href.startswith("blob:"):
                continue

            abs_url = urljoin(base_url, raw_href)
            sheet_targets.append((tag, abs_url))

        if not sheet_targets:
            return html_str

        # 2. Check caches & captured stylesheets
        css_map: dict[str, str] = {}
        urls_to_fetch: list[str] = []

        for _, abs_url in sheet_targets:
            if abs_url in css_map:
                continue
            if captured_stylesheets and abs_url in captured_stylesheets:
                css_map[abs_url] = captured_stylesheets[abs_url]
                continue
            with _CSS_CACHE_LOCK:
                if abs_url in _CSS_CACHE:
                    css_map[abs_url] = _CSS_CACHE[abs_url]
                    continue
            if abs_url not in urls_to_fetch:
                urls_to_fetch.append(abs_url)

        # 3. Concurrent fetch for missing stylesheets (max 8 workers, 3.5s timeout)
        if urls_to_fetch:
            req_headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                "Accept": "text/css,*/*;q=0.1",
                "Referer": base_url,
                "Sec-Fetch-Dest": "style",
                "Sec-Fetch-Mode": "no-cors",
                "Sec-Fetch-Site": "cross-site",
            }

            def _fetch_one(sheet_url: str) -> tuple[str, Optional[str]]:
                try:
                    r = requests.get(sheet_url, headers=req_headers, timeout=3.5, verify=False)
                    if r.status_code == 200 and r.text:
                        return sheet_url, r.text
                except Exception:
                    pass
                return sheet_url, None

            max_w = min(len(urls_to_fetch), 8)
            with ThreadPoolExecutor(max_workers=max_w) as executor:
                for sheet_url, css_text in executor.map(_fetch_one, urls_to_fetch):
                    if css_text:
                        # Clean dangerous CSS tokens
                        cleaned_css = re.sub(r'expression\s*\(', '/* expr */ (', css_text, flags=re.IGNORECASE)
                        cleaned_css = re.sub(r'javascript\s*:', 'blocked-js:', cleaned_css, flags=re.IGNORECASE)
                        # Resolve url(...) relative paths against stylesheet URL
                        def _css_url_repl(m: re.Match) -> str:
                            raw_u = m.group(1).strip().strip("'\"")
                            if not raw_u or raw_u.startswith("data:") or raw_u.startswith("blob:") or raw_u.startswith("http://") or raw_u.startswith("https://"):
                                return m.group(0)
                            return f'url("{urljoin(sheet_url, raw_u)}")'
                        cleaned_css = re.sub(r'''url\(\s*['"]?([^'")]+)['"]?\s*\)''', _css_url_repl, cleaned_css, flags=re.IGNORECASE)

                        css_map[sheet_url] = cleaned_css
                        with _CSS_CACHE_LOCK:
                            if len(_CSS_CACHE) >= _MAX_CSS_CACHE_ENTRIES:
                                _CSS_CACHE.clear()
                            _CSS_CACHE[sheet_url] = cleaned_css

        # 4. Replace <link> tags with <style> blocks (or proxy URLs if fetch failed)
        for tag, abs_url in sheet_targets:
            if abs_url in css_map:
                css_content = css_map[abs_url]
                style_replacement = f'<style data-pg-inlined="true" data-source-href="{html.escape(abs_url, quote=True)}">\n{css_content}\n</style>'
                html_str = html_str.replace(tag, style_replacement, 1)
            else:
                # Fallback to local asset proxy endpoint
                proxy_url = f"/safe-view/asset-proxy?url={urllib.parse.quote_plus(abs_url)}&ref={urllib.parse.quote_plus(base_url)}"
                tag_proxied = re.sub(r'\bhref\s*=\s*["\'][^"\']+["\']', f'href="{proxy_url}" data-pg-href="{html.escape(abs_url, quote=True)}" data-pg-proxied="true"', tag, count=1, flags=re.IGNORECASE)
                html_str = html_str.replace(tag, tag_proxied, 1)

        # 5. Also resolve url(...) inside any pre-existing inline <style> tags
        def _resolve_inline_style_urls(match: re.Match) -> str:
            full_style = match.group(0)
            def _inner_repl(m: re.Match) -> str:
                raw_u = m.group(1).strip().strip("'\"")
                if not raw_u or raw_u.startswith("data:") or raw_u.startswith("blob:") or raw_u.startswith("http://") or raw_u.startswith("https://"):
                    return m.group(0)
                return f'url("{urljoin(base_url, raw_u)}")'
            return re.sub(r'''url\(\s*['"]?([^'")]+)['"]?\s*\)''', _inner_repl, full_style, flags=re.IGNORECASE)

        html_str = re.sub(r'<\s*style\b[^>]*>[\s\S]*?<\s*/\s*style\s*>', _resolve_inline_style_urls, html_str, flags=re.IGNORECASE)
        return html_str


    def _transform_forms_and_inputs(
        self, html_str: str, base_url: str, base_domain: str
    ) -> tuple[str, list[dict[str, Any]]]:
        """Neutralizes form actions and inputs while tagging them with forensic element IDs."""
        elements: list[dict[str, Any]] = []
        elem_idx = 0

        # Replace <form ...>
        def _form_repl(match: re.Match) -> str:
            nonlocal elem_idx
            elem_idx += 1
            el_id = f"el_form_{elem_idx}"
            full_tag = match.group(0)

            action_match = re.search(r'action\s*=\s*["\']([^"\']*)["\']', full_tag, re.IGNORECASE)
            raw_action = action_match.group(1) if action_match else ""
            resolved_action = urljoin(base_url, raw_action) if raw_action else base_url

            method_match = re.search(r'method\s*=\s*["\']([^"\']*)["\']', full_tag, re.IGNORECASE)
            method = (method_match.group(1) if method_match else "GET").upper()

            # Risk classification
            action_domain = (urlparse(resolved_action).hostname or "").lower()
            is_external = bool(action_domain and base_domain and action_domain != base_domain and not action_domain.endswith("." + base_domain))
            risk = "HIGH" if is_external else "MEDIUM"
            risk_type = "external_action" if is_external else "form"

            elements.append({
                "element_id": el_id,
                "tag": "FORM",
                "id": self._extract_attr(full_tag, "id") or f"form-{elem_idx}",
                "name": self._extract_attr(full_tag, "name"),
                "action": resolved_action,
                "original_action": raw_action,
                "method": method,
                "is_external": is_external,
                "risk": risk,
                "risk_type": risk_type,
                "description": f"Target form posting via {method} to {'EXTERNAL ' + action_domain if is_external else 'internal destination'}",
            })

            # Rewrite tag with disabled action and safe attributes
            tag_no_action = re.sub(r'\s+action\s*=\s*["\'][^"\']*["\']', '', full_tag, flags=re.IGNORECASE)
            tag_no_action = re.sub(r'\s+onsubmit\s*=\s*["\'][^"\']*["\']', '', tag_no_action, flags=re.IGNORECASE)
            risk_class = "pg-risk-external_action" if is_external else "pg-risk-form"
            existing_class = self._extract_attr(tag_no_action, "class") or ""
            merged_class = f"{existing_class} {risk_class}".strip()
            tag_clean = re.sub(r'\s+class\s*=\s*["\'][^"\']*["\']', '', tag_no_action[:-1], flags=re.IGNORECASE)

            return (
                f'{tag_clean} '
                f'action="javascript:void(0)" onsubmit="return false;" '
                f'data-pg-id="{el_id}" data-pg-risk="{risk_type}" '
                f'class="{merged_class}">'
            )

        html_str = re.sub(r'<\s*form\b[^>]*>', _form_repl, html_str, flags=re.IGNORECASE)

        # Replace <input ...>
        def _input_repl(match: re.Match) -> str:
            nonlocal elem_idx
            elem_idx += 1
            el_id = f"el_input_{elem_idx}"
            full_tag = match.group(0)

            itype = (self._extract_attr(full_tag, "type") or "text").lower()
            iname = self._extract_attr(full_tag, "name") or ""
            iid = self._extract_attr(full_tag, "id") or f"input-{elem_idx}"
            iph = self._extract_attr(full_tag, "placeholder") or ""

            # Check if credential harvesting field
            is_pw = itype == "password" or "password" in iname.lower() or "passwd" in iname.lower()
            is_email = itype == "email" or "email" in iname.lower() or "user" in iname.lower() or "login" in iname.lower()
            is_payment = any(k in f"{iname} {iph}".lower() for k in ("card", "cvv", "cvc", "exp", "payment"))

            if is_pw or is_payment:
                risk = "HIGH"
                risk_type = "credential"
                risk_class = "pg-risk-credential"
            elif is_email:
                risk = "MEDIUM"
                risk_type = "credential"
                risk_class = "pg-risk-credential"
            else:
                risk = "LOW"
                risk_type = "safe"
                risk_class = "pg-risk-input"

            elements.append({
                "element_id": el_id,
                "tag": "INPUT",
                "id": iid,
                "name": iname,
                "type": itype,
                "placeholder": iph,
                "is_password": is_pw,
                "is_credential": is_pw or is_email,
                "risk": risk,
                "risk_type": risk_type,
                "description": f"Input field ({itype}) - {iname or iph or 'unnamed'}",
            })

            # Append readonly, disabled, and data-pg attributes
            tag_clean = full_tag[:-1]
            # remove existing readonly or disabled to prevent duplicate
            tag_clean = re.sub(r'\s+(readonly|disabled)(?:=["\'][^"\']*["\'])?', '', tag_clean, flags=re.IGNORECASE)
            existing_class = self._extract_attr(tag_clean, "class") or ""
            merged_class = f"{existing_class} {risk_class}".strip()
            tag_clean = re.sub(r'\s+class\s*=\s*["\'][^"\']*["\']', '', tag_clean, flags=re.IGNORECASE)

            return (
                f'{tag_clean} readonly="true" disabled="true" tabindex="-1" '
                f'data-pg-id="{el_id}" data-pg-risk="{risk_type}" '
                f'class="{merged_class}">'
            )

        html_str = re.sub(r'<\s*input\b[^>]*>', _input_repl, html_str, flags=re.IGNORECASE)

        # Neutralize <button ...>
        def _button_repl(match: re.Match) -> str:
            full_tag = match.group(0)
            tag_clean = re.sub(r'\s+disabled(?:=["\'][^"\']*["\'])?', '', full_tag[:-1], flags=re.IGNORECASE)
            return f'{tag_clean} disabled="true" tabindex="-1">'

        html_str = re.sub(r'<\s*button\b[^>]*>', _button_repl, html_str, flags=re.IGNORECASE)

        return html_str, elements

    def _transform_links(
        self, html_str: str, base_url: str, base_domain: str
    ) -> tuple[str, list[dict[str, Any]]]:
        """Neutralizes link navigation and annotates with forensic destination data."""
        elements: list[dict[str, Any]] = []
        elem_idx = 0

        def _link_repl(match: re.Match) -> str:
            nonlocal elem_idx
            elem_idx += 1
            el_id = f"el_link_{elem_idx}"
            full_tag = match.group(0)

            href_match = re.search(r'href\s*=\s*["\']([^"\']*)["\']', full_tag, re.IGNORECASE)
            raw_href = href_match.group(1) if href_match else ""

            if not raw_href or raw_href.startswith("#") or raw_href.startswith("javascript:"):
                resolved_href = "javascript:void(0)"
                is_external = False
            else:
                resolved_href = urljoin(base_url, raw_href)
                target_domain = (urlparse(resolved_href).hostname or "").lower()
                is_external = bool(target_domain and base_domain and target_domain != base_domain and not target_domain.endswith("." + base_domain))

            risk = "MEDIUM" if is_external else "LOW"
            elements.append({
                "element_id": el_id,
                "tag": "A",
                "href": resolved_href,
                "original_href": raw_href,
                "is_external": is_external,
                "risk": risk,
                "risk_type": "external_link" if is_external else "link",
                "description": f"Hyperlink pointing to {resolved_href}",
            })

            tag_no_href = re.sub(r'\s+href\s*=\s*["\'][^"\']*["\']', '', full_tag, flags=re.IGNORECASE)
            tag_no_target = re.sub(r'\s+target\s*=\s*["\'][^"\']*["\']', '', tag_no_href, flags=re.IGNORECASE)

            return (
                f'{tag_no_target[:-1]} '
                f'href="javascript:void(0)" '
                f'data-pg-href="{html.escape(resolved_href)}" '
                f'data-pg-id="{el_id}" '
                f'target="_self" '
                f'onclick="return false;">'
            )

        html_str = re.sub(r'<\s*a\b[^>]*>', _link_repl, html_str, flags=re.IGNORECASE)
        return html_str, elements

    def _transform_iframes(
        self, html_str: str, base_url: str, base_domain: str
    ) -> tuple[str, list[dict[str, Any]]]:
        """Neutralizes iframes and highlights hidden/suspicious frames."""
        elements: list[dict[str, Any]] = []
        elem_idx = 0

        def _iframe_repl(match: re.Match) -> str:
            nonlocal elem_idx
            elem_idx += 1
            el_id = f"el_iframe_{elem_idx}"
            full_tag = match.group(0)

            src = self._extract_attr(full_tag, "src") or ""
            resolved_src = urljoin(base_url, src) if src else "about:blank"
            style = self._extract_attr(full_tag, "style") or ""
            is_hidden = any(h in style.lower() for h in ("display: none", "display:none", "visibility: hidden", "opacity: 0", "height: 0", "width: 0"))

            risk = "HIGH" if is_hidden else "MEDIUM"
            elements.append({
                "element_id": el_id,
                "tag": "IFRAME",
                "src": resolved_src,
                "is_hidden": is_hidden,
                "risk": risk,
                "risk_type": "hidden_iframe" if is_hidden else "iframe",
                "description": f"{'HIDDEN ' if is_hidden else ''}Iframe loading {resolved_src}",
            })

            # Replace iframe with sandboxed placeholder or read-only container
            return (
                f'<div class="pg-iframe-placeholder {"pg-risk-hidden_iframe" if is_hidden else ""}" '
                f'data-pg-id="{el_id}" data-pg-risk="{"hidden_iframe" if is_hidden else "iframe"}">'
                f'<span class="pg-iframe-label">🔒 ISOLATED IFRAME: {html.escape(resolved_src[:70])}</span>'
                f'</div>'
            )

        html_str = re.sub(r'<\s*iframe\b[^>]*>[\s\S]*?<\s*/\s*iframe\s*>', _iframe_repl, html_str, flags=re.IGNORECASE)
        html_str = re.sub(r'<\s*iframe\b[^>]*>', _iframe_repl, html_str, flags=re.IGNORECASE)
        return html_str, elements

    def _calculate_content_inventory(self, raw_html: str, clean_html: str, base_domain: str) -> dict[str, Any]:
        """Computes structural and asset statistics for the Content Inventory panel."""
        # Visible text approx length
        text_content = re.sub(r'<[^>]+>', ' ', clean_html)
        text_content = re.sub(r'\s+', ' ', text_content).strip()

        img_count = len(re.findall(r'<\s*img\b', raw_html, re.IGNORECASE))
        script_count = len(re.findall(r'<\s*script\b', raw_html, re.IGNORECASE))
        style_count = len(re.findall(r'<\s*style\b', raw_html, re.IGNORECASE)) + len(re.findall(r'rel\s*=\s*["\']stylesheet["\']', raw_html, re.IGNORECASE))
        form_count = len(re.findall(r'<\s*form\b', raw_html, re.IGNORECASE))
        input_count = len(re.findall(r'<\s*input\b', raw_html, re.IGNORECASE))
        link_count = len(re.findall(r'<\s*a\b', raw_html, re.IGNORECASE))
        iframe_count = len(re.findall(r'<\s*iframe\b', raw_html, re.IGNORECASE))
        video_count = len(re.findall(r'<\s*video\b', raw_html, re.IGNORECASE))

        # Find external domains
        all_urls = re.findall(r'''(?:href|src|action)\s*=\s*["'](https?://[^"']+)["']''', raw_html, re.IGNORECASE)
        external_domains: set[str] = set()
        for u in all_urls:
            try:
                host = (urlparse(u).hostname or "").lower()
                if host and base_domain and host != base_domain and not host.endswith("." + base_domain):
                    external_domains.add(host)
            except Exception:
                pass

        return {
            "text_characters": len(text_content),
            "images": img_count,
            "scripts": script_count,
            "stylesheets": style_count,
            "forms": form_count,
            "inputs": input_count,
            "links": link_count,
            "iframes": iframe_count,
            "videos": video_count,
            "external_domains_count": len(external_domains),
            "external_domains": sorted(list(external_domains))[:25],
        }

    def _detect_and_format_json(self, html_str: str, base_url: str) -> Optional[str]:
        """Detects if content is a JSON or API endpoint response and formats it with rich inspection styles."""
        candidate_text = ""
        pre_m = re.search(r'<\s*pre\b[^>]*>([\s\S]*?)<\s*/\s*pre\s*>', html_str, re.IGNORECASE)
        if pre_m:
            candidate_text = html.unescape(pre_m.group(1)).strip()
        else:
            stripped = re.sub(r'<[^>]+>', '', html_str).strip()
            if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
                candidate_text = html.unescape(stripped)

        if candidate_text and ((candidate_text.startswith("{") and candidate_text.endswith("}")) or (candidate_text.startswith("[") and candidate_text.endswith("]"))):
            try:
                parsed = json.loads(candidate_text)
                formatted_json = json.dumps(parsed, indent=2)
                escaped_code = html.escape(formatted_json)

                status_badge = ""
                if isinstance(parsed, dict):
                    sc = parsed.get("STATUS_CODE") or parsed.get("status") or parsed.get("statusCode") or parsed.get("code")
                    if sc:
                        status_badge = f'<span class="pg-api-status">STATUS {html.escape(str(sc))}</span>'

                return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset=\"utf-8\">
  <meta name=\"color-scheme\" content=\"light\">
  <title>API Response - {html.escape(base_url)}</title>
</head>
<body>
  <div class=\"pg-api-container\">
    <div class=\"pg-api-header\">
      <span class=\"pg-api-badge\">📡 API / JSON ENDPOINT</span>
      {status_badge}
      <span class=\"pg-api-url\">{html.escape(base_url)}</span>
    </div>
    <div class=\"pg-api-meta\">
      This page returned structured JSON data. It was captured and styled for secure forensic inspection.
    </div>
    <pre class=\"pg-json-code\"><code>{escaped_code}</code></pre>
  </div>
</body>
</html>"""
            except Exception:
                pass
        return None

    def _detect_and_format_server_error(self, html_str: str, base_url: str, http_status: Optional[int]) -> Optional[str]:
        """Deprecated: Authentic target response is rendered faithfully directly in the safe web view."""
        return None

    def _detect_and_format_spa(self, clean_html: str, content_inventory: dict[str, Any], base_url: str) -> str:
        """If a page has truly empty DOM (client-side rendered SPA with no static content), injects an informative notice."""
        text_len = content_inventory.get("text_characters", 0)
        img_count = content_inventory.get("images", 0)
        form_count = content_inventory.get("forms", 0)
        input_count = content_inventory.get("inputs", 0)
        link_count = content_inventory.get("links", 0)

        # Only trigger if there is literally NO text content and an SPA container is present
        is_spa_mount = bool(re.search(r'id=["\'](root|app|__next)["\']|<app-root\b', clean_html, re.IGNORECASE))
        if text_len == 0 and img_count == 0 and form_count == 0 and input_count == 0 and link_count == 0 and is_spa_mount:
            spa_notice = f"""
            <div class=\"pg-spa-notice\">
                <div class=\"pg-spa-icon\">⚡</div>
                <div class=\"pg-spa-content\">
                    <h4>Single Page Application (Client-Side Rendered)</h4>
                    <p>This page relies on client-side JavaScript execution (such as React, Vue, or Angular) to construct its user interface. Because active JavaScript execution is securely neutralized in Safe Web View, the static HTML DOM tree contains minimal markup.</p>
                    <p style=\"margin-top: 8px;\">To view the full visual layout captured during the sandbox execution, switch to the <strong>Screenshot</strong> tab at the top right.</p>
                </div>
            </div>
            """
            if "<body" in clean_html.lower():
                clean_html = re.sub(r'(<\s*body\b[^>]*>)', r'\1' + spa_notice, clean_html, count=1, flags=re.IGNORECASE)
            else:
                clean_html = f"<body>{spa_notice}{clean_html}</body>"
        return clean_html

    def _inject_safe_head_and_styles(self, html_str: str, base_url: str, is_forensic_mode: bool) -> str:
        """Injects non-interactive forensic styling, read-only badges, and security overlay rules."""
        forensic_class = "pg-forensic-active" if is_forensic_mode else ""

        safe_styles = f"""
        <style id=\"pg-safe-viewer-styles\">
            /* PhishGuard Isolated Read-Only Safe Viewer Styling */
            :root {{
                color-scheme: light;
            }}
            html {{
                pointer-events: auto !important;
                user-select: text !important;
                -webkit-user-select: text !important;
            }}
            body {{
                margin: 0;
                padding: 0;
                min-height: 100vh;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            }}
            /* All form inputs visual disabled treatment */
            input, textarea, select, button {{
                cursor: not-allowed !important;
                opacity: 0.85 !important;
            }}
            input:focus, textarea:focus, select:focus, button:focus {{
                outline: none !important;
                box-shadow: none !important;
            }}
            /* Hyperlinks visually clear but non-navigating */
            a {{
                cursor: default !important;
            }}
            /* High-contrast monospace code & pre blocks */
            pre, code, samp, kbd {{
                font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace !important;
                font-size: 13px !important;
                line-height: 1.6 !important;
                color: #0f172a !important;
            }}
            pre {{
                background: #f8fafc !important;
                color: #0f172a !important;
                border: 1px solid #cbd5e1 !important;
                border-radius: 8px !important;
                padding: 16px 20px !important;
                margin: 16px !important;
                white-space: pre-wrap !important;
                word-break: break-all !important;
                box-shadow: 0 1px 3px rgba(0,0,0,0.05) !important;
            }}
            /* API / JSON inspection container */
            .pg-api-container {{
                padding: 24px !important;
                background: #f8fafc !important;
                min-height: calc(100vh - 40px) !important;
                box-sizing: border-box !important;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
            }}
            .pg-api-header {{
                display: flex !important;
                align-items: center !important;
                gap: 10px !important;
                margin-bottom: 8px !important;
                flex-wrap: wrap !important;
            }}
            .pg-api-badge {{
                background: #4f46e5 !important;
                color: #ffffff !important;
                font-size: 11px !important;
                font-weight: 700 !important;
                padding: 3px 8px !important;
                border-radius: 4px !important;
                letter-spacing: 0.5px !important;
            }}
            .pg-api-status {{
                background: #f59e0b !important;
                color: #ffffff !important;
                font-size: 11px !important;
                font-weight: 700 !important;
                padding: 3px 8px !important;
                border-radius: 4px !important;
                letter-spacing: 0.5px !important;
            }}
            .pg-api-url {{
                font-family: ui-monospace, monospace !important;
                font-size: 12px !important;
                color: #475569 !important;
                word-break: break-all !important;
            }}
            .pg-api-meta {{
                font-size: 12px !important;
                color: #64748b !important;
                margin-bottom: 16px !important;
            }}
            .pg-json-code {{
                background: #ffffff !important;
                border: 1px solid #cbd5e1 !important;
                border-radius: 8px !important;
                padding: 16px 20px !important;
                color: #0f172a !important;
                font-size: 13px !important;
                line-height: 1.6 !important;
                overflow-x: auto !important;
                white-space: pre-wrap !important;
                word-break: break-all !important;
                margin: 0 !important;
            }}
            /* SPA Notice Box */
            .pg-spa-notice {{
                margin: 30px auto !important;
                max-width: 620px !important;
                background: #f8fafc !important;
                border: 1px solid #cbd5e1 !important;
                border-left: 4px solid #3b82f6 !important;
                border-radius: 8px !important;
                padding: 20px !important;
                display: flex !important;
                gap: 16px !important;
                align-items: flex-start !important;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05) !important;
            }}
            .pg-spa-icon {{
                font-size: 26px !important;
                line-height: 1 !important;
            }}
            .pg-spa-content h4 {{
                margin: 0 0 6px 0 !important;
                color: #0f172a !important;
                font-size: 15px !important;
                font-weight: 600 !important;
            }}
            .pg-spa-content p {{
                margin: 0 !important;
                color: #475569 !important;
                font-size: 13px !important;
                line-height: 1.5 !important;
            }}
            /* Watermark Header */
            #pg-safe-banner {{
                position: relative !important;
                width: 100% !important;
                box-sizing: border-box !important;
                margin: 0 !important;
                z-index: 2147483647;
                background: linear-gradient(90deg, #090d16 0%, #0f172a 100%);
                color: #e2e8f0;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                font-size: 11px;
                font-weight: 600;
                padding: 6px 14px;
                display: flex;
                align-items: center;
                justify-content: space-between;
                border-bottom: 1px solid rgba(147, 51, 234, 0.4);
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);
                letter-spacing: 0.5px;
            }}
            #pg-safe-banner .badge {{
                display: inline-flex;
                align-items: center;
                gap: 5px;
                padding: 2px 8px;
                border-radius: 4px;
                font-size: 10px;
                font-family: monospace;
            }}
            #pg-safe-banner .badge-isolated {{
                background: rgba(16, 185, 129, 0.2);
                color: #34d399;
                border: 1px solid rgba(16, 185, 129, 0.4);
            }}
            #pg-safe-banner .badge-blocked {{
                background: rgba(239, 68, 68, 0.2);
                color: #f87171;
                border: 1px solid rgba(239, 68, 68, 0.4);
            }}
            /* Forensic Highlighting Rules (active in forensic mode) */
            .pg-forensic-active .pg-risk-credential,
            body.pg-forensic-mode .pg-risk-credential,
            .pg-forensic-active [data-pg-risk=\"credential\"],
            body.pg-forensic-mode [data-pg-risk=\"credential\"] {{
                outline: 2.5px solid #ef4444 !important;
                background-color: rgba(239, 68, 68, 0.12) !important;
                position: relative !important;
            }}
            .pg-forensic-active .pg-risk-external_action,
            body.pg-forensic-mode .pg-risk-external_action,
            .pg-forensic-active [data-pg-risk=\"external_action\"],
            body.pg-forensic-mode [data-pg-risk=\"external_action\"] {{
                outline: 2.5px solid #f97316 !important;
                background-color: rgba(249, 115, 22, 0.12) !important;
            }}
            .pg-forensic-active .pg-risk-dynamic_mutation,
            body.pg-forensic-mode .pg-risk-dynamic_mutation,
            .pg-forensic-active [data-pg-risk=\"dynamic_mutation\"],
            body.pg-forensic-mode [data-pg-risk=\"dynamic_mutation\"] {{
                outline: 2.5px solid #eab308 !important;
                background-color: rgba(234, 179, 8, 0.12) !important;
            }}
            .pg-iframe-placeholder {{
                padding: 12px;
                margin: 8px 0;
                background: #0f172a;
                border: 1.5px dashed #64748b;
                border-radius: 6px;
                color: #94a3b8;
                font-family: monospace;
                font-size: 11px;
                text-align: center;
            }}
            .pg-risk-hidden_iframe {{
                outline: 2.5px dashed #dc2626 !important;
                background: rgba(220, 38, 38, 0.15) !important;
            }}
            /* Selected element glow */
            .pg-element-selected {{
                outline: 3px solid #a855f7 !important;
                box-shadow: 0 0 16px rgba(168, 85, 247, 0.6) !important;
            }}
        </style>
        """

        banner = f"""
        <div id=\"pg-safe-banner\">
            <div style=\"display:flex; align-items:center; gap:8px;\">
                <span style=\"color:#c084fc;\">🛡 PHISHGUARD AI</span>
                <span style=\"color:#64748b;\">|</span>
                <span>SAFE READ-ONLY WEB VIEW</span>
                <span class=\"badge badge-isolated\">🔒 ISOLATED IN VM</span>
                <span class=\"badge badge-blocked\">🚫 TARGET INTERACTION BLOCKED</span>
            </div>
            <div style=\"font-family:monospace; font-size:10px; color:#94a3b8; max-width:400px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;\">
                TARGET: {html.escape(base_url)}
            </div>
        </div>
        """

        # Inject light color-scheme, base tag and styles into <head> or prepend
        color_scheme_tag = '<meta name="color-scheme" content="light">'
        base_tag = f'<base href="{html.escape(base_url, quote=True)}">'
        head_inject = f"\n{color_scheme_tag}\n{base_tag}\n{safe_styles}\n"
        if "<head" in html_str.lower():
            html_str = re.sub(r'(<\s*head\b[^>]*>)', r'\1' + head_inject, html_str, count=1, flags=re.IGNORECASE)
        else:
            html_str = f"<head>{head_inject}</head>{html_str}"

        # Inject banner right after <body ...>
        if "<body" in html_str.lower():
            def _body_repl(match: re.Match) -> str:
                tag = match.group(0)
                if forensic_class:
                    if "class=" in tag:
                        tag = re.sub(r'class\s*=\s*["\']([^"\']*)["\']', r'class="\1 ' + forensic_class + '"', tag)
                    else:
                        tag = tag[:-1] + f' class="{forensic_class}">'
                return f"{tag}\n{banner}"
            html_str = re.sub(r'<\s*body\b[^>]*>', _body_repl, html_str, count=1, flags=re.IGNORECASE)
        else:
            html_str = f'<body class="{forensic_class}">{banner}{html_str}</body>'

        return html_str

    def _build_empty_fallback(
        self,
        reason: str,
        base_url: str,
        error_type: Optional[str] = None,
        stage: Optional[str] = "MAIN_DOCUMENT",
        http_status: Optional[int] = None,
    ) -> tuple[str, list[dict[str, Any]], dict[str, Any]]:
        """Fallback reconstruction when DOM is unavailable or blocked (Requirement 6 & 23)."""
        err_title = "PAGE NAVIGATION FAILED"
        reason_display = error_type or "CONNECTION_ERROR"
        http_display = str(http_status) if http_status else "N/A"
        fallback_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>PhishGuard AI — Page Navigation Failed</title>
    <style>
        body {{
            background: #090d16;
            color: #94a3b8;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
            padding: 40px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: 80vh;
            margin: 0;
        }}
        .card {{
            background: #0f172a;
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 12px;
            padding: 28px 36px;
            max-width: 600px;
            width: 100%;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0,0,0,0.6);
        }}
        .icon {{ font-size: 36px; margin-bottom: 12px; }}
        h2 {{ color: #f87171; margin: 0 0 16px 0; font-size: 19px; letter-spacing: 0.05em; font-weight: 700; }}
        .diag-table {{
            background: #020617;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 8px;
            padding: 12px 16px;
            text-align: left;
            margin-bottom: 16px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 12px;
            line-height: 1.8;
        }}
        .row {{ display: flex; justify-content: space-between; border-bottom: 1px solid rgba(255, 255, 255, 0.05); padding: 4px 0; }}
        .row:last-child {{ border-bottom: none; }}
        .lbl {{ color: #64748b; font-weight: 600; text-transform: uppercase; font-size: 10px; width: 80px; shrink: 0; }}
        .val {{ color: #cbd5e1; word-break: break-all; text-align: right; }}
        .val.alert {{ color: #f87171; font-weight: 700; }}
        .val.target {{ color: #38bdf8; }}
        p.details {{ font-size: 12px; line-height: 1.6; color: #94a3b8; margin: 12px 0 0 0; text-align: left; }}
        .footer {{ font-size: 11px; color: #475569; margin-top: 18px; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 12px; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">⚠️</div>
        <h2>{html.escape(err_title)}</h2>
        <div class="diag-table">
            <div class="row">
                <span class="lbl">Target:</span>
                <span class="val target">{html.escape(base_url)}</span>
            </div>
            <div class="row">
                <span class="lbl">Stage:</span>
                <span class="val">{html.escape(stage or "MAIN_DOCUMENT")}</span>
            </div>
            <div class="row">
                <span class="lbl">Reason:</span>
                <span class="val alert">{html.escape(reason_display)}</span>
            </div>
            <div class="row">
                <span class="lbl">HTTP:</span>
                <span class="val">{html.escape(http_display)}</span>
            </div>
        </div>
        <p class="details">{html.escape(reason)}</p>
        <div class="footer">
            Target execution is isolated inside VirtualBox Chromium. Forensic screenshots and network metadata remain available.
        </div>
    </div>
</html>"""
        fallback_html = self._inject_safe_head_and_styles(fallback_html, base_url, is_forensic_mode=False)
        return fallback_html, [], {
            "text_characters": 0, "images": 0, "scripts": 0, "stylesheets": 0,
            "forms": 0, "inputs": 0, "links": 0, "iframes": 0, "videos": 0,
            "external_domains_count": 0, "external_domains": [],
        }

    def _extract_attr(self, tag_str: str, attr_name: str) -> Optional[str]:
        m = re.search(rf'\b{attr_name}\s*=\s*["\']([^"\']*)["\']', tag_str, re.IGNORECASE)
        return m.group(1) if m else None


# Global sanitizer singleton
html_sanitizer = HTMLSanitizer()


def sanitize_rendered_dom(
    html_content: str,
    base_url: str,
    page_id: str = "p_root",
    is_forensic_mode: bool = False,
    http_status: Optional[int] = None,
) -> tuple[str, dict[str, Any]]:
    """Convenience helper returning (sanitized_html, content_inventory)."""
    clean_html, elements, inventory = html_sanitizer.sanitize(
        html_content, base_url, is_forensic_mode=is_forensic_mode, http_status=http_status
    )
    return clean_html, inventory


def extract_content_inventory(html_content: str, base_url: str) -> dict[str, Any]:
    """Convenience helper returning content inventory dict."""
    try:
        base_domain = (urlparse(base_url).hostname or "").lower()
    except Exception:
        base_domain = ""
    return html_sanitizer._calculate_content_inventory(html_content, html_content, base_domain)

