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
from flask import has_request_context, request
from detection.ssrf_guard import validate_url_safe

# Suppress certificate verification warnings for external asset fetching
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# In-memory stylesheet cache to eliminate redundant downloads and hotlink blocks
_CSS_CACHE: dict[str, str] = {}
_CSS_CACHE_LOCK = threading.Lock()
_MAX_CSS_CACHE_ENTRIES = 500



# Regex patterns for stripping dangerous tags and attributes
_SCRIPT_RE = re.compile(r"<\s*script[^>]*>[\s\S]*?<\s*/\s*script\s*>", re.IGNORECASE)
_NOSCRIPT_RE = re.compile(r"<\s*noscript[^>]*>([\s\S]*?)<\s*/\s*noscript\s*>", re.IGNORECASE)
_HTML_COMMENT_RE = re.compile(r"<!--(?!\[if)[\s\S]*?-->", re.IGNORECASE)
_META_REFRESH_RE = re.compile(r"<\s*meta[^>]*http-equiv\s*=\s*['\"]?refresh['\"]?[^>]*>", re.IGNORECASE)
_BASE_TAG_RE = re.compile(r"<\s*base[^>]*>", re.IGNORECASE)
_COLOR_SCHEME_RE = re.compile(r"<\s*meta[^>]*name\s*=\s*['\"]?color-scheme['\"]?[^>]*>", re.IGNORECASE)
_EMBED_OBJECT_RE = re.compile(r"<\s*(?:embed|object|applet)[^>]*>[\s\S]*?<\s*/\s*(?:embed|object|applet)\s*>", re.IGNORECASE)
_EVENT_HANDLER_ATTR_RE = re.compile(r"""\s+on[a-z]+\s*=\s*(?:'[^']*'|"[^"]*"|[^\s>]+)""", re.IGNORECASE)
_JAVASCRIPT_URI_ATTR_RE = re.compile(r"""(href|src|action|data)\s*=\s*['"]\s*javascript:[^'"]*['"]""", re.IGNORECASE)
_STYLE_TAG_RE = re.compile(r"<\s*style\b[^>]*>[\s\S]*?<\s*/\s*style\s*>", re.IGNORECASE)
_HEAD_TAG_RE = re.compile(r"<\s*head\b[^>]*>[\s\S]*?<\s*/\s*head\s*>", re.IGNORECASE)
_TITLE_TAG_RE = re.compile(r"<\s*title\b[^>]*>([\s\S]*?)<\s*/\s*title\s*>", re.IGNORECASE)
_BODY_INNER_RE = re.compile(r"<\s*body\b[^>]*>([\s\S]*)<\s*/\s*body\s*>", re.IGNORECASE)
_SPA_MOUNT_RE = re.compile(
    r"(?:\bid\s*=\s*['\"](?:root|app|__next|__nuxt|svelte|mount|__app)['\"]|<\s*app-root\b|\bdata-reactroot\b)",
    re.IGNORECASE,
)
_SPA_JS_BOILERPLATE_RE = re.compile(
    r"(?:"
    r"enable\s+javascript"
    r"|javascript\s+(?:is\s+)?(?:required|disabled|needed|turned\s+off|must\s+be\s+enabled)"
    r"|to\s+run\s+this\s+app"
    r"|without\s+javascript"
    r"|does\s*(?:n't|not)\s+(?:support|work\s+(?:properly\s+)?without)\s+javascript"
    r"|please\s+(?:turn\s+on|activate|enable)\s+javascript"
    r")",
    re.IGNORECASE,
)
_BOT_CHALLENGE_HINT_RE = re.compile(
    r"(?:cloudflare|cf-browser-verification|ddos-guard|enable\s+javascript\s+and\s+cookies|captcha|access\s+denied)",
    re.IGNORECASE,
)

_REVEAL_EXCLUDED_TOKENS = (
    "modal", "popup", "overlay", "backdrop", "layer", "dropdown", "menu",
    "tooltip", "popover", "slide", "carousel", "tab", "drawer", "dialog",
    "toast", "alert", "badge", "spinner", "loader", "hover", "hidden",
    "hide", "close", "sr-only", "visually-hidden", "radio", "check",
    "input", "btn", "button", "arrow", "nav", "accordion", "collapse",
)
_REVEAL_ACTIVE_SUFFIXES = (
    "animate", "animated", "active", "visible", "is-visible", "in",
    "show", "loaded", "revealed", "entered", "in-view", "aos-animate",
    "appear", "appeared", "done",
)


class HTMLSanitizer:
    """Sanitizes rendered DOM and enriches it for Safe Web View & Forensic Mode."""

    def __init__(self) -> None:
        pass

    def _promote_async_stylesheets(self, html_str: str) -> str:
        """Converts async <link rel='preload' as='style' onload=...> and media='print' onload=... into active stylesheets before event handlers are stripped."""
        def _link_repl(match: re.Match) -> str:
            tag = match.group(0)
            if not re.search(r'\bonload\s*=', tag, re.IGNORECASE):
                return tag
            if re.search(r'\brel\s*=\s*["\']preload["\']', tag, re.IGNORECASE) and re.search(r'\bas\s*=\s*["\']style["\']', tag, re.IGNORECASE):
                tag = re.sub(r'\brel\s*=\s*["\']preload["\']', 'rel="stylesheet"', tag, count=1, flags=re.IGNORECASE)
            if re.search(r'\bmedia\s*=\s*["\']print["\']', tag, re.IGNORECASE):
                tag = re.sub(r'\s+media\s*=\s*["\']print["\']', '', tag, count=1, flags=re.IGNORECASE)
            return tag

        return re.sub(r'<\s*link\b[^>]*>', _link_repl, html_str, flags=re.IGNORECASE)

    def _extract_visible_body_text(self, html_str: str) -> str:
        """Extracts normalized visible text inside <body>, excluding <head>, <title>, <script>, and <style>."""
        body_m = _BODY_INNER_RE.search(html_str)
        source = body_m.group(1) if body_m else _HEAD_TAG_RE.sub(" ", html_str)
        source = _SCRIPT_RE.sub(" ", source)
        source = _STYLE_TAG_RE.sub(" ", source)
        source = _TITLE_TAG_RE.sub(" ", source)
        text = re.sub(r"<[^>]+>", " ", source)
        return re.sub(r"\s+", " ", text).strip()

    def is_unhandled_spa_noscript(self, safe_html: str, http_status: Optional[int] = None) -> bool:
        """Returns True if cached Safe View HTML still renders raw boilerplate SPA no-JS fallback text."""
        if not safe_html or "pg-spa-notice" in safe_html or (http_status is not None and http_status >= 400):
            return False
        if not _SPA_MOUNT_RE.search(safe_html):
            return False
        body_text = self._extract_visible_body_text(safe_html)
        return len(body_text) < 350 and bool(_SPA_JS_BOILERPLATE_RE.search(body_text))

    def _process_noscript_blocks(self, html_str: str, http_status: Optional[int] = None) -> str:
        """
        Safely removes <noscript> wrapper tags while preserving:
          1. Any <style> rules inside <noscript> (needed for no-JS fallback rules like hiding lazy placeholders).
          2. Full <noscript> fallback content when the rest of the body has minimal visible text
             (e.g. Cloudflare/JS gates), while suppressing generic SPA boilerplate notices like
             'You need to enable JavaScript to run this app.' so the Safe View SPA banner renders cleanly.
        Guarantees no <noscript> tags remain in the output.
        """
        if "<noscript" not in html_str.lower():
            return html_str

        without_noscript = _NOSCRIPT_RE.sub("", html_str)
        visible_text = self._extract_visible_body_text(without_noscript)
        unwrap_all_text = len(visible_text) < 40
        has_spa_mount = bool(_SPA_MOUNT_RE.search(without_noscript))
        is_error_status = http_status is not None and http_status >= 400
        doc_has_challenge = is_error_status or bool(_BOT_CHALLENGE_HINT_RE.search(without_noscript))

        def _noscript_repl(match: re.Match) -> str:
            inner = match.group(1) or ""
            styles = _STYLE_TAG_RE.findall(inner)
            if not unwrap_all_text:
                return "\n".join(styles) if styles else ""

            inner_no_style = _STYLE_TAG_RE.sub(" ", inner)
            inner_plain = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", inner_no_style)).strip()
            is_challenge = doc_has_challenge or bool(_BOT_CHALLENGE_HINT_RE.search(inner_plain))
            has_rich_fallback = bool(re.search(r"<\s*(?:form|input|a|img|table)\b", inner_no_style, re.IGNORECASE))
            is_spa_boilerplate = (
                not is_challenge
                and not has_rich_fallback
                and bool(inner_plain)
                and len(inner_plain) < 260
                and bool(_SPA_JS_BOILERPLATE_RE.search(inner_plain))
                and (has_spa_mount or len(visible_text) == 0)
            )
            if is_spa_boilerplate:
                return "\n".join(styles) if styles else ""
            return inner

        return _NOSCRIPT_RE.sub(_noscript_repl, html_str)

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

        # Step 2: Strip active executable elements & HTML comments
        clean = _SCRIPT_RE.sub("", source_content)
        clean = _HTML_COMMENT_RE.sub("", clean)
        clean = self._promote_async_stylesheets(clean)
        clean = self._promote_nav_and_toggle_controls(clean, base_url)
        clean = _META_REFRESH_RE.sub("", clean)
        clean = _BASE_TAG_RE.sub("", clean)
        clean = _EMBED_OBJECT_RE.sub("", clean)
        clean = _EVENT_HANDLER_ATTR_RE.sub("", clean)
        clean = _JAVASCRIPT_URI_ATTR_RE.sub(r'\1="javascript:void(0)"', clean)
        clean = self._process_noscript_blocks(clean, http_status=http_status)

        # Step 3: Content Inventory Counts
        content_inventory = self._calculate_content_inventory(html_content, clean, base_domain)

        # Step 4: Resolve relative URLs & lazy-loaded image attributes so layout is preserved
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
            clean = self._detect_and_format_spa(
                clean,
                content_inventory,
                base_url,
                http_status=http_status,
                raw_html=html_content,
            )

        # Step 9: Inject Safe Sandbox Stylesheet & Visual Watermarks
        final_html = self._inject_safe_head_and_styles(clean, base_url, is_forensic_mode)

        return final_html, elements_map, content_inventory

    def _promote_nav_and_toggle_controls(self, html_str: str, base_url: str) -> str:
        """
        Extracts static navigation destinations from inline onclick handlers and
        SPA/custom routing attributes before event handlers are stripped.
        """
        blocked_schemes = ("javascript:", "vbscript:", "data:", "blob:", "file:", "mailto:", "tel:", "sms:")

        def _normalize_nav_dest(raw_val: str) -> Optional[str]:
            val = html.unescape(raw_val or "").strip()
            if not val or val == "#" or val.startswith("#"):
                return None
            if val.lower().startswith(blocked_schemes):
                return None
            abs_u = urljoin(base_url, val)
            if (urlparse(abs_u).scheme or "").lower() not in ("http", "https"):
                return None
            return abs_u

        def _append_attr(tag_str: str, attr_fragment: str) -> str:
            if tag_str.rstrip().endswith("/>"):
                base_part = tag_str.rstrip()[:-2].rstrip()
                return f"{base_part} {attr_fragment} />"
            return f"{tag_str[:-1]} {attr_fragment}>"

        onclick_nav_re = re.compile(
            r'''(?:(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=\s*|(?:(?:window\.|document\.|top\.|self\.)?location\.(?:assign|replace)|(?:window\.)?open|router\.push|navigate|goToUrl|redirect)\s*\(\s*)(?:["'`]([^"'`]+)["'`]|&quot;([^&]+)&quot;|&#39;([^&]+)&#39;)''',
            re.IGNORECASE,
        )

        def _promote_tag(match: re.Match) -> str:
            full_tag = match.group(0)
            if re.search(r'\bdata-pg-href\s*=', full_tag, re.IGNORECASE):
                return full_tag
            if re.search(r'\btype\s*=\s*["\']?reset\b', full_tag, re.IGNORECASE):
                return full_tag

            tag_name = match.group(1).lower()
            if tag_name == "input" and not re.search(r'\btype\s*=\s*["\']?button\b', full_tag, re.IGNORECASE):
                return full_tag

            # Check formaction on buttons/inputs
            fa_m = re.search(r'''\bformaction\s*=\s*["']([^"']+)["']''', full_tag, re.IGNORECASE)
            if fa_m:
                abs_dest = _normalize_nav_dest(fa_m.group(1).strip())
                if abs_dest:
                    return _append_attr(full_tag, f'data-pg-href="{html.escape(abs_dest)}"')

            oc_m = re.search(r'''\bonclick\s*=\s*(?:"([^"]*)"|'([^']*)')''', full_tag, re.IGNORECASE)
            if oc_m:
                oc_val = html.unescape(oc_m.group(1) or oc_m.group(2) or "")
                nav_m = onclick_nav_re.search(oc_val)
                if nav_m:
                    raw_dest = nav_m.group(1) or nav_m.group(2) or nav_m.group(3) or ""
                    abs_dest = _normalize_nav_dest(raw_dest)
                    if abs_dest:
                        return _append_attr(full_tag, f'data-pg-href="{html.escape(abs_dest)}"')

            if tag_name not in ("img", "source"):
                spa_m = re.search(
                    r'''\b(?:data-href|data-to|routerlink|data-url|data-route|data-link|data-link-url|data-target-url|data-path|data-navigate|data-destination|data-permalink|data-page|data-slug)\s*=\s*["']([^"']+)["']''',
                    full_tag,
                    re.IGNORECASE,
                )
                if spa_m:
                    raw_dest = spa_m.group(1).strip()
                    if raw_dest.startswith("#") and len(raw_dest) > 1:
                        if not re.search(r'\bdata-pg-hash\s*=', full_tag, re.IGNORECASE):
                            return _append_attr(full_tag, f'data-pg-hash="{html.escape(raw_dest)}"')
                    else:
                        abs_dest = _normalize_nav_dest(raw_dest)
                        if abs_dest:
                            return _append_attr(full_tag, f'data-pg-href="{html.escape(abs_dest)}"')

                # Also check data-target when it looks like a path or URL (not a CSS selector like #myModal)
                dt_m = re.search(r'''\bdata-target\s*=\s*["']([^"']+)["']''', full_tag, re.IGNORECASE)
                if dt_m:
                    dt_val = dt_m.group(1).strip()
                    if dt_val.startswith(("/", "http://", "https://")):
                        abs_dest = _normalize_nav_dest(dt_val)
                        if abs_dest:
                            return _append_attr(full_tag, f'data-pg-href="{html.escape(abs_dest)}"')

                # Also check href on button or custom tags (some frameworks put href on button)
                if tag_name != "a":
                    hr_m = re.search(r'''\bhref\s*=\s*["']([^"']+)["']''', full_tag, re.IGNORECASE)
                    if hr_m:
                        hr_val = hr_m.group(1).strip()
                        if hr_val.startswith("#") and len(hr_val) > 1:
                            if not re.search(r'\bdata-pg-hash\s*=', full_tag, re.IGNORECASE):
                                return _append_attr(full_tag, f'data-pg-hash="{html.escape(hr_val)}"')
                        else:
                            abs_dest = _normalize_nav_dest(hr_val)
                            if abs_dest:
                                return _append_attr(full_tag, f'data-pg-href="{html.escape(abs_dest)}"')

            return full_tag

        return re.sub(
            r'<\s*([a-zA-Z0-9]+-[a-zA-Z0-9_-]+|a|area|button|div|span|li|td|tr|figure|article|section|p|h[1-6]|img|input)\b[^>]*>',
            _promote_tag,
            html_str,
            flags=re.IGNORECASE,
        )

    def _resolve_relative_urls(self, html_str: str, base_url: str) -> str:
        """Resolve relative src, srcset, link href, lazy-image attributes, and CSS url(...) to absolute URLs."""
        def _is_placeholder_src(val: str) -> bool:
            vl = val.strip().lower()
            if not vl:
                return True
            if vl.startswith("data:image/gif") or vl.startswith("data:image/svg+xml"):
                return len(vl) < 250
            return any(k in vl for k in ("placeholder", "blank.gif", "spacer.gif", "loading.gif", "1x1."))

        def _promote_lazy_attrs(match: re.Match) -> str:
            tag = match.group(0)
            src_m = re.search(r'''\bsrc\s*=\s*["']([^"']*)["']''', tag, re.IGNORECASE)
            curr_src = src_m.group(1).strip() if src_m else ""
            if not curr_src or _is_placeholder_src(curr_src):
                for lazy_attr in ("data-src", "data-lazy-src", "data-original", "data-lazy", "data-url"):
                    lm = re.search(rf'''\b{lazy_attr}\s*=\s*["']([^"']+)["']''', tag, re.IGNORECASE)
                    if lm and lm.group(1).strip() and not lm.group(1).strip().startswith("javascript:"):
                        lazy_val = html.unescape(lm.group(1).strip())
                        if src_m:
                            tag = re.sub(r'''\bsrc\s*=\s*["'][^"']*["']''', f'src="{lazy_val}"', tag, count=1, flags=re.IGNORECASE)
                        else:
                            tag = tag[:-1] + f' src="{lazy_val}">'
                        break

            srcset_m = re.search(r'''\bsrcset\s*=\s*["']([^"']*)["']''', tag, re.IGNORECASE)
            if not srcset_m or not srcset_m.group(1).strip():
                for lazy_ss in ("data-srcset", "data-lazy-srcset"):
                    lsm = re.search(rf'''\b{lazy_ss}\s*=\s*["']([^"']+)["']''', tag, re.IGNORECASE)
                    if lsm and lsm.group(1).strip():
                        ss_val = html.unescape(lsm.group(1).strip())
                        if srcset_m:
                            tag = re.sub(r'''\bsrcset\s*=\s*["'][^"']*["']''', f'srcset="{ss_val}"', tag, count=1, flags=re.IGNORECASE)
                        else:
                            tag = tag[:-1] + f' srcset="{ss_val}">'
                        break
            return tag

        html_str = re.sub(r'<\s*(?:img|source)\b[^>]*>', _promote_lazy_attrs, html_str, flags=re.IGNORECASE)

        def _replace_src(match: re.Match) -> str:
            attr = match.group(1)
            val = html.unescape(match.group(2).strip())
            if not val or val.startswith("#") or val.startswith("data:") or val.startswith("blob:") or val.startswith("http://") or val.startswith("https://"):
                return match.group(0)
            abs_url = urljoin(base_url, val)
            return f'{attr}="{abs_url}"'

        # Replace img src, source src, video/audio src, poster
        html_str = re.sub(r'''\b(src|poster)\s*=\s*["']([^"']+)["']''', _replace_src, html_str, flags=re.IGNORECASE)

        # Replace srcset
        def _replace_srcset(match: re.Match) -> str:
            srcset_val = html.unescape(match.group(1).strip())
            candidates = srcset_val.split(',')
            new_candidates = []
            for cand in candidates:
                cand = cand.strip()
                if not cand:
                    continue
                parts = cand.split()
                if parts:
                    u = parts[0]
                    if not (u.startswith("#") or u.startswith("data:") or u.startswith("blob:") or u.startswith("http://") or u.startswith("https://")):
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
            val = html.unescape(href_m.group(1).strip())
            if not val or val.startswith("#") or val.startswith("data:") or val.startswith("blob:") or val.startswith("http://") or val.startswith("https://"):
                return full_link
            abs_url = urljoin(base_url, val)
            return re.sub(r'''\bhref\s*=\s*["'][^"']+["']''', f'href="{abs_url}"', full_link, count=1, flags=re.IGNORECASE)

        html_str = re.sub(r'<\s*link\b[^>]*>', _replace_link_href, html_str, flags=re.IGNORECASE)

        # Replace CSS url(...) in style tags and inline styles (preserve #fragment refs for inline SVGs)
        def _replace_css_url(match: re.Match) -> str:
            raw_url = html.unescape(match.group(1).strip().strip("'\""))
            if not raw_url or raw_url.startswith("#") or raw_url.startswith("data:") or raw_url.startswith("blob:") or raw_url.startswith("http://") or raw_url.startswith("https://"):
                return match.group(0)
            abs_url = urljoin(base_url, raw_url)
            return f'url("{abs_url}")'

        html_str = re.sub(r'''url\(\s*['"]?([^'")]+)['"]?\s*\)''', _replace_css_url, html_str, flags=re.IGNORECASE)
        return html_str

    def _clean_css_text(self, css_text: str, sheet_url: str, resolve_imports: bool = True) -> str:
        """Sanitizes CSS text, resolves relative url(...) / @import paths, and prevents </style> breakout."""
        cleaned_css = re.sub(r'expression\s*\(', '/* expr */ (', css_text, flags=re.IGNORECASE)
        cleaned_css = re.sub(r'javascript\s*:', 'blocked-js:', cleaned_css, flags=re.IGNORECASE)
        cleaned_css = re.sub(r'</\s*style', '<\\/style', cleaned_css, flags=re.IGNORECASE)

        # Normalize @import "..." into @import url("...")
        cleaned_css = re.sub(
            r'''@import\s+["']([^"']+)["']''',
            lambda m: f'@import url("{urljoin(sheet_url, html.unescape(m.group(1).strip()))}")',
            cleaned_css,
            flags=re.IGNORECASE,
        )

        # Resolve url(...) relative paths against stylesheet URL (skip #fragment refs)
        def _css_url_repl(m: re.Match) -> str:
            raw_u = html.unescape(m.group(1).strip().strip("'\""))
            if not raw_u or raw_u.startswith("#") or raw_u.startswith("data:") or raw_u.startswith("blob:") or raw_u.startswith("http://") or raw_u.startswith("https://"):
                return m.group(0)
            return f'url("{urljoin(sheet_url, raw_u)}")'

        cleaned_css = re.sub(r'''url\(\s*['"]?([^'")]+)['"]?\s*\)''', _css_url_repl, cleaned_css, flags=re.IGNORECASE)

        # Inline up to 6 @import url(...) directives (1 level deep) so CDN/nested imports render cleanly
        if resolve_imports and "@import" in cleaned_css.lower():
            imports_inlined = 0

            def _import_repl(m: re.Match) -> str:
                nonlocal imports_inlined
                if imports_inlined >= 6:
                    return m.group(0)
                imp_url = html.unescape(m.group(1).strip().strip("'\""))
                if not imp_url.startswith(("http://", "https://")):
                    return m.group(0)
                ssrf_res = validate_url_safe(imp_url)
                if not ssrf_res.get("safe", True):
                    return "/* blocked @import */"
                imports_inlined += 1
                sub_css = self._fetch_stylesheet_text(imp_url, referer=sheet_url)
                if sub_css:
                    return self._clean_css_text(sub_css, imp_url, resolve_imports=False)
                return m.group(0)

            cleaned_css = re.sub(
                r'''@import\s+url\(\s*['"]?([^'")]+)['"]?\s*\)\s*;?''',
                _import_repl,
                cleaned_css,
                flags=re.IGNORECASE,
            )

        return cleaned_css

    def _fetch_stylesheet_text(self, sheet_url: str, referer: str) -> Optional[str]:
        """Fetches a stylesheet over HTTP/HTTPS with SSRF guard and HTML-response rejection."""
        ssrf_res = validate_url_safe(sheet_url)
        if not ssrf_res.get("safe", True):
            return None

        with _CSS_CACHE_LOCK:
            if sheet_url in _CSS_CACHE:
                return _CSS_CACHE[sheet_url]

        req_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Accept": "text/css,*/*;q=0.1",
            "Referer": referer,
            "Sec-Fetch-Dest": "style",
            "Sec-Fetch-Mode": "no-cors",
            "Sec-Fetch-Site": "cross-site",
        }
        try:
            r = requests.get(sheet_url, headers=req_headers, timeout=3.5, verify=False)
            if r.status_code == 200 and r.text:
                ct = (r.headers.get("Content-Type") or "").lower()
                head_snip = r.text.lstrip()[:64].lower()
                if "text/html" in ct or "application/xhtml" in ct or head_snip.startswith("<!doctype") or head_snip.startswith("<html"):
                    return None
                return r.text
        except Exception:
            pass
        return None

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

        # Filter for stylesheets
        sheet_targets: list[tuple[str, str]] = []
        for tag in all_links:
            if not re.search(r'\brel\s*=\s*["\'](?:[^"\']*\s+)?stylesheet(?:\s+[^"\']*)?["\']', tag, re.IGNORECASE):
                continue
            href_m = re.search(r'\bhref\s*=\s*["\']([^"\']+)["\']', tag, re.IGNORECASE)
            if not href_m:
                continue
            raw_href = html.unescape(href_m.group(1).strip())
            if not raw_href or raw_href.startswith("data:") or raw_href.startswith("blob:"):
                continue

            abs_url = urljoin(base_url, raw_href)
            sheet_targets.append((tag, abs_url))

        # 2. Check caches & captured stylesheets
        css_map: dict[str, str] = {}
        urls_to_fetch: list[str] = []

        for _, abs_url in sheet_targets:
            if abs_url in css_map:
                continue
            if captured_stylesheets and abs_url in captured_stylesheets:
                css_map[abs_url] = self._clean_css_text(captured_stylesheets[abs_url], abs_url)
                continue
            with _CSS_CACHE_LOCK:
                if abs_url in _CSS_CACHE:
                    css_map[abs_url] = _CSS_CACHE[abs_url]
                    continue
            if abs_url not in urls_to_fetch:
                urls_to_fetch.append(abs_url)

        # 3. Concurrent fetch for missing stylesheets (max 8 workers, 3.5s timeout)
        if urls_to_fetch:
            def _fetch_one(sheet_url: str) -> tuple[str, Optional[str]]:
                return sheet_url, self._fetch_stylesheet_text(sheet_url, referer=base_url)

            max_w = min(len(urls_to_fetch), 8)
            with ThreadPoolExecutor(max_workers=max_w) as executor:
                for sheet_url, css_text in executor.map(_fetch_one, urls_to_fetch):
                    if css_text:
                        cleaned_css = self._clean_css_text(css_text, sheet_url)
                        css_map[sheet_url] = cleaned_css
                        with _CSS_CACHE_LOCK:
                            if len(_CSS_CACHE) >= _MAX_CSS_CACHE_ENTRIES:
                                _CSS_CACHE.clear()
                            _CSS_CACHE[sheet_url] = cleaned_css

        # 4. Replace <link> tags with <style> blocks (or absolute proxy URLs if fetch failed)
        proxy_prefix = ""
        if has_request_context():
            try:
                proxy_prefix = request.url_root.rstrip("/")
            except Exception:
                proxy_prefix = ""

        for tag, abs_url in sheet_targets:
            if abs_url in css_map:
                css_content = css_map[abs_url]
                style_replacement = f'<style data-pg-inlined="true" data-source-href="{html.escape(abs_url, quote=True)}">\n{css_content}\n</style>'
                html_str = html_str.replace(tag, style_replacement, 1)
            else:
                proxy_url = f"{proxy_prefix}/safe-view/asset-proxy?url={urllib.parse.quote_plus(abs_url)}&ref={urllib.parse.quote_plus(base_url)}"
                tag_proxied = re.sub(r'\bhref\s*=\s*["\'][^"\']+["\']', f'href="{proxy_url}" data-pg-href="{html.escape(abs_url, quote=True)}" data-pg-proxied="true"', tag, count=1, flags=re.IGNORECASE)
                html_str = html_str.replace(tag, tag_proxied, 1)

        # 5. Also resolve url(...) and @import inside any pre-existing inline <style> tags
        def _resolve_inline_style_urls(match: re.Match) -> str:
            full_style = match.group(0)
            if 'data-pg-inlined="true"' in full_style:
                return full_style
            open_end = full_style.find(">")
            close_start = full_style.lower().rfind("</style")
            if open_end == -1 or close_start == -1:
                return full_style
            open_tag = full_style[:open_end + 1]
            inner_css = full_style[open_end + 1:close_start]
            close_tag = full_style[close_start:]
            return open_tag + self._clean_css_text(inner_css, base_url) + close_tag

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

        # Neutralize submit/reset/form buttons while keeping read-only UI/nav buttons clickable
        form_spans: list[tuple[int, int]] = []
        form_stack: list[int] = []
        for fm in re.finditer(r'<\s*(/?)\s*form\b[^>]*>', html_str, flags=re.IGNORECASE):
            if fm.group(1):
                if form_stack:
                    form_spans.append((form_stack.pop(), fm.end()))
            else:
                form_stack.append(fm.start())
        for unclosed_start in form_stack:
            form_spans.append((unclosed_start, len(html_str)))

        def _is_inside_form(pos: int) -> bool:
            return any(s <= pos <= e for s, e in form_spans)

        def _button_repl(match: re.Match) -> str:
            full_tag = match.group(0)
            tag_clean = re.sub(r'\s+disabled(?:=["\'][^"\']*["\'])?', '', full_tag[:-1], flags=re.IGNORECASE)
            has_pg_nav = bool(re.search(r'\bdata-pg-href\s*=', tag_clean, re.IGNORECASE))
            is_explicit_submit = bool(re.search(r'\btype\s*=\s*["\']?(?:submit|reset)\b', tag_clean, re.IGNORECASE))
            is_explicit_button = bool(re.search(r'\btype\s*=\s*["\']?button\b', tag_clean, re.IGNORECASE))
            is_ui_trigger = bool(
                re.search(
                    r'\b(?:aria-controls|aria-expanded|aria-haspopup|data-bs-toggle|data-bs-target|data-toggle|data-target|data-tab)\s*=',
                    tag_clean,
                    re.IGNORECASE,
                )
            )

            if has_pg_nav:
                tag_clean = re.sub(r'\s+type\s*=\s*["\']?[^"\'\s>]+["\']?', '', tag_clean, flags=re.IGNORECASE)
                return f'{tag_clean} type="button" data-pg-control="nav">'

            if is_explicit_submit or (_is_inside_form(match.start()) and not is_explicit_button and not is_ui_trigger):
                return f'{tag_clean} disabled="true" tabindex="-1">'

            if not re.search(r'\btype\s*=', tag_clean, re.IGNORECASE):
                tag_clean = f'{tag_clean} type="button"'
            else:
                tag_clean = re.sub(r'\btype\s*=\s*["\']?submit["\']?', 'type="button"', tag_clean, flags=re.IGNORECASE)
            return f'{tag_clean} data-pg-control="ui">'

        html_str = re.sub(r'<\s*button\b[^>]*>', _button_repl, html_str, flags=re.IGNORECASE)

        def _readonly_field_repl(match: re.Match) -> str:
            full_tag = match.group(0)
            tag_clean = re.sub(r'\s+(readonly|disabled)(?:=["\'][^"\']*["\'])?', '', full_tag[:-1], flags=re.IGNORECASE)
            return f'{tag_clean} readonly="true" disabled="true" tabindex="-1">'

        html_str = re.sub(r'<\s*(?:textarea|select)\b[^>]*>', _readonly_field_repl, html_str, flags=re.IGNORECASE)

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
            is_area = bool(re.match(r'^<\s*area\b', full_tag, re.IGNORECASE))

            href_match = re.search(r'\bhref\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))', full_tag, re.IGNORECASE)
            raw_href = html.unescape((href_match.group(1) or href_match.group(2) or href_match.group(3) or "")).strip() if href_match else ""
            lower_raw = raw_href.lower()
            has_download = bool(re.search(r'\sdownload(?:\s*=\s*["\'][^"\']*["\']|\s|>|$)', full_tag, re.IGNORECASE))

            promoted_match = re.search(r'\bdata-pg-href\s*=\s*["\']([^"\']*)["\']', full_tag, re.IGNORECASE)
            promoted_href = html.unescape(promoted_match.group(1)).strip() if promoted_match else ""

            hash_attr = ""
            blocked_scheme_attr = ""
            if (not raw_href or lower_raw.startswith("javascript:") or raw_href == "#") and promoted_href.startswith(("http://", "https://")):
                resolved_href = promoted_href
                parsed_res = urlparse(resolved_href)
                target_domain = (parsed_res.hostname or "").lower()
                is_external = bool(target_domain and base_domain and target_domain != base_domain and not target_domain.endswith("." + base_domain))
            elif not raw_href or lower_raw.startswith("javascript:") or raw_href == "#":
                resolved_href = "javascript:void(0)"
                is_external = False
            elif raw_href.startswith("#"):
                resolved_href = "javascript:void(0)"
                hash_attr = f' data-pg-hash="{html.escape(raw_href)}"'
                is_external = False
            elif any(lower_raw.startswith(p) for p in ("mailto:", "tel:", "sms:", "data:", "blob:", "file:", "vbscript:")):
                resolved_href = "javascript:void(0)"
                scheme_name = lower_raw.split(":", 1)[0]
                blocked_scheme_attr = f' data-pg-blocked-scheme="{html.escape(scheme_name)}"'
                is_external = False
            else:
                resolved_href = urljoin(base_url, raw_href)
                parsed_res = urlparse(resolved_href)
                if (parsed_res.scheme or "").lower() not in ("http", "https"):
                    resolved_href = "javascript:void(0)"
                    is_external = False
                else:
                    target_domain = (parsed_res.hostname or "").lower()
                    is_external = bool(target_domain and base_domain and target_domain != base_domain and not target_domain.endswith("." + base_domain))

            risk = "MEDIUM" if is_external else "LOW"
            elements.append({
                "element_id": el_id,
                "tag": "AREA" if is_area else "A",
                "href": resolved_href,
                "original_href": raw_href,
                "is_external": is_external,
                "risk": risk,
                "risk_type": "external_link" if is_external else "link",
                "description": f"Hyperlink pointing to {resolved_href}",
            })

            tag_clean = re.sub(r'\s+href\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s>]+)', '', full_tag, flags=re.IGNORECASE)
            tag_clean = re.sub(r'\s+data-pg-href\s*=\s*["\'][^"\']*["\']', '', tag_clean, flags=re.IGNORECASE)
            tag_clean = re.sub(r'\s+target\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s>]+)', '', tag_clean, flags=re.IGNORECASE)
            tag_clean = re.sub(r'\s+download(?:\s*=\s*["\'][^"\']*["\'])?', '', tag_clean, flags=re.IGNORECASE)
            tag_body = tag_clean.rstrip()
            if tag_body.endswith("/>"):
                tag_body = tag_body[:-2].rstrip()
            elif tag_body.endswith(">"):
                tag_body = tag_body[:-1].rstrip()

            download_attr = ' data-pg-download="true"' if has_download else ""
            pg_href_attr = f' data-pg-href="{html.escape(resolved_href)}"' if resolved_href != "javascript:void(0)" else ""

            return (
                f'{tag_body} '
                f'href="javascript:void(0)"'
                f'{pg_href_attr}'
                f'{hash_attr}{blocked_scheme_attr}{download_attr} '
                f'data-pg-id="{el_id}" '
                f'target="_self">'
            )

        html_str = re.sub(r'<\s*(?:a|area|[a-zA-Z0-9]+-anchor)\b[^>]*>', _link_repl, html_str, flags=re.IGNORECASE)
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
        # Visible text approx length (excludes <head>, <title>, <script>, and <style>)
        text_content = self._extract_visible_body_text(clean_html)

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

    def _detect_and_format_spa(
        self,
        clean_html: str,
        content_inventory: dict[str, Any],
        base_url: str,
        http_status: Optional[int] = None,
        raw_html: str = "",
    ) -> str:
        """If a page has truly empty DOM (client-side rendered SPA with no static content), injects an informative notice."""
        text_len = content_inventory.get("text_characters", 0)
        img_count = content_inventory.get("images", 0)
        form_count = content_inventory.get("forms", 0)
        input_count = content_inventory.get("inputs", 0)
        link_count = content_inventory.get("links", 0)

        is_spa_mount = bool(_SPA_MOUNT_RE.search(clean_html))
        is_error_status = http_status is not None and http_status >= 400
        raw_had_spa_noscript = bool(raw_html and _SPA_JS_BOILERPLATE_RE.search(raw_html)) and not is_error_status
        visible_text = self._extract_visible_body_text(clean_html)
        is_empty_or_loading = text_len == 0 or (
            text_len <= 24
            and bool(re.fullmatch(r"(?:loading|please wait|initializing)[\s.]*", visible_text, re.IGNORECASE))
        )

        if is_empty_or_loading and img_count == 0 and form_count == 0 and input_count == 0 and link_count == 0 and (is_spa_mount or raw_had_spa_noscript) and not is_error_status:
            title_m = _TITLE_TAG_RE.search(clean_html) or (_TITLE_TAG_RE.search(raw_html) if raw_html else None)
            raw_title = re.sub(r"\s+", " ", html.unescape(title_m.group(1))).strip() if title_m else ""
            title_prefix = f"{html.escape(raw_title[:80])} — " if raw_title else ""
            spa_notice = f"""
            <div class=\"pg-spa-notice\">
                <div class=\"pg-spa-icon\">⚡</div>
                <div class=\"pg-spa-content\">
                    <h4>{title_prefix}Single Page Application (Client-Side Rendered)</h4>
                    <p>This page relies on client-side JavaScript execution (such as React, Vue, or Angular) to render its interface. Active scripts are blocked in Safe Read-Only Web View, and the captured static shell contains only an empty mount container.</p>
                    <p style=\"margin-top: 8px;\">If a sandbox screenshot was captured for this page, switch to the <strong>Screenshot</strong> tab at the top right to inspect the rendered page.</p>
                </div>
            </div>
            """
            if "<body" in clean_html.lower():
                clean_html = re.sub(r'(<\s*body\b[^>]*>)', r'\1' + spa_notice, clean_html, count=1, flags=re.IGNORECASE)
            else:
                clean_html = f"<body>{spa_notice}{clean_html}</body>"
        return clean_html

    def _build_reveal_override_css(self, html_str: str) -> str:
        """
        Inspects page CSS for scroll-reveal / pre-animation classes that set `opacity: 0`
        (and have a corresponding active/animate/visible state) so static/pre-scroll captures
        never hide the page behind opacity: 0.
        """
        style_blocks = re.findall(r'<\s*style\b[^>]*>([\s\S]*?)<\s*/\s*style\s*>', html_str, re.IGNORECASE)
        if not style_blocks:
            return ""
        combined_css = "\n".join(style_blocks)
        if "opacity" not in combined_css.lower():
            return ""

        hidden_classes: set[str] = set()
        for m in re.finditer(r'\.([a-zA-Z_-][a-zA-Z0-9_-]{1,48})\s*\{([^}]{1,400})\}', combined_css):
            cls_name = m.group(1)
            body = m.group(2).lower()
            if not re.search(r'opacity\s*:\s*0(?:\.0+)?\s*(?:;|!important|$)', body):
                continue
            cls_lower = cls_name.lower()
            if any(tok in cls_lower for tok in _REVEAL_EXCLUDED_TOKENS):
                continue
            if "position:fixed" in body.replace(" ", "") and "width:0" in body.replace(" ", ""):
                continue
            hidden_classes.add(cls_name)

        if not hidden_classes:
            return ""

        reveal_selectors: list[str] = []
        suffix_pat = "|".join(_REVEAL_ACTIVE_SUFFIXES)
        for cls_name in sorted(hidden_classes):
            if re.search(rf'\.{re.escape(cls_name)}\s*\.\s*(?:{suffix_pat})\b', combined_css, re.IGNORECASE):
                reveal_selectors.append(f".{cls_name}")

        if not reveal_selectors:
            return ""

        joined = ", ".join(reveal_selectors[:40])
        return f"""
        <style id="pg-reveal-overrides">
            {joined} {{
                opacity: 1 !important;
                visibility: visible !important;
                transform: none !important;
            }}
        </style>
        """

    def _inject_safe_head_and_styles(self, html_str: str, base_url: str, is_forensic_mode: bool) -> str:
        """Injects non-interactive forensic styling, read-only badges, and security overlay rules."""
        forensic_class = "pg-forensic-active" if is_forensic_mode else ""
        has_color_scheme_meta = bool(_COLOR_SCHEME_RE.search(html_str))
        reveal_overrides = self._build_reveal_override_css(html_str)

        safe_styles = f"""
        <style id=\"pg-safe-viewer-styles\" data-pg-sanitizer-v=\"2\" data-pg-nav-v=\"3\">
            /* PhishGuard Isolated Read-Only Safe Viewer Styling */
            html {{
                pointer-events: auto !important;
                user-select: text !important;
                -webkit-user-select: text !important;
                opacity: 1 !important;
                visibility: visible !important;
            }}
            body {{
                margin: 0;
                padding: 0;
                min-height: 100vh;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                opacity: 1 !important;
                visibility: visible !important;
            }}
            main, #root, #app, #__next, #__nuxt, #outerWrapper,
            fluent-design-system-provider, entry-point, app-root, [shadowrootmode] {{
                display: block !important;
                opacity: 1 !important;
                visibility: visible !important;
            }}
            /* Ensure page remains scrollable even if a modal applied a scroll lock to body/html */
            html, body {{
                overflow-x: hidden !important;
                overflow-y: auto !important;
                height: auto !important;
                position: static !important;
            }}
            /* Dismiss JS-dependent fullscreen preloaders & reveal hidden scroll-animation elements */
            #preloader, .preloader, #page-loader, .page-loader,
            #loader-wrapper, .loader-wrapper, .loading-overlay, #loading-overlay,
            .loader-overlay, #loader-overlay, .splash-screen, #splash-screen,
            .se-pre-con, .site-preloader, .preloader-wrapper, #loading-screen, .loading-screen,
            .pace, .page-transition-overlay {{
                display: none !important;
                visibility: hidden !important;
                opacity: 0 !important;
                pointer-events: none !important;
            }}
            /* Suppress intrusive cookie consent modals, GDPR popups, and blocking backdrops across websites */
            #onetrust-consent-sdk, #onetrust-banner-sdk, #onetrust-pc-sdk, .onetrust-pc-dark, .ot-sdk-container, .ot-pc-container,
            #CybotCookiebotDialog, #CybotCookiebotDialogBodyUnderlay,
            #truste-consent-track, .truste_box_overlay, .truste_overlay,
            #usercentrics-root, [id*="usercentrics" i],
            .qc-cmp2-container, .qc-cmp-cleanslate,
            #cmpbox, #cmpbox2, .cmp-root,
            .cc-window, .cc-banner, .cc-overlay,
            #cookie-law-info-bar, #cookie-law-info-again,
            .cookie-notice, .cookie-banner, .cookie-consent, #cookie-banner, #cookie-consent,
            .cookie-modal, #cookie-modal, .cookie-popup, #cookie-popup, [id*="cookie-banner" i], [id*="cookie-notice" i],
            #gdpr-consent-notice, .gdpr-banner, .gdpr-consent,
            .osano-cm-window, .osano-cm-dialog,
            .klaro, .klaro .cookie-modal,
            #didomi-host, #didomi-notice, #didomi-popup,
            #axeptio_overlay,
            .modal-backdrop, .overlay-backdrop {{
                display: none !important;
                visibility: hidden !important;
                opacity: 0 !important;
                pointer-events: none !important;
            }}
            [data-aos], .wow, .reveal, .scroll-reveal, .animate-on-scroll,
            .fade-in-section, .js-reveal, .sr-reveal, [data-scroll], [data-reveal],
            .lazyload, .lazyloading, .wf-loading * {{
                opacity: 1 !important;
                visibility: visible !important;
                transform: none !important;
            }}
            /* All form inputs visual disabled treatment */
            input, textarea, select, button[disabled] {{
                cursor: not-allowed !important;
                opacity: 0.85 !important;
            }}
            input:focus, textarea:focus, select:focus, button:focus {{
                outline: none !important;
                box-shadow: none !important;
            }}
            /* Clickable read-only navigation links and safe UI controls show pointer */
            a[data-pg-href]:not([data-pg-href="javascript:void(0)"]),
            a[data-pg-href]:not([data-pg-href="javascript:void(0)"]) *,
            a[data-pg-hash],
            a[data-pg-hash] *,
            [data-pg-href]:not([data-pg-href="javascript:void(0)"]),
            [data-pg-href]:not([data-pg-href="javascript:void(0)"]) *,
            [data-pg-hash],
            [data-pg-hash] *,
            button[data-pg-control="ui"],
            button[data-pg-control="nav"],
            summary,
            [role="tab"],
            [role="button"]:not([disabled]),
            [aria-controls]:not([disabled]),
            [data-bs-toggle]:not([disabled]),
            [data-toggle]:not([disabled]) {{
                cursor: pointer !important;
                opacity: 1 !important;
            }}
            a[data-pg-href="javascript:void(0)"]:not([data-pg-hash]) {{
                cursor: default !important;
            }}
            /* Let clicks on buttons inside navigational links pass through to the anchor */
            a[data-pg-href]:not([data-pg-href="javascript:void(0)"]) button,
            a[data-pg-hash] button {{
                pointer-events: none !important;
                opacity: 1 !important;
            }}
            /* Pure CSS dropdown & UI toggle support for sandboxed menus/accordions/tabs */
            li:hover > ul,
            li:hover > .sub-menu,
            li:hover > .children,
            li:hover > .dropdown-menu,
            .dropdown:hover > .dropdown-menu,
            .menu-item-has-children:hover > ul,
            .pg-dropdown-open > ul,
            .pg-dropdown-open > .sub-menu,
            .pg-dropdown-open > .children,
            .pg-dropdown-open > .dropdown-menu,
            .pg-dropdown-open > [role="menu"],
            .pg-panel-open {{
                display: block !important;
                visibility: visible !important;
                opacity: 1 !important;
                pointer-events: auto !important;
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
                position: sticky !important;
                top: 0 !important;
                width: 100% !important;
                box-sizing: border-box !important;
                margin: 0 !important;
                z-index: 2147483647 !important;
                background: #090d16 !important;
                color: #cbd5e1 !important;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
                font-size: 10px !important;
                font-weight: 500 !important;
                padding: 2px 10px !important;
                height: 22px !important;
                line-height: 18px !important;
                display: flex !important;
                align-items: center !important;
                justify-content: space-between !important;
                border-bottom: 1px solid rgba(147, 51, 234, 0.25) !important;
                letter-spacing: 0.3px !important;
            }}
            #pg-safe-banner .badge {{
                display: inline-flex;
                align-items: center;
                gap: 4px;
                padding: 1px 6px;
                border-radius: 3px;
                font-size: 9px;
                font-family: monospace;
            }}
            #pg-safe-banner .badge-isolated {{
                background: rgba(16, 185, 129, 0.15);
                color: #34d399;
                border: 1px solid rgba(16, 185, 129, 0.3);
            }}
            #pg-safe-banner .badge-blocked {{
                background: rgba(239, 68, 68, 0.15);
                color: #f87171;
                border: 1px solid rgba(239, 68, 68, 0.3);
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
            <div style=\"display:flex; align-items:center; gap:6px;\">
                <span style=\"color:#c084fc; font-weight:600;\">🛡 PHISHGUARD</span>
                <span style=\"color:#475569;\">•</span>
                <span>Safe Read-Only View</span>
                <span class=\"badge badge-isolated\">🔒 Isolated</span>
                <span class=\"badge badge-blocked\">🚫 Writes Blocked</span>
            </div>
            <div style=\"font-family:monospace; font-size:9px; color:#64748b; max-width:320px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;\">
                {html.escape(base_url)}
            </div>
        </div>
        """

        # Inject base tag (and default light color-scheme only if page has none) at start of <head>,
        # and inject safe_styles + reveal_overrides at the end of <head> so they outrank page rules cleanly.
        color_scheme_tag = '' if has_color_scheme_meta else '<meta name="color-scheme" content="light">\n'
        base_tag = f'<base href="{html.escape(base_url, quote=True)}">'
        head_start_inject = f"\n{color_scheme_tag}{base_tag}\n"
        head_end_inject = f"\n{safe_styles}\n{reveal_overrides}\n"

        if "<head" in html_str.lower():
            html_str = re.sub(r'(<\s*head\b[^>]*>)', lambda m: m.group(1) + head_start_inject, html_str, count=1, flags=re.IGNORECASE)
            if "</head>" in html_str.lower():
                html_str = re.sub(r'</\s*head\s*>', lambda m: head_end_inject + m.group(0), html_str, count=1, flags=re.IGNORECASE)
            else:
                html_str = re.sub(r'(<\s*head\b[^>]*>)', lambda m: m.group(1) + head_end_inject, html_str, count=1, flags=re.IGNORECASE)
        else:
            html_str = f"<head>{head_start_inject}{head_end_inject}</head>{html_str}"

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
        http_display = str(http_status) if (http_status and http_status >= 400) else "N/A"
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

