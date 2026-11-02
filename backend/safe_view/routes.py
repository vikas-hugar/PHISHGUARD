"""
PhishGuard AI V7.2 — Safe Web View: Flask API Routes
==================================================
Exposes clean REST endpoints for Safe Web View & Forensic Inspection:
  POST /safe-view/analyze                          — Initiate analysis session
  GET  /safe-view/session/<session_id>             — Session status & page index
  GET  /safe-view/pages/<session_id>               — List of discovered pages
  GET  /safe-view/session/<session_id>/page/<page_id> — Single page representation API (Section 7)
  GET  /safe-view/session/<session_id>/page/<page_id>/render — Sandboxed HTML with strict CSP
  GET  /safe-view/page/<page_id>                   — Page forensic details & inventory
  GET  /safe-view/dom/<page_id>                    — DOM diff, mutations, initial/final snapshots
  GET  /safe-view/network/<page_id>                — Network forensics & dependency chain
  GET  /safe-view/timeline/<page_id>               — Millisecond temporal event timeline
  GET  /safe-view/render/<page_id>                 — Sandboxed HTML with strict CSP (script-src 'none')
  GET  /safe-view/screenshot/<page_id>             — Full-page base64 screenshot binary/json
"""

from __future__ import annotations

import base64
import time
from urllib.parse import urlparse
from flask import Blueprint, request, jsonify, make_response, Response, has_request_context
from typing import Optional
from .session_manager import session_manager
from .safe_view_engine import safe_view_engine
from .sanitizer import html_sanitizer

safe_view_bp = Blueprint("safe_view", __name__, url_prefix="/safe-view")


def _find_page(page_id: str, session_id: Optional[str] = None) -> tuple[Optional[dict], Optional[str]]:
    """Helper to locate a page and its session_id across active sessions, analyzing on-demand if needed."""
    t_find_start = time.perf_counter()
    # Check explicitly requested session_id first
    sid = session_id
    if not sid and has_request_context():
        try:
            sid = request.args.get("session_id") or request.args.get("sid")
        except Exception:
            sid = None

    if sid:
        sess = session_manager.get_session(sid)
        if sess:
            # 1. Instant check via LRU cache / memory / disk (0ms)
            existing = sess.get_page(page_id)
            if existing and (existing.get("scan_status") in ("AVAILABLE", "PARTIAL", "SUCCESS") or existing.get("safe_html")):
                elapsed = round((time.perf_counter() - t_find_start) * 1000, 2)
                print(f"[PERF] _find_page cache HIT for {page_id} in {elapsed}ms", flush=True)
                return existing, sid

            # Root page is scanned in initial Deep Scan — NEVER re-scan p_root on demand
            if page_id == "p_root" or page_id == sess.root_page_id:
                root_p = sess.get_page(sess.root_page_id or "p_root")
                if root_p:
                    return root_p, sid

            # 2. If discovered candidate, analyze on demand / prioritize
            if page_id in sess.discovered_pages and page_id != "p_root" and page_id != sess.root_page_id:
                analyzed = safe_view_engine.analyze_page_on_demand(sid, page_id)
                if analyzed:
                    return analyzed, sid

            # Fallback for explicit session_id match even if failed
            if existing:
                return existing, sid
            if page_id == "p_root" or page_id == sess.root_page_id:
                root_p = sess.get_page(sess.root_page_id or "p_root")
                if root_p:
                    return root_p, sid

    # Fallback: scan sessions in order (most recent first, checks memory + disk)
    active_sids = session_manager.list_active_sessions()

    # Pass 1: Look for AVAILABLE/SUCCESS representations in recent sessions
    for s in active_sids:
        sess = session_manager.get_session(s)
        if sess:
            existing = sess.get_page(page_id)
            if existing and (existing.get("scan_status") in ("AVAILABLE", "PARTIAL", "SUCCESS") or existing.get("safe_html")):
                return existing, s
            if page_id == "p_root" or page_id == sess.root_page_id:
                root_p = sess.get_page(sess.root_page_id or "p_root")
                if root_p:
                    return root_p, s
            if page_id in sess.discovered_pages and page_id != "p_root" and page_id != sess.root_page_id:
                analyzed = safe_view_engine.analyze_page_on_demand(s, page_id)
                if analyzed and (analyzed.get("scan_status") in ("AVAILABLE", "PARTIAL", "SUCCESS") or analyzed.get("safe_html")):
                    return analyzed, s

    # Pass 2: Fallback to any matching page representation even if partial/failed
    for s in active_sids:
        sess = session_manager.get_session(s)
        if sess:
            existing = sess.get_page(page_id)
            if existing:
                return existing, s
            if page_id == "p_root" or page_id == sess.root_page_id:
                root_p = sess.get_page(sess.root_page_id or "p_root")
                if root_p:
                    return root_p, s

    return None, None


def _build_page_payload(page: dict, page_id: str, sess_id: Optional[str]) -> dict:
    """Builds clean, structured metadata dictionary for a page."""
    safe_html = page.get("safe_html", "")
    page_http_status = page.get("http_status", 200)
    has_uninlined_stylesheets = bool(safe_html and "<link" in safe_html and "stylesheet" in safe_html.lower() and "data-pg-inlined=" not in safe_html)
    needs_resanitize = (
        not safe_html
        or has_uninlined_stylesheets
        or ("color-scheme: light !important" in safe_html)
        or ("font-family: -apple-system, BlinkMacSystemFont" in safe_html and "!important" in safe_html)
        or "pg-server-error-container" in safe_html
        or ("<pre>" in safe_html and "pg-api-container" not in safe_html and "{" in safe_html)
    )
    if needs_resanitize:
        raw_source = page.get("dom_snapshot") or page.get("html_raw") or safe_html
        if raw_source:
            url = page.get("url", "")
            try:
                res_html, elems, inv = html_sanitizer.sanitize(
                    raw_source,
                    url,
                    http_status=page_http_status,
                    captured_stylesheets=page.get("captured_stylesheets"),
                )
                safe_html = res_html
                page["safe_html"] = res_html
                if elems and not page.get("elements_map"):
                    page["elements_map"] = elems
                if inv:
                    page["content_inventory"] = inv
            except Exception:
                pass

    return {
        "page_id": page_id,
        "session_id": sess_id,
        "url": page.get("url"),
        "path": page.get("path"),
        "title": page.get("title"),
        "http_status": page.get("http_status", 200),
        "risk_level": page.get("risk_level", "LOW"),
        "has_credentials": page.get("has_credentials", False),
        "load_time_ms": page.get("load_time_ms", 0.0),
        "content_inventory": page.get("content_inventory", {}),
        "elements_map": page.get("elements_map", []),
        "forms": page.get("forms", []),
        "suspicious_indicators": page.get("suspicious_indicators", []),
        "page_states": page.get("page_states", []),
        "security_status": page.get("security_status", {
            "isolated": True,
            "read_only": True,
            "interactions_blocked": True,
            "scripts_disabled": True,
        }),
        "safe_html": safe_html,
        "screenshot_b64": page.get("screenshot_b64"),
        "screenshot_type": page.get("screenshot_type", "full_page"),
        "screenshot_available": bool(page.get("screenshot_b64")),
        "scan_status": page.get("scan_status", "AVAILABLE"),
        "page_available": page.get("page_available", True),
        "error": page.get("error"),
        "error_type": page.get("error_type"),
        "error_details": page.get("error_details"),
        "failed_resources": page.get("failed_resources", []),
        "redirect_chain": page.get("redirect_chain", []),
        "redirect_count": page.get("redirect_count", 0),
        "reachability_state": page.get("reachability_state") or (
            "REACHABLE_HTTP_2XX" if 200 <= page_http_status < 300 else
            "REACHABLE_HTTP_3XX" if 300 <= page_http_status < 400 else
            "REACHABLE_HTTP_4XX" if 400 <= page_http_status < 500 else
            "REACHABLE_HTTP_5XX" if 500 <= page_http_status < 600 else
            "CONNECTION_FAILED"
        ),
        "browser_render_state": page.get("browser_render_state") or (
            "BROWSER_RENDERED" if page.get("page_available", True) else "BROWSER_RENDER_FAILED"
        ),
        "server_response_message": page.get("server_response_message") or (
            f"Server reachable — remote server returned HTTP {page_http_status}." if page_http_status >= 400 else "Server reachable and response received."
        ),
        "device_profile": page.get("device_profile", "desktop"),
    }


@safe_view_bp.route("/analyze", methods=["POST", "OPTIONS"])
def analyze_endpoint():
    """Initiates an isolated Safe Web View analysis session with multi-depth discovery."""
    if request.method == "OPTIONS":
        return jsonify({}), 200

    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"success": False, "status": "error", "error": "No URL provided"}), 400

    parsed = urlparse(url)
    if not parsed.scheme or parsed.scheme not in ("http", "https") or not parsed.netloc:
        return jsonify({"success": False, "status": "error", "error": "Invalid or malformed target URL. Must include http:// or https:// with a valid domain."}), 400

    discover_pages = bool(data.get("discover_pages", True))
    max_pages = int(data.get("max_pages", 50))
    max_depth = int(data.get("max_depth", 2))
    device_profile = str(data.get("device_profile") or "desktop").lower()
    if device_profile not in ("desktop", "tablet", "mobile"):
        device_profile = "desktop"

    result = safe_view_engine.start_analysis(
        url=url,
        discover_pages=discover_pages,
        max_pages=max_pages,
        max_depth=max_depth,
        device_profile=device_profile,
    )

    if result.get("security_block"):
        return jsonify({"success": False, "status": "error", "security_block": True, **result}), 400
    if not result.get("session_id") and result.get("error"):
        return jsonify({"success": False, "status": "error", **result}), 422

    return jsonify({
        "success": True,
        "status": "success",
        "session_id": result.get("session_id"),
        "root_page_id": result.get("root_page_id"),
        "target": result.get("target_url"),
        "pages": result.get("pages", []),
        "discovery": result.get("discovery", {}),
        "discovery_stats": result.get("discovery_stats", {}),
        "session": result,
    }), 200


@safe_view_bp.route("/session/<session_id>", methods=["GET"])
def get_session_endpoint(session_id: str):
    """Returns overall session state and discovered pages summary."""
    sess = session_manager.get_session(session_id)
    if not sess:
        print(f"[SAFEVIEW] Session '{session_id}' not found or expired.", flush=True)
        return jsonify({
            "success": False,
            "error": f"Session '{session_id}' not found or expired.",
            "error_code": "SESSION_EXPIRED",
            "message": "Analysis session expired or backend was restarted. Please run the scan again."
        }), 404

    return jsonify({
        "success": True,
        "session": sess.to_dict(),
        "target": sess.target_url,
        "pages": sess.get_pages_summary(),
        "discovery": sess.discovery_stats,
        "discovery_stats": sess.discovery_stats,
    }), 200


@safe_view_bp.route("/pages/<session_id>", methods=["GET"])
@safe_view_bp.route("/session/<session_id>/pages", methods=["GET"])
def get_pages_endpoint(session_id: str):
    """Returns the complete list of discovered pages, page tree, and live discovery telemetry (Requirement 25 & 27)."""
    sess = session_manager.get_session(session_id)
    if not sess:
        return jsonify({
            "success": False,
            "error": f"Session '{session_id}' not found or expired.",
            "error_code": "SESSION_EXPIRED",
            "message": "Analysis session expired. Please run the scan again."
        }), 404

    pages_summary = sess.get_pages_summary()
    tree = sess.get_page_tree()

    return jsonify({
        "success": True,
        "target": sess.target_url,
        "session_id": session_id,
        "pages": pages_summary,
        "tree": tree,
        "pages_count": len(pages_summary),
        "discovery": sess.discovery_stats,
        "discovery_stats": sess.discovery_stats,
        "blocked_actions": sess.blocked_actions,
        "external_domains": sorted(list(sess.external_domains)),
    }), 200


@safe_view_bp.route("/tree/<session_id>", methods=["GET"])
@safe_view_bp.route("/session/<session_id>/tree", methods=["GET"])
def get_tree_endpoint(session_id: str):
    """Returns the complete hierarchical page tree based on actual discovered relationships (Requirement 19 & 25)."""
    sess = session_manager.get_session(session_id)
    if not sess:
        return jsonify({
            "success": False,
            "error": f"Session '{session_id}' not found or expired.",
            "error_code": "SESSION_EXPIRED",
            "message": "Analysis session expired. Please run the scan again."
        }), 404

    return jsonify({
        "success": True,
        "session_id": session_id,
        "target": sess.target_url,
        "tree": sess.get_page_tree(),
        "pages_count": len(sess.discovered_pages),
        "discovery_stats": sess.discovery_stats,
    }), 200


@safe_view_bp.route("/session/<session_id>/prioritize/<page_id>", methods=["POST", "OPTIONS"])
def prioritize_page_endpoint(session_id: str, page_id: str):
    """Prioritizes a candidate page in the crawl queue (Requirement 6)."""
    if request.method == "OPTIONS":
        return jsonify({}), 200

    promoted = safe_view_engine.prioritize_page(session_id, page_id)
    return jsonify({
        "success": True,
        "session_id": session_id,
        "page_id": page_id,
        "prioritized": promoted,
        "status": "PRIORITIZED",
    }), 200


@safe_view_bp.route("/session/<session_id>/page/<page_id>", methods=["GET"])
def get_session_page_endpoint(session_id: str, page_id: str):
    """
    Reliable Page Representation API (Requirement 7 & 8).
    Returns complete page representation matching:
    {
      "session_id": "...",
      "page_id": "...",
      "url": "https://example.com/",
      "status": 200,
      "title": "Example",
      "available": true,
      "representation": "..."
    }
    """
    print(f"[SAFEVIEW] Viewer request: {session_id}/{page_id}", flush=True)

    sess = session_manager.get_session(session_id)
    if not sess:
        print(f"[SAFEVIEW] Viewer request: {session_id}/{page_id} ERROR: representation not found - session expired or missing", flush=True)
        return jsonify({
            "success": False,
            "available": False,
            "error": "PAGE_REPRESENTATION_NOT_FOUND",
            "error_code": "SESSION_EXPIRED",
            "session_id": session_id,
            "page_id": page_id,
            "message": "The analysis session has expired or is no longer available. Please run the scan again.",
            "reason": "Analysis session expired or backend was restarted.",
        }), 404

    page, _ = _find_page(page_id, session_id=session_id)
    if not page:
        print(f"[SAFEVIEW] Viewer request: {session_id}/{page_id} ERROR: representation not found", flush=True)
        return jsonify({
            "success": False,
            "available": False,
            "error": "PAGE_REPRESENTATION_NOT_FOUND",
            "error_code": "PAGE_NOT_FOUND",
            "session_id": session_id,
            "page_id": page_id,
            "message": f"The requested page representation '{page_id}' is no longer available in this active session.",
            "reason": f"Page '{page_id}' was not found in active session {session_id}.",
        }), 404

    print(f"[SAFEVIEW] Representation found", flush=True)
    print(f"[SAFEVIEW] Returning page", flush=True)

    payload = _build_page_payload(page, page_id, session_id)
    return jsonify({
        "success": True,
        "available": True,
        "session_id": session_id,
        "page_id": page_id,
        "url": page.get("url"),
        "status": page.get("http_status", 200),
        "title": page.get("title", ""),
        "representation": page.get("safe_html", ""),
        "page": payload,
        **payload,
    }), 200


@safe_view_bp.route("/page/<page_id>", methods=["GET"])
def get_page_endpoint(page_id: str):
    """Returns complete forensic details for a single page (with session_id support)."""
    sid = request.args.get("session_id") or request.args.get("sid")
    print(f"[SAFEVIEW] Viewer request: {sid or 'auto'}/{page_id}", flush=True)

    page, sess_id = _find_page(page_id, session_id=sid)
    if not page:
        print(f"[SAFEVIEW] Viewer request: {sid or 'auto'}/{page_id} ERROR: representation not found", flush=True)
        return jsonify({
            "success": False,
            "available": False,
            "error": "PAGE_REPRESENTATION_NOT_FOUND",
            "error_code": "PAGE_NOT_FOUND",
            "session_id": sid,
            "page_id": page_id,
            "message": f"The requested page representation '{page_id}' was not found.",
        }), 404

    print(f"[SAFEVIEW] Representation found", flush=True)
    print(f"[SAFEVIEW] Returning page", flush=True)

    payload = _build_page_payload(page, page_id, sess_id)
    return jsonify({
        "success": True,
        "available": True,
        "session_id": sess_id,
        "page_id": page_id,
        "url": page.get("url"),
        "status": page.get("http_status", 200),
        "title": page.get("title", ""),
        "representation": page.get("safe_html", ""),
        "page": payload,
        **payload,
    }), 200


@safe_view_bp.route("/dom/<page_id>", methods=["GET"])
def get_dom_endpoint(page_id: str):
    """Returns Initial DOM, Final DOM, and DOM Mutation Comparison diff."""
    page, sess_id = _find_page(page_id)
    if not page:
        return jsonify({"success": False, "error": f"Page '{page_id}' not found."}), 404

    return jsonify({
        "success": True,
        "page_id": page_id,
        "session_id": sess_id,
        "url": page.get("url"),
        "dom_diff": page.get("dom_diff", {}),
        "dom_behavior": page.get("dom_behavior", {}),
        "initial_dom": page.get("html_raw", ""),
        "final_dom": page.get("dom_snapshot", ""),
    }), 200


@safe_view_bp.route("/network/<page_id>", methods=["GET"])
def get_network_endpoint(page_id: str):
    """Returns network requests, dependency flow, and external domain inventory."""
    page, sess_id = _find_page(page_id)
    if not page:
        return jsonify({"success": False, "error": f"Page '{page_id}' not found."}), 404

    net = page.get("network_forensics", {})
    return jsonify({
        "success": True,
        "page_id": page_id,
        "session_id": sess_id,
        "url": page.get("url"),
        "network_forensics": net,
        "network": net,
    }), 200


@safe_view_bp.route("/timeline/<page_id>", methods=["GET"])
def get_timeline_endpoint(page_id: str):
    """Returns chronological timeline of execution events."""
    page, sess_id = _find_page(page_id)
    if not page:
        return jsonify({"success": False, "error": f"Page '{page_id}' not found."}), 404

    return jsonify({
        "success": True,
        "page_id": page_id,
        "session_id": sess_id,
        "url": page.get("url"),
        "timeline": page.get("timeline", []),
    }), 200


@safe_view_bp.route("/session/<session_id>/page/<page_id>/render", methods=["GET"])
@safe_view_bp.route("/render/<page_id>", methods=["GET"])
def render_safe_view_endpoint(page_id: str, session_id: Optional[str] = None):
    """
    Renders the sanitized, isolated read-only HTML.
    Protected with strict Content-Security-Policy prohibiting all script execution.
    Handles missing representations cleanly with diagnostic information (Requirement 8 & 20).
    """
    sid = session_id or request.args.get("session_id") or request.args.get("sid")
    page, found_sid = _find_page(page_id, session_id=sid)

    if not page:
        print(f"[SAFEVIEW] Viewer request: {sid or 'auto'}/{page_id} ERROR: representation not found", flush=True)
        display_sid = sid or "Unknown (None provided)"
        error_html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>PhishGuard Safe Web View — Representation Unavailable</title>
  <style>
    body {{
      background: #090d16;
      color: #f87171;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
      padding: 30px;
      margin: 0;
      line-height: 1.5;
    }}
    .card {{
      max-width: 580px;
      margin: 30px auto;
      background: #0f172a;
      border: 1px solid rgba(239, 68, 68, 0.4);
      border-radius: 12px;
      padding: 24px;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
    }}
    h3 {{
      color: #ef4444;
      margin-top: 0;
      font-size: 16px;
      letter-spacing: 0.05em;
    }}
    p {{
      color: #cbd5e1;
      font-size: 13px;
    }}
    .meta-box {{
      background: #020617;
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 8px;
      padding: 12px;
      font-size: 11px;
      font-family: monospace;
      color: #94a3b8;
      margin-top: 14px;
    }}
    .meta-row {{ margin-bottom: 4px; }}
    .meta-row strong {{ color: #e2e8f0; }}
  </style>
</head>
<body>
  <div class="card">
    <h3>PAGE REPRESENTATION UNAVAILABLE</h3>
    <p>The requested page representation is no longer available in the active session.</p>
    <div class="meta-box">
      <div class="meta-row"><strong>Session:</strong> {display_sid}</div>
      <div class="meta-row"><strong>Page:</strong> {page_id}</div>
      <div class="meta-row"><strong>Reason:</strong> Analysis session expired or backend process restarted.</div>
    </div>
    <p style="font-size: 11px; color: #64748b; margin-top: 14px;">
      Please trigger a fresh scan from the main dashboard to establish a new analysis session.
    </p>
  </div>
</body>
</html>"""
        resp = make_response(error_html, 404)
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
        resp.headers["X-SafeView-Status"] = "UNAVAILABLE"
        return resp

    print(f"[SAFEVIEW] Viewer request: {found_sid or sid}/{page_id} Representation found -> Rendering page", flush=True)

    safe_html = page.get("safe_html")
    page_http_status = page.get("http_status", 200)
    has_uninlined_stylesheets = bool(safe_html and "<link" in safe_html and "stylesheet" in safe_html.lower() and "data-pg-inlined=" not in safe_html)
    needs_resanitize = (
        not safe_html
        or has_uninlined_stylesheets
        or ("color-scheme: light !important" in safe_html)
        or ("font-family: -apple-system, BlinkMacSystemFont" in safe_html and "!important" in safe_html)
        or ("<pre>" in safe_html and "pg-api-container" not in safe_html)
        or (page_http_status >= 400 and "pg-server-error-container" not in safe_html)
        or ("[ERR_" in safe_html and "pg-server-error-container" not in safe_html)
    )
    if needs_resanitize:
        raw_source = page.get("dom_snapshot") or page.get("html_raw") or safe_html
        if raw_source:
            url = page.get("url", "")
            try:
                res_html, _, _ = html_sanitizer.sanitize(
                    raw_source,
                    url,
                    http_status=page_http_status,
                    captured_stylesheets=page.get("captured_stylesheets"),
                )
                safe_html = res_html
                page["safe_html"] = res_html
            except Exception:
                pass

    safe_html = safe_html or "<html><body>Empty representation</body></html>"
    resp = make_response(safe_html)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers["X-SafeView-Status"] = "AVAILABLE"

    # CRITICAL SECURITY CSP:
    # default-src 'none': strictly blocks any unapproved connections
    # script-src 'none': ZERO JavaScript execution permitted in analyst's browser
    # form-action 'none': form submission prohibited
    # frame-src 'none': nested frames prohibited
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        "img-src data: blob: http: https:; "
        "style-src 'unsafe-inline' data: blob: http: https:; "
        "font-src data: blob: http: https:; "
        "media-src data: blob: http: https:; "
        "frame-src 'none'; "
        "object-src 'none'; "
        "script-src 'none'; "
        "form-action 'none'; "
        "frame-ancestors 'self' http://localhost:* http://127.0.0.1:*;"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    return resp


@safe_view_bp.route("/screenshot/<page_id>", methods=["GET"])
def get_screenshot_endpoint(page_id: str):
    """Returns the captured page screenshot (as base64 or raw PNG)."""
    sid = request.args.get("session_id") or request.args.get("sid")
    page, _ = _find_page(page_id, session_id=sid)
    if not page or not page.get("screenshot_b64"):
        return jsonify({"success": False, "error": "Screenshot unavailable"}), 404

    b64_data = page.get("screenshot_b64")

    # If raw requested, return binary PNG
    if request.args.get("raw") == "1":
        try:
            raw_bytes = base64.b64decode(b64_data)
            return Response(raw_bytes, mimetype="image/png")
        except Exception:
            pass

    return jsonify({
        "success": True,
        "page_id": page_id,
        "screenshot_b64": b64_data,
        "screenshot_type": page.get("screenshot_type", "full_page"),
    }), 200


@safe_view_bp.route("/asset-proxy", methods=["GET"])
@safe_view_bp.route("/proxy", methods=["GET"])
def asset_proxy_endpoint():
    """
    Safely proxies external stylesheets, fonts, and images with authentic browser headers.
    Solves cross-origin hotlink protection (HTTP 403 Forbidden) and CDN blocking.
    Protected with SSRF validation.
    """
    raw_url = request.args.get("url") or ""
    referer = request.args.get("ref") or request.args.get("referer") or ""
    if not raw_url:
        return "Missing URL parameter", 400

    from detection.ssrf_guard import validate_url_safe
    ssrf = validate_url_safe(raw_url)
    if not ssrf.get("safe", True):
        return f"Blocked by SSRF guard: {ssrf.get('reason')}", 403

    import requests
    try:
        req_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Accept": "*/*",
            "Referer": referer or raw_url,
            "Sec-Fetch-Dest": "style",
            "Sec-Fetch-Mode": "no-cors",
            "Sec-Fetch-Site": "cross-site",
        }
        res = requests.get(raw_url, headers=req_headers, timeout=6.0, verify=False)
        content_type = res.headers.get("Content-Type", "text/css; charset=utf-8")
        resp = make_response(res.content, res.status_code)
        resp.headers["Content-Type"] = content_type
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Cache-Control"] = "public, max-age=86400"
        return resp
    except Exception as e:
        return f"Proxy error: {str(e)}", 502

