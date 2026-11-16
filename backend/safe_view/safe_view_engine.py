"""
PhishGuard AI V7.3 — Safe Web View: Complete Orchestration Engine
=================================================================
Coordinates the complete high-performance Safe Web View lifecycle:
  1. Target SSRF verification
  2. Isolated VirtualBox analysis VM dispatch with browser context reuse
  3. Safe read-only HTML sanitization with strict CSP
  4. Instant root page availability (viewer opens immediately without waiting for crawl)
  5. Asynchronous XML sitemap discovery (non-blocking)
  6. Priority Queue with dynamic promotion (User-selected pages jump the queue)
  7. Controlled concurrent worker pool (default 3 concurrent workers)
  8. Sub-millisecond in-memory representation caching
  9. Real-time live crawl telemetry (discovered, queued, analyzing, available)
  10. [PERF] high-resolution performance metrics
"""

from __future__ import annotations

import os
import re
import html
import time
import uuid
import heapq
import threading
import requests
from requests.adapters import HTTPAdapter
from urllib.parse import urlparse, urldefrag, urljoin
from typing import Any, Optional

from detection.ssrf_guard import validate_url_safe
from deep_scan.vm_controller import run_deep_scan, check_sandbox_availability, get_sandbox_status
from .session_manager import session_manager, SafeViewSession
from .sanitizer import html_sanitizer
from .discovery_engine import page_discovery_engine, _AUTH_KEYWORDS, _INFO_KEYWORDS
from .forensic_engine import forensic_engine


# Executable/archive binary extensions blocked from download in read-only mode
_BLOCKED_DOWNLOAD_EXTENSIONS = (
    ".exe", ".msi", ".dmg", ".apk", ".zip", ".rar", ".7z",
    ".tar", ".gz", ".bin", ".iso", ".bat", ".ps1", ".sh", ".vbs", ".jar",
)

_WRITE_QUERY_RE = re.compile(
    r'(?:^|&)(?:method|_method)=(?:post|put|delete|patch)\b|'
    r'(?:^|&)(?:action|cmd|op)=(?:delete|remove|destroy|wipe|purge|drop|update|edit|create|insert|submit|pay|purchase|checkout|logout|signout|unsubscribe)\b',
    re.IGNORECASE,
)

# Priority Levels (Lower number = higher execution priority)
PRIORITY_USER_SELECTED = 0  # Page explicitly clicked/viewed by user (Queue jump)
PRIORITY_ROOT_CHILD = 1     # Direct children of current page / key auth routes
PRIORITY_IMPORTANT = 2      # Common functional pages (/about, /contact, etc.)
PRIORITY_NORMAL = 3         # General internal discovered links
PRIORITY_SITEMAP = 4        # Asynchronously discovered sitemap entries


class PriorityCrawlQueue:
    """
    Thread-safe priority queue for multi-page crawl jobs with dynamic promotion.
    Enables user-selected pages to immediately jump to the front of the queue.
    """

    def __init__(self) -> None:
        self._heap: list[list[Any]] = []  # [priority, depth, seq_id, candidate_dict]
        self._lock = threading.RLock()
        self._cond = threading.Condition(self._lock)
        self._seq = 0
        self._page_id_map: dict[str, list[Any]] = {}  # page_id -> entry
        self._closed = False

    def push(self, candidate: dict[str, Any], priority: int = PRIORITY_NORMAL, depth: int = 1) -> None:
        with self._lock:
            if self._closed:
                return
            pid = candidate.get("page_id", "")
            if pid and pid in self._page_id_map:
                entry = self._page_id_map[pid]
                if priority < entry[0]:
                    entry[0] = priority
                    heapq.heapify(self._heap)
                    self._cond.notify_all()
                return

            self._seq += 1
            entry = [priority, depth, self._seq, candidate]
            heapq.heappush(self._heap, entry)
            if pid:
                self._page_id_map[pid] = entry
            self._cond.notify()

    def pop(self, timeout: float = 1.0) -> Optional[dict[str, Any]]:
        with self._lock:
            end_time = time.time() + timeout
            while not self._heap and not self._closed:
                remaining = end_time - time.time()
                if remaining <= 0:
                    return None
                self._cond.wait(remaining)

            if not self._heap:
                return None

            entry = heapq.heappop(self._heap)
            cand = entry[3]
            pid = cand.get("page_id", "")
            if pid in self._page_id_map:
                del self._page_id_map[pid]
            return cand

    def promote(self, page_id: str) -> bool:
        """Promote a queued candidate to PRIORITY_USER_SELECTED (Priority 0)."""
        with self._lock:
            if page_id in self._page_id_map:
                entry = self._page_id_map[page_id]
                entry[0] = PRIORITY_USER_SELECTED
                heapq.heapify(self._heap)
                self._cond.notify_all()
                print(f"[CRAWLER] Page {page_id} promoted to PRIORITY_USER_SELECTED (Queue jump)", flush=True)
                return True
            return False

    def contains(self, page_id: str) -> bool:
        with self._lock:
            return page_id in self._page_id_map

    def remove(self, page_id: str) -> Optional[dict[str, Any]]:
        """Removes and returns candidate from queue if present (for direct on-demand taking)."""
        with self._lock:
            if page_id in self._page_id_map:
                entry = self._page_id_map.pop(page_id)
                self._heap = [e for e in self._heap if e[3].get("page_id") != page_id]
                heapq.heapify(self._heap)
                return entry[3]
            return None

    def size(self) -> int:
        with self._lock:
            return len(self._heap)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._cond.notify_all()


class SafeViewEngine:
    """Orchestrator for Safe Web View analysis sessions and multi-page crawling."""

    def __init__(self) -> None:
        self.default_max_pages = int(os.environ.get("PHISHGUARD_CRAWL_MAX_PAGES", "50"))
        self.default_max_depth = int(os.environ.get("PHISHGUARD_CRAWL_MAX_DEPTH", "4"))
        self.default_crawl_timeout = float(os.environ.get("PHISHGUARD_CRAWL_MAX_TIME", "120.0"))
        self.concurrency = int(os.environ.get("PHISHGUARD_CRAWL_CONCURRENCY", "2"))

        self._session_queues: dict[str, PriorityCrawlQueue] = {}
        self._session_locks: dict[str, threading.RLock] = {}
        self._page_events: dict[str, dict[str, threading.Event]] = {}
        self._visited_urls: dict[str, set[str]] = {}
        self._active_workers: dict[str, int] = {}
        self._active_session_id: Optional[str] = None
        self._user_nav_pause_until: float = 0.0
        self._global_lock = threading.RLock()

        # Pooled HTTP session for ultra-fast interactive SSR navigation
        self._http_session = requests.Session()
        _http_adapter = HTTPAdapter(pool_connections=16, pool_maxsize=32)
        self._http_session.mount("http://", _http_adapter)
        self._http_session.mount("https://", _http_adapter)

    def _pause_background_crawl(self, seconds: float = 8.0) -> None:
        """Temporarily yields background crawl workers so interactive user clicks never wait behind VM slots."""
        self._user_nav_pause_until = max(self._user_nav_pause_until, time.time() + seconds)

    def _is_usable_cached_page(self, pdata: Optional[dict[str, Any]]) -> bool:
        """Returns True only if a cached page has usable rendered content (never caches FAILED/TIMEOUT stubs as hits)."""
        if not pdata or not isinstance(pdata, dict):
            return False
        scan_st = str(pdata.get("scan_status") or "").upper()
        if scan_st in ("FAILED", "TIMEOUT", "UNAVAILABLE", "BLOCKED", "ANALYZING", "QUEUED"):
            return False
        if pdata.get("error_type") or not pdata.get("page_available", True):
            return False
        safe_html = pdata.get("safe_html") or ""
        if "PAGE NAVIGATION FAILED" in safe_html:
            return False
        return bool(safe_html) and (scan_st in ("AVAILABLE", "PARTIAL", "SUCCESS") or bool(pdata.get("page_available")))

    def _is_spa_or_bot_gate(self, html_text: str, http_status: Optional[int]) -> bool:
        """Detects client-side JS SPAs and anti-bot challenges that require full VM Chromium execution."""
        if not html_text:
            return True
        low = html_text.lower()
        stripped = html_text.strip()

        challenge_markers = (
            "cf-browser-verification",
            "just a moment...",
            "checking your browser before accessing",
            "enable javascript and cookies to continue",
            "ddos-guard",
            "attention required! | cloudflare",
            "px-captcha",
            "/_Incapsula_Resource",
            "sucuri website firewall",
        )
        if any(m in low for m in challenge_markers):
            return True
        if http_status in (403, 429, 503) and len(stripped) < 2500:
            return True

        # Strip scripts/styles/noscript/tags to measure real server-rendered visible text
        no_script = re.sub(r'<(?:script|style|noscript)\b[^>]*>.*?</\s*(?:script|style|noscript)\s*>', ' ', html_text, flags=re.IGNORECASE | re.DOTALL)
        visible_text = re.sub(r'<[^>]+>', ' ', no_script)
        visible_len = len(re.sub(r'\s+', ' ', visible_text).strip())

        if visible_len < 80:
            has_spa_mount = bool(re.search(r'id=["\'](?:root|app|__next|__nuxt)["\']|ng-app|data-reactroot|enable javascript to run', low))
            script_count = len(re.findall(r'<\s*script\b', low))
            if has_spa_mount or script_count >= 2:
                return True
            if re.search(r'http-equiv\s*=\s*["\']?refresh["\']?', low):
                return True

        return False

    def _get_queue(self, session_id: str) -> PriorityCrawlQueue:
        with self._global_lock:
            if session_id not in self._session_queues:
                self._session_queues[session_id] = PriorityCrawlQueue()
            return self._session_queues[session_id]

    def _get_page_event(self, session_id: str, page_id: str) -> threading.Event:
        with self._global_lock:
            if session_id not in self._page_events:
                self._page_events[session_id] = {}
            if page_id not in self._page_events[session_id]:
                self._page_events[session_id][page_id] = threading.Event()
            return self._page_events[session_id][page_id]

    def _set_page_event(self, session_id: str, page_id: str) -> None:
        with self._global_lock:
            if session_id in self._page_events and page_id in self._page_events[session_id]:
                self._page_events[session_id][page_id].set()

    def start_analysis(
        self,
        url: str,
        discover_pages: bool = True,
        max_pages: Optional[int] = None,
        max_depth: Optional[int] = None,
        device_profile: str = "desktop",
    ) -> dict[str, Any]:
        """
        Initiates a safe analysis session for a suspicious target URL.
        Analyzes the root page immediately so the user can browse right away,
        while background workers concurrently discover and analyze remaining pages.
        """
        t_init = time.perf_counter()
        url = (url or "").strip()
        if not url:
            return {"success": False, "error": "No URL provided"}

        effective_max_pages = max_pages if (max_pages and max_pages > 0) else self.default_max_pages
        effective_max_depth = max_depth if (max_depth and max_depth > 0) else self.default_max_depth

        print(f"[SCAN] scan_id=INIT url={url}", flush=True)

        # Step 1: Pre-navigation SSRF Guard (Requirement 11)
        ssrf = validate_url_safe(url)
        if not ssrf.get("safe", True):
            print(f"[SECURITY] Pre-crawl SSRF blocked: {url} ({ssrf.get('reason')})", flush=True)
            return {
                "success": False,
                "error": f"BLOCKED BY SSRF GUARD: {ssrf.get('reason')}",
                "error_type": "BLOCKED_BY_SSRF_GUARD",
                "security_block": True,
            }

        # Step 2: Create isolated session with configurable bounds
        session = session_manager.create_session(target_url=url)
        self._active_session_id = session.session_id
        session.discovery_stats["max_pages"] = effective_max_pages
        session.discovery_stats["max_depth"] = effective_max_depth
        session.discovery_stats["status"] = "ANALYZING_ROOT"
        session.status = "ANALYZING"

        # Step 3: Analyze the initial root page immediately (Requirement 3: First page loads first)
        t_root_start = time.perf_counter()
        print(f"[CRAWLER] Seed URL={url} session_id={session.session_id} device_profile={device_profile}", flush=True)
        root_page_data = self._scan_and_process_page(
            url=url,
            session_id=session.session_id,
            page_id="p_root",
            is_root=True,
            depth=0,
            parent_page_id=None,
            discovered_from=None,
            fast_mode=False,
            device_profile=device_profile,
        )

        session.add_page("p_root", root_page_data)
        session.root_page_id = "p_root"
        session.status = "READY"
        self._set_page_event(session.session_id, "p_root")

        root_elapsed = round((time.perf_counter() - t_root_start) * 1000, 1)
        print(f"[PERF] Root page ready and AVAILABLE in {root_elapsed}ms", flush=True)

        # Step 4: Page Discovery (DOM Link Extraction from rendered root)
        if discover_pages:
            try:
                rendered_content = root_page_data.get("dom_snapshot") or root_page_data.get("html_raw") or ""
                browser_links = root_page_data.get("discovered_links", [])

                discovery_result = page_discovery_engine.extract_all_links(
                    html_content=rendered_content,
                    current_url=root_page_data.get("final_url", url),
                    target_origin_url=url,
                    current_depth=0,
                    browser_links=browser_links,
                    parent_page_id="p_root",
                )

                candidates = discovery_result.get("candidates", [])
                blocked = discovery_result.get("blocked_actions", [])
                ext_domains = discovery_result.get("external_domains", [])

                session.add_external_domains(ext_domains)
                for b in blocked:
                    session.add_blocked_action(
                        url=b["url"],
                        path=b["path"],
                        reason=b["reason"],
                        context=b.get("context", ""),
                    )

                # Initialize priority queue
                queue = self._get_queue(session.session_id)
                visited: set[str] = {url.lower(), root_page_data.get("final_url", url).lower()}
                with self._global_lock:
                    self._visited_urls[session.session_id] = visited

                for idx, cand in enumerate(candidates):
                    if cand.get("is_root"):
                        continue
                    cand_url = cand.get("url", "")
                    if cand_url.lower() in visited:
                        continue

                    cand_page_id = f"p_{idx + 1}"
                    cand["page_id"] = cand_page_id
                    cand["representation_id"] = cand_page_id

                    # Assign priority based on path heuristics (Requirement 5)
                    cand_path = cand.get("path", "").lower()
                    if any(k in cand_path for k in _AUTH_KEYWORDS):
                        prio = PRIORITY_ROOT_CHILD
                    elif any(k in cand_path for k in _INFO_KEYWORDS):
                        prio = PRIORITY_IMPORTANT
                    else:
                        prio = PRIORITY_NORMAL

                    cand["priority"] = prio

                    session.add_discovered_candidate(
                        page_id=cand_page_id,
                        url=cand["url"],
                        path=cand["path"],
                        depth=cand.get("depth", 1),
                        title=cand.get("title", ""),
                        priority=prio,
                        is_root=False,
                        parent_page_id="p_root",
                        discovered_from=url,
                        canonical_url=cand.get("canonical_url"),
                    )

                    queue.push(cand, priority=prio, depth=cand.get("depth", 1))

                session.discovery_stats["links_found"] = len(candidates) + len(blocked)
                session.discovery_stats["pages_discovered"] = len(session.discovered_pages)
                session.discovery_stats["pages_queued"] = queue.size()
                session.discovery_stats["status"] = "CRAWLING"

                print(f"[CRAWLER] Discovered {len(candidates)} links from root. Queue size={queue.size()}", flush=True)

                # Step 5: Launch non-blocking Asynchronous Sitemap Discovery (Requirement 25)
                threading.Thread(
                    target=self._async_sitemap_fetch,
                    args=(session.session_id, url, effective_max_pages),
                    daemon=True,
                ).start()

                # Step 6: Launch Controlled Concurrent Worker Pool (Requirement 11 & 12)
                for worker_id in range(self.concurrency):
                    worker_thread = threading.Thread(
                        target=self._concurrent_crawler_worker,
                        args=(session.session_id, worker_id, url, effective_max_pages, effective_max_depth),
                        daemon=True,
                    )
                    worker_thread.start()

            except Exception as disc_exc:
                print(f"[PAGE_DISCOVERY] Link discovery warning: {disc_exc}", flush=True)

        total_init_time = round((time.perf_counter() - t_init) * 1000, 1)
        print(f"[PERF] start_analysis completed in {total_init_time}ms | Safe Web View READY", flush=True)

        return session.to_dict()

    def start_background_crawl(
        self,
        session_id: str,
        initial_candidates: list[dict[str, Any]],
        target_origin_url: str,
        max_pages: int = 50,
        max_depth: int = 4,
    ) -> None:
        """
        Launches concurrent background workers to crawl and analyze discovered candidate pages.
        Called when a session is initialized via /predict or /safe-view/analyze.
        """
        session = session_manager.get_session(session_id)
        if not session:
            return

        self._active_session_id = session_id

        queue = self._get_queue(session_id)
        with self._global_lock:
            visited = self._visited_urls.setdefault(session_id, set())
            visited.add(target_origin_url.lower())

        for cand in initial_candidates:
            cand_url = cand.get("url", "")
            if not cand_url or cand_url.lower() in visited:
                continue

            cand_prio = cand.get("priority", PRIORITY_NORMAL)
            cand_depth = cand.get("depth", 1)
            queue.push(cand, priority=cand_prio, depth=cand_depth)

        session.discovery_stats["status"] = "CRAWLING"
        session.discovery_stats["pages_queued"] = queue.size()

        # Launch Asynchronous Sitemap Discovery (Requirement 25)
        threading.Thread(
            target=self._async_sitemap_fetch,
            args=(session_id, target_origin_url, max_pages),
            daemon=True,
        ).start()

        # Launch Concurrent Worker Pool (Requirement 11 & 12)
        for worker_id in range(self.concurrency):
            worker_thread = threading.Thread(
                target=self._concurrent_crawler_worker,
                args=(session_id, worker_id, target_origin_url, max_pages, max_depth),
                daemon=True,
            )
            worker_thread.start()

        print(f"[CRAWLER] Started {self.concurrency} background workers for session {session_id} with {queue.size()} queued items", flush=True)

    # Backward compatibility alias
    _background_discovery_worker = start_background_crawl

    def prioritize_page(self, session_id: str, page_id: str) -> bool:
        """
        Promotes a candidate page to Priority 0 so workers pick it up next (Requirement 6).
        """
        session = session_manager.get_session(session_id)
        if not session:
            return False

        if session.is_page_analyzed(page_id):
            return True

        queue = self._session_queues.get(session_id)
        if queue:
            promoted = queue.promote(page_id)
            if promoted:
                session.update_page_status(page_id, "QUEUED")
                return True
        return False

    def analyze_page_on_demand(
        self,
        session_id: str,
        page_id: str,
        device_profile: str = "desktop",
        force_retry: bool = False,
    ) -> Optional[dict[str, Any]]:
        """
        Immediate on-demand page prioritization when a user clicks a page/link.
        1. Returns immediately if already usable in cache (<1ms)
        2. Yields to in-flight scan (max 6s) or pauses background crawl workers
        3. Serves SSR/static HTML via fast pooled HTTP (~150-450ms) and escalates SPAs/challenges to VM Playwright
        """
        t_demand_start = time.perf_counter()
        session = session_manager.get_session(session_id)
        if not session:
            return None

        # Root page guard: if p_root is already usable in session, return it without rescanning
        if not force_retry and (page_id == "p_root" or page_id == session.root_page_id):
            existing_root = (
                session.get_page(page_id)
                or session.get_page("p_root")
                or (session.get_page(session.root_page_id) if session.root_page_id else None)
            )
            if existing_root and self._is_usable_cached_page(existing_root):
                return existing_root

        # 1. Instant return from cache if already usable in session storage
        existing = session.get_page(page_id)
        if not force_retry and existing and self._is_usable_cached_page(existing):
            existing_profile = existing.get("device_profile", "desktop")
            if existing_profile == device_profile:
                elapsed_cached = round((time.perf_counter() - t_demand_start) * 1000, 2)
                print(f"[PERF] Instant page retrieval for {page_id} in {elapsed_cached}ms (from stored representation)", flush=True)
                return existing
            raw_for_profile = existing.get("dom_snapshot") or existing.get("html_raw")
            if raw_for_profile and len(raw_for_profile) > 50 and "PAGE NAVIGATION FAILED" not in (existing.get("safe_html") or ""):
                safe_html, elements_map, content_inventory = html_sanitizer.sanitize(
                    html_content=raw_for_profile,
                    base_url=existing.get("url", ""),
                    http_status=existing.get("http_status"),
                )
                existing["safe_html"] = safe_html
                existing["elements_map"] = elements_map
                existing["content_inventory"] = content_inventory
                existing["device_profile"] = device_profile
                existing["updated_at"] = time.time()
                return existing

        # 2. Check candidate registry
        disc_info = session.discovered_pages.get(page_id)
        if not disc_info:
            print(f"[SAFEVIEW] Page {page_id} not found in candidate registry for session {session_id}", flush=True)
            return None

        target_url = disc_info["url"]
        ssrf = validate_url_safe(target_url)
        if not ssrf.get("safe", True):
            print(f"[SAFEVIEW] Page {page_id} blocked by SSRF guard: {target_url}", flush=True)
            return None

        self._pause_background_crawl(10.0)

        # 3. Atomically check if another worker/request is actively analyzing this page
        with session.lock:
            disc_info = session.discovered_pages.get(page_id)
            if not disc_info:
                return None
            already_analyzing = disc_info.get("status") == "ANALYZING" and not force_retry
            if not already_analyzing:
                session.update_page_status(page_id, "ANALYZING")
                self._get_page_event(session_id, page_id)

        if already_analyzing:
            print(f"[SAFEVIEW] Worker actively analyzing {page_id}, awaiting completion (max 6.0s)...", flush=True)
            evt = self._get_page_event(session_id, page_id)
            evt.wait(timeout=6.0)
            page_data = session.get_page(page_id)
            if page_data and self._is_usable_cached_page(page_data):
                elapsed = round((time.perf_counter() - t_demand_start) * 1000, 1)
                print(f"[PERF] Prioritized page {page_id} analyzed by worker in {elapsed}ms", flush=True)
                return page_data

        # 4. Immediate on-demand analysis (take directly from queue with ZERO delay)
        queue = self._session_queues.get(session_id)
        if queue:
            queue.remove(page_id)

        print(f"[SAFEVIEW] Fast on-demand analysis for {page_id} ({target_url})", flush=True)
        try:
            page_data = self._fast_render_or_scan_page(
                session=session,
                url=target_url,
                page_id=page_id,
                is_root=disc_info.get("is_root", False),
                depth=disc_info.get("depth", 1),
                parent_page_id=disc_info.get("parent_page_id"),
                discovered_from=disc_info.get("discovered_from"),
                device_profile=device_profile,
            )
            if page_data and not page_data.get("_write_blocked") and not page_data.get("_ssrf_blocked"):
                session.add_page(page_id, page_data)
        finally:
            self._set_page_event(session_id, page_id)

        elapsed = round((time.perf_counter() - t_demand_start) * 1000, 1)
        print(f"[PERF] Fast on-demand page {page_id} completed in {elapsed}ms", flush=True)
        return page_data

    def _fast_render_or_scan_page(
        self,
        session: SafeViewSession,
        url: str,
        page_id: str,
        is_root: bool = False,
        depth: int = 1,
        parent_page_id: Optional[str] = "p_root",
        discovered_from: Optional[str] = None,
        device_profile: str = "desktop",
    ) -> dict[str, Any]:
        """
        Serves static/SSR HTML pages immediately (~150-450ms) via pooled SSRF-safe HTTP
        and escalates SPAs, anti-bot challenges, or HTTP failures to VM Playwright (fast_mode=True).
        """
        t_start = time.perf_counter()
        fast_rec = self.recover_html_via_http(url, fast_interactive=True)
        if fast_rec:
            if fast_rec.get("binary_download"):
                return {
                    "_write_blocked": True,
                    "blocked_url": fast_rec.get("final_url", url),
                    "reason": "Blocked binary file download in read-only mode (only web page viewing allowed)",
                }
            if fast_rec.get("ssrf_redirect_blocked"):
                return {
                    "_ssrf_blocked": True,
                    "blocked_url": fast_rec.get("blocked_url", url),
                    "reason": fast_rec.get("reason", "Redirect target blocked by SSRF guard"),
                }

            rec_html = fast_rec.get("html") or ""
            rec_status = fast_rec.get("http_status")
            final_url = fast_rec.get("final_url") or url

            if rec_html and not self._is_spa_or_bot_gate(rec_html, rec_status):
                parsed = urlparse(final_url)
                path = parsed.path or "/"
                safe_html, elements_map, content_inventory = html_sanitizer.sanitize(
                    html_content=rec_html,
                    base_url=final_url,
                    http_status=rec_status,
                )

                sub_discovery = page_discovery_engine.extract_all_links(
                    html_content=rec_html,
                    current_url=final_url,
                    target_origin_url=session.target_url,
                    current_depth=depth,
                    browser_links=[],
                    parent_page_id=page_id,
                )
                with session.lock:
                    max_p = getattr(session, "max_pages", self.default_max_pages) or self.default_max_pages
                    for b in sub_discovery.get("blocked_actions", []):
                        session.add_blocked_action(
                            url=b["url"],
                            path=b["path"],
                            reason=b["reason"],
                            context=b.get("context", ""),
                        )
                    for sub_cand in sub_discovery.get("candidates", []):
                        if len(session.discovered_pages) >= max_p:
                            break
                        sub_url = sub_cand.get("url")
                        if not sub_url:
                            continue
                        already = any(
                            (d.get("url", "").lower() == sub_url.lower())
                            for d in session.discovered_pages.values()
                        )
                        if not already:
                            cand_pid = f"p_{len(session.discovered_pages) + 1}_{uuid.uuid4().hex[:4]}"
                            session.add_discovered_candidate(
                                page_id=cand_pid,
                                url=sub_url,
                                path=sub_cand.get("path", "/"),
                                depth=min(depth + 1, self.default_max_depth),
                                title=sub_cand.get("title") or sub_cand.get("path", "/"),
                                priority=PRIORITY_NORMAL,
                                is_root=False,
                                parent_page_id=page_id,
                                discovered_from=final_url,
                            )

                load_ms = round((time.perf_counter() - t_start) * 1000, 1)
                ssr_dom_behavior = {
                    "script_modifications": 0,
                    "has_inline_scripts": bool(re.search(r'<\s*script\b', rec_html, re.IGNORECASE)),
                    "mutation_metrics": {"total_mutations": 0},
                    "behavioral_events": [],
                }
                ssr_raw_ds = {
                    "network_requests": [],
                    "redirect_chain": fast_rec.get("redirect_chain", [final_url]),
                    "http_status": rec_status or 200,
                    "scripts": [],
                    "forms": [],
                    "password_fields": [],
                }
                dom_diff = forensic_engine.compute_dom_diff(
                    initial_dom=rec_html,
                    final_dom=rec_html,
                    dom_behavior=ssr_dom_behavior,
                    base_url=final_url,
                )
                network_forensics = forensic_engine.compile_network_forensics(
                    raw_ds=ssr_raw_ds,
                    base_url=final_url,
                )
                if fast_rec.get("redirect_chain"):
                    network_forensics["redirect_chain"] = fast_rec["redirect_chain"]
                timeline = forensic_engine.build_temporal_timeline(
                    raw_ds=ssr_raw_ds,
                    load_time_ms=load_ms,
                    dom_behavior=ssr_dom_behavior,
                    network_requests=network_forensics.get("requests", []),
                )

                has_pw = bool(re.search(r'<input[^>]+type\s*=\s*["\']?password["\']?', rec_html, re.IGNORECASE))
                has_hidden_iframe = any(e.get("risk_type") == "hidden_iframe" for e in elements_map)
                risk_level = "HIGH" if (has_pw or has_hidden_iframe) else ("MEDIUM" if any(e.get("is_external") for e in elements_map) else "LOW")
                scan_status = "AVAILABLE" if (rec_status is None or rec_status < 400) else "PARTIAL"

                print(f"[PERF] Fast SSR navigation {final_url} ({rec_status}) completed in {load_ms}ms", flush=True)
                return {
                    "page_id": page_id,
                    "representation_id": page_id,
                    "session_id": session.session_id,
                    "scan_id": session.session_id,
                    "url": final_url,
                    "original_url": url,
                    "canonical_url": final_url,
                    "path": path,
                    "title": fast_rec.get("page_title") or path,
                    "http_status": rec_status,
                    "depth": depth,
                    "parent_page_id": parent_page_id,
                    "discovered_from": discovered_from,
                    "is_root": is_root,
                    "load_time_ms": load_ms,
                    "risk_level": risk_level,
                    "has_credentials": has_pw,
                    "scan_status": scan_status,
                    "status": scan_status,
                    "page_available": True,
                    "error": None,
                    "error_type": None,
                    "error_details": None,
                    "failed_resources": [],
                    "redirect_chain": fast_rec.get("redirect_chain", [final_url]),
                    "redirect_count": max(0, len(fast_rec.get("redirect_chain", [])) - 1),
                    "screenshot_b64": None,
                    "screenshot_type": "none",
                    "safe_html": safe_html,
                    "html_raw": rec_html,
                    "dom_snapshot": rec_html,
                    "elements_map": elements_map,
                    "content_inventory": content_inventory,
                    "forms": [],
                    "links_count": content_inventory.get("links", 0),
                    "discovered_links": [],
                    "dom_diff": dom_diff,
                    "dom_behavior": {
                        "script_modifications": 0,
                        "has_inline_scripts": bool(re.search(r'<\s*script\b', rec_html, re.IGNORECASE)),
                    },
                    "network_forensics": network_forensics,
                    "timeline": timeline,
                    "suspicious_indicators": ["Credential harvesting form detected"] if has_pw else [],
                    "page_states": [
                        {"name": "Initial SSR HTML (T0)", "status": "Captured", "size": len(rec_html)},
                        {"name": "Sanitized Read-Only DOM", "status": "Captured", "size": len(safe_html)},
                    ],
                    "security_status": {
                        "isolated": True,
                        "read_only": True,
                        "interactions_blocked": True,
                        "scripts_disabled": True,
                    },
                    "reachability_state": (
                        "REACHABLE_HTTP_2XX" if (rec_status is not None and 200 <= rec_status < 300) else
                        "REACHABLE_HTTP_3XX" if (rec_status is not None and 300 <= rec_status < 400) else
                        "REACHABLE_HTTP_4XX" if (rec_status is not None and 400 <= rec_status < 500) else
                        "REACHABLE_HTTP_5XX" if (rec_status is not None and 500 <= rec_status < 600) else
                        "REACHABLE_HTTP_2XX"
                    ),
                    "browser_render_state": "FAST_HTTP_SSR_RENDERED",
                    "server_response_message": f"Server reachable (HTTP {rec_status or 200}) — fast SSR isolated view.",
                    "device_profile": device_profile,
                    "scan_method": "fast_http_ssr",
                    "created_at": time.time(),
                    "updated_at": time.time(),
                }

        # Fallback / SPA escalation: pause background crawl & execute VM Chromium (fast_mode=True)
        self._pause_background_crawl(10.0)
        return self._scan_and_process_page(
            url=url,
            session_id=session.session_id,
            page_id=page_id,
            is_root=is_root,
            depth=depth,
            parent_page_id=parent_page_id,
            discovered_from=discovered_from,
            fast_mode=True,
            device_profile=device_profile,
        )

    def _check_read_only_write_restriction(self, url: str) -> tuple[bool, str]:
        """
        Enforces strict Read-Only navigation policy.
        Blocks destructive, payment, auth state-change, write-method queries, and binary downloads.
        """
        try:
            parsed = urlparse(url)
            lower_path = (parsed.path or "/").lower()
            lower_query = (parsed.query or "").lower()
        except Exception:
            return False, ""

        if any(lower_path.endswith(ext) for ext in _BLOCKED_DOWNLOAD_EXTENSIONS):
            return True, "Blocked file download in read-only mode (only web page viewing allowed)"

        if lower_query and _WRITE_QUERY_RE.search(lower_query):
            return True, "Blocked write/state-changing query action in read-only mode"

        is_destructive, reason = page_discovery_engine._check_destructive_action(lower_path, lower_query)
        if is_destructive:
            return True, reason

        return False, ""

    def _url_lookup_variants(self, raw_url: str) -> set[str]:
        """Produces normalized URL keys for tolerant cache/registry matching."""
        variants: set[str] = set()
        if not raw_url:
            return variants
        clean, _ = urldefrag(raw_url.strip())
        variants.add(clean.lower())
        variants.add(clean.rstrip("/").lower())
        try:
            parsed = urlparse(clean)
            scheme = (parsed.scheme or "https").lower()
            alt_scheme = "http" if scheme == "https" else "https"
            netloc = (parsed.netloc or "").lower()
            path = re.sub(r"/+", "/", parsed.path or "/")
            stripped_path = path.rstrip("/") or "/"
            query = f"?{parsed.query}" if parsed.query else ""
            for sc in (scheme, alt_scheme):
                variants.add(f"{sc}://{netloc}{path}{query}")
                variants.add(f"{sc}://{netloc}{stripped_path}{query}")
        except Exception:
            pass
        return variants

    def navigate_by_url(
        self,
        session_id: str,
        url: str,
        device_profile: str = "desktop",
        force_retry: bool = False,
    ) -> dict[str, Any]:
        """
        Direct browser-like URL navigation inside an active Safe Web View session.
        Enforces strict Read-Only & SSRF policies, serves cached pages in 0ms,
        and scans uncached pages immediately via fast SSR HTTP or fast_mode VM.
        """
        t_nav_start = time.perf_counter()
        session = session_manager.get_session(session_id)
        if not session:
            return {
                "success": False,
                "error_code": "SESSION_EXPIRED",
                "reason": "Analysis session expired or missing. Please run the scan again.",
            }

        clean_url, _ = urldefrag((url or "").strip())
        parsed = urlparse(clean_url)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
            return {
                "success": False,
                "write_blocked": True,
                "error_code": "UNSUPPORTED_SCHEME",
                "reason": "Only HTTP/HTTPS read navigation is permitted in Safe Web View.",
            }

        # 1. SSRF Guard
        ssrf = validate_url_safe(clean_url)
        if not ssrf.get("safe", True):
            reason = ssrf.get("reason") or "Target blocked by SSRF security policy"
            session.add_blocked_action(clean_url, parsed.path or "/", reason, context="Direct Link Navigation")
            return {
                "success": False,
                "security_block": True,
                "write_blocked": True,
                "error_code": "BLOCKED_BY_SSRF_GUARD",
                "reason": reason,
            }

        # 2. Strict Read-Only Write Restriction Check
        is_write_blocked, write_reason = self._check_read_only_write_restriction(clean_url)
        if is_write_blocked:
            session.add_blocked_action(clean_url, parsed.path or "/", write_reason, context="Direct Link Navigation")
            return {
                "success": False,
                "write_blocked": True,
                "error_code": "READ_ONLY_WRITE_BLOCKED",
                "reason": write_reason,
                "blocked_url": clean_url,
            }

        variants = self._url_lookup_variants(clean_url)

        # 3. Check already analyzed pages cache first (0ms), skipping failed stubs so clicks can retry cleanly
        matched_pid: Optional[str] = None
        stale_failed_pid: Optional[str] = None
        with session.lock:
            for pid, pdata in session.pages.items():
                p_urls = {pdata.get("url", ""), pdata.get("original_url", ""), pdata.get("canonical_url", "")}
                if any(self._url_lookup_variants(u) & variants for u in p_urls if u):
                    if not force_retry and self._is_usable_cached_page(pdata):
                        elapsed = round((time.perf_counter() - t_nav_start) * 1000, 2)
                        print(f"[PERF] navigate_by_url cache HIT for {clean_url} ({pid}) in {elapsed}ms", flush=True)
                        return {"success": True, "page_id": pid, "page": pdata, "cached": True}
                    stale_failed_pid = pid

            # 4. Check discovered candidate registry
            for pid, disc in session.discovered_pages.items():
                d_urls = {disc.get("url", ""), disc.get("canonical_url", "")}
                if any(self._url_lookup_variants(u) & variants for u in d_urls if u):
                    matched_pid = pid
                    break

        if not matched_pid and stale_failed_pid:
            matched_pid = stale_failed_pid

        self._pause_background_crawl(10.0)

        if matched_pid:
            retry_flag = force_retry or bool(stale_failed_pid == matched_pid)
            analyzed = self.analyze_page_on_demand(
                session_id,
                matched_pid,
                device_profile=device_profile,
                force_retry=retry_flag,
            )
            if analyzed:
                if analyzed.get("_write_blocked"):
                    session.add_blocked_action(clean_url, parsed.path or "/", analyzed["reason"], context="Direct Link Navigation")
                    return {
                        "success": False,
                        "write_blocked": True,
                        "error_code": "READ_ONLY_WRITE_BLOCKED",
                        "reason": analyzed["reason"],
                        "blocked_url": analyzed.get("blocked_url", clean_url),
                    }
                if analyzed.get("_ssrf_blocked"):
                    return {
                        "success": False,
                        "error_code": "BLOCKED_BY_SSRF_GUARD",
                        "reason": analyzed["reason"],
                    }
                return {"success": True, "page_id": matched_pid, "page": analyzed, "cached": False}

        # 5. Unindexed URL (e.g. beyond max_pages/depth or linked external read-only page): register & scan immediately
        created_new = False
        with session.lock:
            # Re-check under lock in case a concurrent click registered it
            for pid, disc in session.discovered_pages.items():
                d_urls = {disc.get("url", ""), disc.get("canonical_url", "")}
                if any(self._url_lookup_variants(u) & variants for u in d_urls if u):
                    matched_pid = pid
                    break
            if not matched_pid:
                matched_pid = f"p_nav_{len(session.discovered_pages) + 1}_{uuid.uuid4().hex[:4]}"
                session.add_discovered_candidate(
                    page_id=matched_pid,
                    url=clean_url,
                    path=parsed.path or "/",
                    depth=1,
                    title=parsed.path or "/",
                    priority=PRIORITY_USER_SELECTED,
                    is_root=False,
                    parent_page_id="p_root",
                    discovered_from=session.target_url,
                )
                session.update_page_status(matched_pid, "ANALYZING")
                # Register completion event under lock before scanning so concurrent callers await it cleanly
                self._get_page_event(session_id, matched_pid)
                created_new = True

        if created_new:
            with self._global_lock:
                self._visited_urls.setdefault(session_id, set()).add(clean_url.lower())
            try:
                page_data = self._fast_render_or_scan_page(
                    session=session,
                    url=clean_url,
                    page_id=matched_pid,
                    is_root=False,
                    depth=1,
                    parent_page_id="p_root",
                    discovered_from=session.target_url,
                    device_profile=device_profile,
                )
                if page_data.get("_write_blocked"):
                    session.update_page_status(matched_pid, "BLOCKED")
                    session.add_blocked_action(clean_url, parsed.path or "/", page_data["reason"], context="Direct Link Navigation")
                    return {
                        "success": False,
                        "write_blocked": True,
                        "error_code": "READ_ONLY_WRITE_BLOCKED",
                        "reason": page_data["reason"],
                        "blocked_url": page_data.get("blocked_url", clean_url),
                    }
                if page_data.get("_ssrf_blocked"):
                    session.update_page_status(matched_pid, "BLOCKED")
                    return {
                        "success": False,
                        "error_code": "BLOCKED_BY_SSRF_GUARD",
                        "reason": page_data["reason"],
                    }
                session.add_page(matched_pid, page_data)
            finally:
                self._set_page_event(session_id, matched_pid)
            elapsed = round((time.perf_counter() - t_nav_start) * 1000, 1)
            print(f"[PERF] Direct on-demand navigate {clean_url} -> {matched_pid} completed in {elapsed}ms", flush=True)
            return {"success": True, "page_id": matched_pid, "page": page_data, "cached": False}

        analyzed = self.analyze_page_on_demand(session_id, matched_pid, device_profile=device_profile, force_retry=force_retry)
        if analyzed:
            return {"success": True, "page_id": matched_pid, "page": analyzed, "cached": False}
        return {"success": False, "error_code": "NAVIGATION_FAILED", "reason": "Unable to load target page representation."}

    def _async_sitemap_fetch(self, session_id: str, target_origin_url: str, max_pages: int) -> None:
        """
        Background sitemap discovery worker.
        Runs completely asynchronously and does NOT delay the initial Safe Web View (Requirement 25).
        """
        session = session_manager.get_session(session_id)
        if not session:
            return

        try:
            print(f"[CRAWLER] Asynchronous sitemap ingestion starting for {target_origin_url}...", flush=True)
            sitemap_candidates = page_discovery_engine.fetch_sitemap(target_origin_url)
            if not sitemap_candidates:
                return

            queue = self._get_queue(session_id)
            with self._global_lock:
                visited = self._visited_urls.get(session_id, set())

            added = 0
            for sm in sitemap_candidates:
                if len(session.discovered_pages) >= max_pages:
                    break
                sm_url = sm.get("url", "")
                if not sm_url or sm_url.lower() in visited:
                    continue

                existing = any(d.get("url", "").lower() == sm_url.lower() for d in session.discovered_pages.values())
                if existing:
                    continue

                new_pid = f"p_{len(session.discovered_pages) + 1}"
                sm["page_id"] = new_pid
                sm["representation_id"] = new_pid
                sm["priority"] = PRIORITY_SITEMAP

                session.add_discovered_candidate(
                    page_id=new_pid,
                    url=sm_url,
                    path=sm.get("path", "/"),
                    depth=1,
                    title=sm.get("title", ""),
                    priority=PRIORITY_SITEMAP,
                    is_root=False,
                    parent_page_id="p_root",
                    discovered_from=target_origin_url,
                    canonical_url=sm.get("canonical_url"),
                )

                queue.push(sm, priority=PRIORITY_SITEMAP, depth=1)
                added += 1

            if added > 0:
                print(f"[CRAWLER] Asynchronous sitemap added {added} new candidate pages (Priority {PRIORITY_SITEMAP})", flush=True)

        except Exception as sm_exc:
            print(f"[CRAWLER] Asynchronous sitemap fetch notice: {sm_exc}", flush=True)

    def _concurrent_crawler_worker(
        self,
        session_id: str,
        worker_id: int,
        target_origin_url: str,
        max_pages: int,
        max_depth: int,
    ) -> None:
        """
        Concurrent crawler worker that processes candidates from PriorityCrawlQueue (Requirement 11 & 12).
        Runs up to PHISHGUARD_CRAWL_CONCURRENCY workers concurrently.
        """
        session = session_manager.get_session(session_id)
        if not session:
            return

        queue = self._get_queue(session_id)
        crawl_start = time.perf_counter()
        max_crawl_time = self.default_crawl_timeout

        print(f"[CRAWLER] Worker {worker_id} started for session {session_id}", flush=True)

        with self._global_lock:
            self._active_workers[session_id] = self._active_workers.get(session_id, 0) + 1

        try:
            while len(session.pages) < max_pages:
                # Stop worker if a newer analysis session was started
                if self._active_session_id and self._active_session_id != session_id:
                    print(f"[CRAWLER] Worker {worker_id} stopping: session {session_id} superseded by {self._active_session_id}", flush=True)
                    break

                # Check crawl timeout
                if (time.perf_counter() - crawl_start) >= max_crawl_time:
                    session.discovery_stats["limit_reached"] = True
                    session.discovery_stats["limit_reason"] = "MAX_TOTAL_CRAWL_TIME_EXCEEDED"
                    break

                # Yield immediately while interactive user navigation is active
                pause_remaining = self._user_nav_pause_until - time.time()
                if pause_remaining > 0:
                    time.sleep(min(0.4, pause_remaining))
                    continue

                cand = queue.pop(timeout=1.0)
                if cand is None:
                    # If crawl limit reached or already completed
                    if len(session.pages) >= max_pages or session.discovery_stats.get("completed"):
                        break
                    # If other workers are actively scanning, wait for them to potentially discover new links
                    if session.discovery_stats.get("pages_processing", 0) > 0:
                        time.sleep(0.3)
                        continue
                    # Both queue is empty and no workers are currently processing:
                    # Grace period (0.8s) to confirm true queue exhaustion
                    time.sleep(0.8)
                    if queue.size() == 0 and session.discovery_stats.get("pages_processing", 0) == 0:
                        break
                    continue

                cand_url = cand.get("url")
                cand_depth = cand.get("depth", 1)
                cand_page_id = cand.get("page_id")

                if not cand_url or not cand_page_id:
                    continue

                with self._global_lock:
                    visited = self._visited_urls.setdefault(session_id, set())
                    if cand_url.lower() in visited:
                        continue
                    visited.add(cand_url.lower())

                # Skip if already analyzed by on-demand request
                if session.is_page_analyzed(cand_page_id):
                    self._set_page_event(session_id, cand_page_id)
                    continue

                # SSRF check on candidate (Requirement 11)
                ssrf = validate_url_safe(cand_url)
                if not ssrf.get("safe", True):
                    print(f"[CRAWLER] SSRF blocked candidate: {cand_url}", flush=True)
                    session.update_page_status(cand_page_id, "BLOCKED")
                    self._set_page_event(session_id, cand_page_id)
                    continue

                # Update live telemetry to ANALYZING (Requirement 23)
                session.update_page_status(cand_page_id, "ANALYZING")
                session.discovery_stats["current_depth"] = cand_depth
                session.discovery_stats["pages_queued"] = queue.size()
                session.discovery_stats["pages_processing"] = session.discovery_stats.get("pages_processing", 0) + 1

                print(f"[CRAWLER] Worker {worker_id} scanning URL={cand_url} Depth={cand_depth} Page ID={cand_page_id}", flush=True)

                try:
                    # Fast Page Analysis for background candidates (Requirement 13 & 14)
                    page_data = self._scan_and_process_page(
                        url=cand_url,
                        session_id=session_id,
                        page_id=cand_page_id,
                        is_root=False,
                        depth=cand_depth,
                        parent_page_id=cand.get("parent_page_id") or "p_root",
                        discovered_from=cand.get("discovered_from") or target_origin_url,
                        fast_mode=True,
                    )

                    session.add_page(cand_page_id, page_data)
                    self._set_page_event(session_id, cand_page_id)
                    print(f"[CRAWLER] Worker {worker_id} completed {cand_page_id} status={page_data.get('scan_status')} ({len(session.pages)}/{max_pages})", flush=True)

                    # Recursive Link Discovery (Requirement 1 & 7)
                    if cand_depth < max_depth and len(session.discovered_pages) < max_pages:
                        new_rendered = page_data.get("dom_snapshot") or page_data.get("html_raw") or ""
                        browser_links = page_data.get("discovered_links", [])

                        sub_discovery = page_discovery_engine.extract_all_links(
                            html_content=new_rendered,
                            current_url=page_data.get("final_url", cand_url),
                            target_origin_url=target_origin_url,
                            current_depth=cand_depth,
                            browser_links=browser_links,
                            parent_page_id=cand_page_id,
                        )

                        session.add_external_domains(sub_discovery.get("external_domains", []))
                        for b in sub_discovery.get("blocked_actions", []):
                            session.add_blocked_action(
                                url=b["url"],
                                path=b["path"],
                                reason=b["reason"],
                                context=b.get("context", ""),
                            )

                        for sub_cand in sub_discovery.get("candidates", []):
                            if len(session.discovered_pages) >= max_pages:
                                break
                            sub_url = sub_cand["url"]
                            if sub_url.lower() in visited:
                                continue

                            existing_entry = any(d.get("url", "").lower() == sub_url.lower() for d in session.discovered_pages.values())
                            if not existing_entry:
                                new_page_id = f"p_{len(session.discovered_pages) + 1}"
                                sub_cand["page_id"] = new_page_id
                                sub_cand["representation_id"] = new_page_id
                                sub_cand["parent_page_id"] = cand_page_id
                                sub_cand["discovered_from"] = cand_url
                                sub_cand["priority"] = PRIORITY_NORMAL

                                session.add_discovered_candidate(
                                    page_id=new_page_id,
                                    url=sub_url,
                                    path=sub_cand["path"],
                                    depth=cand_depth + 1,
                                    title=sub_cand.get("title", ""),
                                    priority=PRIORITY_NORMAL,
                                    is_root=False,
                                    parent_page_id=cand_page_id,
                                    discovered_from=cand_url,
                                    canonical_url=sub_cand.get("canonical_url"),
                                )

                                queue.push(sub_cand, priority=PRIORITY_NORMAL, depth=cand_depth + 1)

                except Exception as e:
                    print(f"[CRAWLER] Worker {worker_id} error scanning {cand_url}: {e}", flush=True)
                    session.update_page_status(cand_page_id, "FAILED")
                    self._set_page_event(session_id, cand_page_id)

                finally:
                    session.discovery_stats["pages_processing"] = max(0, session.discovery_stats.get("pages_processing", 1) - 1)
                    session.discovery_stats["pages_queued"] = queue.size()

                time.sleep(0.05)
        finally:
            with self._global_lock:
                self._active_workers[session_id] = max(0, self._active_workers.get(session_id, 1) - 1)
                active_remaining = self._active_workers[session_id]

            # When the last active worker exits, finalize crawl status
            if active_remaining == 0:
                if len(session.pages) >= max_pages:
                    session.discovery_stats["limit_reached"] = True
                    session.discovery_stats["limit_reason"] = "MAX_PAGES_REACHED"

                session.discovery_stats["status"] = "COMPLETED"
                session.discovery_stats["completed"] = True
                session.status = "COMPLETED"
                print(f"[CRAWLER] Background crawl completed: {len(session.pages)} pages analyzed, {len(session.discovered_pages)} discovered", flush=True)

    def recover_html_via_http(self, url: str, fast_interactive: bool = False) -> Optional[dict[str, Any]]:
        """
        Resilient Direct HTTP HTML Fetch & Recovery:
        Fetches publicly reachable HTML over pooled HTTP/HTTPS with per-hop SSRF validation.
        Detects binary downloads & enforces read-only content-type bounds.
        Returned HTML is always sanitized by html_sanitizer before rendering.
        """
        fetch_candidates = [url]
        if url.startswith("http://"):
            fetch_candidates.append("https://" + url[7:])
        elif url.startswith("https://"):
            fetch_candidates.append("http://" + url[8:])

        fetch_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Upgrade-Insecure-Requests": "1",
        }
        req_timeout = (2.5, 4.5) if fast_interactive else (3.0, 6.0)
        binary_mime_prefixes = (
            "application/octet-stream",
            "application/zip",
            "application/x-zip",
            "application/x-msdownload",
            "application/x-dosexec",
            "application/pdf",
            "application/vnd.android.package-archive",
            "application/x-rar",
            "application/x-7z-compressed",
            "application/x-tar",
            "application/x-gzip",
        )

        for cand_fetch_url in fetch_candidates:
            current_url = cand_fetch_url
            redirect_chain = [current_url]
            try:
                r_rec = None
                for _hop in range(5):
                    ssrf_gate = validate_url_safe(current_url)
                    if not ssrf_gate.get("safe", True):
                        if fast_interactive and _hop > 0:
                            return {
                                "ssrf_redirect_blocked": True,
                                "blocked_url": current_url,
                                "reason": ssrf_gate.get("reason") or "Redirect blocked by SSRF guard",
                            }
                        r_rec = None
                        break

                    r_rec = self._http_session.get(
                        current_url,
                        headers=fetch_headers,
                        timeout=req_timeout,
                        verify=False,
                        allow_redirects=False,
                    )
                    if r_rec.is_redirect or r_rec.status_code in (301, 302, 303, 307, 308):
                        loc = r_rec.headers.get("Location")
                        if not loc:
                            break
                        next_url = urljoin(current_url, loc)
                        redirect_chain.append(next_url)
                        current_url = next_url
                        continue
                    break

                if r_rec is None:
                    continue

                content_disp = (r_rec.headers.get("Content-Disposition") or "").lower()
                content_type = (r_rec.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
                if "attachment" in content_disp or any(content_type.startswith(p) for p in binary_mime_prefixes):
                    return {
                        "binary_download": True,
                        "content_type": content_type,
                        "final_url": current_url,
                    }

                if r_rec.encoding and r_rec.encoding.lower() == "iso-8859-1" and "charset" not in (r_rec.headers.get("Content-Type") or "").lower():
                    r_rec.encoding = r_rec.apparent_encoding or "utf-8"

                rec_text = (r_rec.text or "")[:4_000_000]
                if rec_text and len(rec_text.strip()) > 0:
                    has_tags = bool(re.search(r'<\s*(html|head|body|div|p|span|table|h[1-6]|pre|main|section|header|footer|a|ul|li)\b', rec_text, re.IGNORECASE))
                    if has_tags or (r_rec.status_code == 200 and len(rec_text.strip()) > 0):
                        title_m = re.search(r'<title[^>]*>(.*?)</title>', rec_text, re.IGNORECASE | re.DOTALL)
                        page_title = html.unescape(re.sub(r'\s+', ' ', title_m.group(1)).strip()) if title_m else ""
                        print(f"[RECOVERY] Fast HTTP fetch succeeded for {current_url} ({len(rec_text)} bytes, HTTP {r_rec.status_code})", flush=True)
                        return {
                            "html": rec_text,
                            "final_url": current_url,
                            "http_status": r_rec.status_code,
                            "page_title": page_title,
                            "redirect_chain": redirect_chain,
                        }
                # Primary scheme responded with HTTP response; don't downgrade HTTPS to plaintext HTTP
                if r_rec is not None:
                    break
            except Exception as rec_err:
                print(f"[RECOVERY] Resilient HTTP recovery notice for {current_url}: {rec_err}", flush=True)
        return None

    def _scan_and_process_page(
        self,
        url: str,
        session_id: str,
        page_id: str,
        is_root: bool = False,
        depth: int = 0,
        parent_page_id: Optional[str] = None,
        discovered_from: Optional[str] = None,
        fast_mode: bool = False,
        device_profile: str = "desktop",
    ) -> dict[str, Any]:
        """
        Executes isolated VM browser scan for a single URL and transforms it
        into a safe, read-only forensic representation.
        Supports fast_mode for rapid background crawl without heavy OCR.
        """
        t_start = time.perf_counter()

        sb = get_sandbox_status()
        if not sb.get("sandbox_available"):
            sb = check_sandbox_availability()

        raw_ds = {}
        if sb.get("sandbox_available"):
            try:
                raw_ds = run_deep_scan(url, fast_mode=fast_mode, device_profile=device_profile)
            except Exception as e:
                raw_ds = {"success": False, "error": str(e), "html_raw": "", "scan_status": "FAILED"}
        else:
            raw_ds = {
                "success": False,
                "error": "VirtualBox VM agent is currently unavailable.",
                "html_raw": "",
                "scan_status": "UNAVAILABLE",
            }

        final_url = raw_ds.get("final_url") or url
        html_raw = raw_ds.get("html_raw") or ""
        dom_snapshot = raw_ds.get("dom_snapshot") or html_raw
        dom_behavior = raw_ds.get("dom_behavior") or {}
        load_time_ms = raw_ds.get("load_time_ms") or round((time.perf_counter() - t_start) * 1000, 1)

        raw_error = raw_ds.get("error")
        error_type = raw_ds.get("error_type")
        http_status = raw_ds.get("http_status") or (200 if raw_ds.get("success") else 500)
        if not error_type and http_status >= 400:
            error_type = f"HTTP_{http_status}" if http_status in (403, 404, 429) else ("HTTP_5XX" if 500 <= http_status <= 599 else f"HTTP_{http_status}")
            if not raw_error:
                raw_error = f"HTTP {http_status} returned by target server"

        failed_resources = raw_ds.get("failed_resources", [])
        redirect_chain = raw_ds.get("redirect_chain", [])
        redirect_count = raw_ds.get("redirect_count", len(redirect_chain))
        discovered_links = raw_ds.get("discovered_links", [])

        # Partial Page Success Handling: page is AVAILABLE if the main document DOM is usable or screenshot captured
        has_usable_dom = bool(dom_snapshot and dom_snapshot.strip() and dom_snapshot != "<html><head></head><body></body></html>")

        # Resilient Direct HTML Recovery:
        if not has_usable_dom and raw_ds.get("scan_status") != "BLOCKED" and not raw_ds.get("security_block"):
            rec = self.recover_html_via_http(url)
            if rec:
                dom_snapshot = rec["html"]
                html_raw = rec["html"]
                final_url = rec["final_url"]
                http_status = rec["http_status"]
                has_usable_dom = True
                raw_error = None
                error_type = None
                if rec.get("page_title"):
                    raw_ds["page_title"] = rec["page_title"]

        if not has_usable_dom:
            raw_http = raw_ds.get("http_status")
            if not raw_http or raw_http == 200:
                http_status = None

        has_screenshot = bool(raw_ds.get("screenshot_b64"))
        page_available = bool(raw_ds.get("page_available") or raw_ds.get("success") or has_usable_dom or has_screenshot)

        if raw_ds.get("scan_status") == "BLOCKED" or raw_ds.get("security_block"):
            scan_status = "BLOCKED"
        elif has_usable_dom:
            scan_status = "AVAILABLE" if (not error_type and (http_status or 200) < 400) else "PARTIAL"
        elif has_screenshot:
            scan_status = "PARTIAL"
        elif raw_ds.get("scan_status") == "TIMEOUT" or error_type == "PAGE_NAVIGATION_TIMEOUT":
            scan_status = "TIMEOUT"
        elif page_available:
            scan_status = "AVAILABLE"
        else:
            scan_status = "FAILED"

        page_error = None if (page_available and scan_status != "BLOCKED") else (raw_error or "Page navigation failed.")
        page_error_type = None if (page_available and scan_status != "BLOCKED") else (error_type or "PAGE_NAVIGATION_FAILED")

        # Sanitize HTML into isolated read-only representation with CSP script-src 'none' (Requirement 30)
        safe_html, elements_map, content_inventory = html_sanitizer.sanitize(
            html_content=dom_snapshot,
            base_url=final_url,
            dynamic_events=dom_behavior.get("behavioral_events"),
            is_forensic_mode=False,
            error_type=page_error_type,
            http_status=http_status,
            captured_stylesheets=raw_ds.get("captured_stylesheets"),
        )

        initial_dom = raw_ds.get("html_raw") if dom_behavior.get("mutation_metrics", {}).get("total_mutations", 0) > 0 else dom_snapshot
        dom_diff = forensic_engine.compute_dom_diff(
            initial_dom=initial_dom,
            final_dom=dom_snapshot,
            dom_behavior=dom_behavior,
            base_url=final_url,
        )

        network_forensics = forensic_engine.compile_network_forensics(
            raw_ds=raw_ds,
            base_url=final_url,
        )
        if failed_resources:
            network_forensics["failed_resources"] = failed_resources
        if redirect_chain:
            network_forensics["redirect_chain"] = redirect_chain

        timeline = forensic_engine.build_temporal_timeline(
            raw_ds=raw_ds,
            load_time_ms=load_time_ms,
            dom_behavior=dom_behavior,
            network_requests=network_forensics.get("requests", []),
        )

        try:
            parsed_url = urlparse(final_url)
            path = parsed_url.path or "/"
        except Exception:
            path = "/"

        has_credentials = len(raw_ds.get("password_fields", [])) > 0 or content_inventory.get("forms", 0) > 0
        has_ext_action = any(e.get("risk_type") == "external_action" for e in elements_map)
        has_dynamic_inj = dom_diff.get("dynamic_password_injection", False) or len(dom_diff.get("form_action_changes", [])) > 0

        if has_ext_action or has_dynamic_inj:
            risk_level = "HIGH"
        elif has_credentials or content_inventory.get("forms", 0) > 0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        suspicious_indicators = []
        if has_dynamic_inj:
            suspicious_indicators.append("Dynamic DOM injection detected (delayed form or password field)")
        if has_ext_action:
            suspicious_indicators.append("Form action submits to external third-party domain")
        if len(raw_ds.get("password_fields", [])) > 0:
            suspicious_indicators.append(f"Credential harvesting form detected ({len(raw_ds['password_fields'])} password field)")
        if any(e.get("risk_type") == "hidden_iframe" for e in elements_map):
            suspicious_indicators.append("Zero-dimension or hidden iframe detected (potential clickjacking)")
        if redirect_count > 1:
            suspicious_indicators.append(f"Multi-hop redirection detected ({redirect_count} hops)")

        total_proc_ms = round((time.perf_counter() - t_start) * 1000, 1)
        print(f"[PERF] Page {page_id} ({url}) processed in {total_proc_ms}ms (fast_mode={fast_mode}, status={scan_status})", flush=True)

        return {
            "page_id": page_id,
            "representation_id": page_id,
            "session_id": session_id,
            "scan_id": session_id,
            "url": final_url,
            "original_url": url,
            "canonical_url": final_url,
            "path": path,
            "title": raw_ds.get("page_title") or path,
            "http_status": http_status,
            "depth": depth,
            "parent_page_id": parent_page_id,
            "discovered_from": discovered_from,
            "is_root": is_root,
            "load_time_ms": load_time_ms,
            "risk_level": risk_level,
            "has_credentials": has_credentials,
            "scan_status": scan_status,
            "status": scan_status,
            "page_available": page_available,
            "error": page_error,
            "error_type": page_error_type,
            "error_details": raw_error if not page_available else None,
            "failed_resources": failed_resources,
            "redirect_chain": redirect_chain,
            "redirect_count": redirect_count,
            "screenshot_b64": raw_ds.get("screenshot_b64"),
            "screenshot_type": raw_ds.get("screenshot_type", "viewport"),
            "safe_html": safe_html,
            "html_raw": html_raw,
            "dom_snapshot": dom_snapshot,
            "elements_map": elements_map,
            "content_inventory": content_inventory,
            "forms": raw_ds.get("forms", []),
            "links_count": content_inventory.get("links", 0),
            "discovered_links": discovered_links,
            "dom_diff": dom_diff,
            "dom_behavior": dom_behavior,
            "network_forensics": network_forensics,
            "timeline": timeline,
            "suspicious_indicators": suspicious_indicators,
            "page_states": [
                {"name": "Initial DOM (T0)", "status": "Captured", "size": len(initial_dom or "")},
                {"name": "Post-JavaScript Settled (T1)", "status": "Captured", "size": len(dom_snapshot or "")},
            ],
            "security_status": {
                "isolated": True,
                "read_only": True,
                "interactions_blocked": True,
                "scripts_disabled": True,
            },
            "reachability_state": raw_ds.get("reachability_state") or (
                "REACHABLE_HTTP_2XX" if (http_status is not None and 200 <= http_status < 300) else
                "REACHABLE_HTTP_3XX" if (http_status is not None and 300 <= http_status < 400) else
                "REACHABLE_HTTP_4XX" if (http_status is not None and 400 <= http_status < 500) else
                "REACHABLE_HTTP_5XX" if (http_status is not None and 500 <= http_status < 600) else
                "CONNECTION_FAILED"
            ),
            "browser_render_state": raw_ds.get("browser_render_state") or (
                "BROWSER_RENDERED" if page_available else "BROWSER_RENDER_FAILED"
            ),
            "server_response_message": raw_ds.get("server_response_message") or (
                f"Server reachable — remote server returned HTTP {http_status}." if (http_status is not None and http_status >= 400) else (
                    "Server reachable and response received." if http_status is not None else "Connection to target server failed."
                )
            ),
            "device_profile": device_profile,
            "created_at": time.time(),
            "updated_at": time.time(),
        }


# Global safe view engine singleton
safe_view_engine = SafeViewEngine()
