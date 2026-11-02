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
import time
import uuid
import heapq
import threading
from urllib.parse import urlparse
from typing import Any, Optional

from detection.ssrf_guard import validate_url_safe
from deep_scan.vm_controller import run_deep_scan, check_sandbox_availability, get_sandbox_status
from .session_manager import session_manager, SafeViewSession
from .sanitizer import html_sanitizer
from .discovery_engine import page_discovery_engine, _AUTH_KEYWORDS, _INFO_KEYWORDS
from .forensic_engine import forensic_engine


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
        self._global_lock = threading.RLock()

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

    def analyze_page_on_demand(self, session_id: str, page_id: str, device_profile: str = "desktop") -> Optional[dict[str, Any]]:
        """
        On-demand page retrieval and analysis (Requirement 6, 7, 8).
        If already analyzed: returns stored representation instantly (0ms).
        If queued: immediately scans page in fast_mode without 10s stalling.
        """
        t_demand_start = time.perf_counter()
        session = session_manager.get_session(session_id)
        if not session:
            return None

        # Root page guard: if p_root is already in session, return it immediately without rescanning
        if page_id == "p_root" or page_id == session.root_page_id:
            existing = session.get_page(page_id) or session.get_page("p_root") or (session.get_page(session.root_page_id) if session.root_page_id else None)
            if existing and (existing.get("safe_html") or existing.get("scan_status") in ("AVAILABLE", "PARTIAL", "SUCCESS")):
                return existing

        # 1. Instant return from cache if already analyzed (Requirement 7 & 8)
        existing = session.get_page(page_id)
        if existing and (existing.get("scan_status") in ("AVAILABLE", "PARTIAL", "SUCCESS") or existing.get("safe_html")):
            elapsed_cached = round((time.perf_counter() - t_demand_start) * 1000, 2)
            print(f"[PERF] Instant page retrieval for {page_id} in {elapsed_cached}ms (from stored representation)", flush=True)
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

        # 3. Check if a worker is currently actively scanning this page
        current_status = disc_info.get("status")
        if current_status == "ANALYZING":
            print(f"[SAFEVIEW] Worker actively analyzing {page_id}, awaiting completion (max 2.5s)...", flush=True)
            evt = self._get_page_event(session_id, page_id)
            evt.wait(timeout=2.5)
            page_data = session.get_page(page_id)
            if page_data and page_data.get("scan_status") in ("AVAILABLE", "PARTIAL", "SUCCESS"):
                elapsed = round((time.perf_counter() - t_demand_start) * 1000, 1)
                print(f"[PERF] Prioritized page {page_id} analyzed by worker in {elapsed}ms", flush=True)
                return page_data

        # 4. Immediate on-demand analysis (take directly from queue with ZERO delay)
        queue = self._session_queues.get(session_id)
        if queue:
            queue.remove(page_id)

        print(f"[SAFEVIEW] Fast on-demand analysis for {page_id} ({target_url})", flush=True)
        session.update_page_status(page_id, "ANALYZING")
        page_data = self._scan_and_process_page(
            url=target_url,
            session_id=session_id,
            page_id=page_id,
            is_root=disc_info.get("is_root", False),
            depth=disc_info.get("depth", 1),
            parent_page_id=disc_info.get("parent_page_id"),
            discovered_from=disc_info.get("discovered_from"),
            fast_mode=True,
            device_profile=device_profile,
        )
        session.add_page(page_id, page_data)
        self._set_page_event(session_id, page_id)

        elapsed = round((time.perf_counter() - t_demand_start) * 1000, 1)
        print(f"[PERF] Fast on-demand page {page_id} completed in {elapsed}ms", flush=True)
        return page_data

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
        has_screenshot = bool(raw_ds.get("screenshot_b64"))
        page_available = bool(raw_ds.get("page_available") or raw_ds.get("success") or has_usable_dom or has_screenshot)

        if raw_ds.get("scan_status") == "BLOCKED" or raw_ds.get("security_block"):
            scan_status = "BLOCKED"
        elif has_usable_dom:
            scan_status = "AVAILABLE" if (not error_type and http_status < 400) else "PARTIAL"
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
                "REACHABLE_HTTP_2XX" if 200 <= http_status < 300 else
                "REACHABLE_HTTP_3XX" if 300 <= http_status < 400 else
                "REACHABLE_HTTP_4XX" if 400 <= http_status < 500 else
                "REACHABLE_HTTP_5XX" if 500 <= http_status < 600 else
                "CONNECTION_FAILED"
            ),
            "browser_render_state": raw_ds.get("browser_render_state") or (
                "BROWSER_RENDERED" if page_available else "BROWSER_RENDER_FAILED"
            ),
            "server_response_message": raw_ds.get("server_response_message") or (
                f"Server reachable — remote server returned HTTP {http_status}." if http_status >= 400 else "Server reachable and response received."
            ),
            "device_profile": device_profile,
            "created_at": time.time(),
            "updated_at": time.time(),
        }


# Global safe view engine singleton
safe_view_engine = SafeViewEngine()
