"""
PhishGuard AI V7.2 — Safe Web View: Session Manager with Persistent Storage
==========================================================================
Manages isolated analysis sessions for the Safe Web Viewer.

Key Requirements Implemented:
  1. Thread-safe in-memory cache + persistent disk-backed storage.
  2. Page representations survive backend restarts and process reloads.
  3. Stable scan_id / session_id / page_id mapping.
  4. Representations remain available for active session duration (default TTL 3600s).
  5. Multi-depth discovered pages inventory (analyzed & candidate).
  6. Standardized [SAFEVIEW] telemetry logging.
"""

from __future__ import annotations

import os
import json
import time
import uuid
import threading
from collections import OrderedDict
from typing import Any, Optional


_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_STORAGE_DIR = os.path.join(_BASE_DIR, "data", "safe_view_sessions")
os.makedirs(_STORAGE_DIR, exist_ok=True)


class LRURepresentationCache:
    """Thread-safe bounded in-memory cache for page representations (Requirement 9)."""
    def __init__(self, capacity: int = 300) -> None:
        self.capacity = capacity
        self.cache: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.lock = threading.Lock()

    def _make_key(self, session_id: str, page_id: str) -> str:
        return f"{session_id}::{page_id}"

    def get(self, session_id: str, page_id: str) -> Optional[dict[str, Any]]:
        key = self._make_key(session_id, page_id)
        with self.lock:
            if key not in self.cache:
                return None
            self.cache.move_to_end(key)
            return self.cache[key]

    def put(self, session_id: str, page_id: str, data: dict[str, Any]) -> None:
        key = self._make_key(session_id, page_id)
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            self.cache[key] = data
            if len(self.cache) > self.capacity:
                self.cache.popitem(last=False)

    def has(self, session_id: str, page_id: str) -> bool:
        key = self._make_key(session_id, page_id)
        with self.lock:
            return key in self.cache

_GLOBAL_REPRESENTATION_CACHE = LRURepresentationCache(capacity=300)


def _safe_atomic_write(target_path: str, data: Any, indent: Optional[int] = None) -> None:
    """Atomic file writer with exponential backoff on Windows file locking."""
    tmp_path = target_path + f".{uuid.uuid4().hex[:6]}.tmp"
    try:
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(tmp_path, "w", encoding="utf-8") as f:
            if indent:
                json.dump(data, f, indent=indent)
            else:
                json.dump(data, f)
        for attempt in range(5):
            try:
                os.replace(tmp_path, target_path)
                return
            except (PermissionError, OSError):
                time.sleep(0.02 * (attempt + 1))
        # Final fallback
        if os.path.exists(tmp_path):
            try:
                if os.path.exists(target_path):
                    os.remove(target_path)
                os.replace(tmp_path, target_path)
            except Exception:
                pass
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


class SafeViewSession:
    """Represents a single isolated Safe Web Viewer analysis session."""

    def __init__(self, session_id: str, target_url: str, ttl_seconds: int = 3600) -> None:
        self.session_id = session_id
        self.target_url = target_url
        self.created_at = time.time()
        self.expires_at = self.created_at + ttl_seconds
        self.status = "INITIALIZING"  # INITIALIZING, DISCOVERING, READY, COMPLETED, ERROR
        self.error: Optional[str] = None

        # Fully analyzed page payloads: page_id -> dict
        self.pages: dict[str, dict[str, Any]] = {}
        # Inventory of all discovered candidate same-origin pages: page_id -> dict
        self.discovered_pages: dict[str, dict[str, Any]] = {}

        self.root_page_id: Optional[str] = None
        self.blocked_actions: list[dict[str, Any]] = []
        self.external_domains: set[str] = set()

        self.discovery_stats: dict[str, Any] = {
            "status": "INITIALIZING",
            "pages_discovered": 1,
            "pages_analyzed": 0,
            "pages_completed": 0,
            "pages_partial": 0,
            "pages_failed": 0,
            "pages_blocked": 0,
            "pages_queued": 0,
            "pages_processing": 0,
            "current_depth": 0,
            "max_depth": 4,
            "max_pages": 50,
            "links_found": 0,
            "blocked_actions": 0,
            "blocked_actions_list": [],
            "external_domains": 0,
            "external_domains_list": [],
            "limit_reached": False,
            "limit_reason": None,
            "completed": False,
        }
        self.lock = threading.RLock()

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def touch(self, extra_seconds: int = 1800) -> None:
        """Extend session expiration when actively accessed."""
        with self.lock:
            self.expires_at = time.time() + extra_seconds
            self._save_metadata_to_disk()

    def add_page(self, page_id: str, page_data: Optional[dict[str, Any]] = None, **kwargs) -> None:
        """Adds or updates a fully analyzed page in the session and persists to disk. Never overwrites other pages."""
        with self.lock:
            data = dict(page_data or {})
            if kwargs:
                data.update(kwargs)
            
            # Ensure stable identifiers
            data["page_id"] = page_id
            data["representation_id"] = page_id
            data["session_id"] = self.session_id
            
            self.pages[page_id] = data
            if self.root_page_id is None:
                self.root_page_id = page_id

            scan_st = data.get("scan_status", "AVAILABLE")

            # Keep discovered_pages in sync with full forensic state
            if page_id in self.discovered_pages:
                self.discovered_pages[page_id].update({
                    "url": data.get("url", self.discovered_pages[page_id].get("url")),
                    "canonical_url": data.get("canonical_url", data.get("url")),
                    "path": data.get("path", self.discovered_pages[page_id].get("path")),
                    "title": data.get("title", self.discovered_pages[page_id].get("title")),
                    "depth": data.get("depth", self.discovered_pages[page_id].get("depth", 0)),
                    "status": scan_st,
                    "http_status": data.get("http_status", 200),
                    "risk_level": data.get("risk_level", "LOW"),
                    "has_credentials": data.get("has_credentials", False),
                    "forms_count": len(data.get("forms", [])),
                    "parent_page_id": data.get("parent_page_id", self.discovered_pages[page_id].get("parent_page_id")),
                    "discovered_from": data.get("discovered_from", self.discovered_pages[page_id].get("discovered_from")),
                })
            else:
                self.discovered_pages[page_id] = {
                    "page_id": page_id,
                    "representation_id": page_id,
                    "url": data.get("url", self.target_url),
                    "canonical_url": data.get("canonical_url", data.get("url", self.target_url)),
                    "path": data.get("path", "/"),
                    "title": data.get("title", data.get("path", "/")),
                    "depth": data.get("depth", 0),
                    "parent_page_id": data.get("parent_page_id"),
                    "discovered_from": data.get("discovered_from"),
                    "priority": 100 if page_id == "p_root" else 50,
                    "is_root": page_id == self.root_page_id,
                    "status": scan_st,
                    "http_status": data.get("http_status", 200),
                    "risk_level": data.get("risk_level", "LOW"),
                    "has_credentials": data.get("has_credentials", False),
                    "forms_count": len(data.get("forms", [])),
                }

            self._sync_stats()
            if self.status != "ERROR" and self.status != "DISCOVERING" and self.status != "CRAWLING":
                self.status = "READY"

            # Persist to in-memory LRU cache and disk
            _GLOBAL_REPRESENTATION_CACHE.put(self.session_id, page_id, data)
            self._save_page_to_disk(page_id, data)
            self._save_metadata_to_disk()

            print(f"[SAFEVIEW] Page created: {page_id}", flush=True)
            print(f"[SAFEVIEW] Representation stored: {page_id}", flush=True)

    def add_discovered_candidate(
        self,
        page_id: str,
        url: str,
        path: str,
        depth: int,
        title: str = "",
        priority: int = 10,
        is_root: bool = False,
        parent_page_id: Optional[str] = None,
        discovered_from: Optional[str] = None,
        canonical_url: Optional[str] = None,
    ) -> None:
        """Registers a discovered candidate same-origin page into the page inventory."""
        with self.lock:
            if page_id not in self.discovered_pages:
                self.discovered_pages[page_id] = {
                    "page_id": page_id,
                    "representation_id": page_id,
                    "url": url,
                    "canonical_url": canonical_url or url,
                    "path": path,
                    "title": title or path,
                    "depth": depth,
                    "parent_page_id": parent_page_id,
                    "discovered_from": discovered_from,
                    "priority": priority,
                    "is_root": is_root,
                    "status": "QUEUED",
                    "http_status": 200,
                }
                self._sync_stats()
                self._save_metadata_to_disk()

    def add_blocked_action(self, url: str, path: str, reason: str, context: str = "") -> None:
        """Records a destructive link blocked by security policy."""
        with self.lock:
            self.blocked_actions.append({
                "url": url,
                "path": path,
                "reason": reason,
                "context": context,
            })
            self._sync_stats()
            self._save_metadata_to_disk()

    def add_external_domains(self, domains: list[str]) -> None:
        """Records third-party external domains found during page discovery."""
        with self.lock:
            for d in domains:
                if d:
                    self.external_domains.add(d.lower())
            self._sync_stats()
            self._save_metadata_to_disk()

    def _sync_stats(self) -> None:
        """Keeps live discovery & crawl statistics strictly consistent."""
        analyzed_count = len(self.pages)
        completed = sum(1 for p in self.pages.values() if p.get("scan_status") in ("AVAILABLE", "SUCCESS"))
        partial = sum(1 for p in self.pages.values() if p.get("scan_status") == "PARTIAL")
        failed = sum(1 for p in self.pages.values() if p.get("scan_status") in ("FAILED", "TIMEOUT"))
        blocked = sum(1 for p in self.pages.values() if p.get("scan_status") == "BLOCKED") + len(self.blocked_actions)
        queued = max(0, len(self.discovered_pages) - analyzed_count)

        self.discovery_stats["pages_discovered"] = len(self.discovered_pages)
        self.discovery_stats["pages_analyzed"] = analyzed_count
        self.discovery_stats["pages_completed"] = completed
        self.discovery_stats["pages_partial"] = partial
        self.discovery_stats["pages_failed"] = failed
        self.discovery_stats["pages_blocked"] = blocked
        self.discovery_stats["pages_queued"] = queued
        self.discovery_stats["blocked_actions"] = len(self.blocked_actions)
        self.discovery_stats["blocked_actions_list"] = self.blocked_actions
        self.discovery_stats["external_domains"] = len(self.external_domains)
        self.discovery_stats["external_domains_list"] = sorted(list(self.external_domains))

    def update_page_status(self, page_id: str, status: str) -> None:
        """Updates live status of a candidate page (e.g. QUEUED -> ANALYZING -> AVAILABLE)."""
        with self.lock:
            if page_id in self.discovered_pages:
                self.discovered_pages[page_id]["status"] = status
                self._sync_stats()
            if page_id in self.pages:
                self.pages[page_id]["scan_status"] = status
                self.pages[page_id]["status"] = status

    def is_page_analyzed(self, page_id: str) -> bool:
        """Fast check whether page has an existing complete representation without loading full payload."""
        with self.lock:
            if page_id in self.pages and (self.pages[page_id].get("scan_status") in ("AVAILABLE", "PARTIAL", "SUCCESS") or self.pages[page_id].get("safe_html")):
                return True
            if _GLOBAL_REPRESENTATION_CACHE.has(self.session_id, page_id):
                return True
            disk_path = os.path.join(_STORAGE_DIR, self.session_id, "pages", f"{page_id}.json")
            return os.path.exists(disk_path)

    def get_page(self, page_id: str) -> Optional[dict[str, Any]]:
        with self.lock:
            # 1. Check in-memory session pages (0ms)
            if page_id in self.pages:
                return self.pages[page_id]

            # 2. Check LRU representation cache (sub-millisecond)
            cached = _GLOBAL_REPRESENTATION_CACHE.get(self.session_id, page_id)
            if cached:
                self.pages[page_id] = cached
                return cached

            # 3. Check persistent disk representation
            loaded = self._load_page_from_disk(page_id)
            if loaded:
                self.pages[page_id] = loaded
                _GLOBAL_REPRESENTATION_CACHE.put(self.session_id, page_id, loaded)
                return loaded

            return None

    def get_pages_summary(self) -> list[dict[str, Any]]:
        """
        Returns complete inventory of all discovered pages (root + internal candidates).
        Distinguishes between fully analyzed pages and pending discovered routes.
        """
        with self.lock:
            summary = []
            for pid, disc_info in self.discovered_pages.items():
                pdata = self.get_page(pid) or {}
                is_analyzed = pid in self.pages
                status = pdata.get("scan_status") or ("AVAILABLE" if is_analyzed else disc_info.get("status", "QUEUED"))

                summary.append({
                    "page_id": pid,
                    "representation_id": pdata.get("representation_id") or disc_info.get("representation_id") or pid,
                    "url": pdata.get("url") or disc_info.get("url", ""),
                    "canonical_url": pdata.get("canonical_url") or disc_info.get("canonical_url") or pdata.get("url") or disc_info.get("url", ""),
                    "path": pdata.get("path") or disc_info.get("path", "/"),
                    "title": pdata.get("title") or disc_info.get("title") or disc_info.get("path", "/"),
                    "http_status": pdata.get("http_status", disc_info.get("http_status", 200)),
                    "depth": pdata.get("depth", disc_info.get("depth", 0)),
                    "parent_page_id": pdata.get("parent_page_id") or disc_info.get("parent_page_id"),
                    "discovered_from": pdata.get("discovered_from") or disc_info.get("discovered_from"),
                    "analyzed": is_analyzed,
                    "status": status,
                    "forms_count": len(pdata.get("forms", [])) if is_analyzed else 0,
                    "has_credentials": pdata.get("has_credentials", False) if is_analyzed else False,
                    "risk_level": pdata.get("risk_level", "LOW") if is_analyzed else "PENDING",
                    "screenshot_available": bool(pdata.get("screenshot_b64")) if is_analyzed else False,
                    "is_root": pid == self.root_page_id or disc_info.get("is_root", False),
                    "priority": disc_info.get("priority", 10),
                })

            # Sort: root first, then analyzed, then by depth and priority descending
            summary.sort(key=lambda x: (not x["is_root"], not x["analyzed"], x["depth"], -x.get("priority", 0)))
            return summary

    def get_page_tree(self) -> dict[str, Any]:
        """Returns the hierarchical page tree representing actual discovered relationships (Requirement 19)."""
        from .discovery_engine import page_discovery_engine
        with self.lock:
            return page_discovery_engine.build_page_tree(self.get_pages_summary(), self.root_page_id or "p_root")

    def to_dict(self) -> dict[str, Any]:
        with self.lock:
            return {
                "session_id": self.session_id,
                "target_url": self.target_url,
                "status": self.status,
                "created_at": self.created_at,
                "expires_at": self.expires_at,
                "error": self.error,
                "root_page_id": self.root_page_id,
                "pages_count": len(self.discovered_pages),
                "pages_analyzed_count": len(self.pages),
                "pages": self.get_pages_summary(),
                "tree": self.get_page_tree(),
                "discovery": self.discovery_stats,
                "discovery_stats": self.discovery_stats,
                "blocked_actions": self.blocked_actions,
                "external_domains": sorted(list(self.external_domains)),
            }

    # ── Disk Persistence Helpers ──────────────────────────────────────────────
    def _get_session_dir(self) -> str:
        sdir = os.path.join(_STORAGE_DIR, self.session_id)
        os.makedirs(sdir, exist_ok=True)
        os.makedirs(os.path.join(sdir, "pages"), exist_ok=True)
        return sdir

    def _save_metadata_to_disk(self) -> None:
        try:
            sdir = self._get_session_dir()
            meta_path = os.path.join(sdir, "session.json")
            meta = {
                "session_id": self.session_id,
                "target_url": self.target_url,
                "created_at": self.created_at,
                "expires_at": self.expires_at,
                "status": self.status,
                "error": self.error,
                "root_page_id": self.root_page_id,
                "discovered_pages": self.discovered_pages,
                "blocked_actions": self.blocked_actions,
                "external_domains": sorted(list(self.external_domains)),
                "discovery_stats": self.discovery_stats,
                "analyzed_page_ids": list(self.pages.keys()),
            }
            _safe_atomic_write(meta_path, meta, indent=2)
        except Exception as e:
            print(f"[SAFEVIEW] Warning: Failed to persist session metadata: {e}", flush=True)

    def _save_page_to_disk(self, page_id: str, data: dict[str, Any]) -> None:
        try:
            sdir = self._get_session_dir()
            page_path = os.path.join(sdir, "pages", f"{page_id}.json")
            _safe_atomic_write(page_path, data)
        except Exception as e:
            print(f"[SAFEVIEW] Warning: Failed to persist page representation {page_id}: {e}", flush=True)

    def _load_page_from_disk(self, page_id: str) -> Optional[dict[str, Any]]:
        try:
            sdir = os.path.join(_STORAGE_DIR, self.session_id)
            page_path = os.path.join(sdir, "pages", f"{page_id}.json")
            if os.path.exists(page_path):
                with open(page_path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            print(f"[SAFEVIEW] Warning: Failed to load page {page_id} from disk: {e}", flush=True)
        return None


class SessionManager:
    """Thread-safe registry for Safe Web View sessions with disk persistence & auto-pruning."""

    def __init__(self, cleanup_interval_sec: int = 300) -> None:
        self._sessions: dict[str, SafeViewSession] = {}
        self._lock = threading.RLock()
        self._cleanup_interval = cleanup_interval_sec
        self._stop_event = threading.Event()
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()

    def create_session(self, target_url: str, ttl_seconds: int = 3600) -> SafeViewSession:
        session_id = f"PG-2026-{uuid.uuid4().hex[:8].upper()}"
        session = SafeViewSession(session_id=session_id, target_url=target_url, ttl_seconds=ttl_seconds)
        with self._lock:
            self._sessions[session_id] = session
            session._save_metadata_to_disk()

        print(f"[SAFEVIEW] Session created: {session_id}", flush=True)
        print(f"[SAFEVIEW] URL: {target_url}", flush=True)
        return session

    def get_session(self, session_id: str) -> Optional[SafeViewSession]:
        """Returns active session from memory or restores from disk if backend was restarted."""
        if not session_id:
            return None

        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                if session.is_expired():
                    del self._sessions[session_id]
                    self._delete_session_dir(session_id)
                    return None
                session.touch()
                return session

            # Session not in memory — attempt to restore from disk storage
            restored = self._restore_session_from_disk(session_id)
            if restored:
                if restored.is_expired():
                    self._delete_session_dir(session_id)
                    return None
                restored.touch()
                self._sessions[session_id] = restored
                print(f"[SAFEVIEW] Representation loaded from disk: {session_id}", flush=True)
                return restored

            return None

    def delete_session(self, session_id: str) -> bool:
        with self._lock:
            existed = session_id in self._sessions
            if existed:
                del self._sessions[session_id]
            self._delete_session_dir(session_id)
            return existed

    def list_active_sessions(self) -> list[str]:
        """Returns all unexpired session IDs across both in-memory cache and persistent disk store."""
        with self._lock:
            now = time.time()
            session_tuples: list[tuple[float, str]] = []

            # Memory sessions
            for sid, s in self._sessions.items():
                if s.expires_at > now:
                    session_tuples.append((s.created_at, sid))

            # Disk sessions
            try:
                if os.path.exists(_STORAGE_DIR):
                    for entry in os.listdir(_STORAGE_DIR):
                        if entry in self._sessions:
                            continue
                        meta_file = os.path.join(_STORAGE_DIR, entry, "session.json")
                        if os.path.exists(meta_file):
                            try:
                                with open(meta_file, "r", encoding="utf-8") as f:
                                    meta = json.load(f)
                                if meta.get("expires_at", 0) > now:
                                    session_tuples.append((meta.get("created_at", 0.0), entry))
                            except Exception:
                                pass
            except Exception:
                pass

            # Sort descending by created_at (most recent first)
            session_tuples.sort(key=lambda x: x[0], reverse=True)
            return [sid for _, sid in session_tuples]

    def _restore_session_from_disk(self, session_id: str) -> Optional[SafeViewSession]:
        """Reconstructs a SafeViewSession instance from on-disk JSON metadata and page representations."""
        meta_file = os.path.join(_STORAGE_DIR, session_id, "session.json")
        if not os.path.exists(meta_file):
            return None

        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)

            session = SafeViewSession(
                session_id=session_id,
                target_url=meta.get("target_url", ""),
                ttl_seconds=int(max(300, meta.get("expires_at", 0) - time.time()))
            )
            session.created_at = meta.get("created_at", session.created_at)
            session.expires_at = meta.get("expires_at", session.expires_at)
            session.status = meta.get("status", "READY")
            session.error = meta.get("error")
            session.root_page_id = meta.get("root_page_id", "p_root")
            session.discovered_pages = meta.get("discovered_pages", {})
            session.blocked_actions = meta.get("blocked_actions", [])
            session.external_domains = set(meta.get("external_domains", []))
            session.discovery_stats = meta.get("discovery_stats", session.discovery_stats)

            # Load stored pages
            pages_dir = os.path.join(_STORAGE_DIR, session_id, "pages")
            if os.path.exists(pages_dir):
                for p_file in os.listdir(pages_dir):
                    if p_file.endswith(".json"):
                        pid = p_file[:-5]
                        try:
                            with open(os.path.join(pages_dir, p_file), "r", encoding="utf-8") as pf:
                                session.pages[pid] = json.load(pf)
                        except Exception:
                            pass

            return session
        except Exception as e:
            print(f"[SAFEVIEW] Error restoring session {session_id} from disk: {e}", flush=True)
            return None

    def _delete_session_dir(self, session_id: str) -> None:
        try:
            import shutil
            sdir = os.path.join(_STORAGE_DIR, session_id)
            if os.path.exists(sdir):
                shutil.rmtree(sdir, ignore_errors=True)
        except Exception:
            pass

    def _cleanup_loop(self) -> None:
        while not self._stop_event.is_set():
            time.sleep(self._cleanup_interval)
            self._prune_expired()

    def _prune_expired(self) -> None:
        with self._lock:
            now = time.time()
            expired_keys = [sid for sid, s in self._sessions.items() if s.expires_at <= now]
            for sid in expired_keys:
                del self._sessions[sid]
                self._delete_session_dir(sid)

            # Also prune expired folders from disk
            try:
                if os.path.exists(_STORAGE_DIR):
                    for entry in os.listdir(_STORAGE_DIR):
                        meta_file = os.path.join(_STORAGE_DIR, entry, "session.json")
                        if os.path.exists(meta_file):
                            try:
                                with open(meta_file, "r", encoding="utf-8") as f:
                                    meta = json.load(f)
                                if meta.get("expires_at", 0) <= now:
                                    self._delete_session_dir(entry)
                            except Exception:
                                pass
            except Exception:
                pass

    def destroy_session(self, session_id: str) -> bool:
        return self.delete_session(session_id)


# Global session manager singleton
session_manager = SessionManager()


def get_session_manager() -> SessionManager:
    return session_manager
