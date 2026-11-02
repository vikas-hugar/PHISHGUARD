"""
PhishGuard AI V7 — Safe Web View Package
========================================
Read-only, isolated forensic web viewer for inspecting suspicious websites
without direct analyst browser interaction.
"""

from .session_manager import session_manager, SafeViewSession
from .sanitizer import html_sanitizer, HTMLSanitizer
from .discovery_engine import page_discovery_engine, PageDiscoveryEngine
from .forensic_engine import forensic_engine, ForensicEngine
from .safe_view_engine import safe_view_engine, SafeViewEngine
from .routes import safe_view_bp

__all__ = [
    "session_manager",
    "SafeViewSession",
    "html_sanitizer",
    "HTMLSanitizer",
    "page_discovery_engine",
    "PageDiscoveryEngine",
    "forensic_engine",
    "ForensicEngine",
    "safe_view_engine",
    "SafeViewEngine",
    "safe_view_bp",
]
