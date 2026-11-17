import React, { useState, useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import {
    Shield, Lock, AlertTriangle, Maximize2, Minimize2, ZoomIn, ZoomOut,
    Monitor, Tablet, Smartphone, FileText, Network, Clock, Code, Server,
    Activity, Database, AlertOctagon, Globe, Sparkles, CornerDownRight,
    Compass, ShieldAlert, ArrowLeft, ArrowRight, RotateCw, X
} from 'lucide-react';

export interface PageTreeNode {
    page_id: string;
    url: string;
    path: string;
    title: string;
    depth: number;
    http_status: number;
    status?: string;
    risk_level?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'PENDING';
    forms_count?: number;
    has_credentials?: boolean;
    is_root?: boolean;
    children?: PageTreeNode[];
}

export interface DiscoveredPage {
    page_id: string;
    url: string;
    path: string;
    title: string;
    http_status: number;
    depth: number;
    forms_count: number;
    has_credentials: boolean;
    risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'PENDING';
    screenshot_available: boolean;
    is_root: boolean;
    analyzed?: boolean;
    status?: string;
    priority?: number;
    is_blocked?: boolean;
    blocked_reason?: string;
}

export interface DiscoveryStats {
    status?: string; // 'DISCOVERING' | 'CRAWLING' | 'COMPLETED' | 'INITIALIZING'
    pages_discovered?: number;
    pages_analyzed?: number;
    pages_queued?: number;
    pages_completed?: number;
    pages_partial?: number;
    pages_failed?: number;
    pages_blocked?: number;
    current_depth?: number;
    max_depth?: number;
    max_pages?: number;
    links_found?: number;
    blocked_actions?: number;
    blocked_actions_list?: Array<{ url: string; path: string; reason: string; context?: string }>;
    external_domains?: number;
    external_domains_list?: string[];
    crawl_limit_reached?: boolean;
    completed?: boolean;
}

interface ContentInventory {
    text_characters: number;
    images: number;
    scripts: number;
    stylesheets: number;
    forms: number;
    inputs: number;
    links: number;
    iframes: number;
    videos: number;
    external_domains_count: number;
    external_domains: string[];
}

interface InspectedElement {
    element_id: string;
    tag: string;
    id?: string;
    name?: string;
    action?: string;
    original_action?: string;
    method?: string;
    href?: string;
    src?: string;
    type?: string;
    placeholder?: string;
    is_external?: boolean;
    is_password?: boolean;
    is_credential?: boolean;
    is_hidden?: boolean;
    risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    risk_type: string;
    description: string;
    created_time?: string;
    modified_time?: string;
}

interface TimelineEvent {
    timestamp_ms: number;
    time_formatted: string;
    type: string;
    title: string;
    detail: string;
    severity: 'CRITICAL' | 'WARNING' | 'MEDIUM' | 'INFO';
}

interface DOMDiff {
    has_initial_dom: boolean;
    has_final_dom: boolean;
    initial_dom_length: number;
    final_dom_length: number;
    size_delta_bytes: number;
    total_mutations: number;
    added_nodes: number;
    modified_attributes: number;
    dynamic_password_injection: boolean;
    dynamic_iframe_injection: boolean;
    form_action_changes: Array<{
        form_id: string;
        before: string;
        after: string;
        flag: string;
        severity: string;
    }>;
    behavioral_events: string[];
}

export interface FailedResource {
    url: string;
    host?: string;
    resource_type?: string;
    status?: string | number;
    error?: string;
}

interface NetworkForensics {
    total_requests: number;
    external_requests_count: number;
    domain_dependency_chain: string[];
    requests: Array<{
        url: string;
        method: string;
        status: number;
        resource_type: string;
        host: string;
        is_external: boolean;
        classification: string;
    }>;
    redirect_chain: string[];
    failed_resources?: FailedResource[];
}

export interface ViewportPreset {
    id: 'desktop' | 'tablet' | 'mobile';
    label: string;
    width: number;
    height: number;
    description: string;
}

export const VIEWPORT_PRESETS: Record<'desktop' | 'tablet' | 'mobile', ViewportPreset> = {
    desktop: {
        id: 'desktop',
        label: 'Desktop',
        width: 1440,
        height: 900,
        description: '1440 × 900 standard desktop viewport',
    },
    tablet: {
        id: 'tablet',
        label: 'Tablet',
        width: 768,
        height: 1024,
        description: '768 × 1024 portrait tablet viewport',
    },
    mobile: {
        id: 'mobile',
        label: 'Mobile',
        width: 390,
        height: 844,
        description: '390 × 844 modern mobile viewport',
    },
};

export interface SafeWebViewerProps {
    sessionId?: string | null;
    initialPageId?: string | null;
    targetUrl: string;
    backendUrl?: string;
    screenshotB64?: string | null;
    screenshotType?: string | null;
    onClose?: () => void;
    onRescan?: () => void;
}

export const SafeWebViewer: React.FC<SafeWebViewerProps> = ({
    sessionId,
    initialPageId = 'p_root',
    targetUrl,
    backendUrl = 'http://localhost:5000',
    screenshotB64,
    screenshotType = 'full_page',
    onClose,
    onRescan,
}) => {
    // Session ID state with sessionStorage persistence across page reloads (Requirement 15)
    const [effectiveSessionId, setEffectiveSessionId] = useState<string | null>(() => {
        if (sessionId) return sessionId;
        try {
            const saved = sessionStorage.getItem('pg_active_safe_view_session');
            if (saved) {
                const parsed = JSON.parse(saved);
                if (parsed.sessionId && (!targetUrl || parsed.targetUrl === targetUrl)) {
                    return parsed.sessionId;
                }
            }
        } catch (e) {}
        return null;
    });

    // Safe View Status (Requirement 22: LOADING, AVAILABLE, PARTIAL, BLOCKED, FAILED, TIMEOUT)
    const [safeViewStatus, setSafeViewStatus] = useState<'LOADING' | 'AVAILABLE' | 'PARTIAL' | 'BLOCKED' | 'FAILED' | 'TIMEOUT' | 'SESSION_EXPIRED' | 'UNAVAILABLE' | 'PENDING'>('LOADING');
    const [representationNotFound, setRepresentationNotFound] = useState<boolean>(false);
    const [notFoundDetails, setNotFoundDetails] = useState<{
        session_id?: string;
        page_id?: string;
        reason?: string;
        isExpired?: boolean;
    } | null>(null);

    // Viewer Mode: 'visual' | 'forensic' | 'screenshot'
    const [viewerMode, setViewerMode] = useState<'visual' | 'forensic' | 'screenshot'>('visual');
    const [viewportSize, setViewportSize] = useState<'desktop' | 'tablet' | 'mobile'>('desktop');
    const [zoomLevel, setZoomLevel] = useState<number>(100);
    const [isFullscreen, setIsFullscreen] = useState<boolean>(false);

    // Active Page & Discovered Pages
    const [activePageId, setActivePageId] = useState<string>(initialPageId || 'p_root');
    const [pagesList, setPagesList] = useState<DiscoveredPage[]>([]);
    const [isRightPanelOpen, setIsRightPanelOpen] = useState<boolean>(false);

    // Browser-like History Stack (Back / Forward)
    const [history, setHistory] = useState<string[]>([initialPageId || 'p_root']);
    const [historyIndex, setHistoryIndex] = useState<number>(0);

    // Forensic Right Panel Tabs: 'overview' | 'content' | 'forms' | 'links' | 'network' | 'dom' | 'timeline'
    const [activeTab, setActiveTab] = useState<'overview' | 'content' | 'forms' | 'links' | 'network' | 'dom' | 'timeline'>('overview');

    // Page Detail Data
    const [pageDetail, setPageDetail] = useState<any>(null);
    const [domData, setDomData] = useState<{ dom_diff?: DOMDiff; initial_dom?: string; final_dom?: string } | null>(null);
    const [networkData, setNetworkData] = useState<NetworkForensics | null>(null);
    const [timelineData, setTimelineData] = useState<TimelineEvent[]>([]);
    const [selectedElement, setSelectedElement] = useState<InspectedElement | null>(null);

    const [isLoading, setIsLoading] = useState<boolean>(true);
    const [isNavigating, setIsNavigating] = useState<boolean>(false);
    const [pendingNavUrl, setPendingNavUrl] = useState<string | null>(null);
    const [blockedActionNotice, setBlockedActionNotice] = useState<string | null>(null);
    const [urlInputValue, setUrlInputValue] = useState<string>('');
    const [isUrlInputFocused, setIsUrlInputFocused] = useState<boolean>(false);

    const iframeRef = useRef<HTMLIFrameElement>(null);
    const containerRef = useRef<HTMLDivElement>(null);

    // In-memory client-side representation cache & deduplication maps for immediate switching
    const pageCacheRef = useRef<Map<string, any>>(new Map());
    const inflightPageFetchRef = useRef<Map<string, Promise<{ ok: boolean; status?: number; pageObj?: any; errJson?: any }>>>(new Map());
    const inflightNavRef = useRef<Map<string, Promise<any>>>(new Map());
    const prefetchStartedRef = useRef<Set<string>>(new Set());
    const [isPrioritizing, setIsPrioritizing] = useState<boolean>(false);
    const getCacheKey = (sidVal: string | null | undefined, pid: string) => `${sidVal || 'default'}::${pid}`;
    // URL to pageId lookup cache for instant browser-like link navigation
    const urlToPageIdRef = useRef<Map<string, string>>(new Map());
    const navSeqRef = useRef<number>(0);
    const pendingHashRef = useRef<string | null>(null);
    const blockedNoticeTimerRef = useRef<number | null>(null);
    const lastHoveredUrlRef = useRef<string | null>(null);
    const hoverPrefetchTimerRef = useRef<number | null>(null);

    const normalizeComparableUrl = (rawUrl: string): string => {
        try {
            const parsed = new URL(rawUrl);
            const cleanPath = parsed.pathname.replace(/\/+$/, '') || '/';
            return `${parsed.origin.toLowerCase()}${cleanPath}${parsed.search}`;
        } catch (_) {
            return rawUrl.split('#')[0].replace(/\/+$/, '');
        }
    };

    const indexPageUrl = (rawUrl: string | undefined, pid: string) => {
        if (!rawUrl || !pid) return;
        const withoutHash = rawUrl.split('#')[0];
        if (!withoutHash) return;
        urlToPageIdRef.current.set(withoutHash, pid);
        urlToPageIdRef.current.set(normalizeComparableUrl(withoutHash), pid);
        if (withoutHash.endsWith('/')) {
            urlToPageIdRef.current.set(withoutHash.slice(0, -1), pid);
        } else {
            urlToPageIdRef.current.set(`${withoutHash}/`, pid);
        }
    };

    const showBlockedNotice = (msg: string) => {
        setBlockedActionNotice(msg);
        if (blockedNoticeTimerRef.current) {
            window.clearTimeout(blockedNoticeTimerRef.current);
        }
        blockedNoticeTimerRef.current = window.setTimeout(() => {
            setBlockedActionNotice(null);
            blockedNoticeTimerRef.current = null;
        }, 4500);
    };

    useEffect(() => {
        return () => {
            if (blockedNoticeTimerRef.current) {
                window.clearTimeout(blockedNoticeTimerRef.current);
            }
            if (hoverPrefetchTimerRef.current) {
                window.clearTimeout(hoverPrefetchTimerRef.current);
            }
        };
    }, []);

    // Keep effectiveSessionId in sync when sessionId prop updates
    useEffect(() => {
        if (sessionId && sessionId !== effectiveSessionId) {
            navSeqRef.current += 1;
            setEffectiveSessionId(sessionId);
            pageCacheRef.current.clear();
            urlToPageIdRef.current.clear();
            inflightPageFetchRef.current.clear();
            inflightNavRef.current.clear();
            prefetchStartedRef.current.clear();
            setPendingNavUrl(null);
            setIsNavigating(false);
            setBlockedActionNotice(null);
        }
    }, [sessionId]);

    // Persist active scan state to sessionStorage (Requirement 15)
    useEffect(() => {
        if (effectiveSessionId) {
            try {
                sessionStorage.setItem('pg_active_safe_view_session', JSON.stringify({
                    sessionId: effectiveSessionId,
                    activePageId,
                    targetUrl,
                    timestamp: Date.now(),
                }));
            } catch (e) {}
        }
    }, [effectiveSessionId, activePageId, targetUrl]);

    // Escape Key listener & body overflow lock for Full-Screen Mode (Requirements 3 & 18)
    useEffect(() => {
        if (!isFullscreen) return;

        const handleKeyDown = (e: KeyboardEvent) => {
            if (e.key === 'Escape') {
                e.preventDefault();
                setIsFullscreen(false);
            }
        };

        document.body.style.overflow = 'hidden';
        window.addEventListener('keydown', handleKeyDown);

        return () => {
            document.body.style.overflow = '';
            window.removeEventListener('keydown', handleKeyDown);
        };
    }, [isFullscreen]);

    // Background polling to index discovered pages for zero-latency click & hover prefetching
    useEffect(() => {
        const sid = effectiveSessionId;
        if (!sid) {
            const fallbackPage: DiscoveredPage = {
                page_id: 'p_root',
                url: targetUrl,
                path: '/',
                title: targetUrl,
                http_status: 200,
                depth: 0,
                forms_count: 1,
                has_credentials: true,
                risk_level: 'HIGH',
                screenshot_available: !!screenshotB64,
                is_root: true,
                analyzed: false,
            };
            setPagesList([fallbackPage]);
            setSafeViewStatus('UNAVAILABLE');
            setRepresentationNotFound(true);
            setNotFoundDetails({
                session_id: 'None',
                page_id: 'p_root',
                reason: 'No active analysis session found. Please run a scan.',
                isExpired: false,
            });
            setIsLoading(false);
            return;
        }

        let isCancelled = false;
        let pollInterval: ReturnType<typeof setInterval> | null = null;

        const fetchPages = async () => {
            try {
                const res = await fetch(`${backendUrl}/safe-view/pages/${encodeURIComponent(sid)}`);
                if (!res.ok || isCancelled) return;
                const data = await res.json();
                if (isCancelled) return;

                if (data.pages && Array.isArray(data.pages)) {
                    data.pages.forEach((p: DiscoveredPage) => {
                        indexPageUrl(p.url, p.page_id);
                    });
                    setPagesList(prev => {
                        if (
                            prev.length === data.pages.length &&
                            prev.every((p, i) => p.status === data.pages[i]?.status && p.page_id === data.pages[i]?.page_id)
                        ) {
                            return prev;
                        }
                        return data.pages;
                    });
                    if (!activePageId && data.pages.length > 0) {
                        setActivePageId(data.pages[0].page_id);
                    }
                }
                const stats = data.discovery || data.discovery_stats;
                if (stats?.completed && pollInterval) {
                    clearInterval(pollInterval);
                    pollInterval = null;
                }
            } catch (err) {
                console.warn('[SAFEVIEW] Failed to fetch pages list:', err);
            }
        };

        fetchPages();
        pollInterval = setInterval(fetchPages, 2000);
        return () => {
            isCancelled = true;
            if (pollInterval) clearInterval(pollInterval);
        };
    }, [effectiveSessionId, backendUrl, targetUrl, screenshotB64]);

    // Keep activePageId in sync when initialPageId changes
    useEffect(() => {
        if (initialPageId) {
            setActivePageId(initialPageId);
            setHistory([initialPageId]);
            setHistoryIndex(0);
        }
    }, [initialPageId, effectiveSessionId]);

    const resolveStatusFromPageObj = (pageObj: any): 'LOADING' | 'AVAILABLE' | 'PARTIAL' | 'BLOCKED' | 'FAILED' | 'TIMEOUT' => {
        if (pageObj?.scan_status === 'BLOCKED' || pageObj?.security_block) return 'BLOCKED';
        if (pageObj?.scan_status === 'TIMEOUT' || pageObj?.error_type === 'PAGE_NAVIGATION_TIMEOUT') return 'TIMEOUT';
        if (pageObj?.scan_status === 'PARTIAL' || (pageObj?.failed_resources && pageObj.failed_resources.length > 0)) return 'PARTIAL';
        if (pageObj?.page_available || pageObj?.safe_html) return 'AVAILABLE';
        if (pageObj?.error_type || pageObj?.error) return 'FAILED';
        return 'AVAILABLE';
    };

    const applyLoadedPageData = (pid: string, pageObj: any) => {
        if (!pageObj) return;
        indexPageUrl(pageObj.url, pid);
        setPageDetail(pageObj);
        setSafeViewStatus(resolveStatusFromPageObj(pageObj));
        setRepresentationNotFound(false);
        setNotFoundDetails(null);
        setIsPrioritizing(false);
        setIsLoading(false);
        setIsNavigating(false);
        setPendingNavUrl(null);

        if (pageObj.dom_diff || pageObj.initial_dom || pageObj.final_dom) {
            setDomData({
                dom_diff: pageObj.dom_diff,
                initial_dom: pageObj.initial_dom,
                final_dom: pageObj.final_dom,
            });
        } else {
            setDomData(null);
        }
        setNetworkData(pageObj.network_forensics || null);
        setTimelineData(Array.isArray(pageObj.timeline) ? pageObj.timeline : []);

        if (pageObj.elements_map && pageObj.elements_map.length > 0) {
            const highRiskElem =
                pageObj.elements_map.find((e: InspectedElement) => e.risk === 'CRITICAL' || e.risk === 'HIGH') ||
                pageObj.elements_map[0];
            setSelectedElement(highRiskElem);
        } else {
            setSelectedElement(null);
        }
    };

    const historyStateRef = useRef({ history, historyIndex });
    historyStateRef.current = { history, historyIndex };

    const pushHistoryPageId = (newPageId: string) => {
        const { history: curHistory, historyIndex: curIndex } = historyStateRef.current;
        if (curHistory[curIndex] === newPageId) return;
        const next = curHistory.slice(0, curIndex + 1);
        next.push(newPageId);
        historyStateRef.current = { history: next, historyIndex: next.length - 1 };
        setHistory(next);
        setHistoryIndex(next.length - 1);
    };

    const isUsablePageRepresentation = (pageObj: any): boolean => {
        if (!pageObj) return false;
        const htmlStr = String(pageObj.safe_html || '');
        if (!htmlStr || htmlStr.includes('PAGE NAVIGATION FAILED')) {
            return false;
        }
        const st = String(pageObj.scan_status || '').toUpperCase();
        if (['QUEUED', 'ANALYZING'].includes(st)) {
            return false;
        }
        // If we have valid safe_html and page is not explicitly an unrendered failure, it is usable
        if (pageObj.page_available === false && !htmlStr) {
            return false;
        }
        return true;
    };

    const fetchAndCachePage = async (
        pageId: string
    ): Promise<{ ok: boolean; status?: number; pageObj?: any; errJson?: any }> => {
        const sid = effectiveSessionId;
        const key = getCacheKey(sid, pageId);

        if (pageCacheRef.current.has(key)) {
            return { ok: true, pageObj: pageCacheRef.current.get(key) };
        }
        const existingInflight = inflightPageFetchRef.current.get(key);
        if (existingInflight) {
            return existingInflight;
        }

        const promise = (async () => {
            try {
                let resPage: Response;
                if (sid) {
                    resPage = await fetch(`${backendUrl}/safe-view/session/${encodeURIComponent(sid)}/page/${encodeURIComponent(pageId)}`);
                    if (!resPage.ok && resPage.status === 404) {
                        const fallbackRes = await fetch(`${backendUrl}/safe-view/page/${encodeURIComponent(pageId)}?session_id=${encodeURIComponent(sid)}`);
                        if (fallbackRes.ok) resPage = fallbackRes;
                    }
                } else {
                    resPage = await fetch(`${backendUrl}/safe-view/page/${encodeURIComponent(pageId)}`);
                }

                if (resPage.ok) {
                    const data = await resPage.json();
                    const pageObj = data.page || data;
                    if (isUsablePageRepresentation(pageObj)) {
                        pageCacheRef.current.set(key, pageObj);
                        indexPageUrl(pageObj.url, pageId);
                    }
                    return { ok: true, pageObj };
                }

                const errJson = await resPage.json().catch(() => ({}));
                return { ok: false, status: resPage.status, errJson };
            } finally {
                inflightPageFetchRef.current.delete(key);
            }
        })();

        inflightPageFetchRef.current.set(key, promise);
        return promise;
    };

    // Navigate to page with browser-like history tracking & instant cache retrieval
    const navigateToPage = (newPageId: string) => {
        if (newPageId === activePageId) return;
        pushHistoryPageId(newPageId);
        setActivePageId(newPageId);

        const cacheKey = getCacheKey(effectiveSessionId, newPageId);
        if (pageCacheRef.current.has(cacheKey)) {
            const cachedPage = pageCacheRef.current.get(cacheKey);
            applyLoadedPageData(newPageId, cachedPage);
            return;
        }

        const targetCand = pagesList.find(p => p.page_id === newPageId);
        if (targetCand && (targetCand.status === 'QUEUED' || !targetCand.analyzed)) {
            setIsPrioritizing(true);
            if (effectiveSessionId) {
                fetch(`${backendUrl}/safe-view/session/${encodeURIComponent(effectiveSessionId)}/prioritize/${encodeURIComponent(newPageId)}`, { method: 'POST' })
                    .catch(() => {});
            }
        } else {
            setIsPrioritizing(false);
        }
    };

    const handleBack = () => {
        if (historyIndex > 0) {
            navSeqRef.current += 1;
            pendingHashRef.current = null;
            setPendingNavUrl(null);
            setIsNavigating(false);
            setBlockedActionNotice(null);
            const prevId = history[historyIndex - 1];
            setHistoryIndex(historyIndex - 1);
            setActivePageId(prevId);
        }
    };

    const handleForward = () => {
        if (historyIndex < history.length - 1) {
            navSeqRef.current += 1;
            pendingHashRef.current = null;
            setPendingNavUrl(null);
            setIsNavigating(false);
            setBlockedActionNotice(null);
            const nextId = history[historyIndex + 1];
            setHistoryIndex(historyIndex + 1);
            setActivePageId(nextId);
        }
    };

    const handleReload = () => {
        if (activePageId) {
            navSeqRef.current += 1;
            pageCacheRef.current.delete(getCacheKey(effectiveSessionId, activePageId));
            setBlockedActionNotice(null);
            fetchPageDetails(activePageId);
        }
    };

    const resolveKnownPage = (resolvedUrlNoHash: string): { pageId?: string; candidate?: DiscoveredPage } => {
        const normTarget = normalizeComparableUrl(resolvedUrlNoHash);
        let targetPageId =
            urlToPageIdRef.current.get(resolvedUrlNoHash) ||
            urlToPageIdRef.current.get(normTarget);

        let candidate = targetPageId ? pagesList.find(p => p.page_id === targetPageId) : undefined;
        if (!targetPageId) {
            candidate = pagesList.find(p => normalizeComparableUrl(p.url) === normTarget);
            if (candidate) {
                targetPageId = candidate.page_id;
                indexPageUrl(candidate.url, candidate.page_id);
            }
        }
        return { pageId: targetPageId, candidate };
    };

    const scrollToHashInIframe = (rawHash: string) => {
        const doc = iframeRef.current?.contentDocument;
        const win = iframeRef.current?.contentWindow;
        if (!doc) return;
        const cleanId = decodeURIComponent(rawHash.replace(/^#/, '').trim());
        if (!cleanId || cleanId.toLowerCase() === 'top') {
            win?.scrollTo({ top: 0, behavior: 'smooth' });
            return;
        }
        let targetEl: Element | null = doc.getElementById(cleanId);
        if (!targetEl) {
            try {
                const escaped = cleanId.replace(/["\\]/g, '\\$&');
                targetEl = doc.querySelector(`[name="${escaped}"]`);
            } catch (_) {}
        }
        if (targetEl) {
            targetEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    };

    // Debounced hover prefetcher: loads ready pages into RAM or prioritizes queued pages before click
    const prefetchUrlOnHover = (rawUrl: string) => {
        const sid = effectiveSessionId;
        if (!sid || !rawUrl) return;
        let resolvedUrl = rawUrl;
        try {
            const base = pageDetail?.url || pagesList.find(p => p.page_id === activePageId)?.url || targetUrl;
            resolvedUrl = new URL(rawUrl, base).href;
        } catch (_) {
            return;
        }
        const urlNoHash = resolvedUrl.split('#')[0];
        const { pageId, candidate } = resolveKnownPage(urlNoHash);
        if (!pageId) return;
        const key = getCacheKey(sid, pageId);
        if (pageCacheRef.current.has(key)) return;

        if (candidate && (candidate.status === 'AVAILABLE' || candidate.analyzed)) {
            fetchAndCachePage(pageId).catch(() => {});
        } else if (candidate && candidate.status === 'QUEUED') {
            fetch(`${backendUrl}/safe-view/session/${encodeURIComponent(sid)}/prioritize/${encodeURIComponent(pageId)}`, { method: 'POST' })
                .catch(() => {});
        }
    };

    const startNavigateRequest = (
        sid: string,
        targetUrlNoHash: string,
        forceRetry = false
    ): Promise<{ ok: boolean; status: number; body: any }> => {
        const navKey = `${sid || 'direct'}::${normalizeComparableUrl(targetUrlNoHash)}`;
        if (!forceRetry) {
            const existingPromise = inflightNavRef.current.get(navKey);
            if (existingPromise) {
                return existingPromise;
            }
        }
        const navPromise = (async () => {
            let res: Response | null = null;
            if (sid) {
                try {
                    res = await fetch(`${backendUrl}/safe-view/session/${encodeURIComponent(sid)}/navigate`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            url: targetUrlNoHash,
                            device_profile: viewportSize,
                            ...(forceRetry ? { retry: true } : {}),
                        }),
                    });
                } catch (_) {
                    res = null;
                }
            }

            // Fallback to fast-load if session missing, expired (404), or unreachable
            if (!res || res.status === 404) {
                try {
                    res = await fetch(`${backendUrl}/safe-view/fast-load`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            url: targetUrlNoHash,
                            device_profile: viewportSize,
                            session_id: sid || undefined,
                            retry: forceRetry,
                        }),
                    });
                } catch (netErr: any) {
                    return { ok: false, status: 503, body: { reason: 'Backend connection failed' } };
                }
            }

            const body = await res.json().catch(() => ({}));
            return { ok: res.ok, status: res.status, body };
        })().finally(() => {
            inflightNavRef.current.delete(navKey);
        });
        inflightNavRef.current.set(navKey, navPromise);
        return navPromise;
    };

    // Speculative head-start on mousedown (before click completes) so uncached navigation begins ~100ms earlier
    const preconnectOrSpeculateOnMouseDown = (rawUrl: string) => {
        const sid = effectiveSessionId;
        if (!sid || !rawUrl) return;
        const currentBaseUrl = pageDetail?.url || pagesList.find(p => p.page_id === activePageId)?.url || targetUrl;
        let resolvedUrl = rawUrl;
        try {
            resolvedUrl = new URL(rawUrl, currentBaseUrl).href;
        } catch (_) {
            return;
        }
        const resolvedNoHash = resolvedUrl.split('#')[0];
        if (!resolvedNoHash || normalizeComparableUrl(resolvedNoHash) === normalizeComparableUrl(currentBaseUrl)) {
            return;
        }
        const { pageId, candidate } = resolveKnownPage(resolvedNoHash);
        if (pageId) {
            const cacheKey = getCacheKey(sid, pageId);
            if (pageCacheRef.current.has(cacheKey)) return;
            if (candidate && (candidate.status === 'AVAILABLE' || candidate.analyzed)) {
                fetchAndCachePage(pageId).catch(() => {});
                return;
            }
        }
        const shouldRetry = !!(candidate && (candidate.status === 'FAILED' || candidate.status === 'TIMEOUT'));
        startNavigateRequest(sid, resolvedNoHash, shouldRetry).catch(() => {});
    };

    // Immediate browser-like navigation by URL — cache-first with seamless non-blanking /navigate fallback
    const navigateByUrl = async (clickedUrl: string) => {
        if (!clickedUrl) return;
        const currentBaseUrl = pageDetail?.url || pagesList.find(p => p.page_id === activePageId)?.url || targetUrl;

        let resolvedUrl = clickedUrl;
        let parsedUrl: URL | null = null;
        try {
            parsedUrl = new URL(clickedUrl, currentBaseUrl);
            resolvedUrl = parsedUrl.href;
        } catch (_) {}

        const hashFragment = parsedUrl?.hash || (clickedUrl.startsWith('#') ? clickedUrl : '');
        const resolvedNoHash = resolvedUrl.split('#')[0];

        // Same-page #anchor navigation -> smooth scroll without reloading
        if (
            hashFragment &&
            normalizeComparableUrl(resolvedNoHash) === normalizeComparableUrl(currentBaseUrl)
        ) {
            setBlockedActionNotice(null);
            scrollToHashInIframe(hashFragment);
            return;
        }

        const seq = ++navSeqRef.current;
        pendingHashRef.current = hashFragment || null;
        setBlockedActionNotice(null);

        const { pageId: targetPageId, candidate } = resolveKnownPage(resolvedNoHash);
        const shouldForceRetry = !!(candidate && (candidate.status === 'FAILED' || candidate.status === 'TIMEOUT' || candidate.status === 'UNAVAILABLE'));

        // 1. Instant 0ms switch if already usable in client RAM cache
        if (targetPageId && !shouldForceRetry) {
            const cacheKey = getCacheKey(effectiveSessionId, targetPageId);
            if (pageCacheRef.current.has(cacheKey)) {
                const cachedObj = pageCacheRef.current.get(cacheKey);
                if (isUsablePageRepresentation(cachedObj)) {
                    navigateToPage(targetPageId);
                    return;
                }
                pageCacheRef.current.delete(cacheKey);
            }
        }

        const sid = effectiveSessionId || '';

        // Keep current page visible while loading in background — update address bar & progress bar immediately
        setPendingNavUrl(resolvedNoHash);
        setIsNavigating(true);

        // 2. If candidate is already analyzed on backend, fetch single usable representation payload
        if (targetPageId && !shouldForceRetry && candidate && (candidate.status === 'AVAILABLE' || candidate.analyzed)) {
            try {
                const res = await fetchAndCachePage(targetPageId);
                if (seq !== navSeqRef.current) return;
                if (res.ok && isUsablePageRepresentation(res.pageObj)) {
                    pushHistoryPageId(targetPageId);
                    setActivePageId(targetPageId);
                    applyLoadedPageData(targetPageId, res.pageObj);
                    return;
                }
            } catch (_) {
                if (seq !== navSeqRef.current) return;
            }
        }

        // 3. Call fast read-only /navigate endpoint (serves SSR HTML immediately or prioritizes/scans via VM)
        try {
            const result = await startNavigateRequest(sid, resolvedNoHash, shouldForceRetry);
            if (seq !== navSeqRef.current) return;

            if (!result.ok) {
                setIsNavigating(false);
                setPendingNavUrl(null);
                if (result.status === 403 || result.body?.write_blocked) {
                    showBlockedNotice(result.body?.reason || 'Read-only mode: write or destructive operation blocked.');
                } else if (result.status === 404 && result.body?.error_code === 'SESSION_EXPIRED') {
                    setSafeViewStatus('SESSION_EXPIRED');
                    setRepresentationNotFound(true);
                    setNotFoundDetails({
                        session_id: sid,
                        page_id: activePageId,
                        reason: result.body?.reason || 'Analysis session expired or backend process restarted.',
                        isExpired: true,
                    });
                } else {
                    showBlockedNotice(result.body?.reason || `Unable to load destination page (HTTP ${result.status}).`);
                }
                return;
            }

            const pageObj = result.body?.page || result.body;
            const newPageId: string = result.body?.page_id || pageObj?.page_id;
            if (result.body?.session_id && result.body.session_id !== effectiveSessionId) {
                setEffectiveSessionId(result.body.session_id);
            }
            if (newPageId && pageObj) {
                const pageUrl = pageObj.url || resolvedNoHash;
                const usable = isUsablePageRepresentation(pageObj);
                const resolvedStatus = usable ? 'AVAILABLE' : (pageObj.scan_status || 'FAILED');
                if (usable) {
                    pageCacheRef.current.set(getCacheKey(sid, newPageId), pageObj);
                } else {
                    pageCacheRef.current.delete(getCacheKey(sid, newPageId));
                }
                indexPageUrl(pageUrl, newPageId);
                indexPageUrl(resolvedNoHash, newPageId);

                setPagesList(prev => {
                    if (prev.some(p => p.page_id === newPageId)) {
                        return prev.map(p => (p.page_id === newPageId ? { ...p, status: resolvedStatus, analyzed: usable, url: pageUrl, title: pageObj.title || p.title } : p));
                    }
                    return [
                        ...prev,
                        {
                            page_id: newPageId,
                            url: pageUrl,
                            path: (() => { try { return new URL(pageUrl).pathname; } catch (_) { return '/'; } })(),
                            title: pageObj.title || pageUrl,
                            http_status: pageObj.http_status || 200,
                            depth: 1,
                            forms_count: pageObj.content_inventory?.forms ?? 0,
                            has_credentials: false,
                            risk_level: 'LOW',
                            screenshot_available: false,
                            is_root: false,
                            analyzed: usable,
                            status: resolvedStatus,
                        },
                    ];
                });

                pushHistoryPageId(newPageId);
                setActivePageId(newPageId);
                applyLoadedPageData(newPageId, pageObj);
            } else {
                setIsNavigating(false);
                setPendingNavUrl(null);
            }
        } catch (err) {
            if (seq !== navSeqRef.current) return;
            console.warn('[SAFEVIEW] Navigation request failed:', err);
            setIsNavigating(false);
            setPendingNavUrl(null);
            showBlockedNotice('Navigation request failed — check backend connection.');
        }
    };

    // Latest handler ref avoids stale closures in iframe document event listeners
    const latestHandlersRef = useRef({
        navigateByUrl,
        prefetchUrlOnHover,
        preconnectOrSpeculateOnMouseDown,
        scrollToHashInIframe,
        showBlockedNotice,
    });
    latestHandlersRef.current = {
        navigateByUrl,
        prefetchUrlOnHover,
        preconnectOrSpeculateOnMouseDown,
        scrollToHashInIframe,
        showBlockedNotice,
    };

    // Pure-DOM fallback toggles for dropdown menus, tabs, accordions, modals, and <details> inside JS-disabled srcDoc
    const toggleInteractiveControlInIframe = (doc: Document, target: Element): boolean => {
        // 1. Native <details>/<summary>
        const summaryEl = target.closest('summary');
        if (summaryEl) {
            const detailsEl = summaryEl.closest('details') as HTMLDetailsElement | null;
            if (detailsEl) {
                detailsEl.open = !detailsEl.open;
                return true;
            }
        }

        const trigger = target.closest(
            'a, button, [role="button"], [role="tab"], .dropdown-toggle, [data-bs-toggle], [data-toggle], [aria-controls], [aria-haspopup], [data-target], [data-bs-target], [data-tab], [data-dismiss], [data-bs-dismiss], .close, .btn-close, .modal-close'
        ) as HTMLElement | null;
        if (!trigger) return false;

        // 0. Cookie Consent / GDPR Banner / Modal / Dialog / Overlay Dismissal
        const isDismissOrConsent =
            trigger.matches(
                '[data-dismiss], [data-bs-dismiss], [aria-label*="close" i], [title*="close" i], .close, .btn-close, .modal-close, .popup-close, .dialog-close, [class*="close-btn" i], [class*="close-icon" i]'
            ) ||
            /^(?:accept|accept all|accept cookies|agree|allow|allow all|reject|reject all|reject optional|decline|dismiss|close|got it|i understand|ok|okay|continue|manage settings|save preferences)$/i.test(
                (trigger.textContent || '').trim().replace(/\s+/g, ' ')
            ) ||
            trigger.closest(
                '#onetrust-consent-sdk, #onetrust-banner-sdk, #CybotCookiebotDialog, .cc-window, .cookie-notice, .cookie-banner, .cookie-consent, [id*="cookie" i], [class*="cookie" i], [id*="consent" i], [class*="consent" i]'
            ) !== null;

        if (isDismissOrConsent) {
            const modalOrBanner =
                trigger.closest(
                    '#onetrust-consent-sdk, #onetrust-banner-sdk, #CybotCookiebotDialog, .cc-window, .cookie-notice, .cookie-banner, .cookie-consent, [id*="cookie" i], [class*="cookie" i], [id*="consent" i], [class*="consent" i], .modal, [role="dialog"], [role="alertdialog"], .dialog, .popup, [class*="popup" i], .overlay, [class*="overlay" i]'
                ) ||
                trigger.closest('div[style*="z-index"], section[style*="z-index"], aside[style*="z-index"]');

            if (modalOrBanner) {
                (modalOrBanner as HTMLElement).style.setProperty('display', 'none', 'important');
                (modalOrBanner as HTMLElement).style.setProperty('visibility', 'hidden', 'important');
                (modalOrBanner as HTMLElement).style.setProperty('pointer-events', 'none', 'important');
                (modalOrBanner as HTMLElement).setAttribute('aria-hidden', 'true');
            }

            // Remove any dark backdrop or modal overlays covering the page
            doc.querySelectorAll(
                '.modal-backdrop, .overlay-backdrop, .backdrop, [class*="backdrop" i], [class*="overlay-bg" i]'
            ).forEach(b => {
                (b as HTMLElement).style.setProperty('display', 'none', 'important');
                (b as HTMLElement).style.setProperty('pointer-events', 'none', 'important');
            });

            // Unlock body and html scrolling so the page can scroll normally
            doc.body.style.setProperty('overflow', 'auto', 'important');
            doc.documentElement.style.setProperty('overflow', 'auto', 'important');
            doc.body.classList.remove('modal-open', 'has-modal', 'cookie-open', 'ot-modal-open');
            return true;
        }

        // Ignore disabled submit/form controls
        if ((trigger as HTMLButtonElement).disabled || trigger.closest('form button[disabled]')) {
            return false;
        }

        // 2. Targeted panels via aria-controls, data-bs-target, data-target, data-tab
        const rawTarget =
            trigger.getAttribute('aria-controls') ||
            trigger.getAttribute('data-bs-target') ||
            trigger.getAttribute('data-target') ||
            trigger.getAttribute('data-tab');
        if (rawTarget) {
            const selector = rawTarget.startsWith('#') || rawTarget.startsWith('.') ? rawTarget : `#${rawTarget.replace(/[^\w\-:.]/g, '')}`;
            try {
                const panel = doc.querySelector(selector) as HTMLElement | null;
                if (panel) {
                    const isTab = trigger.getAttribute('role') === 'tab' || trigger.hasAttribute('data-tab') || panel.getAttribute('role') === 'tabpanel';
                    if (isTab && panel.parentElement) {
                        Array.from(panel.parentElement.children).forEach(sib => {
                            if (sib !== panel) {
                                sib.classList.remove('pg-panel-open', 'show', 'active');
                                if ((sib as HTMLElement).style) (sib as HTMLElement).style.display = 'none';
                            }
                        });
                        if (trigger.parentElement) {
                            trigger.parentElement.querySelectorAll('[role="tab"], .nav-link, .active').forEach(tb => {
                                tb.classList.remove('active');
                                tb.setAttribute('aria-selected', 'false');
                            });
                        }
                        trigger.classList.add('active');
                        trigger.setAttribute('aria-selected', 'true');
                        panel.classList.add('pg-panel-open', 'show', 'active');
                        panel.removeAttribute('hidden');
                        panel.style.display = 'block';
                        return true;
                    }
                    const currentlyOpen = panel.classList.contains('pg-panel-open') || panel.classList.contains('show');
                    panel.classList.toggle('pg-panel-open', !currentlyOpen);
                    panel.classList.toggle('show', !currentlyOpen);
                    if (!currentlyOpen) {
                        panel.removeAttribute('hidden');
                        panel.style.display = 'block';
                    } else {
                        panel.style.display = 'none';
                    }
                    trigger.setAttribute('aria-expanded', currentlyOpen ? 'false' : 'true');
                    return true;
                }
            } catch (_) {}
        }

        // 3. Dropdown / navigation submenus (e.g. "GENRES v", "More v", WordPress .sub-menu, Bootstrap .dropdown-menu)
        const dropdownParent = trigger.closest('li, .dropdown, .menu-item, .nav-item, .has-dropdown') as HTMLElement | null;
        const childMenu = dropdownParent?.querySelector(':scope > ul, :scope > .sub-menu, :scope > .children, :scope > .dropdown-menu, :scope > [role="menu"]') as HTMLElement | null;
        if (dropdownParent && childMenu) {
            const wasOpen = dropdownParent.classList.contains('pg-dropdown-open');
            doc.querySelectorAll('.pg-dropdown-open').forEach(openEl => {
                if (openEl !== dropdownParent && !openEl.contains(dropdownParent)) {
                    openEl.classList.remove('pg-dropdown-open', 'open', 'show');
                }
            });
            dropdownParent.classList.toggle('pg-dropdown-open', !wasOpen);
            dropdownParent.classList.toggle('open', !wasOpen);
            childMenu.classList.toggle('show', !wasOpen);
            childMenu.style.display = wasOpen ? '' : 'block';
            trigger.setAttribute('aria-expanded', wasOpen ? 'false' : 'true');
            return true;
        }

        // 4. Accordion / collapsible sibling block next to a non-form UI button
        const nextEl = trigger.nextElementSibling as HTMLElement | null;
        if (
            nextEl &&
            (nextEl.classList.contains('collapse') ||
                nextEl.classList.contains('accordion-collapse') ||
                nextEl.classList.contains('accordion-body') ||
                nextEl.classList.contains('panel') ||
                nextEl.classList.contains('dropdown-menu') ||
                nextEl.getAttribute('role') === 'region')
        ) {
            const wasOpen = nextEl.classList.contains('pg-panel-open') || nextEl.classList.contains('show');
            nextEl.classList.toggle('pg-panel-open', !wasOpen);
            nextEl.classList.toggle('show', !wasOpen);
            nextEl.style.display = wasOpen ? 'none' : 'block';
            trigger.setAttribute('aria-expanded', wasOpen ? 'false' : 'true');
            return true;
        }

        // 5. Navbar Toggler / Mobile Navigation Menu
        const isNavToggler = trigger.matches(
            '.navbar-toggler, .menu-toggle, .nav-toggle, [aria-label*="menu" i], [title*="menu" i], .hamburger, [class*="hamburger" i], [class*="menu-btn" i], [class*="nav-btn" i], [id*="menu-btn" i], [id*="nav-toggle" i]'
        );
        if (isNavToggler) {
            const navCollapse =
                doc.querySelector(
                    '.navbar-collapse, .nav-menu, .navigation-menu, .mobile-menu, [role="navigation"] ul, header nav, .nav-links, .menu-container'
                ) as HTMLElement | null;
            if (navCollapse) {
                const wasOpen =
                    navCollapse.classList.contains('show') ||
                    navCollapse.classList.contains('pg-panel-open') ||
                    navCollapse.style.display === 'block';
                navCollapse.classList.toggle('show', !wasOpen);
                navCollapse.classList.toggle('pg-panel-open', !wasOpen);
                navCollapse.style.display = wasOpen ? 'none' : 'block';
                trigger.setAttribute('aria-expanded', wasOpen ? 'false' : 'true');
                return true;
            }
        }

        return false;
    };

    const attachIframeHandlers = (fromOnLoad = false) => {
        const iframe = iframeRef.current;
        if (!iframe) return;
        try {
            const doc = iframe.contentDocument;
            if (!doc) return;

            const prevState = (doc as any).__pgListeners;
            if (prevState) {
                doc.removeEventListener('click', prevState.onClick, true);
                doc.removeEventListener('mousedown', prevState.onMouseDown, true);
                doc.removeEventListener('submit', prevState.onSubmit, true);
                doc.removeEventListener('keydown', prevState.onEditAttempt, true);
                doc.removeEventListener('input', prevState.onEditAttempt, true);
                doc.removeEventListener('change', prevState.onEditAttempt, true);
                doc.removeEventListener('mouseover', prevState.onMouseOver, true);
            }

            const onSubmit = (e: Event) => {
                e.preventDefault();
                e.stopPropagation();
                latestHandlersRef.current.showBlockedNotice('Read-only mode: form submissions are blocked.');
            };

            const onEditAttempt = (e: Event) => {
                const target = e.target as Element | null;
                if (target?.closest('input, textarea, select, [contenteditable]')) {
                    const keyEvent = e as KeyboardEvent;
                    if (e.type === 'keydown' && ['Tab', 'Escape', 'ArrowUp', 'ArrowDown', 'PageUp', 'PageDown'].includes(keyEvent.key)) {
                        return;
                    }
                    e.preventDefault();
                    e.stopPropagation();
                    latestHandlersRef.current.showBlockedNotice('Read-only mode: editing inputs and forms is disabled.');
                }
            };

            function findInComposedPath(event: Event, selector: string): Element | null {
                if (typeof (event as any).composedPath === 'function') {
                    const path = (event as any).composedPath();
                    for (let i = 0; i < path.length; i++) {
                        const el = path[i];
                        if (el && (el as Element).nodeType === 1) {
                            if (typeof (el as Element).matches === 'function' && (el as Element).matches(selector)) {
                                return el as Element;
                            }
                        }
                    }
                }
                const target = (event as MouseEvent).target as Element | null;
                return target && typeof target.closest === 'function' ? target.closest(selector) : null;
            }

            const onClick = (e: Event) => {
                const mouseEvent = e as MouseEvent;
                const path = typeof mouseEvent.composedPath === 'function' ? mouseEvent.composedPath() : [];
                const target = (path[0] as Element | null) || (mouseEvent.target as Element | null);
                if (!target) return;

                // 0. Backdrop click: dismiss any active modal or cookie overlay
                if (target.matches('.modal-backdrop, .overlay-backdrop, .backdrop, [class*="backdrop" i]')) {
                    mouseEvent.preventDefault();
                    mouseEvent.stopPropagation();
                    doc.querySelectorAll(
                        '.modal, [role="dialog"], [role="alertdialog"], .modal-backdrop, [class*="backdrop" i], #onetrust-consent-sdk, #onetrust-banner-sdk, #CybotCookiebotDialog'
                    ).forEach(el => {
                        (el as HTMLElement).style.setProperty('display', 'none', 'important');
                        (el as HTMLElement).style.setProperty('pointer-events', 'none', 'important');
                    });
                    doc.body.style.setProperty('overflow', 'auto', 'important');
                    doc.documentElement.style.setProperty('overflow', 'auto', 'important');
                    return;
                }

                // 1. Block downloads explicitly
                const downloadEl = findInComposedPath(mouseEvent, '[data-pg-download], a[download]');
                if (downloadEl) {
                    mouseEvent.preventDefault();
                    mouseEvent.stopPropagation();
                    latestHandlersRef.current.showBlockedNotice('Read-only mode: file downloads are blocked for your safety.');
                    return;
                }

                // 2. Block unsupported URI schemes (mailto:, tel:, data:, blob:, etc.)
                const blockedSchemeEl = findInComposedPath(mouseEvent, '[data-pg-blocked-scheme]');
                if (blockedSchemeEl) {
                    mouseEvent.preventDefault();
                    mouseEvent.stopPropagation();
                    const scheme = blockedSchemeEl.getAttribute('data-pg-blocked-scheme') || 'external';
                    latestHandlersRef.current.showBlockedNotice(`Read-only mode: "${scheme}:" links are blocked.`);
                    return;
                }

                // 3. Block sanitized write/destructive action links
                const disabledActionEl = findInComposedPath(mouseEvent, '[data-pg-disabled-action="true"]');
                if (disabledActionEl) {
                    mouseEvent.preventDefault();
                    mouseEvent.stopPropagation();
                    latestHandlersRef.current.showBlockedNotice('Read-only mode: write or destructive actions are blocked.');
                    return;
                }

                // 4. Same-page #anchor links (checked before data-pg-href since hash links may carry javascript:void(0))
                const hashLink = findInComposedPath(mouseEvent, '[data-pg-hash]') as HTMLElement | null;
                if (hashLink) {
                    mouseEvent.preventDefault();
                    mouseEvent.stopPropagation();
                    const hash = hashLink.getAttribute('data-pg-hash');
                    if (hash) latestHandlersRef.current.scrollToHashInIframe(hash);
                    return;
                }

                // 5. Universal URL Destination Resolver for all clickable buttons, links, cards, and navigation controls
                const resolveTargetUrl = (): string | null => {
                    // Check direct navigation elements or attributes on target or its composed ancestors
                    const navEl = findInComposedPath(
                        mouseEvent,
                        '[data-pg-href], a[href], area[href], button[data-pg-href], [data-href], [data-url], [data-to], [data-link], [data-link-url], [data-target-url], [data-route], [data-path], [data-navigate], [data-destination], [data-permalink], [data-page], [formaction], button[href]'
                    ) as HTMLElement | null;

                    if (navEl) {
                        const raw =
                            navEl.getAttribute('data-pg-href') ||
                            navEl.getAttribute('href') ||
                            navEl.getAttribute('data-url') ||
                            navEl.getAttribute('data-href') ||
                            navEl.getAttribute('data-to') ||
                            navEl.getAttribute('data-link') ||
                            navEl.getAttribute('data-link-url') ||
                            navEl.getAttribute('data-target-url') ||
                            navEl.getAttribute('data-route') ||
                            navEl.getAttribute('data-path') ||
                            navEl.getAttribute('data-navigate') ||
                            navEl.getAttribute('data-destination') ||
                            navEl.getAttribute('data-permalink') ||
                            navEl.getAttribute('data-page') ||
                            navEl.getAttribute('formaction') ||
                            '';
                        const trimmed = raw.trim();
                        if (
                            trimmed &&
                            trimmed !== '#' &&
                            !trimmed.toLowerCase().startsWith('javascript:') &&
                            !trimmed.toLowerCase().startsWith('mailto:') &&
                            !trimmed.toLowerCase().startsWith('tel:')
                        ) {
                            return trimmed;
                        }
                    }

                    // Check if an anchor exists inside the clicked element (e.g. <button><a href="...">...</a></button>)
                    const innerAnchor = target
                        .closest('button, [role="button"], div, li, [data-pg-control]')
                        ?.querySelector('a[href], a[data-pg-href], [data-pg-href]') as HTMLElement | null;
                    if (innerAnchor) {
                        const raw = innerAnchor.getAttribute('data-pg-href') || innerAnchor.getAttribute('href') || '';
                        const trimmed = raw.trim();
                        if (trimmed && trimmed !== '#' && !trimmed.toLowerCase().startsWith('javascript:')) {
                            return trimmed;
                        }
                    }

                    // Check if clicked element is an action button inside a card/article/list-item (e.g. "Learn More", "Read More", "Explore")
                    const containerCard = target.closest(
                        '.card, .tile, .item, .product, article, li, .post, .teaser, .story, .block, [class*="card" i]'
                    );
                    if (containerCard) {
                        const cardLink = containerCard.querySelector('a[href], [data-pg-href]') as HTMLElement | null;
                        if (cardLink) {
                            const raw = cardLink.getAttribute('data-pg-href') || cardLink.getAttribute('href') || '';
                            const trimmed = raw.trim();
                            if (trimmed && trimmed !== '#' && !trimmed.toLowerCase().startsWith('javascript:')) {
                                return trimmed;
                            }
                        }
                    }

                    // Check if clicked button is inside a <form> with an action attribute
                    const enclosingForm = target.closest('form');
                    if (enclosingForm) {
                        const formAction = enclosingForm.getAttribute('action');
                        if (formAction && formAction.trim() && !formAction.toLowerCase().startsWith('javascript:')) {
                            return formAction.trim();
                        }
                    }

                    return null;
                };

                const destUrl = resolveTargetUrl();
                if (destUrl) {
                    if (destUrl.startsWith('#') && destUrl.length > 1) {
                        mouseEvent.preventDefault();
                        mouseEvent.stopPropagation();
                        if (!toggleInteractiveControlInIframe(doc, target)) {
                            latestHandlersRef.current.scrollToHashInIframe(destUrl);
                        }
                        return;
                    }
                    mouseEvent.preventDefault();
                    mouseEvent.stopPropagation();
                    latestHandlersRef.current.navigateByUrl(destUrl);
                    return;
                }

                // 6. Interactive read-only UI toggles (cookie banner dismissal, modals, dropdowns, tabs, accordions, hamburger menus)
                if (toggleInteractiveControlInIframe(doc, target)) {
                    mouseEvent.preventDefault();
                    mouseEvent.stopPropagation();
                    return;
                }

                // 7. Standalone UI button with no destination and no toggle
                const uiControlBtn = findInComposedPath(
                    mouseEvent,
                    'button[data-pg-control="ui"], button[type="button"], button:not([disabled])'
                ) as HTMLElement | null;
                if (uiControlBtn) {
                    mouseEvent.preventDefault();
                    mouseEvent.stopPropagation();
                    return;
                }

                // 8. Block write/form controls (inputs, selects, submit buttons)
                const writeControl = findInComposedPath(
                    mouseEvent,
                    'input:not([type="button"]):not([type="submit"]), textarea, select, option, button[disabled], form button[disabled], [contenteditable]'
                );
                if (writeControl) {
                    mouseEvent.preventDefault();
                    mouseEvent.stopPropagation();
                    latestHandlersRef.current.showBlockedNotice('Read-only mode: form inputs and write controls are disabled.');
                }
            };

            const onMouseDown = (e: Event) => {
                const mouseEvent = e as MouseEvent;
                if (mouseEvent.button !== 0) return;
                if (findInComposedPath(mouseEvent, '[data-pg-download], a[download], [data-pg-blocked-scheme], [data-pg-disabled-action="true"], [data-pg-hash]')) return;
                const navEl = findInComposedPath(mouseEvent, '[data-pg-href], a[href], area[href], button[data-pg-href], [data-href], [data-url], [data-to]') as HTMLElement | null;
                if (!navEl) return;
                const href = (navEl.getAttribute('data-pg-href') || navEl.getAttribute('href') || navEl.getAttribute('data-url') || navEl.getAttribute('data-href') || navEl.getAttribute('data-to') || '').trim();
                if (!href || href === '#' || href.startsWith('#') || href.toLowerCase().startsWith('javascript:')) return;
                latestHandlersRef.current.preconnectOrSpeculateOnMouseDown(href);
            };

            const onMouseOver = (e: Event) => {
                const navLink = findInComposedPath(e as MouseEvent, '[data-pg-href], a[href], [data-url], [data-href], [data-to]') as HTMLElement | null;
                const href = navLink?.getAttribute('data-pg-href') || navLink?.getAttribute('href') || navLink?.getAttribute('data-url') || navLink?.getAttribute('data-href') || navLink?.getAttribute('data-to');
                if (!href || href.toLowerCase().startsWith('javascript:') || href === lastHoveredUrlRef.current) return;
                if (navLink?.hasAttribute('data-pg-download') || navLink?.hasAttribute('data-pg-blocked-scheme') || navLink?.hasAttribute('data-pg-disabled-action')) return;
                lastHoveredUrlRef.current = href;
                if (hoverPrefetchTimerRef.current) {
                    window.clearTimeout(hoverPrefetchTimerRef.current);
                }
                hoverPrefetchTimerRef.current = window.setTimeout(() => {
                    latestHandlersRef.current.prefetchUrlOnHover(href);
                }, 65);
            };

            doc.addEventListener('click', onClick, true);
            doc.addEventListener('mousedown', onMouseDown, true);
            doc.addEventListener('submit', onSubmit, true);
            doc.addEventListener('keydown', onEditAttempt, true);
            doc.addEventListener('input', onEditAttempt, true);
            doc.addEventListener('change', onEditAttempt, true);
            doc.addEventListener('mouseover', onMouseOver, true);
            (doc as any).__pgListeners = { onClick, onMouseDown, onSubmit, onEditAttempt, onMouseOver };

            if (fromOnLoad || doc.readyState === 'complete') {
                if (pendingHashRef.current) {
                    const pendingHash = pendingHashRef.current;
                    pendingHashRef.current = null;
                    latestHandlersRef.current.scrollToHashInIframe(pendingHash);
                } else if (fromOnLoad) {
                    iframe.contentWindow?.scrollTo(0, 0);
                }
            }
        } catch (_) {
            // Sandbox boundary
        }
    };

    // Re-attach iframe read-only click/scroll/hover handlers whenever srcDoc content updates
    useEffect(() => {
        attachIframeHandlers();
    }, [activePageId, pageDetail?.safe_html]);

    // Fetch Full Forensic Details & Representation for the Active Page
    const fetchPageDetails = async (pageId: string) => {
        if (!pageId) return;
        const seq = navSeqRef.current;
        const hasVisibleContent = !!pageDetail?.safe_html;
        if (hasVisibleContent) {
            setIsNavigating(true);
        } else {
            setIsLoading(true);
        }
        setRepresentationNotFound(false);
        setNotFoundDetails(null);

        const sid = effectiveSessionId;
        try {
            const res = await fetchAndCachePage(pageId);
            if (seq !== navSeqRef.current) return;

            if (res.ok && res.pageObj) {
                const pageObj = res.pageObj;

                // If candidate is still processing in background, poll rapidly until ready
                if (pageObj.scan_status === 'QUEUED' || pageObj.scan_status === 'ANALYZING') {
                    setPageDetail(pageObj);
                    setSafeViewStatus('LOADING');
                    setIsPrioritizing(true);
                    setTimeout(() => {
                        if (activePageId === pageId && seq === navSeqRef.current) {
                            fetchPageDetails(pageId);
                        }
                    }, 600);
                    return;
                }

                applyLoadedPageData(pageId, pageObj);

                // Fallback only if inline forensic payloads are missing
                if (pageObj.network_forensics === undefined && pageObj.timeline === undefined) {
                    const queryParam = sid ? `?session_id=${encodeURIComponent(sid)}` : '';
                    fetch(`${backendUrl}/safe-view/dom/${encodeURIComponent(pageId)}${queryParam}`)
                        .then(r => (r.ok ? r.json() : null))
                        .then(dataDom => { if (dataDom) setDomData(dataDom); })
                        .catch(() => {});
                    fetch(`${backendUrl}/safe-view/network/${encodeURIComponent(pageId)}${queryParam}`)
                        .then(r => (r.ok ? r.json() : null))
                        .then(dataNet => { if (dataNet) setNetworkData(dataNet.network_forensics || null); })
                        .catch(() => {});
                    fetch(`${backendUrl}/safe-view/timeline/${encodeURIComponent(pageId)}${queryParam}`)
                        .then(r => (r.ok ? r.json() : null))
                        .then(dataTimeline => { if (dataTimeline) setTimelineData(dataTimeline.timeline || []); })
                        .catch(() => {});
                }
            } else {
                const navTargetUrl = targetUrl || currentDisplayUrl;
                if (navTargetUrl && !pageDetail?.safe_html) {
                    try {
                        const fastRes = await fetch(`${backendUrl}/safe-view/fast-load`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ url: navTargetUrl, device_profile: viewportSize, session_id: sid || undefined }),
                        });
                        if (fastRes.ok) {
                            const fastData = await fastRes.json();
                            const fastPage = fastData.page || fastData;
                            if (fastPage && isUsablePageRepresentation(fastPage)) {
                                if (fastData.session_id && fastData.session_id !== effectiveSessionId) {
                                    setEffectiveSessionId(fastData.session_id);
                                }
                                pageCacheRef.current.set(getCacheKey(fastData.session_id || sid, pageId), fastPage);
                                applyLoadedPageData(pageId, fastPage);
                                return;
                            }
                        }
                    } catch (_) {}
                }
                const errJson = res.errJson || {};
                const isExpired = errJson.error_code === 'SESSION_EXPIRED' || (errJson.message && errJson.message.toLowerCase().includes('expired'));
                setSafeViewStatus(isExpired ? 'SESSION_EXPIRED' : 'UNAVAILABLE');
                setRepresentationNotFound(true);
                setNotFoundDetails({
                    session_id: sid || 'None',
                    page_id: pageId,
                    reason: errJson.message || errJson.reason || (isExpired ? 'Analysis session expired or backend process restarted.' : 'The requested page representation is not available in the active session.'),
                    isExpired,
                });
                setIsLoading(false);
                setIsNavigating(false);
                setPendingNavUrl(null);
            }
        } catch (err: any) {
            if (seq !== navSeqRef.current) return;
            console.error('[SAFEVIEW] Network error requesting representation:', err);
            setSafeViewStatus('UNAVAILABLE');
            setRepresentationNotFound(true);
            setNotFoundDetails({
                session_id: sid || 'None',
                page_id: pageId,
                reason: 'Unable to connect to PhishGuard backend service.',
                isExpired: false,
            });
            setIsLoading(false);
            setIsNavigating(false);
            setPendingNavUrl(null);
        }
    };

    useEffect(() => {
        const cacheKey = getCacheKey(effectiveSessionId, activePageId);
        if (pageCacheRef.current.has(cacheKey)) {
            const cached = pageCacheRef.current.get(cacheKey);
            applyLoadedPageData(activePageId, cached);
            return;
        }
        fetchPageDetails(activePageId);
    }, [activePageId, backendUrl, effectiveSessionId]);

    // Background cache warming: prefetch analyzed pages AND gently warm top same-origin navbar links
    useEffect(() => {
        const sid = effectiveSessionId;
        if (!sid) return;

        let cancelled = false;

        // Collect URLs visible inside current page DOM to prioritize first
        const visibleLinkedUrls = new Set<string>();
        const navbarWarmUrls: string[] = [];
        try {
            const doc = iframeRef.current?.contentDocument;
            if (doc) {
                const base = pageDetail?.url || targetUrl;
                let baseHost = '';
                try { baseHost = new URL(base).hostname.toLowerCase(); } catch (_) {}

                function queryAllDeep(root: Node, selector: string, acc: Element[] = []): Element[] {
                    if ((root as Element).querySelectorAll) {
                        (root as Element).querySelectorAll(selector).forEach(el => acc.push(el));
                    }
                    const children = (root as any).childNodes;
                    if (children) {
                        for (let i = 0; i < children.length; i++) {
                            const child = children[i];
                            if (child && child.shadowRoot) {
                                queryAllDeep(child.shadowRoot, selector, acc);
                            }
                        }
                    }
                    return acc;
                }

                queryAllDeep(doc, '[data-pg-href]').forEach((el) => {
                    if (el.hasAttribute('data-pg-download') || el.hasAttribute('data-pg-blocked-scheme') || el.hasAttribute('data-pg-disabled-action')) return;
                    const raw = el.getAttribute('data-pg-href');
                    if (raw && !raw.toLowerCase().startsWith('javascript:')) {
                        try {
                            const absUrl = new URL(raw, base);
                            const cleanAbs = absUrl.href.split('#')[0];
                            visibleLinkedUrls.add(normalizeComparableUrl(cleanAbs));
                            if (
                                navbarWarmUrls.length < 4 &&
                                absUrl.hostname.toLowerCase() === baseHost &&
                                normalizeComparableUrl(cleanAbs) !== normalizeComparableUrl(base) &&
                                el.closest('header, nav, .navbar, .menu, [role="navigation"]')
                            ) {
                                navbarWarmUrls.push(cleanAbs);
                            }
                        } catch (_) {}
                    }
                });
            }
        } catch (_) {}

        const readyCandidates = pagesList.filter(p => {
            if (p.page_id === activePageId) return false;
            if (!(p.status === 'AVAILABLE' || p.analyzed)) return false;
            const key = getCacheKey(sid, p.page_id);
            return !pageCacheRef.current.has(key) && !prefetchStartedRef.current.has(key);
        });

        readyCandidates.sort((a, b) => {
            const aVis = visibleLinkedUrls.has(normalizeComparableUrl(a.url)) ? 0 : 1;
            const bVis = visibleLinkedUrls.has(normalizeComparableUrl(b.url)) ? 0 : 1;
            return aVis - bVis;
        });

        const batch = readyCandidates.slice(0, 8);
        let idx = 0;
        const worker = async () => {
            while (!cancelled && idx < batch.length) {
                const cand = batch[idx++];
                const key = getCacheKey(sid, cand.page_id);
                if (pageCacheRef.current.has(key) || prefetchStartedRef.current.has(key)) continue;
                prefetchStartedRef.current.add(key);
                await fetchAndCachePage(cand.page_id).catch(() => {});
            }
        };

        const warmTopNavbarLinks = async () => {
            for (const navUrl of navbarWarmUrls) {
                if (cancelled) break;
                const { pageId, candidate } = resolveKnownPage(navUrl);
                if (pageId && pageCacheRef.current.has(getCacheKey(sid, pageId))) continue;
                if (candidate && (candidate.status === 'BLOCKED' || candidate.status === 'FAILED')) continue;
                const warmKey = `warm::${sid}::${normalizeComparableUrl(navUrl)}`;
                if (prefetchStartedRef.current.has(warmKey)) continue;
                prefetchStartedRef.current.add(warmKey);
                try {
                    const res = await startNavigateRequest(sid, navUrl, false);
                    const pObj = res.body?.page || res.body;
                    const pId = res.body?.page_id || pObj?.page_id;
                    if (res.ok && pId && isUsablePageRepresentation(pObj)) {
                        pageCacheRef.current.set(getCacheKey(sid, pId), pObj);
                        indexPageUrl(pObj.url || navUrl, pId);
                        indexPageUrl(navUrl, pId);
                    }
                } catch (_) {}
            }
        };

        void Promise.all([worker(), worker()]).then(() => {
            if (!cancelled && navbarWarmUrls.length > 0) {
                return warmTopNavbarLinks();
            }
        });

        return () => {
            cancelled = true;
        };
    }, [effectiveSessionId, backendUrl, activePageId, pageDetail?.safe_html, pagesList]);

    // Apply Forensic Mode styling inside iframe
    useEffect(() => {
        const iframe = iframeRef.current;
        if (!iframe) return;

        const applyForensics = () => {
            try {
                const doc = iframe.contentDocument;
                if (doc && doc.body) {
                    // Ensure transparent pages default to white without clobbering dark-themed html backgrounds
                    try {
                        const win = iframe.contentWindow;
                        if (win && win.getComputedStyle) {
                            const bodyBg = win.getComputedStyle(doc.body).backgroundColor;
                            const htmlBg = win.getComputedStyle(doc.documentElement).backgroundColor;
                            const isTransparent = (c: string) => !c || c === 'transparent' || c === 'rgba(0, 0, 0, 0)';
                            if (isTransparent(bodyBg) && isTransparent(htmlBg)) {
                                doc.body.style.backgroundColor = '#ffffff';
                            }
                        }
                    } catch (_) {}

                    if (viewerMode === 'forensic') {
                        doc.body.classList.add('pg-forensic-mode');
                        doc.documentElement.classList.add('pg-forensic-active');
                    } else {
                        doc.body.classList.remove('pg-forensic-mode');
                        doc.documentElement.classList.remove('pg-forensic-active');
                    }

                    // Highlight currently selected element inside the iframe
                    const allSelected = doc.querySelectorAll('.pg-element-selected');
                    allSelected.forEach((el) => el.classList.remove('pg-element-selected'));

                    if (selectedElement && selectedElement.element_id) {
                        const targetEl = doc.querySelector(`[data-pg-id="${selectedElement.element_id}"]`);
                        if (targetEl) {
                            targetEl.classList.add('pg-element-selected');
                            targetEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                        }
                    }
                }
            } catch (e) {
                // Sandboxed boundary
            }
        };

        applyForensics();
        iframe.addEventListener('load', applyForensics);
        return () => iframe.removeEventListener('load', applyForensics);
    }, [viewerMode, selectedElement, activePageId, pageDetail?.safe_html]);

    const activePage = pagesList.find((p) => p.page_id === activePageId) || pagesList[0];
    const currentDisplayUrl = pendingNavUrl || pageDetail?.url || activePage?.url || targetUrl;
    const targetHttpStatus = pageDetail?.http_status ?? activePage?.http_status ?? 200;
    const effectiveSid = effectiveSessionId || sessionId || '';
    const sessionQuery = effectiveSid ? `?session_id=${encodeURIComponent(effectiveSid)}` : '';
    const isLocalVite = typeof window !== 'undefined' && (window.location.port === '5173' || window.location.port === '3000');
    const iframeUrl = effectiveSid
        ? `${isLocalVite && (backendUrl === 'http://localhost:5000' || backendUrl.includes('localhost:5000')) ? '' : backendUrl}/safe-view/session/${encodeURIComponent(effectiveSid)}/page/${encodeURIComponent(activePageId)}/render`
        : `${isLocalVite && (backendUrl === 'http://localhost:5000' || backendUrl.includes('localhost:5000')) ? '' : backendUrl}/safe-view/render/${encodeURIComponent(activePageId)}${sessionQuery}`;

    const activePreset = VIEWPORT_PRESETS[viewportSize] || VIEWPORT_PRESETS.desktop;
    const scale = zoomLevel / 100;
    const scaledWidth = Math.round(activePreset.width * scale);
    const scaledHeight = Math.round(activePreset.height * scale);

    const getViewportWidth = () => {
        return `${activePreset.width}px`;
    };

    useEffect(() => {
        if (!isUrlInputFocused && currentDisplayUrl) {
            setUrlInputValue(currentDisplayUrl);
        }
    }, [currentDisplayUrl, isUrlInputFocused]);

    // ── Unified Modern Browser Omnibar / Toolbar ──
    const renderBrowserToolbar = () => {
        return (
            <div className="bg-slate-900 px-3 py-2 border-b border-slate-800 flex items-center justify-between gap-2 sm:gap-3 font-sans select-none shrink-0 sticky top-0 z-30">
                {/* Left: Navigation Controls */}
                <div className="flex items-center gap-1.5 shrink-0">
                    <div className="flex items-center gap-0.5 bg-slate-950/80 p-0.5 rounded-lg border border-slate-800">
                        <button
                            type="button"
                            onClick={handleBack}
                            disabled={historyIndex <= 0}
                            className="p-1.5 rounded hover:bg-slate-800 disabled:opacity-30 disabled:hover:bg-transparent text-slate-400 hover:text-slate-200 transition-all cursor-pointer"
                            title="Back"
                            aria-label="Go back"
                        >
                            <ArrowLeft className="w-3.5 h-3.5" />
                        </button>
                        <button
                            type="button"
                            onClick={handleForward}
                            disabled={historyIndex >= history.length - 1}
                            className="p-1.5 rounded hover:bg-slate-800 disabled:opacity-30 disabled:hover:bg-transparent text-slate-400 hover:text-slate-200 transition-all cursor-pointer"
                            title="Forward"
                            aria-label="Go forward"
                        >
                            <ArrowRight className="w-3.5 h-3.5" />
                        </button>
                        <button
                            type="button"
                            onClick={handleReload}
                            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-all cursor-pointer"
                            title="Reload Page"
                            aria-label="Reload"
                        >
                            <RotateCw className={`w-3.5 h-3.5 ${isLoading || isNavigating ? 'animate-spin text-red-400' : ''}`} />
                        </button>
                    </div>
                </div>

                {/* Center: Sleek Unified Address Bar with Interactive Input */}
                <div className="flex-1 min-w-0 max-w-3xl mx-1 sm:mx-2">
                    <form
                        onSubmit={(e) => {
                            e.preventDefault();
                            const target = (urlInputValue || currentDisplayUrl || '').trim();
                            if (target) {
                                navigateByUrl(target);
                                (document.activeElement as HTMLElement)?.blur();
                            }
                        }}
                        className={`flex items-center gap-2 px-3 py-1 rounded-lg bg-slate-950/90 border transition-all text-xs shadow-inner ${
                            isUrlInputFocused ? 'border-red-500/80 ring-1 ring-red-500/30' : 'border-slate-800'
                        }`}
                    >
                        <Lock className="w-3.5 h-3.5 text-white shrink-0" />
                        <span className="hidden sm:inline-flex items-center text-[10px] font-semibold uppercase tracking-wider text-white bg-white/10 px-1.5 py-0.5 rounded border border-white/20 shrink-0">
                            Safe View
                        </span>
                        <div className="h-3 w-px bg-slate-800 hidden sm:block shrink-0" />
                        <input
                            type="text"
                            value={isUrlInputFocused ? urlInputValue : (urlInputValue || currentDisplayUrl || '')}
                            onChange={(e) => setUrlInputValue(e.target.value)}
                            onFocus={() => {
                                setIsUrlInputFocused(true);
                                setUrlInputValue(currentDisplayUrl || '');
                            }}
                            onBlur={() => {
                                setIsUrlInputFocused(false);
                            }}
                            onKeyDown={(e) => {
                                if (e.key === 'Escape') {
                                    setUrlInputValue(currentDisplayUrl || '');
                                    (e.target as HTMLInputElement).blur();
                                }
                            }}
                            placeholder="Enter URL to safely inspect (e.g. https://example.com)..."
                            className="bg-transparent text-slate-100 font-mono text-[11px] sm:text-xs flex-1 min-w-0 outline-none border-0 p-0 focus:ring-0 placeholder:text-slate-500 select-all"
                            aria-label="Target website address"
                        />
                        {isNavigating ? (
                            <span className="flex items-center gap-1.5 text-[10px] text-white font-medium shrink-0">
                                <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-ping" />
                                <span className="hidden md:inline">Loading...</span>
                            </span>
                        ) : isUrlInputFocused || (urlInputValue && urlInputValue !== currentDisplayUrl) ? (
                            <button
                                type="submit"
                                className="px-2 py-0.5 bg-red-600 hover:bg-red-500 text-white rounded text-[10px] font-semibold tracking-wider uppercase transition-colors shrink-0 cursor-pointer"
                            >
                                Go
                            </button>
                        ) : null}
                        {(pageDetail?.http_status && pageDetail.http_status >= 400) || (activePage?.http_status && activePage.http_status >= 400) ? (
                            <span className="px-1.5 py-0.5 rounded bg-[#1A1A1A] text-white border border-[#808080] text-[10px] font-bold font-mono shrink-0">
                                HTTP {pageDetail?.http_status || activePage?.http_status}
                            </span>
                        ) : null}
                    </form>
                </div>

                {/* Right: Essential Tools & View Switcher */}
                <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
                    {/* View Mode Switcher: Safe View | Screenshot */}
                    <div className="hidden sm:flex items-center p-0.5 bg-slate-950/80 rounded-lg border border-slate-800 text-xs">
                        <button
                            type="button"
                            onClick={() => setViewerMode('visual')}
                            className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-all cursor-pointer ${
                                viewerMode === 'visual' ? 'bg-slate-800 text-white shadow-sm border border-slate-700' : 'text-slate-400 hover:text-white'
                            }`}
                            title="Safe Web View (Sanitized DOM)"
                        >
                            Safe View
                        </button>
                        <button
                            type="button"
                            onClick={() => setViewerMode('screenshot')}
                            className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-all cursor-pointer ${
                                viewerMode === 'screenshot' ? 'bg-slate-800 text-red-300 shadow-sm border border-red-500/30' : 'text-slate-400 hover:text-white'
                            }`}
                            title="Captured Screenshot"
                        >
                            Screenshot
                        </button>
                    </div>

                    {/* Forensics Drawer Toggle */}
                    <button
                        type="button"
                        onClick={() => setIsRightPanelOpen(!isRightPanelOpen)}
                        className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-xs font-medium transition-all cursor-pointer ${
                            isRightPanelOpen
                                ? 'bg-[#1A1A1A] text-white border-white shadow-sm'
                                : 'bg-[#111111] text-[#808080] border-[#1A1A1A] hover:text-white'
                        }`}
                        title={isRightPanelOpen ? "Close Forensics Panel" : "Open Forensics Panel"}
                        aria-label="Toggle Forensics Panel"
                    >
                        <Activity className="w-3.5 h-3.5 text-white" />
                        <span className="hidden md:inline text-[11px]">Forensics</span>
                    </button>

                    {/* Single Full Screen Toggle */}
                    {isFullscreen ? (
                        <button
                            id="btn-exit-fullscreen"
                            type="button"
                            onClick={() => setIsFullscreen(false)}
                            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:opacity-90 text-black font-semibold text-xs transition-colors cursor-pointer shrink-0 shadow-sm"
                            title="Exit Full Screen (Esc)"
                            aria-label="Exit full screen"
                        >
                            <Minimize2 className="w-3.5 h-3.5" />
                            <span>Exit Full Screen</span>
                        </button>
                    ) : (
                        <button
                            id="btn-open-fullscreen"
                            type="button"
                            onClick={() => setIsFullscreen(true)}
                            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-100 font-medium text-xs border border-slate-700 transition-all cursor-pointer shrink-0"
                            title="Open Full Screen View"
                            aria-label="Open full screen"
                        >
                            <Maximize2 className="w-3.5 h-3.5 text-slate-300" />
                            <span className="hidden sm:inline">Full Screen</span>
                        </button>
                    )}

                    {onClose && !isFullscreen && (
                        <button
                            type="button"
                            onClick={onClose}
                            className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white rounded-lg border border-slate-700 text-xs font-medium cursor-pointer"
                            title="Close"
                            aria-label="Close"
                        >
                            <X className="w-3.5 h-3.5" />
                        </button>
                    )}
                </div>
            </div>
        );
    };

    // ── Diagnostic / Unavailable Representation Screen (Requirements 8, 9, 20) ──
    const renderRepresentationUnavailable = (isFullMode: boolean) => {
        const isExpired = notFoundDetails?.isExpired || safeViewStatus === 'SESSION_EXPIRED';
        const displaySid = notFoundDetails?.session_id || effectiveSid || 'None';
        const displayPid = notFoundDetails?.page_id || activePageId || 'p_root';
        const reasonText = notFoundDetails?.reason || (isExpired
            ? 'Analysis session expired. Please run the scan again.'
            : 'The requested page representation is not available in the active session.');

        return (
            <div className={`flex-1 flex flex-col items-center justify-center p-6 text-center font-mono ${isFullMode ? 'min-h-[500px]' : 'min-h-[480px]'}`}>
                <div className="p-6 rounded-2xl bg-black/80 border border-[#1A1A1A] shadow-2xl max-w-xl w-full text-left space-y-4">
                    <div className="flex items-center gap-3 border-b border-white/10 pb-4">
                        <div className="p-2.5 rounded-xl border bg-black border-[#1A1A1A] text-white">
                            {isExpired ? <Clock className="w-6 h-6" /> : <AlertOctagon className="w-6 h-6" />}
                        </div>
                        <div>
                            <h3 className="text-sm font-bold tracking-wider text-white">
                                {isExpired ? 'ANALYSIS SESSION EXPIRED' : 'PAGE REPRESENTATION UNAVAILABLE'}
                            </h3>
                            <p className="text-[11px] text-slate-400 mt-0.5">
                                {isExpired ? 'Session lifetime elapsed or backend process was restarted.' : 'Requested snapshot is missing from sandbox session storage.'}
                            </p>
                        </div>
                    </div>

                    <div className="space-y-2 text-xs bg-black/50 p-3 rounded-xl border border-white/5">
                        <div className="flex items-center justify-between">
                            <span className="text-slate-500 text-[10px] uppercase tracking-wider">Session ID:</span>
                            <span className="font-mono text-white font-bold text-[11px] select-all">{displaySid}</span>
                        </div>
                        <div className="flex items-center justify-between">
                            <span className="text-slate-500 text-[10px] uppercase tracking-wider">Page ID:</span>
                            <span className="font-mono text-white text-[11px]">{displayPid}</span>
                        </div>
                        <div className="flex items-center justify-between">
                            <span className="text-slate-500 text-[10px] uppercase tracking-wider">Target URL:</span>
                            <span className="font-mono text-slate-200 text-[11px] truncate max-w-[280px]" title={activePage?.url || targetUrl}>
                                {activePage?.url || targetUrl}
                            </span>
                        </div>
                        <div className="flex items-center justify-between pt-1 border-t border-white/5">
                            <span className="text-slate-500 text-[10px] uppercase tracking-wider">Target HTTP Status:</span>
                            <span className="text-white font-bold text-[11px]">HTTP {targetHttpStatus}</span>
                        </div>
                        <div className="flex items-center justify-between">
                            <span className="text-slate-500 text-[10px] uppercase tracking-wider">Safe View Status:</span>
                            <span className="font-bold text-[11px] text-white">{safeViewStatus}</span>
                        </div>
                        <div className="pt-2 border-t border-white/5">
                            <span className="text-slate-500 text-[10px] uppercase tracking-wider block mb-1">Reason:</span>
                            <div className="p-2 rounded bg-black border border-[#1A1A1A] text-slate-300 text-[11px] leading-relaxed">
                                {reasonText}
                            </div>
                        </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 pt-2">
                        <button
                            type="button"
                            onClick={handleReload}
                            className="flex-1 min-w-[140px] px-3.5 py-2 rounded-lg bg-white/10 hover:bg-white/20 text-white text-xs font-semibold flex items-center justify-center gap-2 border border-white/10 transition-all cursor-pointer"
                        >
                            <RotateCw className="w-3.5 h-3.5 text-white" />
                            <span>Check Session Again</span>
                        </button>
                        {onRescan && (
                            <button
                                type="button"
                                onClick={onRescan}
                                className="flex-1 min-w-[140px] px-3.5 py-2 rounded-lg bg-white hover:opacity-90 text-black text-xs font-bold flex items-center justify-center gap-2 shadow-lg transition-all cursor-pointer"
                            >
                                <Sparkles className="w-3.5 h-3.5 text-black" />
                                <span>Run Fresh Deep Scan</span>
                            </button>
                        )}
                        {screenshotB64 && (
                            <button
                                type="button"
                                onClick={() => setViewerMode('screenshot')}
                                className="w-full px-3 py-1.5 rounded-lg bg-black/60 hover:bg-black/90 text-slate-300 hover:text-white text-[11px] font-mono flex items-center justify-center gap-1.5 border border-white/10 transition-all cursor-pointer"
                            >
                                <FileText className="w-3 h-3 text-cyan-400" />
                                <span>Switch to Forensic Screenshot View</span>
                            </button>
                        )}
                    </div>
                </div>
            </div>
        );
    };

    // ── Unified Application Workspace (Normal & Full-Screen) ──
    const viewerWorkspace = (
        <div
            ref={containerRef}
            className={`flex flex-col bg-slate-900 text-slate-100 border border-slate-800 font-sans transition-all duration-200 ${
                isFullscreen
                    ? "fixed inset-0 z-[999999] w-screen h-screen rounded-none shadow-2xl m-0 overflow-hidden"
                    : "rounded-xl shadow-xl w-full h-[820px] max-h-[90vh] overflow-hidden"
            }`}
        >
            {/* Top Sticky Toolbar */}
            {renderBrowserToolbar()}

            {/* 2-Column Workspace: Center Viewer + Right Forensics Panel */}
            <div className="flex flex-col lg:flex-row flex-1 min-h-0 overflow-hidden">

                {/* ─────────────────────────────────────────────────────────────────
                    CENTER PANEL: SAFE WEB VIEWER
                ───────────────────────────────────────────────────────────────── */}
                <div className="flex-1 bg-slate-950 flex flex-col relative min-w-0 overflow-hidden">
                    <div className="viewer-shell w-full h-full flex-1 flex flex-col min-w-0 overflow-hidden relative">
                        {isNavigating && (
                            <div className="h-0.5 w-full bg-slate-900 overflow-hidden shrink-0 z-10">
                                <div className="h-full w-full bg-gradient-to-r from-red-500 via-rose-500 to-red-500 animate-pulse" />
                            </div>
                        )}

                        {blockedActionNotice && (
                            <div className="px-3.5 py-1.5 bg-amber-950/80 border-b border-amber-500/40 text-amber-200 text-xs flex items-center justify-between gap-2 shrink-0 z-10">
                                <div className="flex items-center gap-2 min-w-0">
                                    <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0" />
                                    <span className="truncate">{blockedActionNotice}</span>
                                </div>
                                <button
                                    type="button"
                                    onClick={() => setBlockedActionNotice(null)}
                                    className="text-amber-300/80 hover:text-amber-100 p-0.5 rounded transition-colors cursor-pointer shrink-0"
                                    aria-label="Dismiss read-only notice"
                                >
                                    <X className="w-3.5 h-3.5" />
                                </button>
                            </div>
                        )}

                        {/* Viewport Frame Container — Edge-to-Edge Expansion */}
                        <div className="viewer-viewport flex-1 w-full h-full min-h-0 relative flex flex-col bg-white overflow-hidden">
                            {(isLoading && !pageDetail?.safe_html) ? (
                                <div className="flex-1 flex flex-col items-center justify-center p-8 text-center space-y-3 min-h-[400px] bg-slate-950">
                                    <div className="w-12 h-12 rounded-full border-2 border-slate-700 border-t-red-500 animate-spin flex items-center justify-center">
                                        <Globe className="w-5 h-5 text-red-400 animate-pulse" />
                                    </div>
                                    <div className="space-y-1 font-mono">
                                        <h4 className="text-sm font-semibold text-white">
                                            {isPrioritizing ? 'Prioritizing & Analyzing Page...' : 'Loading Page Representation'}
                                        </h4>
                                        <p className="text-xs text-slate-400 break-all">{currentDisplayUrl}</p>
                                        <p className="text-[11px] text-red-400">
                                            {isPrioritizing ? 'Promoted to Priority 0 — processing immediately in sandbox...' : 'Status: Analyzing in isolated sandbox...'}
                                        </p>
                                    </div>
                                </div>
                            ) : (!pageDetail?.safe_html && (pageDetail?.error || pageDetail?.error_type)) ? (
                                (() => {
                                    const rState = pageDetail.reachability_state || (
                                        pageDetail.http_status >= 200 && pageDetail.http_status < 600
                                            ? `REACHABLE_HTTP_${Math.floor(pageDetail.http_status / 100)}XX`
                                            : 'CONNECTION_FAILED'
                                    );
                                    const isNetFail = ['DNS_FAILED', 'CONNECTION_FAILED', 'TLS_FAILED', 'TIMEOUT', 'SSRF_BLOCKED'].includes(rState) || pageDetail.error_type === 'SSRF_BLOCKED';
                                    const isServerResp = rState.startsWith('REACHABLE_HTTP_') || (pageDetail.http_status && pageDetail.http_status >= 400);

                                    const errorCategory = isNetFail
                                        ? 'NETWORK ERROR'
                                        : isServerResp
                                            ? `SERVER RESPONSE (HTTP ${pageDetail.http_status || 400})`
                                            : 'BROWSER RENDERING ERROR';

                                    const categoryDescription = isNetFail
                                        ? 'Could not establish a connection to the destination server.'
                                        : isServerResp
                                            ? `Destination server is reachable and returned HTTP ${pageDetail.http_status}.`
                                            : 'The destination was reachable, but the isolated browser could not complete page rendering.';

                                    const headerColor = isNetFail ? 'text-red-400' : isServerResp ? 'text-amber-400' : 'text-orange-400';
                                    const badgeBg = isNetFail ? 'bg-red-500/10 border-red-500/30' : isServerResp ? 'bg-amber-500/10 border-amber-500/30' : 'bg-orange-500/10 border-orange-500/30';

                                    return (
                                        <div className="flex-1 flex flex-col items-center justify-center p-8 text-center space-y-3 min-h-[400px] font-mono bg-slate-950">
                                            <div className={`w-12 h-12 rounded-full ${badgeBg} border flex items-center justify-center`}>
                                                {isNetFail ? <Network className={`w-6 h-6 ${headerColor}`} /> : isServerResp ? <Server className={`w-6 h-6 ${headerColor}`} /> : <ShieldAlert className={`w-6 h-6 ${headerColor}`} />}
                                            </div>
                                            <h4 className={`text-sm font-bold ${headerColor} tracking-wider uppercase`}>{errorCategory}</h4>
                                            <p className="text-xs text-slate-300 max-w-md">{categoryDescription}</p>

                                            <div className="p-4 bg-slate-900/90 border border-slate-800 rounded-xl text-left max-w-lg w-full space-y-2 text-xs">
                                                <div className="flex items-center justify-between pb-1 border-b border-white/5">
                                                    <span className="text-slate-400 text-[10px] uppercase tracking-wider">Reachability State:</span>
                                                    <span className={`font-bold font-mono text-[11px] ${isNetFail ? 'text-red-300' : 'text-emerald-300'}`}>{rState}</span>
                                                </div>
                                                {pageDetail.http_status ? (
                                                    <div className="flex items-center justify-between pb-1 border-b border-white/5">
                                                        <span className="text-slate-400 text-[10px] uppercase tracking-wider">HTTP Status:</span>
                                                        <span className="font-bold font-mono text-[11px] text-amber-300">HTTP {pageDetail.http_status}</span>
                                                    </div>
                                                ) : null}
                                                <div>
                                                    <span className="text-slate-400 block text-[10px] uppercase tracking-wider">Details:</span>
                                                    <span className="text-slate-200 break-all">{pageDetail.error || pageDetail.error_details || pageDetail.server_response_message || 'Sandbox page processing error.'}</span>
                                                </div>
                                                {pageDetail.redirect_chain && pageDetail.redirect_chain.length > 1 && (
                                                    <div className="pt-2 border-t border-white/5 text-[11px]">
                                                        <span className="text-slate-400 block mb-1">Redirect Chain ({pageDetail.redirect_chain.length} hops):</span>
                                                        <div className="space-y-1">
                                                            {pageDetail.redirect_chain.map((hop: string, idx: number) => (
                                                                <div key={idx} className="text-slate-300 flex items-center gap-1.5">
                                                                    <span className="text-amber-400 font-bold">{idx + 1}.</span>
                                                                    <span className="truncate">{hop}</span>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                            <button
                                                type="button"
                                                onClick={handleReload}
                                                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 rounded-lg text-xs font-semibold flex items-center gap-2 cursor-pointer transition-all"
                                            >
                                                <RotateCw className="w-3.5 h-3.5" />
                                                Retry Sandbox Representation
                                            </button>
                                        </div>
                                    );
                                })()
                            ) : viewerMode === 'screenshot' ? (
                                <div className="w-full h-full min-h-[500px] bg-slate-950 flex flex-col items-center justify-center overflow-auto p-4">
                                    {screenshotB64 ? (
                                        <img
                                            src={`data:image/png;base64,${screenshotB64}`}
                                            alt="Captured Full Page Screenshot"
                                            className="w-full max-w-6xl object-contain max-h-[85vh] rounded-lg shadow-2xl border border-slate-800"
                                        />
                                    ) : (
                                        <div className="text-slate-400 text-xs font-mono flex flex-col items-center gap-2">
                                            <FileText className="w-8 h-8 text-slate-500" />
                                            <span>No screenshot captured for this page.</span>
                                        </div>
                                    )}
                                </div>
                            ) : representationNotFound || safeViewStatus === 'SESSION_EXPIRED' || safeViewStatus === 'UNAVAILABLE' ? (
                                renderRepresentationUnavailable(isFullscreen)
                            ) : (
                                <div className="w-full h-full flex-1 relative bg-white">
                                    <iframe
                                        ref={iframeRef}
                                        src={pageDetail?.safe_html ? undefined : iframeUrl}
                                        srcDoc={pageDetail?.safe_html || undefined}
                                        onLoad={() => attachIframeHandlers(true)}
                                        title="Safe Web Viewer Sandboxed Document"
                                        sandbox="allow-same-origin"
                                        className="w-full h-full flex-1 border-0 bg-white block"
                                        style={{ width: '100%', height: '100%', minHeight: '100%' }}
                                    />
                                    {screenshotB64 && viewerMode === 'visual' && (pageDetail?.content_inventory?.text_characters ?? 100) < 30 && (pageDetail?.content_inventory?.forms ?? 0) === 0 && (
                                        <div className="absolute bottom-4 right-4 z-20 bg-slate-900/90 backdrop-blur-md border border-slate-700 text-xs text-slate-200 px-3 py-2 rounded-lg shadow-xl flex items-center gap-2.5">
                                            <Sparkles className="w-4 h-4 text-red-400 shrink-0" />
                                            <span>Minimal static markup. Sandbox screenshot available:</span>
                                            <button
                                                type="button"
                                                onClick={() => setViewerMode('screenshot')}
                                                className="px-2.5 py-1 bg-red-600 hover:bg-red-500 text-white font-semibold text-[11px] rounded transition-all cursor-pointer"
                                            >
                                                View Screenshot
                                            </button>
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    </div>
                </div>

                {/* ─────────────────────────────────────────────────────────────────
                    RIGHT PANEL: TABBED FORENSIC INSPECTION
                ───────────────────────────────────────────────────────────────── */}
                {isRightPanelOpen && (
                    <div className="w-full lg:w-96 bg-slate-900 border-t lg:border-t-0 lg:border-l border-slate-800 flex flex-col shrink-0 transition-all">
                    {/* Tab Navigation */}
                    <div className="flex items-center border-b border-slate-800 bg-slate-950 overflow-x-auto text-xs font-medium">
                        <button
                            type="button"
                            onClick={() => setActiveTab('overview')}
                            className={`px-3 py-2.5 border-b-2 flex items-center gap-1.5 transition-all shrink-0 cursor-pointer ${
                                activeTab === 'overview' ? 'border-slate-300 text-white font-medium bg-slate-800/50' : 'border-transparent text-slate-400 hover:text-slate-200'
                            }`}
                        >
                            <span>Overview</span>
                        </button>
                        <button
                            type="button"
                            onClick={() => setActiveTab('content')}
                            className={`px-3 py-2.5 border-b-2 flex items-center gap-1.5 transition-all shrink-0 cursor-pointer ${
                                activeTab === 'content' ? 'border-slate-300 text-white font-medium bg-slate-800/50' : 'border-transparent text-slate-400 hover:text-slate-200'
                            }`}
                        >
                            <span>Content</span>
                        </button>
                        <button
                            type="button"
                            onClick={() => setActiveTab('forms')}
                            className={`px-3 py-2.5 border-b-2 flex items-center gap-1.5 transition-all shrink-0 cursor-pointer ${
                                activeTab === 'forms' ? 'border-slate-300 text-white font-medium bg-slate-800/50' : 'border-transparent text-slate-400 hover:text-slate-200'
                            }`}
                        >
                            <span>Forms</span>
                        </button>
                        <button
                            type="button"
                            onClick={() => setActiveTab('links')}
                            className={`px-3 py-2.5 border-b-2 flex items-center gap-1.5 transition-all shrink-0 cursor-pointer ${
                                activeTab === 'links' ? 'border-slate-300 text-white font-medium bg-slate-800/50' : 'border-transparent text-slate-400 hover:text-slate-200'
                            }`}
                        >
                            <span>Links</span>
                        </button>
                        <button
                            type="button"
                            onClick={() => setActiveTab('network')}
                            className={`px-3 py-2.5 border-b-2 flex items-center gap-1.5 transition-all shrink-0 cursor-pointer ${
                                activeTab === 'network' ? 'border-slate-300 text-white font-medium bg-slate-800/50' : 'border-transparent text-slate-400 hover:text-slate-200'
                            }`}
                        >
                            <span>Network</span>
                        </button>
                        <button
                            type="button"
                            onClick={() => setActiveTab('dom')}
                            className={`px-3 py-2.5 border-b-2 flex items-center gap-1.5 transition-all shrink-0 cursor-pointer ${
                                activeTab === 'dom' ? 'border-slate-300 text-white font-medium bg-slate-800/50' : 'border-transparent text-slate-400 hover:text-slate-200'
                            }`}
                        >
                            <span>DOM</span>
                        </button>
                    </div>

                    {/* Tab Body Content */}
                    <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs font-sans">
                        {/* TAB 0: OVERVIEW */}
                        {activeTab === 'overview' && (
                            <div className="space-y-4 font-sans text-xs">
                                <div className="space-y-1">
                                    <h4 className="text-xs font-semibold text-slate-200">Page Overview</h4>
                                    <p className="text-slate-400 text-[11px] font-mono truncate">{pageDetail?.url || activePage?.url}</p>
                                </div>

                                <div className="space-y-2 p-3 bg-slate-950/60 border border-slate-800 rounded-lg text-slate-300">
                                    <div className="flex justify-between py-1 border-b border-slate-800/80">
                                        <span className="text-slate-400">Page title:</span>
                                        <span className="text-slate-200 font-medium truncate max-w-[180px]">{pageDetail?.title || activePage?.title || 'Home'}</span>
                                    </div>
                                    <div className="flex justify-between py-1 border-b border-slate-800/80">
                                        <span className="text-slate-400">Images:</span>
                                        <span className="text-slate-200 font-medium">{pageDetail?.content_inventory?.images ?? 0}</span>
                                    </div>
                                    <div className="flex justify-between py-1 border-b border-slate-800/80">
                                        <span className="text-slate-400">Links:</span>
                                        <span className="text-slate-200 font-medium">{pageDetail?.content_inventory?.links ?? 0}</span>
                                    </div>
                                    <div className="flex justify-between py-1 border-b border-slate-800/80">
                                        <span className="text-slate-400">Forms:</span>
                                        <span className="text-slate-200 font-medium">{pageDetail?.content_inventory?.forms ?? activePage?.forms_count ?? 0}</span>
                                    </div>
                                    <div className="flex justify-between py-1 border-b border-slate-800/80">
                                        <span className="text-slate-400">Scripts removed:</span>
                                        <span className="text-slate-200 font-medium">{pageDetail?.content_inventory?.scripts ?? 0}</span>
                                    </div>
                                    <div className="flex justify-between py-1">
                                        <span className="text-slate-400">External domains:</span>
                                        <span className="text-slate-200 font-medium">{pageDetail?.content_inventory?.external_domains_count ?? 0}</span>
                                    </div>
                                </div>

                                <button
                                    type="button"
                                    onClick={() => setActiveTab('content')}
                                    className="w-full py-2 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-colors cursor-pointer"
                                >
                                    View details
                                </button>
                            </div>
                        )}

                        {/* TAB 1: CONTENT */}
                        {activeTab === 'content' && (
                            <div className="space-y-4">
                                <div className="p-3 bg-white/5 rounded-xl border border-white/10 space-y-2 font-mono">
                                    <span className="text-[10px] text-white font-bold uppercase tracking-wider block">
                                        Page Identity
                                    </span>
                                    <div className="text-sm font-semibold text-white break-words">
                                        {pageDetail?.title || activePage?.title}
                                    </div>
                                    <div className="text-[11px] text-slate-400 break-all bg-black/40 p-2 rounded border border-white/5">
                                        {pageDetail?.url || activePage?.url}
                                    </div>
                                </div>

                                <div>
                                    <span className="text-xs font-bold text-slate-300 flex items-center gap-1.5 mb-2.5">
                                        <Database className="w-3.5 h-3.5 text-white" />
                                        Content Inventory
                                    </span>
                                    <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                                        <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                                            <span className="text-slate-400 block text-[10px]">Text Chars</span>
                                            <span className="text-base font-bold text-white">
                                                {pageDetail?.content_inventory?.text_characters?.toLocaleString() ?? 0}
                                            </span>
                                        </div>
                                        <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                                            <span className="text-slate-400 block text-[10px]">Images</span>
                                            <span className="text-base font-bold text-white">
                                                {pageDetail?.content_inventory?.images ?? 0}
                                            </span>
                                        </div>
                                        <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                                            <span className="text-slate-400 block text-[10px]">Scripts Stripped</span>
                                            <span className="text-base font-bold text-white">
                                                {pageDetail?.content_inventory?.scripts ?? 0}
                                            </span>
                                        </div>
                                        <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                                            <span className="text-slate-400 block text-[10px]">Stylesheets</span>
                                            <span className="text-base font-bold text-white">
                                                {pageDetail?.content_inventory?.stylesheets ?? 0}
                                            </span>
                                        </div>
                                        <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                                            <span className="text-slate-400 block text-[10px]">Forms / Inputs</span>
                                            <span className="text-base font-bold text-white">
                                                {pageDetail?.content_inventory?.forms ?? 0} / {pageDetail?.content_inventory?.inputs ?? 0}
                                            </span>
                                        </div>
                                        <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                                            <span className="text-slate-400 block text-[10px]">Links</span>
                                            <span className="text-base font-bold text-white">
                                                {pageDetail?.content_inventory?.links ?? 0}
                                            </span>
                                        </div>
                                        <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                                            <span className="text-slate-400 block text-[10px]">Iframes Neutralized</span>
                                            <span className="text-base font-bold text-white">
                                                {pageDetail?.content_inventory?.iframes ?? 0}
                                            </span>
                                        </div>
                                        <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                                            <span className="text-slate-400 block text-[10px]">External Domains</span>
                                            <span className="text-base font-bold text-white">
                                                {pageDetail?.content_inventory?.external_domains_count ?? 0}
                                            </span>
                                        </div>
                                    </div>
                                </div>

                                {pageDetail?.content_inventory?.external_domains?.length > 0 && (
                                    <div className="space-y-1.5 font-mono">
                                        <span className="text-[11px] font-bold text-slate-300">Third-Party External Domains</span>
                                        <div className="bg-black/50 p-2.5 rounded-lg border border-white/5 space-y-1 max-h-36 overflow-y-auto text-[10px]">
                                            {pageDetail.content_inventory.external_domains.map((d: string) => (
                                                <div key={d} className="text-amber-300 flex items-center gap-1.5">
                                                    <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
                                                    <span className="truncate">{d}</span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* TAB 2: LINKS */}
                        {activeTab === 'links' && (
                            <div className="space-y-4">
                                <div className="flex items-center justify-between font-mono">
                                    <span className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                                        <Compass className="w-3.5 h-3.5 text-amber-400" />
                                        Element Inspector
                                    </span>
                                    <span className="text-[10px] text-slate-500">
                                        {pageDetail?.elements_map?.length ?? 0} indexed
                                    </span>
                                </div>

                                {selectedElement ? (
                                    <div className="p-3.5 bg-black/60 rounded-xl border border-purple-500/30 space-y-2.5 font-mono text-[11px]">
                                        <div className="flex items-center justify-between">
                                            <span className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/40 font-bold">
                                                {selectedElement.tag}
                                            </span>
                                            <span
                                                className={`px-2 py-0.5 rounded font-bold uppercase text-[9px] ${
                                                    selectedElement.risk === 'CRITICAL' || selectedElement.risk === 'HIGH'
                                                        ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                                                        : 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                                                }`}
                                            >
                                                Risk: {selectedElement.risk}
                                            </span>
                                        </div>

                                        <div className="text-slate-300 text-xs font-semibold">
                                            {selectedElement.description}
                                        </div>

                                        <div className="space-y-1.5 pt-2 border-t border-white/5 text-[10px]">
                                            {selectedElement.id && (
                                                <div className="flex justify-between">
                                                    <span className="text-slate-500">ID:</span>
                                                    <span className="text-white truncate max-w-[200px]">{selectedElement.id}</span>
                                                </div>
                                            )}
                                            {selectedElement.name && (
                                                <div className="flex justify-between">
                                                    <span className="text-slate-500">Name:</span>
                                                    <span className="text-white truncate max-w-[200px]">{selectedElement.name}</span>
                                                </div>
                                            )}
                                            {selectedElement.type && (
                                                <div className="flex justify-between">
                                                    <span className="text-slate-500">Type:</span>
                                                    <span className="text-amber-300 font-bold">{selectedElement.type}</span>
                                                </div>
                                            )}
                                            {selectedElement.action && (
                                                <div className="space-y-0.5">
                                                    <span className="text-slate-500 block">Form Destination:</span>
                                                    <span className="text-red-400 break-all block bg-black/80 p-1.5 rounded border border-white/5">
                                                        {selectedElement.action}
                                                    </span>
                                                </div>
                                            )}
                                            {selectedElement.href && (
                                                <div className="space-y-0.5">
                                                    <span className="text-slate-500 block">Link Destination:</span>
                                                    <span className="text-red-300 break-all block bg-black/80 p-1.5 rounded border border-white/5">
                                                        {selectedElement.href}
                                                    </span>
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                ) : (
                                    <div className="p-6 bg-black/40 rounded-xl border border-white/10 text-center text-slate-500 text-xs font-mono">
                                        Select an element from the list below.
                                    </div>
                                )}

                                <div className="space-y-1 font-mono">
                                    <span className="text-[10px] text-slate-400 uppercase tracking-wider block">
                                        Indexed Elements
                                    </span>
                                    <div className="space-y-1 max-h-56 overflow-y-auto">
                                        {pageDetail?.elements_map?.map((elem: InspectedElement) => (
                                            <button
                                                key={elem.element_id}
                                                type="button"
                                                onClick={() => setSelectedElement(elem)}
                                                className={`w-full text-left p-2 rounded-lg text-[10px] flex items-center justify-between border transition-all ${
                                                    selectedElement?.element_id === elem.element_id
                                                        ? 'bg-purple-900/40 border-purple-500/60 text-white'
                                                        : 'bg-black/30 border-white/5 text-slate-400 hover:text-white hover:bg-white/5'
                                                }`}
                                            >
                                                <span className="truncate max-w-[200px]">
                                                    <strong className="text-purple-300">{elem.tag}</strong> {elem.name || elem.id || elem.type || elem.action?.slice(0, 20)}
                                                </span>
                                                <span className={`px-1 rounded text-[9px] ${elem.risk === 'HIGH' ? 'text-red-400 font-bold' : 'text-slate-400'}`}>
                                                    {elem.risk}
                                                </span>
                                            </button>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* TAB 3: FORMS */}
                        {activeTab === 'forms' && (
                            <div className="space-y-4 font-mono">
                                <span className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                                    <Lock className="w-3.5 h-3.5 text-red-400" />
                                    Inspected Forms (Read-Only)
                                </span>

                                {pageDetail?.forms?.length > 0 ? (
                                    pageDetail.forms.map((form: any, idx: number) => (
                                        <div key={idx} className="p-3.5 bg-black/60 rounded-xl border border-red-500/30 space-y-2.5 text-[11px]">
                                            <div className="flex items-center justify-between">
                                                <span className="font-bold text-white">Form #{idx + 1}</span>
                                                <span className="text-[10px] px-1.5 py-0.5 rounded bg-white/10 text-slate-300">
                                                    METHOD: {form.method?.toUpperCase() || 'GET'}
                                                </span>
                                            </div>

                                            <div className="space-y-1">
                                                <span className="text-[10px] text-slate-500">Action Destination:</span>
                                                <div className="p-1.5 rounded bg-black/80 border border-white/10 text-red-400 break-all text-[10px]">
                                                    {form.action || 'Self (No action specified)'}
                                                </div>
                                            </div>

                                            <div className="space-y-1.5 pt-2 border-t border-white/5">
                                                <span className="text-[10px] text-slate-400 font-semibold block">
                                                    Locked Input Fields ({form.input_types?.length ?? 0}):
                                                </span>
                                                {form.input_types?.map((itype: string, i: number) => (
                                                    <div key={i} className="flex items-center justify-between px-2 py-1 rounded bg-white/5 text-[10px]">
                                                        <span className="text-slate-300 capitalize">{itype} Field</span>
                                                        <span className="text-[9px] text-amber-400 font-bold flex items-center gap-0.5">
                                                            <Lock className="w-2.5 h-2.5" /> DISABLED &amp; READONLY
                                                        </span>
                                                    </div>
                                                ))}
                                            </div>

                                            <div className="text-[10px] p-2 bg-red-950/30 border border-red-500/20 rounded text-red-300 flex items-center gap-1.5">
                                                <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                                                <span>Submissions blocked: Forms cannot transmit analyst data.</span>
                                            </div>
                                        </div>
                                    ))
                                ) : (
                                    <div className="text-center py-8 text-slate-500 text-xs">
                                        No interactive forms detected on this page.
                                    </div>
                                )}
                            </div>
                        )}

                        {/* TAB 4: DOM DIFF */}
                        {activeTab === 'dom' && (
                            <div className="space-y-4 font-mono">
                                <span className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                                    <Code className="w-3.5 h-3.5 text-yellow-400" />
                                    DOM Mutation Diff (T0 vs T1)
                                </span>

                                <div className="grid grid-cols-2 gap-2 text-[10px]">
                                    <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                                        <span className="text-slate-400 block">Total Mutations</span>
                                        <span className="text-sm font-bold text-yellow-300">
                                            {domData?.dom_diff?.total_mutations ?? 0}
                                        </span>
                                    </div>
                                    <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                                        <span className="text-slate-400 block">Added Nodes</span>
                                        <span className="text-sm font-bold text-white">
                                            {domData?.dom_diff?.added_nodes ?? 0}
                                        </span>
                                    </div>
                                </div>

                                {domData?.dom_diff?.dynamic_password_injection && (
                                    <div className="p-3 rounded-lg bg-red-950/40 border border-red-500/40 text-red-300 text-[11px] flex items-start gap-2">
                                        <AlertOctagon className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                                        <div>
                                            <strong className="block text-red-200">Dynamic Password Field Injected</strong>
                                            <span>Password inputs were dynamically injected after page load via JavaScript.</span>
                                        </div>
                                    </div>
                                )}

                                {domData?.dom_diff?.behavioral_events && domData.dom_diff.behavioral_events.length > 0 && (
                                    <div className="space-y-1">
                                        <span className="text-[10px] text-slate-400 block">Behavioral Events</span>
                                        <div className="bg-black/50 p-2.5 rounded-lg border border-white/5 space-y-1 max-h-48 overflow-y-auto text-[10px]">
                                            {domData.dom_diff.behavioral_events.map((ev, i) => (
                                                <div key={i} className="text-slate-300 flex items-start gap-1.5">
                                                    <span className="text-yellow-400 shrink-0">›</span>
                                                    <span className="break-all">{ev}</span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* TAB 5: TIMELINE */}
                        {activeTab === 'timeline' && (
                            <div className="space-y-4 font-mono">
                                <span className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                                    <Clock className="w-3.5 h-3.5 text-cyan-400" />
                                    Execution Timeline ({timelineData.length} Events)
                                </span>

                                <div className="relative pl-4 space-y-3 before:absolute before:left-1.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-white/10">
                                    {timelineData.map((ev, i) => (
                                        <div key={i} className="relative text-[11px] space-y-0.5">
                                            <span className={`absolute -left-4 top-1 w-2 h-2 rounded-full ring-2 ring-[#0a0e1c] ${
                                                ev.severity === 'CRITICAL' ? 'bg-red-500' : ev.severity === 'WARNING' ? 'bg-amber-400' : 'bg-cyan-400'
                                            }`} />
                                            <div className="flex items-center justify-between text-[10px] text-slate-500">
                                                <span className="text-cyan-300 font-bold">{ev.time_formatted || `+${ev.timestamp_ms}ms`}</span>
                                                <span>{ev.type}</span>
                                            </div>
                                            <div className="font-semibold text-white">{ev.title}</div>
                                            <div className="text-[10px] text-slate-400">{ev.detail}</div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* TAB 6: NETWORK */}
                        {activeTab === 'network' && (
                            <div className="space-y-4 font-mono">
                                <span className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                                    <Network className="w-3.5 h-3.5 text-emerald-400" />
                                    Network Forensics ({networkData?.requests?.length ?? 0} Requests)
                                </span>

                                {/* Redirect Chain Card */}
                                {((pageDetail?.redirect_chain && pageDetail.redirect_chain.length > 1) || (networkData?.redirect_chain && networkData.redirect_chain.length > 1)) && (
                                    <div className="p-3 rounded-xl bg-purple-950/30 border border-purple-500/30 space-y-2">
                                        <span className="text-xs font-bold text-purple-300 flex items-center gap-1.5 uppercase tracking-wider">
                                            <CornerDownRight className="w-3.5 h-3.5 text-purple-400" />
                                            REDIRECT CHAIN ({pageDetail?.redirect_count || (pageDetail?.redirect_chain?.length ? pageDetail.redirect_chain.length - 1 : 0)} Hops)
                                        </span>
                                        <div className="space-y-1.5 text-[10px]">
                                            {(pageDetail?.redirect_chain || networkData?.redirect_chain || []).map((hop: string, idx: number, arr: string[]) => (
                                                <div key={idx} className="flex flex-col">
                                                    <div className="flex items-center gap-1.5 text-slate-200">
                                                        <span className="text-purple-400 font-bold shrink-0">{idx + 1}.</span>
                                                        <span className="truncate break-all" title={hop}>{hop}</span>
                                                    </div>
                                                    {idx < arr.length - 1 && (
                                                        <div className="text-purple-400 pl-3 text-[11px] leading-tight select-none">↓</div>
                                                    )}
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                {/* Failed / Blocked Resources Card */}
                                {((pageDetail?.failed_resources && pageDetail.failed_resources.length > 0) || (networkData?.failed_resources && networkData.failed_resources.length > 0)) && (
                                    <div className="p-3 rounded-xl bg-red-950/30 border border-red-500/30 space-y-2">
                                        <span className="text-xs font-bold text-red-300 flex items-center gap-1.5 uppercase tracking-wider">
                                            <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                                            FAILED / BLOCKED RESOURCES ({(pageDetail?.failed_resources || networkData?.failed_resources || []).length})
                                        </span>
                                        <div className="space-y-1.5 max-h-56 overflow-y-auto">
                                            {(pageDetail?.failed_resources || networkData?.failed_resources || []).map((fr: any, idx: number) => (
                                                <div key={idx} className="p-2 rounded bg-black/60 border border-red-500/20 text-[10px] space-y-0.5">
                                                    <div className="flex items-center justify-between">
                                                        <strong className="text-red-300 truncate">{fr.host || 'Unknown Host'}</strong>
                                                        <span className="px-1.5 py-0.2 rounded font-bold uppercase bg-red-500/20 text-red-400 border border-red-500/30 text-[9px]">
                                                            {fr.status || fr.error || 'blocked'}
                                                        </span>
                                                    </div>
                                                    <div className="text-slate-400 text-[9px] flex items-center gap-2">
                                                        <span>Type: <strong className="text-slate-300">{fr.resource_type || 'resource'}</strong></span>
                                                    </div>
                                                    <div className="text-slate-300 truncate break-all text-[9px]" title={fr.url}>
                                                        {fr.url}
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                {networkData?.requests?.map((req, i) => (
                                    <div key={i} className="p-2.5 rounded-lg bg-black/40 border border-white/5 space-y-1 text-[10px]">
                                        <div className="flex items-center justify-between">
                                            <span className="font-bold text-purple-300">{req.method}</span>
                                            <span className={`px-1.5 py-0.2 rounded font-bold ${
                                                req.is_external ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' : 'bg-emerald-500/20 text-emerald-400'
                                            }`}>
                                                {req.is_external ? 'EXTERNAL' : 'SAME-ORIGIN'}
                                            </span>
                                        </div>
                                        <div className="text-white break-all">{req.url}</div>
                                        <div className="flex items-center justify-between text-slate-500 text-[9px]">
                                            <span>Type: {req.resource_type}</span>
                                            <span>Host: {req.host}</span>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
                )}
            </div>

            {/* Consolidated Bottom Status / Security Strip */}
            <div className="px-3.5 py-1.5 bg-black border-t border-[#1A1A1A] text-[11px] text-[#808080] flex items-center justify-between gap-2 shrink-0 select-none font-mono">
                <div className="flex items-center gap-3">
                    <span className="flex items-center gap-1.5 text-white font-medium">
                        <span className="w-1.5 h-1.5 rounded-full bg-white animate-pulse"></span>
                        Read-only Sandbox
                    </span>
                    <span className="text-slate-600 hidden sm:inline">•</span>
                    <span className="text-slate-400 hidden sm:inline">Active Scripts &amp; Writes Blocked</span>
                    <span className="text-slate-600 hidden md:inline">•</span>
                    <span className="text-slate-500 hidden md:inline">Forms: {pageDetail?.content_inventory?.forms ?? activePage?.forms_count ?? 0}</span>
                    <span className="text-slate-600 hidden md:inline">•</span>
                    <span className="text-slate-500 hidden md:inline">Links: {pageDetail?.content_inventory?.links ?? 0}</span>
                </div>
                <div className="flex items-center gap-3 text-[10px] text-slate-500">
                    <span>Render: {pageDetail?.load_time_ms ?? 0}ms</span>
                    <span className="text-slate-700">•</span>
                    <span className="text-white font-medium">VM Isolated</span>
                </div>
            </div>
        </div>
    );

    if (isFullscreen && typeof document !== 'undefined') {
        return createPortal(viewerWorkspace, document.body);
    }

    return viewerWorkspace;
};
