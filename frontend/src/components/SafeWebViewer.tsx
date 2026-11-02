import React, { useState, useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import {
    Shield, Lock, Eye, EyeOff, AlertTriangle, CheckCircle, ExternalLink,
    Maximize2, Minimize2, ZoomIn, ZoomOut, RotateCcw, Monitor, Tablet,
    Smartphone, FileText, Layers, Network, Clock, Code, ChevronRight,
    Search, Server, Activity, Database, AlertOctagon, Terminal, Globe,
    Radio, Sparkles, Filter, CornerDownRight, Compass, ShieldAlert, Cpu,
    ArrowLeft, ArrowRight, RotateCw, CheckCircle2, X, ChevronDown, ChevronUp,
    Folder, FolderOpen, List, Sliders, PanelLeftClose, PanelLeftOpen, PanelRightClose, PanelRightOpen
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
    const [isDrawerOpen, setIsDrawerOpen] = useState<boolean>(false);
    const [showBlockedSection, setShowBlockedSection] = useState<boolean>(false);

    // Active Page & Discovered Pages
    const [activePageId, setActivePageId] = useState<string>(initialPageId || 'p_root');
    const [pagesList, setPagesList] = useState<DiscoveredPage[]>([]);
    const [pageTree, setPageTree] = useState<PageTreeNode[]>([]);
    const [viewMode, setViewMode] = useState<'tree' | 'list'>('tree');
    const [isLeftPanelOpen, setIsLeftPanelOpen] = useState<boolean>(true);
    const [isRightPanelOpen, setIsRightPanelOpen] = useState<boolean>(true);
    const [expandedTreeNodes, setExpandedTreeNodes] = useState<Record<string, boolean>>({});
    const [pageFilter, setPageFilter] = useState<'all' | 'auth' | 'risk'>('all');
    const [searchQuery, setSearchQuery] = useState<string>('');
    const [discoveryStats, setDiscoveryStats] = useState<DiscoveryStats | null>(null);

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
    const [errorMsg, setErrorMsg] = useState<string | null>(null);

    const iframeRef = useRef<HTMLIFrameElement>(null);
    const containerRef = useRef<HTMLDivElement>(null);

    // In-memory client-side representation cache (Requirement 8 & 9: Instant page switching)
    const pageCacheRef = useRef<Map<string, any>>(new Map());
    const [isPrioritizing, setIsPrioritizing] = useState<boolean>(false);

    // Keep effectiveSessionId in sync when sessionId prop updates
    useEffect(() => {
        if (sessionId) {
            setEffectiveSessionId(sessionId);
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

    // Fetch Pages List & Discovery Telemetry for Session
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

        const fetchPages = async () => {
            try {
                const res = await fetch(`${backendUrl}/safe-view/pages/${sid}`);
                if (res.ok) {
                    const data = await res.json();
                    if (data.pages && Array.isArray(data.pages)) {
                        setPagesList(prev => {
                            if (prev.length === data.pages.length && prev.every((p, i) => p.status === data.pages[i]?.status && p.page_id === data.pages[i]?.page_id)) {
                                return prev;
                            }
                            return data.pages;
                        });
                        if (!activePageId && data.pages.length > 0) {
                            setActivePageId(data.pages[0].page_id);
                        }
                    }
                    if (data.tree) {
                        const rawTree = data.tree;
                        const newTree = Array.isArray(rawTree) ? rawTree : [rawTree];
                        setPageTree(prev => {
                            if (prev.length === newTree.length && JSON.stringify(prev) === JSON.stringify(newTree)) return prev;
                            return newTree;
                        });
                    }
                    if (data.discovery || data.discovery_stats) {
                        const newStats = data.discovery || data.discovery_stats;
                        setDiscoveryStats(prev => {
                            if (prev && prev.pages_analyzed === newStats.pages_analyzed && prev.pages_discovered === newStats.pages_discovered && prev.pages_queued === newStats.pages_queued && prev.status === newStats.status) {
                                return prev;
                            }
                            return newStats;
                        });
                    }
                }
            } catch (err) {
                console.warn('[SAFEVIEW] Failed to fetch pages list:', err);
            }
        };

        fetchPages();
        // Poll every 2 seconds to catch live background crawling progression
        const pollInterval = setInterval(fetchPages, 2000);
        return () => clearInterval(pollInterval);
    }, [effectiveSessionId, backendUrl, targetUrl, screenshotB64]);

    // Keep activePageId in sync when initialPageId changes
    useEffect(() => {
        if (initialPageId) {
            setActivePageId(initialPageId);
            setHistory([initialPageId]);
            setHistoryIndex(0);
        }
    }, [initialPageId, effectiveSessionId]);

    // Navigate to page with browser-like history tracking & instant cache retrieval
    const navigateToPage = (newPageId: string) => {
        if (newPageId === activePageId) return;
        const nextHistory = history.slice(0, historyIndex + 1);
        nextHistory.push(newPageId);
        setHistory(nextHistory);
        setHistoryIndex(nextHistory.length - 1);
        setActivePageId(newPageId);
        setIsDrawerOpen(false); // Close drawer in full screen if open

        // 1. Instant check from in-memory client cache (Requirement 8: 0ms switch)
        if (pageCacheRef.current.has(newPageId)) {
            const cachedPage = pageCacheRef.current.get(newPageId);
            setPageDetail(cachedPage);
            setSafeViewStatus(cachedPage.scan_status || 'AVAILABLE');
            setIsLoading(false);
            setRepresentationNotFound(false);
            console.log(`[PERF] Instant client cache HIT for ${newPageId} (0ms switch)`);
            return;
        }

        // 2. If queued, immediately send prioritize signal to backend (Requirement 6)
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
            const prevId = history[historyIndex - 1];
            setHistoryIndex(historyIndex - 1);
            setActivePageId(prevId);
        }
    };

    const handleForward = () => {
        if (historyIndex < history.length - 1) {
            const nextId = history[historyIndex + 1];
            setHistoryIndex(historyIndex + 1);
            setActivePageId(nextId);
        }
    };

    const handleReload = () => {
        if (activePageId) {
            fetchPageDetails(activePageId);
        }
    };

    // Fetch Full Forensic Details & Representation for the Active Page (Requirement 7, 8, 16)
    const fetchPageDetails = async (pageId: string) => {
        if (!pageId) return;
        setIsLoading(true);
        setErrorMsg(null);
        setRepresentationNotFound(false);
        setNotFoundDetails(null);

        const sid = effectiveSessionId;
        console.log(`[SAFEVIEW] Active session: ${sid || 'none'}`);
        console.log(`[SAFEVIEW] Active page: ${pageId}`);
        console.log(`[SAFEVIEW] Requesting representation...`);

        try {
            // First attempt: reliable Page Representation API (Section 7)
            let resPage: Response;
            if (sid) {
                resPage = await fetch(`${backendUrl}/safe-view/session/${encodeURIComponent(sid)}/page/${encodeURIComponent(pageId)}`);
                if (!resPage.ok && resPage.status === 404) {
                    // Fallback to query param endpoint
                    const fallbackRes = await fetch(`${backendUrl}/safe-view/page/${encodeURIComponent(pageId)}?session_id=${encodeURIComponent(sid)}`);
                    if (fallbackRes.ok) {
                        resPage = fallbackRes;
                    }
                }
            } else {
                resPage = await fetch(`${backendUrl}/safe-view/page/${encodeURIComponent(pageId)}`);
            }

            console.log(`[SAFEVIEW] Response: ${resPage.status}`);

            if (resPage.ok) {
                const data = await resPage.json();
                const pageObj = data.page || data;
                setPageDetail(pageObj);
                setRepresentationNotFound(false);
                setIsPrioritizing(false);

                // Cache in client-side in-memory map for instant future switching
                pageCacheRef.current.set(pageId, pageObj);

                // If candidate is still processing in background, poll rapidly until ready
                if (pageObj.scan_status === 'QUEUED' || pageObj.scan_status === 'ANALYZING') {
                    setSafeViewStatus('LOADING');
                    setIsLoading(true);
                    setIsPrioritizing(true);
                    setTimeout(() => {
                        if (activePageId === pageId) {
                            fetchPageDetails(pageId);
                        }
                    }, 600);
                    return;
                }

                // Requirement 22: LOADING, AVAILABLE, PARTIAL, BLOCKED, FAILED, TIMEOUT
                if (pageObj.scan_status === 'BLOCKED' || pageObj.security_block) {
                    setSafeViewStatus('BLOCKED');
                } else if (pageObj.scan_status === 'TIMEOUT' || pageObj.error_type === 'PAGE_NAVIGATION_TIMEOUT') {
                    setSafeViewStatus('TIMEOUT');
                } else if (pageObj.scan_status === 'PARTIAL' || (pageObj.failed_resources && pageObj.failed_resources.length > 0)) {
                    setSafeViewStatus('PARTIAL');
                } else if (pageObj.page_available || pageObj.safe_html) {
                    setSafeViewStatus('AVAILABLE');
                } else if (pageObj.error_type || pageObj.error) {
                    setSafeViewStatus('FAILED');
                } else {
                    setSafeViewStatus('AVAILABLE');
                }

                console.log(`[SAFEVIEW] Representation ${pageObj.scan_status || 'AVAILABLE'}`);
                console.log('[SAFEVIEW] Rendering page');

                if (pageObj.elements_map && pageObj.elements_map.length > 0) {
                    const highRiskElem = pageObj.elements_map.find((e: InspectedElement) => e.risk === 'CRITICAL' || e.risk === 'HIGH') || pageObj.elements_map[0];
                    setSelectedElement(highRiskElem);
                }
            } else {
                const errJson = await resPage.json().catch(() => ({}));
                console.warn('[SAFEVIEW] ERROR: representation not found', errJson);
                const isExpired = errJson.error_code === 'SESSION_EXPIRED' || (errJson.message && errJson.message.toLowerCase().includes('expired'));
                setSafeViewStatus(isExpired ? 'SESSION_EXPIRED' : 'UNAVAILABLE');
                setRepresentationNotFound(true);
                setNotFoundDetails({
                    session_id: sid || 'None',
                    page_id: pageId,
                    reason: errJson.message || errJson.reason || (isExpired ? 'Analysis session expired or backend process restarted.' : 'The requested page representation is not available in the active session.'),
                    isExpired,
                });
            }

            // Also fetch DOM Diff, Network Forensics, Timeline in parallel
            const queryParam = sid ? `?session_id=${encodeURIComponent(sid)}` : '';
            fetch(`${backendUrl}/safe-view/dom/${encodeURIComponent(pageId)}${queryParam}`)
                .then(r => r.ok ? r.json() : null)
                .then(dataDom => { if (dataDom) setDomData(dataDom); })
                .catch(() => {});

            fetch(`${backendUrl}/safe-view/network/${encodeURIComponent(pageId)}${queryParam}`)
                .then(r => r.ok ? r.json() : null)
                .then(dataNet => { if (dataNet) setNetworkData(dataNet.network_forensics || null); })
                .catch(() => {});

            fetch(`${backendUrl}/safe-view/timeline/${encodeURIComponent(pageId)}${queryParam}`)
                .then(r => r.ok ? r.json() : null)
                .then(dataTimeline => { if (dataTimeline) setTimelineData(dataTimeline.timeline || []); })
                .catch(() => {});

        } catch (err: any) {
            console.error('[SAFEVIEW] Network error requesting representation:', err);
            setSafeViewStatus('UNAVAILABLE');
            setRepresentationNotFound(true);
            setNotFoundDetails({
                session_id: sid || 'None',
                page_id: pageId,
                reason: 'Unable to connect to PhishGuard backend service.',
                isExpired: false,
            });
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        // If client cache has the representation, skip redundant network call!
        if (pageCacheRef.current.has(activePageId)) {
            const cached = pageCacheRef.current.get(activePageId);
            setPageDetail(cached);
            setSafeViewStatus(cached.scan_status || 'AVAILABLE');
            setIsLoading(false);
            setRepresentationNotFound(false);
            return;
        }
        fetchPageDetails(activePageId);
    }, [activePageId, backendUrl, effectiveSessionId]);

    // Apply Forensic Mode styling inside iframe
    useEffect(() => {
        const iframe = iframeRef.current;
        if (!iframe) return;

        const applyForensics = () => {
            try {
                const doc = iframe.contentDocument;
                if (doc && doc.body) {
                    // Ensure authentic styling renders without destructive !important overrides
                    try {
                        doc.documentElement.style.setProperty('color-scheme', 'light');
                        const win = iframe.contentWindow;
                        if (win && win.getComputedStyle) {
                            const computed = win.getComputedStyle(doc.body);
                            const computedBg = computed.backgroundColor;
                            if (!computedBg || computedBg === 'transparent' || computedBg === 'rgba(0, 0, 0, 0)') {
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

    // Filter pages list
    const filteredPages = pagesList.filter((p) => {
        if (pageFilter === 'auth' && !p.has_credentials) return false;
        if (pageFilter === 'risk' && p.risk_level !== 'HIGH' && p.risk_level !== 'CRITICAL') return false;
        if (searchQuery) {
            const q = searchQuery.toLowerCase();
            return (
                p.path.toLowerCase().includes(q) ||
                p.title.toLowerCase().includes(q) ||
                (p.url && p.url.toLowerCase().includes(q)) ||
                (p.page_id && p.page_id.toLowerCase().includes(q))
            );
        }
        return true;
    });

    const activePage = pagesList.find((p) => p.page_id === activePageId) || pagesList[0];
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

    const toggleTreeNode = (pageId: string, e: React.MouseEvent) => {
        e.stopPropagation();
        setExpandedTreeNodes((prev) => ({
            ...prev,
            [pageId]: prev[pageId] === undefined ? false : !prev[pageId],
        }));
    };

    const buildFallbackTree = (pages: DiscoveredPage[]): PageTreeNode[] => {
        if (!pages || pages.length === 0) return [];
        const root = pages.find((p) => p.is_root || p.depth === 0) || pages[0];
        const others = pages.filter((p) => p.page_id !== root.page_id);
        return [
            {
                page_id: root.page_id,
                url: root.url,
                path: root.path || '/',
                title: root.title || 'Home',
                depth: 0,
                http_status: root.http_status || 200,
                status: root.status || (root.analyzed !== false ? 'AVAILABLE' : 'QUEUED'),
                risk_level: root.risk_level,
                has_credentials: root.has_credentials,
                forms_count: root.forms_count,
                is_root: true,
                children: others.map((o) => ({
                    page_id: o.page_id,
                    url: o.url,
                    path: o.path,
                    title: o.title || o.path,
                    depth: o.depth || 1,
                    http_status: o.http_status || 200,
                    status: o.status || (o.analyzed !== false ? 'AVAILABLE' : 'QUEUED'),
                    risk_level: o.risk_level,
                    has_credentials: o.has_credentials,
                    forms_count: o.forms_count,
                    is_root: false,
                    children: [],
                })),
            },
        ];
    };

    const renderTreeNodes = (nodes: PageTreeNode[], indent = 0): React.ReactNode => {
        return nodes.map((node) => {
            const isSelected = node.page_id === activePageId;
            const hasChildren = node.children && node.children.length > 0;
            const isExpanded = expandedTreeNodes[node.page_id] !== false; // true by default
            const isRoot = node.is_root || node.depth === 0;

            const isBlocked = node.status === 'BLOCKED';
            const isHttpError = Boolean(node.http_status && node.http_status >= 400);
            const isPartial = node.status === 'PARTIAL';
            const isAvailable = (node.status === 'AVAILABLE' || node.status === 'READY') && !isHttpError;
            const isQueued = node.status === 'QUEUED' || node.status === 'LOADING' || node.status === 'DISCOVERED';

            const statusBadge = isBlocked ? (
                <span className="text-[9px] px-1.5 py-0.2 rounded bg-red-500/20 text-red-300 border border-red-500/30">Blocked</span>
            ) : isHttpError ? (
                <span className="text-[9px] px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 font-mono">
                    HTTP {node.http_status}
                </span>
            ) : isPartial ? (
                <span className="text-[9px] px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">Partial</span>
            ) : isAvailable ? (
                <span className="text-[9px] px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">Available</span>
            ) : isQueued ? (
                <span className="text-[9px] px-1.5 py-0.2 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30 animate-pulse">Queued</span>
            ) : (
                <span className="text-[9px] px-1.5 py-0.2 rounded bg-white/10 text-slate-300 font-mono">HTTP {node.http_status || 200}</span>
            );

            return (
                <div key={node.page_id} className="flex flex-col select-none">
                    <div
                        onClick={() => navigateToPage(node.page_id)}
                        className={`flex items-center gap-1.5 py-1.5 px-2 rounded-lg cursor-pointer text-xs font-mono transition-all border my-0.5 ${
                            isSelected
                                ? 'bg-slate-800 border-slate-700 text-slate-100 font-semibold shadow-sm'
                                : 'border-transparent text-slate-400 hover:bg-slate-800/40 hover:text-slate-200'
                        }`}
                        style={{ paddingLeft: `${Math.max(6, indent * 16 + 6)}px` }}
                    >
                        {hasChildren ? (
                            <button
                                type="button"
                                onClick={(e) => toggleTreeNode(node.page_id, e)}
                                className="p-0.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 shrink-0"
                                title={isExpanded ? 'Collapse' : 'Expand'}
                            >
                                {isExpanded ? <ChevronDown className="w-3.5 h-3.5 text-slate-300" /> : <ChevronRight className="w-3.5 h-3.5 text-slate-400" />}
                            </button>
                        ) : (
                            <span className="w-3.5 shrink-0 inline-block text-center text-slate-600 font-mono">
                                {indent > 0 ? '├' : ''}
                            </span>
                        )}

                        <span className="text-sm shrink-0">
                            {isRoot ? '🏠' : hasChildren ? (isExpanded ? '📂' : '📁') : '📄'}
                        </span>

                        <span className="truncate flex-1 font-medium" title={node.url}>
                            {node.title && node.title !== node.url && node.title.length > 1 ? node.title : (node.path || '/')}
                        </span>

                        <div className="flex items-center gap-1 shrink-0 ml-1">
                            {node.has_credentials && (
                                <span className="text-[9px] px-1 py-0.2 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30" title="Authentication / Credentials Form">
                                    🔒
                                </span>
                            )}
                            <span className="text-[9px] px-1.5 py-0.2 rounded bg-white/10 text-slate-400">
                                D{node.depth}
                            </span>
                            {statusBadge}
                        </div>
                    </div>

                    {hasChildren && isExpanded && (
                        <div className="flex flex-col border-l border-white/5 ml-3 pl-1">
                            {renderTreeNodes(node.children!, indent + 1)}
                        </div>
                    )}
                </div>
            );
        });
    };

    // ── Helper Component for Discovered Pages List ──
    const renderPagesList = () => {
        const effectiveTree = pageTree && pageTree.length > 0 ? pageTree : buildFallbackTree(filteredPages);

        return (
            <div className="flex flex-col h-full bg-[#0a0f1d]">
                {/* Website Analysis Progress Banner */}
                {discoveryStats && (discoveryStats.status === 'CRAWLING' || discoveryStats.status === 'DISCOVERING') ? (
                    <div className="p-3 bg-slate-900 border-b border-slate-800 text-xs">
                        <div className="flex items-center justify-between text-slate-200 font-medium mb-1.5">
                            <span className="flex items-center gap-1.5">
                                <Radio className="w-3.5 h-3.5 text-blue-400 animate-pulse" />
                                Analyzing website pages...
                            </span>
                            <span className="text-[10px] px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                                In Progress
                            </span>
                        </div>
                        <div className="text-[11px] text-slate-400 grid grid-cols-2 gap-x-2 gap-y-0.5 font-sans">
                            <span>Discovered: <strong className="text-slate-200">{discoveryStats.pages_discovered ?? pagesList.length}</strong></span>
                            <span>Analyzed: <strong className="text-emerald-400">{discoveryStats.pages_analyzed ?? pagesList.filter(p => p.analyzed !== false).length}</strong></span>
                        </div>
                    </div>
                ) : discoveryStats && discoveryStats.status === 'COMPLETED' ? (
                    <div className="p-3 bg-slate-900 border-b border-slate-800 text-xs">
                        <div className="flex items-center justify-between text-slate-200 font-medium mb-1">
                            <span className="flex items-center gap-1.5">
                                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                                Website analysis complete
                            </span>
                            <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                                {discoveryStats.pages_discovered ?? pagesList.length} pages
                            </span>
                        </div>
                        <div className="text-[11px] text-slate-400 flex flex-wrap items-center gap-x-3 gap-y-0.5 font-sans">
                            <span>{discoveryStats.pages_discovered ?? pagesList.length} pages discovered</span>
                            <span>·</span>
                            <span className="text-emerald-400 font-medium">{discoveryStats.pages_completed ?? discoveryStats.pages_analyzed ?? pagesList.length} analyzed</span>
                            {(discoveryStats.pages_blocked ?? 0) > 0 && (
                                <>
                                    <span>·</span>
                                    <span className="text-slate-400">{discoveryStats.pages_blocked} unavailable</span>
                                </>
                            )}
                        </div>
                    </div>
                ) : null}

                {/* Header with Title, Count, and View Switcher */}
                <div className="p-3 border-b border-white/10 bg-[#0d1424]">
                    <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-bold text-slate-200 flex items-center gap-1.5 uppercase tracking-wider">
                            <Layers className="w-3.5 h-3.5 text-purple-400" />
                            Pages ({pagesList.length})
                        </span>
                        {/* Tree vs List View Switcher */}
                        <div className="flex items-center gap-1 bg-black/60 p-0.5 rounded-lg border border-white/10 text-[10px]">
                            <button
                                type="button"
                                onClick={() => setViewMode('tree')}
                                className={`px-2 py-0.5 rounded flex items-center gap-1 font-mono transition-all ${
                                    viewMode === 'tree' ? 'bg-purple-600/50 text-white font-bold border border-purple-500/50' : 'text-slate-400 hover:text-white'
                                }`}
                                title="Hierarchical Page Tree View"
                            >
                                <Folder className="w-3 h-3 text-purple-400" />
                                <span>Tree</span>
                            </button>
                            <button
                                type="button"
                                onClick={() => setViewMode('list')}
                                className={`px-2 py-0.5 rounded flex items-center gap-1 font-mono transition-all ${
                                    viewMode === 'list' ? 'bg-purple-600/50 text-white font-bold border border-purple-500/50' : 'text-slate-400 hover:text-white'
                                }`}
                                title="Flat Page List View"
                            >
                                <List className="w-3 h-3 text-purple-400" />
                                <span>List</span>
                            </button>
                        </div>
                    </div>

                    {/* Search Bar */}
                    <div className="relative mb-2">
                        <Search className="w-3 h-3 text-slate-400 absolute left-2.5 top-2.5" />
                        <input
                            type="text"
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            placeholder="Search routes..."
                            className="w-full bg-slate-950/70 border border-slate-800 rounded-md pl-7 pr-2.5 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-slate-600 font-mono"
                        />
                    </div>

                    {/* Quick Filters */}
                    <div className="flex items-center gap-1 text-[10px] font-medium text-slate-400">
                        <button
                            type="button"
                            onClick={() => setPageFilter('all')}
                            className={`px-2 py-0.5 rounded transition-colors ${pageFilter === 'all' ? 'bg-slate-800 text-slate-200 border border-slate-700 font-medium' : 'hover:text-slate-200'}`}
                        >
                            All ({pagesList.length})
                        </button>
                        <button
                            type="button"
                            onClick={() => setPageFilter('auth')}
                            className={`px-2 py-0.5 rounded transition-colors ${pageFilter === 'auth' ? 'bg-amber-500/10 text-amber-300 border border-amber-500/30 font-medium' : 'hover:text-slate-200'}`}
                        >
                            Auth ({pagesList.filter((p) => p.has_credentials).length})
                        </button>
                        <button
                            type="button"
                            onClick={() => setPageFilter('risk')}
                            className={`px-2 py-0.5 rounded transition-colors ${pageFilter === 'risk' ? 'bg-red-500/10 text-red-300 border border-red-500/30 font-medium' : 'hover:text-slate-200'}`}
                        >
                            Risk ({pagesList.filter((p) => p.risk_level === 'HIGH' || p.risk_level === 'CRITICAL').length})
                        </button>
                    </div>
                </div>

                {/* Content: Tree View or List View */}
                <div className="flex-1 overflow-y-auto p-2 space-y-1">
                    {viewMode === 'tree' ? (
                        effectiveTree.length > 0 ? (
                            renderTreeNodes(effectiveTree)
                        ) : (
                            <div className="text-center py-8 text-xs text-slate-500 font-mono">
                                No pages discovered yet.
                            </div>
                        )
                    ) : (
                        filteredPages.map((page) => {
                            const isSelected = page.page_id === activePageId;
                            const isBlocked = page.is_blocked;
                            const isHttpError = Boolean(page.http_status && page.http_status >= 400);
                            const hasCredentials = page.has_credentials;

                            const pageTitle = page.title && page.title !== page.url && page.title.length > 1
                                ? page.title
                                : (page.path === '/' ? 'Home' : page.path);

                            return (
                                <button
                                    key={page.page_id}
                                    type="button"
                                    onClick={() => navigateToPage(page.page_id)}
                                    className={`w-full text-left px-3 py-2 rounded-lg transition-colors flex items-center justify-between gap-2 border cursor-pointer ${
                                        isSelected
                                            ? 'bg-slate-800 border-slate-700 text-slate-100 shadow-sm'
                                            : 'bg-transparent border-transparent hover:bg-slate-800/50 text-slate-300'
                                    }`}
                                >
                                    <div className="flex items-center gap-2 min-w-0">
                                        <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                                            isBlocked ? 'bg-red-400' : isHttpError ? 'bg-amber-400' : hasCredentials ? 'bg-amber-400' : 'bg-emerald-400'
                                        }`} />
                                        <div className="truncate">
                                            <span className="text-xs font-medium text-slate-200 block truncate">
                                                {pageTitle}
                                            </span>
                                            <span className="text-[11px] font-mono text-slate-500 block truncate">
                                                {page.path || '/'}
                                            </span>
                                        </div>
                                    </div>

                                    {/* Accurate status classification */}
                                    {isBlocked ? (
                                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 shrink-0">
                                            Blocked
                                        </span>
                                    ) : isHttpError ? (
                                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 font-mono shrink-0">
                                            HTTP {page.http_status}
                                        </span>
                                    ) : hasCredentials ? (
                                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 shrink-0">
                                            Auth
                                        </span>
                                    ) : null}
                                </button>
                            );
                        })
                    )}

                    {viewMode === 'list' && filteredPages.length === 0 && (
                        <div className="text-center py-8 text-xs text-slate-500 font-mono">
                            No discovered pages match filter.
                        </div>
                    )}
                </div>

                {/* Blocked Actions Section (Requirement 5) */}
                {discoveryStats && discoveryStats.blocked_actions && discoveryStats.blocked_actions > 0 ? (
                    <div className="border-t border-red-500/20 bg-red-950/20 p-2.5 text-xs font-mono shrink-0">
                        <button
                            type="button"
                            onClick={() => setShowBlockedSection(!showBlockedSection)}
                            className="w-full flex items-center justify-between text-[11px] font-bold text-red-400 hover:text-red-300"
                        >
                            <span className="flex items-center gap-1.5">
                                <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                                BLOCKED ACTIONS ({discoveryStats.blocked_actions})
                            </span>
                            {showBlockedSection ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                        </button>
                        {showBlockedSection && discoveryStats.blocked_actions_list && (
                            <div className="mt-2 space-y-1 max-h-32 overflow-y-auto text-[10px]">
                                {discoveryStats.blocked_actions_list.map((item, i) => (
                                    <div key={i} className="p-1.5 rounded bg-black/60 border border-red-500/30 text-red-300 space-y-0.5">
                                        <div className="font-bold truncate">{item.path}</div>
                                        <div className="text-[9px] text-slate-400">{item.reason}</div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                ) : null}

                {/* Scope & Crawler Guard Strip */}
                <div className="p-2.5 bg-black/60 border-t border-white/10 text-[10px] text-slate-400 font-mono flex items-center justify-between shrink-0">
                    <span className="flex items-center gap-1">
                        <Shield className="w-3 h-3 text-emerald-400" /> Scope: Same-Origin
                    </span>
                    <span>Max Depth: {discoveryStats?.max_depth ?? 4}</span>
                </div>
            </div>
        );
    };

    // ── Helper Component for Browser Omnibar / Toolbar ──
    const renderBrowserToolbar = () => {
        const totalPages = discoveryStats?.pages_discovered ?? pagesList.length;
        const httpErrorPages = pagesList.filter(p => p.http_status && p.http_status >= 400).length;
        const blockedPages = (discoveryStats?.pages_blocked ?? 0) || pagesList.filter(p => p.is_blocked || p.status === 'BLOCKED').length;
        const availablePages = Math.max(0, totalPages - blockedPages - httpErrorPages);
        const unavailablePages = blockedPages + httpErrorPages;

        return (
            <div className="bg-slate-900 px-3 sm:px-4 py-2.5 border-b border-slate-800 flex flex-col gap-2 font-sans select-none shrink-0 sticky top-0 z-30">
                {/* Row 1: Primary Controls & Identity */}
                <div className="flex flex-wrap items-center justify-between gap-3 w-full">
                    {/* Top-Left: Exit Full Screen (if active) + Safe Web View Identity */}
                    <div className="flex items-center gap-2.5 min-w-0">
                        {isFullscreen && (
                            <button
                                id="btn-topleft-exit-fullscreen"
                                type="button"
                                onClick={() => setIsFullscreen(false)}
                                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs transition-colors cursor-pointer shrink-0 shadow-sm"
                                title="Exit Full Screen (Esc)"
                                aria-label="Exit full screen"
                            >
                                <ArrowLeft className="w-3.5 h-3.5" />
                                <span>Exit Full Screen</span>
                            </button>
                        )}

                        <div className="flex flex-col min-w-0">
                            <div className="flex items-center gap-2">
                                <h3 className="text-xs sm:text-sm font-semibold text-slate-100">Safe Web View</h3>
                                <span className="inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 shrink-0">
                                    <Lock className="w-2.5 h-2.5" /> Read-only • Isolated analysis
                                </span>
                            </div>
                            <div className="flex items-center gap-1.5 text-[11px] font-mono text-slate-400 truncate max-w-sm sm:max-w-md lg:max-w-xl" title={activePage?.url || targetUrl}>
                                <span className="text-slate-500 shrink-0">Current page:</span>
                                <span className="truncate text-slate-300">{activePage?.url || targetUrl}</span>
                            </div>
                        </div>
                    </div>

                    {/* Top-Center / Navigation & Dynamic Page Count */}
                    <div className="flex items-center gap-2 shrink-0">
                        {/* History Navigation: Back / Forward / Reload */}
                        <div className="flex items-center gap-0.5 bg-slate-950/70 p-1 rounded-lg border border-slate-800">
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
                                title="Reload Page Representation"
                                aria-label="Reload"
                            >
                                <RotateCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-blue-400' : ''}`} />
                            </button>
                        </div>

                        {/* Meaningful Dynamic Page Count Badge (Requirement 12) */}
                        <div className="hidden md:flex items-center gap-1.5 text-[11px] bg-slate-950/70 px-2.5 py-1.5 rounded-lg border border-slate-800 font-mono text-slate-400">
                            <span>{totalPages} {totalPages === 1 ? 'page' : 'pages'} analyzed</span>
                            {availablePages > 0 && (
                                <>
                                    <span className="text-slate-600">·</span>
                                    <span className="text-emerald-400">{availablePages} available</span>
                                </>
                            )}
                            {httpErrorPages > 0 && (
                                <>
                                    <span className="text-slate-600">·</span>
                                    <span className="text-amber-400">{httpErrorPages} HTTP {totalPages === 1 && (activePage?.http_status || pageDetail?.http_status) ? (activePage?.http_status || pageDetail?.http_status) : 'error'}</span>
                                </>
                            )}
                            {blockedPages > 0 && (
                                <>
                                    <span className="text-slate-600">·</span>
                                    <span className="text-red-400">{blockedPages} blocked</span>
                                </>
                            )}
                        </div>
                    </div>

                    {/* Top-Right: Panel Toggles & Full Screen / Exit Button */}
                    <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
                        {/* Pages Panel Toggle (Requirement 7) */}
                        <button
                            type="button"
                            onClick={() => setIsLeftPanelOpen(!isLeftPanelOpen)}
                            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition-all cursor-pointer ${
                                isLeftPanelOpen
                                    ? 'bg-slate-800 text-slate-100 border-slate-700 shadow-sm'
                                    : 'bg-slate-950/60 text-slate-400 border-slate-800 hover:text-slate-200'
                            }`}
                            title={isLeftPanelOpen ? "Collapse Pages Panel" : "Open Pages Panel"}
                            aria-label="Toggle Pages Panel"
                        >
                            <Layers className="w-3.5 h-3.5 text-slate-400" />
                            <span>Pages ({pagesList.length})</span>
                        </button>

                        {/* Forensics Panel Toggle (Requirement 8) */}
                        <button
                            type="button"
                            onClick={() => setIsRightPanelOpen(!isRightPanelOpen)}
                            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition-all cursor-pointer ${
                                isRightPanelOpen
                                    ? 'bg-slate-800 text-slate-100 border-slate-700 shadow-sm'
                                    : 'bg-slate-950/60 text-slate-400 border-slate-800 hover:text-slate-200'
                            }`}
                            title={isRightPanelOpen ? "Collapse Forensic Panel" : "Open Forensic Panel"}
                            aria-label="Toggle Forensics Panel"
                        >
                            <Activity className="w-3.5 h-3.5 text-slate-400" />
                            <span className="hidden sm:inline">Forensics</span>
                        </button>

                        {/* Full Screen Toggle Button (Requirement 13 & 14) */}
                        {isFullscreen ? (
                            <button
                                id="btn-exit-fullscreen"
                                type="button"
                                onClick={() => setIsFullscreen(false)}
                                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/40 font-medium text-xs transition-all cursor-pointer shrink-0"
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
                                className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-100 font-medium text-xs border border-slate-700 transition-all cursor-pointer shrink-0"
                                title="Open Full Screen Safe Web Viewer"
                                aria-label="Open full screen"
                            >
                                <Maximize2 className="w-3.5 h-3.5 text-slate-300" />
                                <span>Open Full Screen</span>
                            </button>
                        )}

                        {onClose && !isFullscreen && (
                            <button
                                type="button"
                                onClick={onClose}
                                className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white rounded-lg border border-slate-700 text-xs font-medium cursor-pointer"
                                aria-label="Close"
                            >
                                Close
                            </button>
                        )}
                    </div>
                </div>

                {/* Row 2: Secondary View Controls (Device, Zoom, Mode) */}
                <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800/80 text-xs text-slate-400">
                    {/* Left: Device Presets (Desktop, Tablet, Mobile) */}
                    <div className="flex items-center gap-2">
                        <span className="text-[11px] text-slate-500 font-medium">Device:</span>
                        <div className="flex items-center p-0.5 bg-slate-950/80 rounded-lg border border-slate-800 text-slate-400">
                            <button
                                type="button"
                                onClick={() => setViewportSize('desktop')}
                                title="Desktop View (1440 × 900)"
                                className={`px-2 py-1 rounded text-xs flex items-center gap-1 font-mono cursor-pointer transition-colors ${
                                    viewportSize === 'desktop' ? 'bg-slate-800 text-white font-medium border border-slate-700' : 'hover:text-white'
                                }`}
                            >
                                <Monitor className="w-3.5 h-3.5" />
                                <span className="text-[10px]">Desktop</span>
                            </button>
                            <button
                                type="button"
                                onClick={() => setViewportSize('tablet')}
                                title="Tablet View (768 × 1024)"
                                className={`px-2 py-1 rounded text-xs flex items-center gap-1 font-mono cursor-pointer transition-colors ${
                                    viewportSize === 'tablet' ? 'bg-slate-800 text-white font-medium border border-slate-700' : 'hover:text-white'
                                }`}
                            >
                                <Tablet className="w-3.5 h-3.5" />
                                <span className="text-[10px]">Tablet</span>
                            </button>
                            <button
                                type="button"
                                onClick={() => setViewportSize('mobile')}
                                title="Mobile View (390 × 844)"
                                className={`px-2 py-1 rounded text-xs flex items-center gap-1 font-mono cursor-pointer transition-colors ${
                                    viewportSize === 'mobile' ? 'bg-slate-800 text-white font-medium border border-slate-700' : 'hover:text-white'
                                }`}
                            >
                                <Smartphone className="w-3.5 h-3.5" />
                                <span className="text-[10px]">Mobile</span>
                            </button>
                        </div>
                    </div>

                    {/* Center: Zoom Controls */}
                    <div className="flex items-center gap-2">
                        <span className="text-[11px] text-slate-500 font-medium">Zoom:</span>
                        <div className="flex items-center gap-1 text-xs bg-slate-950/80 px-2 py-1 rounded-lg border border-slate-800 text-slate-300 font-mono">
                            <button
                                type="button"
                                onClick={() => setZoomLevel((z) => Math.max(50, z - 10))}
                                className="p-0.5 hover:text-white cursor-pointer"
                                title="Zoom Out (−)"
                                aria-label="Zoom out"
                            >
                                <ZoomOut className="w-3 h-3" />
                            </button>
                            <span className="w-9 text-center text-[11px] font-medium select-none">{zoomLevel}%</span>
                            <button
                                type="button"
                                onClick={() => setZoomLevel((z) => Math.min(150, z + 10))}
                                className="p-0.5 hover:text-white cursor-pointer"
                                title="Zoom In (+)"
                                aria-label="Zoom in"
                            >
                                <ZoomIn className="w-3 h-3" />
                            </button>
                            <button
                                type="button"
                                onClick={() => setZoomLevel(100)}
                                className="px-1.5 py-0.5 hover:text-white text-[10px] bg-slate-800 hover:bg-slate-700 rounded cursor-pointer ml-0.5 border border-slate-700"
                                title="Reset Zoom (100%)"
                            >
                                Reset
                            </button>
                        </div>
                    </div>

                    {/* Right: View Mode Tabs (Safe View | Forensic | Screenshot) */}
                    <div className="flex items-center p-0.5 bg-slate-950/80 rounded-lg border border-slate-800 text-xs font-medium">
                        <button
                            type="button"
                            onClick={() => setViewerMode('visual')}
                            className={`px-2.5 py-1 rounded-md transition-all cursor-pointer ${
                                viewerMode === 'visual' ? 'bg-slate-800 text-white shadow-sm border border-slate-700' : 'text-slate-400 hover:text-white'
                            }`}
                            title="Safe Web View (Sanitized DOM)"
                        >
                            Safe View
                        </button>
                        <button
                            type="button"
                            onClick={() => setViewerMode('forensic')}
                            className={`px-2.5 py-1 rounded-md transition-all cursor-pointer ${
                                viewerMode === 'forensic' ? 'bg-slate-800 text-amber-300 shadow-sm border border-amber-500/30' : 'text-slate-400 hover:text-white'
                            }`}
                            title="Forensic Overlay (Highlighted Elements)"
                        >
                            Forensic
                        </button>
                        <button
                            type="button"
                            onClick={() => setViewerMode('screenshot')}
                            className={`px-2.5 py-1 rounded-md transition-all cursor-pointer ${
                                viewerMode === 'screenshot' ? 'bg-slate-800 text-blue-300 shadow-sm border border-blue-500/30' : 'text-slate-400 hover:text-white'
                            }`}
                            title="Full Page Screenshot"
                        >
                            Screenshot
                        </button>
                    </div>
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
                <div className="p-6 rounded-2xl bg-black/80 border border-purple-500/30 shadow-2xl max-w-xl w-full text-left space-y-4">
                    <div className="flex items-center gap-3 border-b border-white/10 pb-4">
                        <div className={`p-2.5 rounded-xl border ${isExpired ? 'bg-amber-500/15 border-amber-500/30 text-amber-400' : 'bg-red-500/15 border-red-500/30 text-red-400'}`}>
                            {isExpired ? <Clock className="w-6 h-6" /> : <AlertOctagon className="w-6 h-6" />}
                        </div>
                        <div>
                            <h3 className={`text-sm font-bold tracking-wider ${isExpired ? 'text-amber-300' : 'text-red-400'}`}>
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
                            <span className="font-mono text-purple-300 font-bold text-[11px] select-all">{displaySid}</span>
                        </div>
                        <div className="flex items-center justify-between">
                            <span className="text-slate-500 text-[10px] uppercase tracking-wider">Page ID:</span>
                            <span className="font-mono text-white text-[11px]">{displayPid}</span>
                        </div>
                        <div className="flex items-center justify-between">
                            <span className="text-slate-500 text-[10px] uppercase tracking-wider">Target URL:</span>
                            <span className="font-mono text-cyan-300 text-[11px] truncate max-w-[280px]" title={activePage?.url || targetUrl}>
                                {activePage?.url || targetUrl}
                            </span>
                        </div>
                        <div className="flex items-center justify-between pt-1 border-t border-white/5">
                            <span className="text-slate-500 text-[10px] uppercase tracking-wider">Target HTTP Status:</span>
                            <span className="text-emerald-400 font-bold text-[11px]">HTTP {targetHttpStatus}</span>
                        </div>
                        <div className="flex items-center justify-between">
                            <span className="text-slate-500 text-[10px] uppercase tracking-wider">Safe View Status:</span>
                            <span className={`font-bold text-[11px] ${isExpired ? 'text-amber-400' : 'text-red-400'}`}>{safeViewStatus}</span>
                        </div>
                        <div className="pt-2 border-t border-white/5">
                            <span className="text-slate-500 text-[10px] uppercase tracking-wider block mb-1">Reason:</span>
                            <div className="p-2 rounded bg-red-950/30 border border-red-500/20 text-red-300 text-[11px] leading-relaxed">
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
                            <RotateCw className="w-3.5 h-3.5 text-purple-400" />
                            <span>Check Session Again</span>
                        </button>
                        {onRescan && (
                            <button
                                type="button"
                                onClick={onRescan}
                                className="flex-1 min-w-[140px] px-3.5 py-2 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-xs font-bold flex items-center justify-center gap-2 shadow-lg shadow-purple-500/25 border border-purple-400/30 transition-all cursor-pointer"
                            >
                                <Sparkles className="w-3.5 h-3.5 text-yellow-300" />
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
                    : "rounded-xl shadow-xl w-full h-[800px] max-h-[85vh] my-6 overflow-hidden"
            }`}
        >
            {/* Top Sticky Toolbar */}
            {renderBrowserToolbar()}

            {/* 3-Column Workspace */}
            <div className="flex flex-col lg:flex-row flex-1 min-h-0 overflow-hidden">
                {/* ─────────────────────────────────────────────────────────────────
                    LEFT PANEL: WEBSITE PAGES DISCOVERY
                ───────────────────────────────────────────────────────────────── */}
                {isLeftPanelOpen && (
                    <div className="w-full lg:w-80 bg-slate-900 border-b lg:border-b-0 lg:border-r border-slate-800 flex flex-col shrink-0 transition-all">
                        {renderPagesList()}
                    </div>
                )}

                {/* ─────────────────────────────────────────────────────────────────
                    CENTER PANEL: SAFE WEB VIEWER
                ───────────────────────────────────────────────────────────────── */}
                <div className="flex-1 bg-slate-950 flex flex-col relative min-w-0 overflow-hidden">
                    <div className="viewer-shell w-full h-full flex-1 flex flex-col min-w-0 overflow-hidden relative">
                        {/* Clean Security Address Bar */}
                        <div className="bg-slate-900 px-3.5 py-2 border-b border-slate-800 flex items-center justify-between gap-2.5 text-xs shrink-0">
                            <div className="flex items-center gap-1.5 shrink-0">
                                <span className="w-2.5 h-2.5 rounded-full bg-slate-700 inline-block" />
                                <span className="w-2.5 h-2.5 rounded-full bg-slate-700 inline-block" />
                                <span className="w-2.5 h-2.5 rounded-full bg-slate-700 inline-block" />
                            </div>
                            <div className="flex-1 mx-2 px-3 py-1 rounded-lg bg-slate-950 border border-slate-800 flex items-center gap-2 text-slate-300 text-xs truncate">
                                <Lock className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                                <span className="text-emerald-400 font-medium shrink-0">Read-only</span>
                                <span className="text-slate-600 shrink-0">|</span>
                                <span className="text-slate-400 hidden sm:inline shrink-0">Isolated Sandbox</span>
                                {(pageDetail?.http_status && pageDetail.http_status >= 400) || (activePage?.http_status && activePage.http_status >= 400) ? (
                                    <>
                                        <span className="text-slate-600 shrink-0">|</span>
                                        <span className="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 text-[10px] font-bold font-mono shrink-0">
                                            HTTP {pageDetail?.http_status || activePage?.http_status}
                                        </span>
                                    </>
                                ) : null}
                                <span className="text-slate-600 shrink-0">|</span>
                                <span className="truncate text-slate-200 font-mono text-[11px]">{activePage?.url || targetUrl}</span>
                            </div>
                            <div className="flex items-center gap-2 shrink-0">
                                <span className="text-[10px] text-slate-400 font-mono hidden sm:inline">
                                    {activePreset.label} ({activePreset.width}×{activePreset.height})
                                </span>
                                <button
                                    id="btn-inner-fullscreen"
                                    type="button"
                                    onClick={() => setIsFullscreen(!isFullscreen)}
                                    className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 hover:text-white border border-slate-700 text-xs font-medium transition-colors cursor-pointer shadow-sm"
                                    title={isFullscreen ? "Exit Full Screen (Esc)" : "Open Full Screen"}
                                >
                                    {isFullscreen ? <Minimize2 className="w-3.5 h-3.5 text-slate-400" /> : <Maximize2 className="w-3.5 h-3.5 text-slate-400" />}
                                    <span>{isFullscreen ? 'Exit Full Screen' : 'Full Screen'}</span>
                                </button>
                            </div>
                        </div>

                        {/* Viewport Frame Container */}
                        <div className="viewer-viewport flex-1 w-full min-h-0 overflow-auto p-2 sm:p-4 flex flex-col items-center justify-start bg-slate-950">
                            {isLoading ? (
                                <div className="flex-1 flex flex-col items-center justify-center p-8 text-center space-y-3 min-h-[400px]">
                                    <div className="w-12 h-12 rounded-full border-2 border-slate-700 border-t-blue-500 animate-spin flex items-center justify-center">
                                        <Globe className="w-5 h-5 text-blue-400 animate-pulse" />
                                    </div>
                                    <div className="space-y-1 font-mono">
                                        <h4 className="text-sm font-semibold text-white">
                                            {isPrioritizing ? 'Prioritizing & Analyzing Page...' : 'Loading Page Representation'}
                                        </h4>
                                        <p className="text-xs text-slate-400 break-all">{activePage?.url || targetUrl}</p>
                                        <p className="text-[11px] text-blue-400">
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
                                        <div className="flex-1 flex flex-col items-center justify-center p-8 text-center space-y-3 min-h-[400px] font-mono">
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
                                <div className="w-full h-full min-h-[500px] bg-slate-950 flex flex-col items-center justify-center overflow-auto p-2">
                                    {screenshotB64 ? (
                                        <img
                                            src={`data:image/png;base64,${screenshotB64}`}
                                            alt="Captured Full Page Screenshot"
                                            className="w-full object-contain max-h-[800px] rounded shadow-lg border border-slate-800"
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
                                <div
                                    className="viewer-page-wrapper w-full flex flex-col items-center justify-start transition-all"
                                    style={viewportSize === 'desktop' && zoomLevel === 100 ? { width: '100%', height: '100%', minHeight: '600px' } : {
                                        width: `${scaledWidth}px`,
                                        minHeight: `${scaledHeight}px`,
                                        margin: '0 auto',
                                        position: 'relative',
                                        flexShrink: 0,
                                    }}
                                >
                                    <div
                                        className="viewer-page bg-white rounded-lg shadow-xl overflow-hidden border border-slate-700 w-full h-full relative flex flex-col"
                                        style={viewportSize === 'desktop' && zoomLevel === 100 ? { width: '100%', height: '100%', minHeight: '600px' } : {
                                            width: `${activePreset.width}px`,
                                            height: `${activePreset.height}px`,
                                            transform: `scale(${scale})`,
                                            transformOrigin: 'top center',
                                        }}
                                    >

                                        <iframe
                                            ref={iframeRef}
                                            src={iframeUrl}
                                            srcDoc={pageDetail?.safe_html || undefined}
                                            title="Safe Web Viewer Sandboxed Document"
                                            sandbox="allow-same-origin"
                                            className="w-full flex-1 border-0 bg-white"
                                            style={viewportSize === 'desktop' && zoomLevel === 100 ? { width: '100%', height: '100%', minHeight: '600px' } : {
                                                width: `${activePreset.width}px`,
                                                height: `${activePreset.height}px`,
                                            }}
                                        />
                                        {screenshotB64 && viewerMode === 'visual' && (pageDetail?.content_inventory?.text_characters ?? 100) < 30 && (pageDetail?.content_inventory?.forms ?? 0) === 0 && (
                                            <div className="absolute bottom-4 right-4 z-20 bg-slate-900/90 backdrop-blur-md border border-slate-700 text-xs text-slate-200 px-3 py-2 rounded-lg shadow-xl flex items-center gap-2.5">
                                                <Sparkles className="w-4 h-4 text-cyan-400 shrink-0" />
                                                <span>Minimal static markup. Sandbox screenshot available:</span>
                                                <button
                                                    type="button"
                                                    onClick={() => setViewerMode('screenshot')}
                                                    className="px-2.5 py-1 bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-[11px] rounded transition-all cursor-pointer"
                                                >
                                                    View Screenshot
                                                </button>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            )}
                        </div>

                        {/* Viewer Bottom Telemetry Strip (Requirement 22) */}
                        <div className="bg-slate-950 px-4 py-2 border-t border-slate-800 flex flex-wrap items-center justify-between text-[11px] font-mono text-slate-400 gap-2 shrink-0 select-none">
                            <div className="flex items-center gap-4 flex-wrap">
                                <span>Status: <strong className="text-emerald-400">Captured &amp; Isolated</strong></span>
                                <span>Forms: <strong className="text-white">{pageDetail?.content_inventory?.forms ?? activePage?.forms_count ?? 0}</strong></span>
                                <span>Links: <strong className="text-white">{pageDetail?.content_inventory?.links ?? 0}</strong></span>
                                <span>Render Time: <strong className="text-slate-300">{pageDetail?.load_time_ms ?? 0}ms</strong></span>
                            </div>
                            <div className="flex items-center gap-2">
                                <span className="text-slate-400 text-[10px]">
                                    🛡 Isolated Read-Only VM View
                                </span>
                            </div>
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
                                    <span className="text-[10px] text-purple-400 font-bold uppercase tracking-wider block">
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
                                        <Database className="w-3.5 h-3.5 text-purple-400" />
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
                                            <span className="text-base font-bold text-amber-300">
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
                                            <span className="text-base font-bold text-red-400">
                                                {pageDetail?.content_inventory?.forms ?? 0} / {pageDetail?.content_inventory?.inputs ?? 0}
                                            </span>
                                        </div>
                                        <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                                            <span className="text-slate-400 block text-[10px]">Links</span>
                                            <span className="text-base font-bold text-blue-400">
                                                {pageDetail?.content_inventory?.links ?? 0}
                                            </span>
                                        </div>
                                        <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                                            <span className="text-slate-400 block text-[10px]">Iframes Neutralized</span>
                                            <span className="text-base font-bold text-purple-300">
                                                {pageDetail?.content_inventory?.iframes ?? 0}
                                            </span>
                                        </div>
                                        <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                                            <span className="text-slate-400 block text-[10px]">External Domains</span>
                                            <span className="text-base font-bold text-orange-400">
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
                                                    <span className="text-blue-300 break-all block bg-black/80 p-1.5 rounded border border-white/5">
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

            {/* Bottom Status / Telemetry Strip */}
            <div className="px-4 py-2 bg-slate-900 border-t border-slate-800 text-[11px] text-slate-400 flex flex-wrap items-center justify-between gap-2 shrink-0">
                <div className="flex items-center gap-2 sm:gap-3">
                    <span className="flex items-center gap-1.5 text-slate-300 font-medium">
                        <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                        Read-only
                    </span>
                    <span className="text-slate-600">•</span>
                    <span className="text-slate-400">Isolated analysis</span>
                    <span className="text-slate-600">•</span>
                    <span className="truncate max-w-xs sm:max-w-md font-mono text-[10px] text-slate-300">
                        {activePage?.url || targetUrl}
                    </span>
                </div>
                <div className="flex items-center gap-2 text-[10px] text-slate-500">
                    <span>Target interaction blocked</span>
                    <span className="text-slate-700">•</span>
                    <span>VM Sandboxed</span>
                </div>
            </div>
        </div>
    );

    if (isFullscreen && typeof document !== 'undefined') {
        return createPortal(viewerWorkspace, document.body);
    }

    return viewerWorkspace;
};
