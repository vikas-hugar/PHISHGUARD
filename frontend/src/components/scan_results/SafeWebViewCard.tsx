import React, { useState } from 'react';
import { Shield, Lock, Eye, ExternalLink, ChevronDown, ChevronUp, Layers, CheckCircle2, AlertOctagon } from 'lucide-react';
import { SafeWebViewer } from '../SafeWebViewer';

interface SafeWebViewCardProps {
    sessionId?: string | null;
    pageId?: string | null;
    targetUrl: string;
    backendUrl: string;
    screenshotB64?: string | null;
    screenshotType?: string | null;
    pagesAnalyzed?: number;
    pagesAvailable?: number;
    pagesBlocked?: number;
    onRescan?: () => void;
}

export const SafeWebViewCard: React.FC<SafeWebViewCardProps> = ({
    sessionId,
    pageId = 'p_root',
    targetUrl,
    backendUrl,
    screenshotB64,
    screenshotType = 'full_page',
    pagesAnalyzed = 1,
    pagesAvailable = 1,
    pagesBlocked = 0,
    onRescan,
}) => {
    const [isOpen, setIsOpen] = useState(false);

    return (
        <div className="rounded-xl bg-slate-900/80 border border-slate-800 overflow-hidden">
            {/* Header / Summary Section */}
            <div className="p-5 sm:p-6 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div className="space-y-1">
                        <div className="flex items-center gap-2">
                            <Lock className="w-4 h-4 text-emerald-400" />
                            <h3 className="text-base font-semibold text-slate-100">Safe Web View</h3>
                            <span className="text-[11px] font-medium px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                Isolated Sandbox
                            </span>
                        </div>
                        <p className="text-xs text-slate-400 max-w-xl">
                            Explore the analyzed website in a protected, read-only environment without executing untrusted scripts on your device.
                        </p>
                    </div>

                    <div className="flex items-center gap-2">
                        <button
                            type="button"
                            onClick={() => setIsOpen(!isOpen)}
                            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white transition-all cursor-pointer shadow-sm"
                        >
                            <Eye className="w-3.5 h-3.5" />
                            <span>{isOpen ? 'Close Safe Web View' : 'Open Safe Web View'}</span>
                            {isOpen ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                        </button>
                    </div>
                </div>

                {/* Metrics Row */}
                <div className="grid grid-cols-3 gap-2 pt-2 border-t border-slate-800/80 text-center">
                    <div className="p-2.5 rounded-lg bg-slate-950/40 border border-slate-800/60">
                        <span className="text-[11px] font-medium text-slate-400 block mb-0.5">Pages analyzed</span>
                        <span className="text-sm sm:text-base font-semibold text-slate-100">{pagesAnalyzed}</span>
                    </div>
                    <div className="p-2.5 rounded-lg bg-slate-950/40 border border-slate-800/60">
                        <span className="text-[11px] font-medium text-slate-400 block mb-0.5">Pages available</span>
                        <span className="text-sm sm:text-base font-semibold text-emerald-400">{pagesAvailable}</span>
                    </div>
                    <div className="p-2.5 rounded-lg bg-slate-950/40 border border-slate-800/60">
                        <span className="text-[11px] font-medium text-slate-400 block mb-0.5">Pages blocked</span>
                        <span className={`text-sm sm:text-base font-semibold ${pagesBlocked > 0 ? 'text-amber-400' : 'text-slate-400'}`}>
                            {pagesBlocked}
                        </span>
                    </div>
                </div>
            </div>

            {/* Embedded Safe Web Viewer (Expanded on request) */}
            {isOpen && (
                <div className="border-t border-slate-800 bg-slate-950 p-2 sm:p-4">
                    <div className="w-full rounded-lg overflow-hidden border border-slate-800 bg-slate-900">
                        <SafeWebViewer
                            sessionId={sessionId}
                            initialPageId={pageId}
                            targetUrl={targetUrl}
                            backendUrl={backendUrl}
                            screenshotB64={screenshotB64}
                            screenshotType={screenshotType}
                            onRescan={onRescan}
                            onClose={() => setIsOpen(false)}
                        />
                    </div>
                </div>
            )}
        </div>
    );
};
