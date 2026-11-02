import React, { useState } from 'react';
import { AlertCircle, RefreshCw, ChevronDown, ChevronUp, ShieldAlert } from 'lucide-react';

interface ScanErrorProps {
    url: string;
    errorMessage: string;
    isSsrfBlock?: boolean;
    errorDiagnostic?: {
        target: string;
        reason: string;
        stage: string;
        timeoutSec?: number;
        retry?: string;
        details?: string;
    } | null;
    onRetry: () => void;
    onReset: () => void;
}

export const ScanError: React.FC<ScanErrorProps> = ({
    url,
    errorMessage,
    isSsrfBlock,
    errorDiagnostic,
    onRetry,
    onReset,
}) => {
    const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);

    const title = isSsrfBlock
        ? 'Website access restricted by security policy'
        : 'Page could not be fully analyzed';

    const description = isSsrfBlock
        ? 'The destination address resolves to a reserved, internal, or loopback network address that is blocked to protect network security.'
        : 'The website did not respond normally enough for complete analysis. Supporting resources or connection handshakes timed out.';

    return (
        <div className="p-5 sm:p-6 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4 text-left">
            <div className="flex items-start gap-3">
                <div className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ${
                    isSsrfBlock ? 'bg-red-500/10 text-red-400' : 'bg-amber-500/10 text-amber-400'
                }`}>
                    {isSsrfBlock ? <ShieldAlert className="w-5 h-5" /> : <AlertCircle className="w-5 h-5" />}
                </div>
                <div className="space-y-1">
                    <h3 className="text-base font-semibold text-slate-100">{title}</h3>
                    <p className="text-xs text-slate-400 leading-relaxed max-w-xl">{description}</p>
                </div>
            </div>

            <div className="flex flex-wrap items-center gap-3 pt-2 border-t border-slate-800">
                <button
                    type="button"
                    onClick={onRetry}
                    className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium bg-blue-600 hover:bg-blue-500 text-white transition-colors cursor-pointer"
                >
                    <RefreshCw className="w-3.5 h-3.5" />
                    <span>Try again</span>
                </button>
                <button
                    type="button"
                    onClick={onReset}
                    className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors cursor-pointer"
                >
                    <span>Analyze another URL</span>
                </button>
                <button
                    type="button"
                    onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
                    className="ml-auto inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
                >
                    <span>{showTechnicalDetails ? 'Hide technical details' : 'View technical details'}</span>
                    {showTechnicalDetails ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                </button>
            </div>

            {showTechnicalDetails && (
                <div className="mt-3 p-3.5 rounded-lg bg-slate-950/60 border border-slate-800 font-mono text-xs text-slate-400 space-y-2">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                        <div>
                            <span className="text-slate-500 block text-[11px]">TARGET URL</span>
                            <span className="text-slate-300 truncate block">{url}</span>
                        </div>
                        <div>
                            <span className="text-slate-500 block text-[11px]">DIAGNOSTIC STAGE</span>
                            <span className="text-slate-300 block">{errorDiagnostic?.stage || 'Inspection Pipeline'}</span>
                        </div>
                    </div>
                    {errorMessage && (
                        <div>
                            <span className="text-slate-500 block text-[11px]">RAW ERROR</span>
                            <span className="text-amber-400 block break-words">{errorMessage}</span>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};
