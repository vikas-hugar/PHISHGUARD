import React, { useState } from 'react';
import { motion } from 'framer-motion';
import {
    AlertTriangle,
    RotateCcw,
    Search,
    ChevronDown,
    ChevronUp,
    Shield,
    WifiOff,
    Info,
    ExternalLink,
} from 'lucide-react';

interface UnreachableUrlProps {
    url: string;
    status?: string;
    reason?: string;
    message?: string;
    recommendation?: string;
    onRetry?: () => void;
    onReset?: () => void;
}

export const UnreachableUrl: React.FC<UnreachableUrlProps> = ({
    url,
    status = 'DNS_FAILED',
    reason,
    message,
    recommendation,
    onRetry,
    onReset,
}) => {
    const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);

    // Format human-friendly status label
    const formatStatus = (s: string): { label: string; desc: string } => {
        switch (s) {
            case 'DNS_FAILED':
                return {
                    label: 'DNS Resolution Failed',
                    desc: 'The domain name does not exist or authoritative nameservers did not respond.',
                };
            case 'CONNECTION_TIMEOUT':
                return {
                    label: 'Connection Timeout',
                    desc: 'The target server failed to complete a TCP/HTTP handshake within the timeout limit.',
                };
            case 'CONNECTION_REFUSED':
                return {
                    label: 'Connection Refused',
                    desc: 'The host server actively rejected the connection (port closed or firewall block).',
                };
            case 'TLS_FAILED':
                return {
                    label: 'TLS Handshake Failed',
                    desc: 'Unable to establish a secure TLS/HTTPS session with the remote host.',
                };
            case 'HOST_UNAVAILABLE':
                return {
                    label: 'Host Unavailable',
                    desc: 'The remote host is offline, unreachable, or returned a Bad Gateway (HTTP 502/504).',
                };
            case 'REDIRECT_UNAVAILABLE':
                return {
                    label: 'Redirect Unavailable',
                    desc: 'Excessive redirect chain or invalid redirect destination detected.',
                };
            case 'INVALID_URL':
                return {
                    label: 'Malformed URL Syntax',
                    desc: 'The submitted URL has invalid syntax or dangerous characters.',
                };
            default:
                return {
                    label: s.replace(/_/g, ' '),
                    desc: reason || 'The target URL could not be reached from the secure scanning environment.',
                };
        }
    };

    const statusInfo = formatStatus(status);

    return (
        <div className="rounded-2xl p-6 sm:p-7 bg-slate-900/90 border border-amber-500/40 shadow-2xl shadow-amber-950/20 text-left space-y-6">
            {/* Header Badge */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-5 border-b border-slate-800">
                <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-amber-500/15 border border-amber-500/30 flex items-center justify-center text-amber-400 shrink-0">
                        <AlertTriangle className="w-5 h-5" />
                    </div>
                    <div>
                        <div className="flex items-center gap-2">
                            <span className="text-xs font-bold tracking-wider uppercase text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">
                                Pre-Scan Gate Result
                            </span>
                            <span className="text-xs font-mono text-slate-400">
                                Status: {status}
                            </span>
                        </div>
                        <h3 className="text-xl font-bold text-slate-100 tracking-tight mt-0.5">
                            URL Not Reachable
                        </h3>
                    </div>
                </div>

                <div className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700/60 text-xs font-medium text-slate-300">
                    <WifiOff className="w-3.5 h-3.5 text-amber-400" />
                    <span>Scan Not Performed</span>
                </div>
            </div>

            {/* Target URL banner */}
            <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 font-mono text-xs flex flex-wrap items-center justify-between gap-2">
                <span className="text-slate-400">Target:</span>
                <span className="text-amber-300 font-semibold truncate max-w-md sm:max-w-xl" title={url}>
                    {url}
                </span>
            </div>

            {/* Status & Explanation Box */}
            <div className="space-y-4">
                <div className="p-4 rounded-xl bg-amber-500/5 border border-amber-500/20 space-y-2">
                    <div className="flex items-center gap-2 text-sm font-semibold text-amber-300">
                        <Info className="w-4 h-4 shrink-0 text-amber-400" />
                        <span>Status: {statusInfo.label}</span>
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed">
                        {message || 'Full phishing analysis was not performed because the website could not be reached.'}
                    </p>
                    <p className="text-xs text-slate-400 leading-relaxed font-mono">
                        {reason || statusInfo.desc}
                    </p>
                </div>

                {/* Critical Security Policy Notice */}
                <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-2.5">
                    <div className="flex items-center gap-2 text-xs font-bold text-slate-200 tracking-wide uppercase">
                        <Shield className="w-4 h-4 text-blue-400" />
                        <span>PhishGuard Security Policy: Unreachable ≠ Safe</span>
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed">
                        {recommendation || 'This does NOT mean the URL is safe. Do not treat this result as proof that the URL is safe.'}
                    </p>
                    <p className="text-xs text-slate-400 leading-relaxed">
                        An unreachable domain may be parked, temporarily offline, cloaking against automated analysis crawlers, or using geographic access filtering. No security verdict or fake low-risk score is assigned when a website cannot be accessed.
                    </p>
                </div>
            </div>

            {/* Action Buttons */}
            <div className="flex flex-wrap items-center gap-3 pt-4 border-t border-slate-800">
                <button
                    type="button"
                    onClick={onReset}
                    className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white transition-all shadow-lg shadow-blue-600/20 cursor-pointer"
                >
                    <Search className="w-4 h-4" />
                    <span>Try Another URL</span>
                </button>

                {onRetry && (
                    <button
                        type="button"
                        onClick={onRetry}
                        className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors cursor-pointer"
                    >
                        <RotateCcw className="w-3.5 h-3.5" />
                        <span>Retry Accessibility Check</span>
                    </button>
                )}

                <button
                    type="button"
                    onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
                    className="ml-auto inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
                >
                    <span>{showTechnicalDetails ? 'Hide technical diagnostics' : 'View technical diagnostics'}</span>
                    {showTechnicalDetails ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                </button>
            </div>

            {/* Technical Diagnostics Accordion */}
            {showTechnicalDetails && (
                <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    className="pt-3 border-t border-slate-800/60 font-mono text-xs space-y-3"
                >
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-3.5 rounded-lg bg-slate-950/80 border border-slate-800/80">
                        <div>
                            <span className="text-slate-500 block text-[11px] uppercase tracking-wider">Reachability Status</span>
                            <span className="text-amber-400 font-semibold">{status}</span>
                        </div>
                        <div>
                            <span className="text-slate-500 block text-[11px] uppercase tracking-wider">Analysis Pipeline</span>
                            <span className="text-slate-300">Skipped (Pre-Scan Gate)</span>
                        </div>
                        <div>
                            <span className="text-slate-500 block text-[11px] uppercase tracking-wider">Browser Sandbox</span>
                            <span className="text-slate-300">Not launched (Resource conserved)</span>
                        </div>
                        <div>
                            <span className="text-slate-500 block text-[11px] uppercase tracking-wider">Security Verdict</span>
                            <span className="text-slate-300">INCONCLUSIVE (No fake score)</span>
                        </div>
                    </div>

                    {reason && (
                        <div className="p-3 rounded-lg bg-slate-950/50 border border-slate-800/60">
                            <span className="text-slate-500 block text-[11px] uppercase tracking-wider">Raw Diagnostic Detail</span>
                            <span className="text-slate-300 break-words">{reason}</span>
                        </div>
                    )}
                </motion.div>
            )}
        </div>
    );
};
