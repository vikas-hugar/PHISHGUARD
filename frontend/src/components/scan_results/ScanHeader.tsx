import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, CheckCircle2, Lock, Globe, Clock, Shield } from 'lucide-react';

interface ScanHeaderProps {
    url: string;
    verdict: string;
    riskScore: number;
    timestamp?: number;
    detectionType?: string;
}

export const ScanHeader: React.FC<ScanHeaderProps> = ({
    url,
    verdict = 'Legitimate',
    riskScore = 0,
    timestamp,
    detectionType,
}) => {
    const v = verdict.toLowerCase();
    const isPhishing = v.includes('phish');
    const isSuspicious = v.includes('suspicious');
    const isSafe = !isPhishing && !isSuspicious;

    const statusConfig = isPhishing
        ? {
              label: 'Phishing',
              icon: ShieldAlert,
              badgeClass: 'bg-red-500/10 text-red-400 border-red-500/20',
              barClass: 'bg-red-500',
              summary: 'This website is confirmed or strongly indicated as phishing. Do not submit sensitive data.',
          }
        : isSuspicious
        ? {
              label: 'Suspicious',
              icon: AlertTriangle,
              badgeClass: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
              barClass: 'bg-amber-500',
              summary: 'This website shows several signs commonly associated with deceptive or suspicious websites.',
          }
        : {
              label: 'Safe',
              icon: ShieldCheck,
              badgeClass: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
              barClass: 'bg-emerald-500',
              summary: 'No major phishing indicators or deceptive patterns were detected.',
          };

    const StatusIcon = statusConfig.icon;
    const formattedDate = timestamp
        ? new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
        : 'Just now';

    return (
        <div className="space-y-4">
            {/* Minimal Header Breadcrumb */}
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400 font-sans">
                <div className="flex items-center gap-2">
                    <span className="font-semibold text-slate-200">PhishGuard</span>
                    <span className="text-slate-600">/</span>
                    <span>Scan Result</span>
                </div>
                <div className="flex items-center gap-1.5 text-slate-400 text-xs">
                    <Clock className="w-3.5 h-3.5 text-slate-500" />
                    <span>Completed {formattedDate}</span>
                </div>
            </div>

            {/* URL Display */}
            <div className="flex items-center gap-2.5 p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-sm text-slate-200">
                <Globe className="w-4 h-4 text-slate-400 shrink-0" />
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider shrink-0">URL:</span>
                <span className="font-mono text-xs sm:text-sm text-slate-100 truncate flex-1" title={url}>
                    {url}
                </span>
            </div>

            {/* Main Result Card */}
            <div className="p-5 sm:p-6 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div className="space-y-1.5">
                        <span className="text-xs font-medium text-slate-400 uppercase tracking-wider block">
                            Verdict
                        </span>
                        <div className="flex items-center gap-2.5">
                            <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-sm font-semibold border ${statusConfig.badgeClass}`}>
                                <StatusIcon className="w-4 h-4" />
                                {statusConfig.label}
                            </span>
                            {detectionType === 'WHITELIST' && (
                                <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                                    Verified Domain
                                </span>
                            )}
                        </div>
                    </div>

                    {/* Risk Score */}
                    <div className="sm:text-right min-w-[160px]">
                        <span className="text-xs font-medium text-slate-400 uppercase tracking-wider block mb-1">
                            Risk Score
                        </span>
                        <div className="flex items-baseline sm:justify-end gap-1 font-mono">
                            <span className="text-2xl font-bold text-white">{Math.round(riskScore)}</span>
                            <span className="text-xs text-slate-500">/ 100</span>
                        </div>
                    </div>
                </div>

                {/* Clean Horizontal Score Bar */}
                <div className="space-y-1.5">
                    <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                        <div
                            className={`h-full rounded-full transition-all duration-700 ${statusConfig.barClass}`}
                            style={{ width: `${Math.min(Math.max(riskScore, 0), 100)}%` }}
                        />
                    </div>
                </div>

                {/* Summary Statement */}
                <p className="text-sm text-slate-300 leading-relaxed pt-1 border-t border-slate-800/80">
                    {statusConfig.summary}
                </p>
            </div>
        </div>
    );
};
