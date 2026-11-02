import React from 'react';
import { Check, ChevronRight } from 'lucide-react';

interface SecurityChecksProps {
    onViewTechnicalDetails?: () => void;
}

export const SecurityChecks: React.FC<SecurityChecksProps> = ({ onViewTechnicalDetails }) => {
    const checks = [
        { id: 'url', label: 'URL structure' },
        { id: 'content', label: 'Website content' },
        { id: 'behavior', label: 'Page behavior' },
        { id: 'threat_intel', label: 'Threat intelligence' },
        { id: 'identity', label: 'Website identity' },
        { id: 'visual', label: 'Visual appearance' },
        { id: 'forms', label: 'Forms and inputs' },
        { id: 'redirects', label: 'Redirects' },
        { id: 'network', label: 'Network activity' },
        { id: 'source', label: 'Website source code' },
    ];

    return (
        <div className="p-5 sm:p-6 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
                <div>
                    <h3 className="text-base font-semibold text-slate-100">What we checked</h3>
                    <p className="text-xs text-slate-400 mt-0.5">Automated inspection across core security layers</p>
                </div>
                <span className="text-xs font-medium px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                    10 checks completed
                </span>
            </div>

            {/* 2-column clean checklist */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 pt-1">
                {checks.map((item) => (
                    <div
                        key={item.id}
                        className="flex items-center gap-2.5 px-3 py-2 rounded-lg bg-slate-950/40 border border-slate-800/80 text-xs text-slate-300"
                    >
                        <div className="w-4 h-4 rounded-full bg-emerald-500/10 text-emerald-400 flex items-center justify-center shrink-0">
                            <Check className="w-3 h-3 stroke-[2.5]" />
                        </div>
                        <span className="font-medium text-slate-200">{item.label}</span>
                    </div>
                ))}
            </div>

            {onViewTechnicalDetails && (
                <div className="pt-2 flex justify-start">
                    <button
                        type="button"
                        onClick={onViewTechnicalDetails}
                        className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-400 hover:text-blue-300 transition-colors cursor-pointer group"
                    >
                        <span>View technical analysis</span>
                        <ChevronRight className="w-3.5 h-3.5 transition-transform group-hover:translate-x-0.5" />
                    </button>
                </div>
            )}
        </div>
    );
};
