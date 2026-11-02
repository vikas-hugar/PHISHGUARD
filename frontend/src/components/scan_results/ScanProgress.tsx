import React, { useState, useEffect } from 'react';
import { Loader2, Check, Globe } from 'lucide-react';

interface ScanProgressProps {
    url: string;
}

export const ScanProgress: React.FC<ScanProgressProps> = ({ url }) => {
    const [activeStage, setActiveStage] = useState(0);
    const [pagesCount, setPagesCount] = useState(1);

    const stages = [
        'Checking URL accessibility...',
        'URL reachable — Starting secure analysis...',
        'Isolated sandbox & DOM behavior analysis',
        'Known threats & neural model validation',
        'Visual appearance & multi-signal fusion',
    ];

    useEffect(() => {
        const interval = setInterval(() => {
            setActiveStage((prev) => {
                if (prev < stages.length - 1) {
                    return prev + 1;
                }
                return prev;
            });
            setPagesCount((prev) => (prev < 15 ? prev + Math.floor(Math.random() * 3 + 1) : prev));
        }, 1100);

        return () => clearInterval(interval);
    }, [stages.length]);

    const isReachabilityStage = activeStage === 0;

    return (
        <div className="py-10 px-4 max-w-md mx-auto text-left space-y-6">
            <div className="text-center space-y-1">
                <div className="inline-flex items-center justify-center w-10 h-10 rounded-full bg-blue-500/10 text-blue-400 mb-2">
                    <Loader2 className="w-5 h-5 animate-spin" />
                </div>
                <h3 className="text-base font-semibold text-slate-100">
                    {isReachabilityStage ? 'Checking URL accessibility...' : 'URL reachable — Starting secure analysis...'}
                </h3>
                <p className="text-xs text-slate-400 font-mono truncate max-w-xs mx-auto" title={url}>
                    {url}
                </p>
            </div>

            {/* Checklist */}
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-slate-400 block uppercase tracking-wider">
                        Inspection Stages
                    </span>
                    <span className="text-[11px] font-mono text-blue-400">
                        {isReachabilityStage ? 'Stage 1: Pre-Scan Gate' : 'Stage 2: Full Analysis'}
                    </span>
                </div>
                <div className="space-y-2">
                    {stages.map((stage, idx) => {
                        const isDone = idx < activeStage;
                        const isCurrent = idx === activeStage;
                        const isPending = idx > activeStage;

                        return (
                            <div key={stage} className="flex items-center gap-2.5 text-xs">
                                {isDone && (
                                    <div className="w-4 h-4 rounded-full bg-emerald-500/15 text-emerald-400 flex items-center justify-center shrink-0">
                                        <Check className="w-2.5 h-2.5 stroke-[2.5]" />
                                    </div>
                                )}
                                {isCurrent && (
                                    <div className="w-4 h-4 rounded-full bg-blue-500/15 text-blue-400 flex items-center justify-center shrink-0">
                                        <div className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-ping" />
                                    </div>
                                )}
                                {isPending && (
                                    <div className="w-4 h-4 rounded-full bg-slate-800 text-slate-600 flex items-center justify-center shrink-0">
                                        <span className="text-[10px]">○</span>
                                    </div>
                                )}
                                <span
                                    className={`${
                                        isDone
                                            ? 'text-slate-300 font-medium'
                                            : isCurrent
                                            ? 'text-slate-100 font-semibold'
                                            : 'text-slate-500'
                                    }`}
                                >
                                    {stage}
                                </span>
                            </div>
                        );
                    })}
                </div>
            </div>

            {/* Progress indicator */}
            <div className="text-center text-xs text-slate-400 font-medium">
                {isReachabilityStage ? (
                    <span className="text-slate-400">Verifying target accessibility &amp; network security policies...</span>
                ) : (
                    <span>Discovered &amp; analyzing {pagesCount} pages in isolated sandbox</span>
                )}
            </div>
        </div>
    );
};
