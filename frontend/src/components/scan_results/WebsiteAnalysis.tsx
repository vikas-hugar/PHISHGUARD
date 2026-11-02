import React from 'react';
import { Globe, AlertTriangle, CheckCircle2, Shield, ArrowRightLeft, FileCode, Users, ExternalLink } from 'lucide-react';

interface AnalysisRow {
    check: string;
    result: string;
    status: 'safe' | 'warning' | 'danger' | 'neutral';
    detail?: string;
}

interface WebsiteAnalysisProps {
    urlPatternResult?: string;
    threatDatabaseResult?: string;
    formsResult?: string;
    redirectCount?: number;
    behaviorResult?: string;
    thirdPartyWebsitesCount?: number;
    targetBrand?: string;
}

export const WebsiteAnalysis: React.FC<WebsiteAnalysisProps> = ({
    urlPatternResult = 'Normal structure',
    threatDatabaseResult = 'No known match',
    formsResult = 'None detected',
    redirectCount = 0,
    behaviorResult = 'Normal',
    thirdPartyWebsitesCount = 0,
    targetBrand,
}) => {
    // Generate clean rows
    const rows: AnalysisRow[] = [
        {
            check: 'URL',
            result: urlPatternResult,
            status: urlPatternResult.toLowerCase().includes('suspicious') || urlPatternResult.toLowerCase().includes('phish')
                ? 'warning'
                : 'safe',
        },
        {
            check: 'Threat database',
            result: threatDatabaseResult,
            status: threatDatabaseResult.toLowerCase().includes('match') && !threatDatabaseResult.toLowerCase().includes('no ')
                ? 'danger'
                : 'safe',
        },
        {
            check: 'Forms and inputs',
            result: formsResult,
            status: formsResult.toLowerCase().includes('credential') || formsResult.toLowerCase().includes('harvest')
                ? 'warning'
                : formsResult.toLowerCase().includes('none')
                ? 'safe'
                : 'neutral',
        },
        {
            check: 'Redirects',
            result: redirectCount > 0 ? `${redirectCount} hop${redirectCount > 1 ? 's' : ''}` : 'Direct (0 hops)',
            status: redirectCount > 3 ? 'warning' : 'safe',
        },
        {
            check: 'Page behavior',
            result: behaviorResult,
            status: behaviorResult.toLowerCase().includes('anomal') || behaviorResult.toLowerCase().includes('decept') || behaviorResult.toLowerCase().includes('high')
                ? 'warning'
                : 'safe',
        },
        {
            check: 'Third-party websites',
            result: thirdPartyWebsitesCount > 0 ? `${thirdPartyWebsitesCount} external domain${thirdPartyWebsitesCount > 1 ? 's' : ''}` : 'None',
            status: thirdPartyWebsitesCount > 10 ? 'neutral' : 'safe',
        },
    ];

    if (targetBrand && targetBrand !== 'None') {
        rows.push({
            check: 'Brand impersonation check',
            result: `Targeting ${targetBrand}`,
            status: 'warning',
        });
    }

    return (
        <div className="p-5 sm:p-6 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
            <div>
                <h3 className="text-base font-semibold text-slate-100">Website analysis</h3>
                <p className="text-xs text-slate-400 mt-0.5">Key findings from static and behavioral inspection</p>
            </div>

            <div className="overflow-hidden rounded-lg border border-slate-800">
                <table className="w-full text-left text-xs">
                    <thead className="bg-slate-950/60 text-slate-400 font-medium border-b border-slate-800">
                        <tr>
                            <th className="py-2.5 px-4 w-1/3">Check</th>
                            <th className="py-2.5 px-4 w-2/3">Result</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 bg-slate-900/40">
                        {rows.map((row, idx) => {
                            let badgeStyle = 'text-slate-300';
                            let dotStyle = 'bg-slate-500';

                            if (row.status === 'safe') {
                                badgeStyle = 'text-emerald-400';
                                dotStyle = 'bg-emerald-400';
                            } else if (row.status === 'warning') {
                                badgeStyle = 'text-amber-400 font-medium';
                                dotStyle = 'bg-amber-400';
                            } else if (row.status === 'danger') {
                                badgeStyle = 'text-red-400 font-semibold';
                                dotStyle = 'bg-red-400';
                            }

                            return (
                                <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                                    <td className="py-3 px-4 font-medium text-slate-300">{row.check}</td>
                                    <td className="py-3 px-4">
                                        <div className="flex items-center gap-2">
                                            <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${dotStyle}`} />
                                            <span className={badgeStyle}>{row.result}</span>
                                        </div>
                                    </td>
                                </tr>
                            );
                        })}
                    </tbody>
                </table>
            </div>
        </div>
    );
};
