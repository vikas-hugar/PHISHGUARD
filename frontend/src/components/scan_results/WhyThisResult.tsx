import React from 'react';
import { AlertCircle, CheckCircle, Info } from 'lucide-react';

interface FindingItem {
    isWarning: boolean;
    text: string;
}

interface WhyThisResultProps {
    verdict: string;
    riskScore: number;
    targetBrand?: string;
    threatIntelligenceFound?: boolean;
    hasCredentialHarvesting?: boolean;
    hasPaymentFields?: boolean;
    homoglyphDetected?: boolean;
    punycodeDetected?: boolean;
    typosquattingDetected?: boolean;
    modelAnomaliesDetected?: boolean;
    reasons?: string[];
}

export const WhyThisResult: React.FC<WhyThisResultProps> = ({
    verdict,
    riskScore,
    targetBrand,
    threatIntelligenceFound,
    hasCredentialHarvesting,
    hasPaymentFields,
    homoglyphDetected,
    punycodeDetected,
    typosquattingDetected,
    modelAnomaliesDetected,
    reasons,
}) => {
    const v = (verdict || '').toLowerCase();
    const isPhishing = v.includes('phish');
    const isSuspicious = v.includes('suspicious');
    const isSafe = !isPhishing && !isSuspicious;

    // Build structured, human-readable findings
    const findings: FindingItem[] = [];

    if (threatIntelligenceFound) {
        findings.push({
            isWarning: true,
            text: 'Website address matches a confirmed malicious signature in security threat databases.',
        });
    } else {
        findings.push({
            isWarning: false,
            text: 'No known malicious match was found in the threat intelligence repository.',
        });
    }

    if (targetBrand && targetBrand !== 'None' && (isPhishing || isSuspicious)) {
        findings.push({
            isWarning: true,
            text: `Domain characteristics suggest potential impersonation of ${targetBrand}.`,
        });
    }

    if (homoglyphDetected || punycodeDetected || typosquattingDetected) {
        findings.push({
            isWarning: true,
            text: 'Look-alike or spoofed characters detected in the domain name.',
        });
    }

    if (hasCredentialHarvesting || hasPaymentFields) {
        findings.push({
            isWarning: true,
            text: 'Suspicious credential or sensitive data input fields detected on page.',
        });
    } else {
        findings.push({
            isWarning: false,
            text: 'No suspicious credential harvesting or payment forms were detected.',
        });
    }

    if (modelAnomaliesDetected || riskScore >= 35) {
        findings.push({
            isWarning: true,
            text: 'Pattern analysis identified structural characteristics associated with deceptive websites.',
        });
    } else {
        findings.push({
            isWarning: false,
            text: 'URL structure and page composition are consistent with legitimate websites.',
        });
    }

    // Overall assessment text
    let overallAssessment = '';
    if (isPhishing) {
        overallAssessment =
            'This website exhibits critical phishing indicators, such as known malicious signatures or credential interception patterns. Direct interaction is dangerous.';
    } else if (isSuspicious) {
        overallAssessment =
            'The website displays several warning characteristics, but does not present sufficient evidence to classify as confirmed phishing. Caution is recommended.';
    } else {
        overallAssessment =
            'PhishGuard verified the domain reputation, page structure, and behavior. No malicious patterns or security risks were identified.';
    }

    return (
        <div className="p-5 sm:p-6 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
            <h3 className="text-base font-semibold text-white">
                Why this result?
            </h3>

            {/* Findings List */}
            <div className="space-y-2">
                <span className="text-xs font-medium text-slate-400 block mb-1">
                    Key Observations:
                </span>
                <div className="space-y-2 font-sans">
                    {findings.map((item, idx) => (
                        <div key={idx} className="flex items-start gap-2.5 text-xs sm:text-sm">
                            {item.isWarning ? (
                                <span className="text-amber-400 shrink-0 mt-0.5 font-bold">⚠</span>
                            ) : (
                                <span className="text-emerald-400 shrink-0 mt-0.5 font-bold">✓</span>
                            )}
                            <span className={item.isWarning ? 'text-slate-200' : 'text-slate-300'}>
                                {item.text}
                            </span>
                        </div>
                    ))}
                </div>
            </div>

            {/* Overall Assessment */}
            <div className="pt-3 border-t border-slate-800/80 space-y-1">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block">
                    Overall Assessment
                </span>
                <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
                    {overallAssessment}
                </p>
            </div>
        </div>
    );
};
