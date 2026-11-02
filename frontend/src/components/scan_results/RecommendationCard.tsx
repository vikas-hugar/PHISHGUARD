import React from 'react';
import { ShieldAlert, AlertTriangle, ShieldCheck, HelpCircle } from 'lucide-react';

interface RecommendationCardProps {
    verdict: string;
    customRecommendation?: string;
}

export const RecommendationCard: React.FC<RecommendationCardProps> = ({
    verdict,
    customRecommendation,
}) => {
    const v = (verdict || '').toLowerCase();
    const isPhishing = v.includes('phish');
    const isSuspicious = v.includes('suspicious');
    const isSafe = !isPhishing && !isSuspicious;

    let title = 'What you should do';
    let subtitle = '';
    let advice = '';
    let icon = ShieldCheck;
    let cardStyle = 'border-slate-800 bg-slate-900/80';
    let iconColor = 'text-emerald-400';

    if (isPhishing) {
        subtitle = 'Because this website was classified as confirmed or high-risk phishing:';
        advice =
            customRecommendation ||
            'Do not enter passwords, one-time passcodes (OTPs), card details, or personal credentials. Close this browser tab immediately. If you have already entered account information on this page, immediately change your credentials from an official device or app.';
        icon = ShieldAlert;
        cardStyle = 'border-red-500/30 bg-red-950/20';
        iconColor = 'text-red-400';
    } else if (isSuspicious) {
        subtitle = 'Because this website was classified as suspicious:';
        advice =
            customRecommendation ||
            'Do not enter passwords, OTPs, payment information, or personal details unless you have verified the website through an independent official source. Avoid downloading files or granting permissions.';
        icon = AlertTriangle;
        cardStyle = 'border-amber-500/30 bg-amber-950/20';
        iconColor = 'text-amber-400';
    } else {
        subtitle = 'Because no major phishing indicators were detected:';
        advice =
            customRecommendation ||
            'The website appears legitimate. However, always exercise normal security hygiene: check that the address bar shows the expected domain before submitting sensitive financial or login credentials.';
        icon = ShieldCheck;
        cardStyle = 'border-emerald-500/30 bg-emerald-950/20';
        iconColor = 'text-emerald-400';
    }

    const IconComponent = icon;

    return (
        <div className={`p-5 sm:p-6 rounded-xl border ${cardStyle} space-y-3`}>
            <div className="flex items-center gap-2.5">
                <IconComponent className={`w-5 h-5 ${iconColor} shrink-0`} />
                <h3 className="text-base font-semibold text-slate-100">{title}</h3>
            </div>

            <p className="text-xs text-slate-300 font-medium">{subtitle}</p>

            <p className="text-xs sm:text-sm text-slate-200 leading-relaxed font-sans">{advice}</p>
        </div>
    );
};
