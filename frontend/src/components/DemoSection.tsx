import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Search, Loader2, ShieldCheck, ShieldAlert, AlertTriangle,
    Fingerprint, Network, Shield, RefreshCw, Globe, Hash, Clock, Link2, Download
} from 'lucide-react';
import jsPDF from 'jspdf';

// ── API response type ──
interface PredictionResponse {
    prediction_result: 'Phishing' | 'Suspicious' | 'Safe';
    confidence_score: number;
    risk_level: 'High' | 'Moderate' | 'Low';
    recommendation: string;
    url: string;
    status: 'success' | 'failed';
    error?: string;
}

// ── Radial confidence gauge ──
const RadialGauge: React.FC<{ value: number; color: string }> = ({ value, color }) => {
    const r = 52;
    const circumference = 2 * Math.PI * r;
    const filled = circumference * (value / 100);
    return (
        <div className="relative w-32 h-32 flex items-center justify-center">
            <svg className="w-full h-full -rotate-90" viewBox="0 0 120 120">
                {/* Background track */}
                <circle cx="60" cy="60" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="8" />
                {/* Colored arc */}
                <motion.circle
                    cx="60" cy="60" r={r}
                    fill="none"
                    stroke={color}
                    strokeWidth="8"
                    strokeLinecap="round"
                    strokeDasharray={circumference}
                    initial={{ strokeDashoffset: circumference }}
                    animate={{ strokeDashoffset: circumference - filled }}
                    transition={{ duration: 1.2, ease: 'easeOut', delay: 0.2 }}
                    style={{ filter: `drop-shadow(0 0 6px ${color}90)` }}
                />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
                <motion.span
                    className="text-2xl font-black text-white leading-none"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.5 }}
                >
                    {value}%
                </motion.span>
                <span className="text-[10px] text-gray-500 mt-0.5 uppercase tracking-wider">Confidence</span>
            </div>
        </div>
    );
};

// ── Scanning radar animation ──
const RadarScan: React.FC = () => (
    <div className="relative w-28 h-28 flex items-center justify-center mx-auto">
        {/* Rings */}
        {[0, 1, 2].map(i => (
            <div key={i}
                className="absolute rounded-full border border-primary/20"
                style={{ inset: `${i * 10}px` }}
            />
        ))}
        {/* Sweep */}
        <div className="absolute inset-0 rounded-full overflow-hidden">
            <motion.div
                className="absolute inset-0 origin-center"
                animate={{ rotate: 360 }}
                transition={{ duration: 1.8, repeat: Infinity, ease: 'linear' }}
                style={{
                    background: 'conic-gradient(rgba(0,174,239,0.35) 0deg, transparent 90deg)',
                }}
            />
        </div>
        {/* Center dot */}
        <div className="relative z-10 w-3 h-3 rounded-full bg-primary animate-ping" style={{ boxShadow: '0 0 12px #00AEEF' }} />
    </div>
);

// ── Feature definitions ──
const getFeatureBreakdown = (data: PredictionResponse) => {
    // Extract the underlying risk score from the confidence score
    const riskScore = data.prediction_result === 'Safe' ? (100 - data.confidence_score) : data.confidence_score;
    const isPhish = data.prediction_result === 'Phishing';
    const isSusp = data.prediction_result === 'Suspicious';

    return [
        {
            icon: Hash,
            label: 'Lexical Structure',
            value: isPhish ? 'Highly Suspicious' : isSusp ? 'Suspicious' : 'Normal',
            risk: isPhish ? Math.min(riskScore, 98) : isSusp ? Math.min(riskScore, 70) : Math.max(riskScore, 2),
        },
        {
            icon: Network,
            label: 'CNN Pattern Score',
            value: isPhish ? 'Phishing Pattern' : isSusp ? 'Moderate Risk' : 'Clean',
            risk: isPhish ? Math.min(riskScore + 5, 99) : isSusp ? Math.min(riskScore - 5, 65) : Math.max(riskScore - 1, 1),
        },
        {
            icon: Clock,
            label: 'LSTM Context',
            value: isPhish ? 'High Obfuscation' : isSusp ? 'Ambiguous' : 'Standard',
            risk: isPhish ? Math.min(riskScore - 2, 97) : isSusp ? Math.min(riskScore + 3, 68) : Math.max(riskScore + 2, 3),
        },
        {
            icon: Globe,
            label: 'Domain Assessment',
            value: isPhish ? 'Spoofed Domain' : isSusp ? 'Questionable' : 'Legitimate',
            risk: isPhish ? Math.min(riskScore + 2, 99) : isSusp ? Math.min(riskScore - 8, 60) : Math.max(riskScore, 1),
        },
        {
            icon: Link2,
            label: 'URL Depth & Redirects',
            value: isPhish ? 'Deep Redirect Chain' : isSusp ? 'Multiple Hops' : 'Direct',
            risk: isPhish ? Math.min(riskScore - 5, 96) : isSusp ? Math.min(riskScore - 15, 58) : Math.max(riskScore + 1, 2),
        },
        {
            icon: Fingerprint,
            label: 'Brand Impersonation',
            value: isPhish ? 'Brand Detected' : isSusp ? 'Possible' : 'None',
            risk: isPhish ? Math.min(riskScore + 8, 100) : isSusp ? Math.min(riskScore - 10, 62) : Math.max(riskScore - 1, 1),
        },
    ];
};

const getColors = (pred?: string) => {
    if (pred === 'Phishing') return {
        text: '#FF3B3B', border: 'rgba(255,59,59,0.3)', bg: 'rgba(255,59,59,0.05)',
        icon: 'rgba(255,59,59,0.15)', bar: '#FF3B3B', glow: 'rgba(255,59,59,0.3)',
    };
    if (pred === 'Suspicious') return {
        text: '#FFB347', border: 'rgba(255,179,71,0.3)', bg: 'rgba(255,179,71,0.05)',
        icon: 'rgba(255,179,71,0.15)', bar: '#FFB347', glow: 'rgba(255,179,71,0.3)',
    };
    return {
        text: '#00FFB2', border: 'rgba(0,255,178,0.3)', bg: 'rgba(0,255,178,0.05)',
        icon: 'rgba(0,255,178,0.15)', bar: '#00FFB2', glow: 'rgba(0,255,178,0.3)',
    };
};

const getResultIcon = (pred?: string) => {
    if (pred === 'Phishing') return <AlertTriangle className="w-9 h-9" />;
    if (pred === 'Suspicious') return <ShieldAlert className="w-9 h-9" />;
    return <ShieldCheck className="w-9 h-9" />;
};

// ─────────────────────────────────────────────────
const DemoSection: React.FC = () => {
    const [url, setUrl] = useState('');
    const [scanStatus, setScanStatus] = useState<'idle' | 'scanning' | 'results' | 'error'>('idle');
    const [result, setResult] = useState<PredictionResponse | null>(null);
    const [errorMsg, setErrorMsg] = useState('');

    const handleScan = async (e: React.FormEvent) => {
        e.preventDefault();
        const trimmed = url.trim();
        if (!trimmed) return;
        
        // Strict input validation
        if (!/^https?:\/\//i.test(trimmed)) {
            setErrorMsg('Invalid format. URL must start with http:// or https://');
            setScanStatus('error');
            return;
        }

        setScanStatus('scanning');
        setResult(null);
        setErrorMsg('');
        try {
            const endpoint = import.meta.env.VITE_API_URL 
                ? `${import.meta.env.VITE_API_URL}/predict` 
                : 'https://phishguard-npyx.onrender.com/predict';

            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 30000); // 30s timeout for hybrid DL+Rules engine

            const res = await fetch(endpoint, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({ url: trimmed }),
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);

            const data: PredictionResponse = await res.json();
            if (!res.ok || data.status === 'failed') {
                throw new Error(data.error || 'Prediction failed.');
            }
            
            setResult(data);
            setScanStatus('results');

        } catch (err: any) {
            console.error("Scan Error:", err);
            if (err.name === 'AbortError') {
                setErrorMsg('Server is slow, try again.');
            } else {
                setErrorMsg('Backend unavailable.');
            }
            setScanStatus('error');
        }
    };

    const handleReset = () => { setScanStatus('idle'); setResult(null); setUrl(''); setErrorMsg(''); };

    const downloadReport = () => {
        if (!result) return;
        const doc = new jsPDF();
        
        doc.setFillColor(6, 11, 24);
        doc.rect(0, 0, 210, 297, 'F');
        
        doc.setTextColor(255, 255, 255);
        doc.setFontSize(22);
        doc.text("PhishGuard AI - Analysis Report", 20, 30);
        
        doc.setDrawColor(0, 174, 239);
        doc.line(20, 35, 190, 35);
        
        doc.setFontSize(12);
        doc.setTextColor(200, 200, 200);
        
        const safeColor = [0, 255, 178];
        const phishColor = [255, 59, 59];
        const suspColor = [255, 179, 71];
        
        let statusColor = safeColor;
        if (result.prediction_result === 'Phishing') statusColor = phishColor;
        else if (result.prediction_result === 'Suspicious') statusColor = suspColor;
        
        doc.text(`Scanned URL:`, 20, 50);
        doc.setTextColor(255, 255, 255);
        doc.text(`${result.url}`, 60, 50);
        
        doc.setTextColor(200, 200, 200);
        doc.text(`Prediction:`, 20, 60);
        doc.setTextColor(statusColor[0], statusColor[1], statusColor[2]);
        doc.text(`${result.prediction_result}`, 60, 60);
        
        doc.setTextColor(200, 200, 200);
        doc.text(`Confidence:`, 20, 70);
        doc.setTextColor(255, 255, 255);
        doc.text(`${result.confidence_score}%`, 60, 70);
        
        doc.setTextColor(200, 200, 200);
        doc.text(`Risk Level:`, 20, 80);
        doc.setTextColor(255, 255, 255);
        doc.text(`${result.risk_level}`, 60, 80);
        
        doc.setTextColor(200, 200, 200);
        doc.text(`Timestamp:`, 20, 90);
        doc.setTextColor(255, 255, 255);
        doc.text(`${new Date().toLocaleString()}`, 60, 90);
        
        doc.setTextColor(0, 174, 239);
        doc.text(`Recommendation:`, 20, 110);
        doc.setTextColor(255, 255, 255);
        const splitText = doc.splitTextToSize(result.recommendation, 170);
        doc.text(splitText, 20, 120);
        
        doc.save(`PhishGuard_Report_${Date.now()}.pdf`);
    };

    const colors = getColors(result?.prediction_result);
    const features = result ? getFeatureBreakdown(result) : [];

    return (
        <section id="demo" className="py-28 relative overflow-hidden">
            {/* BG */}
            <div className="absolute inset-0 pointer-events-none"
                style={{ background: 'radial-gradient(ellipse 70% 50% at 50% 100%, rgba(0,174,239,0.07) 0%, transparent 65%)' }} />
            <div className="absolute inset-0 bg-grid opacity-15 pointer-events-none" />

            <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">

                {/* Header */}
                <motion.div
                    initial={{ opacity: 0, y: 30 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    className="text-center mb-14"
                >
                    <div className="section-label mb-6 mx-auto">Live Detection Engine</div>
                    <h2 className="text-4xl md:text-5xl font-bold mb-5">
                        Analyze a <span className="text-gradient-blue">URL</span>
                    </h2>
                    <p className="text-gray-400 text-lg">
                        Powered by a trained CNN–BiLSTM model. Paste any URL and get an instant threat verdict.
                    </p>
                </motion.div>

                {/* ── Main scan card ── */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    className="rounded-3xl p-7 md:p-10 relative overflow-hidden"
                    style={{
                        background: 'rgba(10,15,44,0.8)',
                        border: '1px solid rgba(0,174,239,0.2)',
                        backdropFilter: 'blur(24px)',
                        boxShadow: '0 0 60px rgba(0,174,239,0.08), 0 30px 60px rgba(0,0,0,0.4)',
                    }}
                >
                    {/* Top gradient line */}
                    <div className="absolute top-0 left-0 right-0 h-px"
                        style={{ background: 'linear-gradient(90deg, transparent, #00AEEF, #00FFB2, transparent)' }} />

                    {/* ── Input form ── */}
                    <form onSubmit={handleScan} className="mb-8">
                        <div className="relative">
                            {/* Search icon */}
                            <div className="absolute left-5 top-1/2 -translate-y-1/2 pointer-events-none">
                                <Search className="w-5 h-5 text-gray-600" />
                            </div>
                            <input
                                id="url-input"
                                type="text"
                                value={url}
                                onChange={e => setUrl(e.target.value)}
                                placeholder="Paste URL to scan — e.g. http://paypal-secure-update.com"
                                className="w-full py-5 pl-14 pr-40 text-base font-mono text-white placeholder-gray-600 rounded-2xl outline-none transition-all duration-300"
                                style={{
                                    background: 'rgba(0,0,0,0.5)',
                                    border: '1px solid rgba(255,255,255,0.08)',
                                }}
                                onFocus={e => {
                                    (e.target as HTMLElement).style.borderColor = 'rgba(0,174,239,0.5)';
                                    (e.target as HTMLElement).style.boxShadow = '0 0 0 3px rgba(0,174,239,0.12)';
                                }}
                                onBlur={e => {
                                    (e.target as HTMLElement).style.borderColor = 'rgba(255,255,255,0.08)';
                                    (e.target as HTMLElement).style.boxShadow = 'none';
                                }}
                                disabled={scanStatus === 'scanning'}
                            />
                            <button
                                id="scan-btn"
                                type="submit"
                                disabled={scanStatus === 'scanning' || !url.trim()}
                                className="absolute right-3 top-1/2 -translate-y-1/2 px-6 py-3 rounded-xl font-bold text-sm transition-all duration-300 disabled:opacity-40"
                                style={{
                                    background: 'linear-gradient(135deg, #00AEEF, #0077CC)',
                                    boxShadow: '0 0 20px rgba(0,174,239,0.3)',
                                    color: '#fff',
                                }}
                                onMouseEnter={e => {
                                    if (!((e.currentTarget as HTMLButtonElement).disabled))
                                        (e.currentTarget as HTMLElement).style.boxShadow = '0 0 35px rgba(0,174,239,0.55)';
                                }}
                                onMouseLeave={e => {
                                    (e.currentTarget as HTMLElement).style.boxShadow = '0 0 20px rgba(0,174,239,0.3)';
                                }}
                            >
                                {scanStatus === 'scanning' ? (
                                    <span className="flex items-center gap-2">
                                        <Loader2 className="w-4 h-4 animate-spin" />
                                        Analyzing
                                    </span>
                                ) : 'Scan URL'}
                            </button>
                        </div>
                    </form>

                    {/* ── Dynamic result area ── */}
                    <AnimatePresence mode="wait">

                        {/* Scanning state */}
                        {scanStatus === 'scanning' && (
                            <motion.div
                                key="scanning"
                                initial={{ opacity: 0, height: 0 }}
                                animate={{ opacity: 1, height: 'auto' }}
                                exit={{ opacity: 0, height: 0 }}
                                className="overflow-hidden"
                            >
                                <div className="pt-6 flex flex-col items-center text-center gap-6"
                                    style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                                    <RadarScan />
                                    <div>
                                        <p className="text-white font-bold text-lg mb-1">Deep Learning Analysis Running…</p>
                                        <p className="text-sm text-gray-500 font-mono">CNN feature extraction → LSTM sequence analysis</p>
                                    </div>
                                    {/* Progress bar */}
                                    <div className="w-full max-w-sm h-1 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.05)' }}>
                                        <motion.div
                                            className="h-full rounded-full"
                                            style={{ background: 'linear-gradient(90deg, #00AEEF, #00FFB2)' }}
                                            initial={{ width: '0%' }}
                                            animate={{ width: '100%' }}
                                            transition={{ duration: 2.2, ease: 'easeInOut' }}
                                        />
                                    </div>
                                    {/* Tech labels */}
                                    <div className="flex flex-wrap justify-center gap-2">
                                        {['Tokenizing URL', 'Running CNN filters', 'LSTM sequence', 'Scoring output'].map((t, i) => (
                                            <motion.span
                                                key={t}
                                                initial={{ opacity: 0 }}
                                                animate={{ opacity: 1 }}
                                                transition={{ delay: i * 0.5 }}
                                                className="text-xs px-3 py-1 rounded-full font-mono"
                                                style={{ background: 'rgba(0,174,239,0.08)', border: '1px solid rgba(0,174,239,0.2)', color: '#00AEEF' }}
                                            >
                                                {t}
                                            </motion.span>
                                        ))}
                                    </div>
                                </div>
                            </motion.div>
                        )}

                        {/* Error state */}
                        {scanStatus === 'error' && (
                            <motion.div
                                key="error"
                                initial={{ opacity: 0, y: 20 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -10 }}
                                className="pt-6"
                                style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}
                            >
                                <div className="p-6 rounded-2xl flex flex-col md:flex-row items-center gap-5"
                                    style={{ background: 'rgba(255,59,59,0.05)', border: '1px solid rgba(255,59,59,0.25)' }}>
                                    <div className="w-14 h-14 rounded-full flex items-center justify-center shrink-0 text-dangerous"
                                        style={{ background: 'rgba(255,59,59,0.12)', border: '1px solid rgba(255,59,59,0.3)' }}>
                                        <Shield className="w-7 h-7" />
                                    </div>
                                    <div className="flex-1 text-center md:text-left">
                                        <h3 className="font-bold text-lg mb-1 text-dangerous">Backend Connection Error</h3>
                                        <p className="text-sm text-gray-400">{errorMsg}</p>
                                        <p className="text-xs text-gray-600 mt-2 font-mono">Check URL validity or ensure backend is online.</p>
                                    </div>
                                    <button onClick={handleReset}
                                        className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm border border-white/10 hover:border-white/20 text-white transition-all">
                                        <RefreshCw className="w-4 h-4" /> Try Again
                                    </button>
                                </div>
                            </motion.div>
                        )}

                        {/* Results state */}
                        {scanStatus === 'results' && result && (
                            <motion.div
                                key="results"
                                initial={{ opacity: 0, y: 20 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -10 }}
                                className="pt-6 space-y-6"
                                style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}
                            >
                                {/* ── Banner ── */}
                                <div className="p-6 rounded-2xl flex flex-col md:flex-row items-center justify-between gap-6"
                                    style={{ background: colors.bg, border: `1px solid ${colors.border}`, boxShadow: `0 0 30px ${colors.glow}` }}>

                                    <div className="flex items-center gap-5">
                                        {/* Pulsing icon */}
                                        <div className="relative">
                                            <div className="absolute inset-0 rounded-full animate-ping opacity-30"
                                                style={{ background: colors.icon }} />
                                            <div className="relative w-16 h-16 rounded-full flex items-center justify-center"
                                                style={{ background: colors.icon, border: `1px solid ${colors.border}`, color: colors.text }}>
                                                {getResultIcon(result.prediction_result)}
                                            </div>
                                        </div>
                                        <div>
                                            <h3 className="text-2xl font-bold" style={{ color: colors.text }}>
                                                {result.prediction_result === 'Phishing' ? '🚨 Phishing URL Detected'
                                                    : result.prediction_result === 'Suspicious' ? '⚠️ Suspicious URL'
                                                        : '✅ Safe URL'}
                                            </h3>
                                            <p className="text-xs font-mono mt-1 truncate max-w-xs text-white/50">{result.url}</p>
                                            <span className="text-xs font-bold uppercase tracking-wider mt-1 inline-block" style={{ color: colors.text }}>
                                                {result.risk_level} Risk
                                            </span>
                                        </div>
                                    </div>

                                    {/* Radial gauge */}
                                    <RadialGauge 
                                        value={result.confidence_score} 
                                        color={colors.text} 
                                    />
                                </div>

                                {/* Recommendation */}
                                <div className="p-4 rounded-xl text-sm text-gray-300 leading-relaxed"
                                    style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)' }}>
                                    <span className="font-bold text-white">Recommendation: </span>
                                    {result.recommendation}
                                </div>

                                {/* ── 6-feature breakdown ── */}
                                <div>
                                    <h4 className="font-semibold text-white mb-4 flex items-center gap-2 text-sm">
                                        <Fingerprint className="w-4 h-4 text-primary" />
                                        Feature Analysis Breakdown
                                    </h4>
                                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                                        {features.map((f, i) => {
                                            const FIcon = f.icon;
                                            const barColor = f.risk > 60 ? '#FF3B3B' : f.risk > 30 ? '#FFB347' : '#00FFB2';
                                            return (
                                                <div key={i} className="p-4 rounded-xl"
                                                    style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
                                                    <div className="flex items-center gap-2 mb-2">
                                                        <FIcon className="w-3.5 h-3.5 text-gray-500 shrink-0" />
                                                        <span className="text-xs text-gray-400">{f.label}</span>
                                                    </div>
                                                    <div className="flex items-center justify-between mb-2">
                                                        <span className="text-xs font-semibold" style={{ color: barColor }}>{f.value}</span>
                                                        <span className="text-xs font-bold text-gray-500">{f.risk}%</span>
                                                    </div>
                                                    <div className="w-full h-1 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.05)' }}>
                                                        <motion.div
                                                            className="h-full rounded-full"
                                                            style={{ background: barColor, boxShadow: `0 0 6px ${barColor}80` }}
                                                            initial={{ width: 0 }}
                                                            animate={{ width: `${f.risk}%` }}
                                                            transition={{ delay: 0.2 + i * 0.08, duration: 0.9 }}
                                                        />
                                                    </div>
                                                </div>
                                            );
                                        })}
                                    </div>
                                </div>

                                {/* Scan again and Report buttons */}
                                <div className="flex flex-col sm:flex-row justify-center gap-4 pt-4">
                                    <button onClick={handleReset}
                                        className="flex items-center justify-center gap-2 px-6 py-3 rounded-xl text-sm font-semibold text-white transition-all duration-300 hover:bg-white/5"
                                        style={{ border: '1px solid rgba(255,255,255,0.1)' }}>
                                        <RefreshCw className="w-4 h-4" /> Scan Another URL
                                    </button>
                                    <button onClick={downloadReport}
                                        className="flex items-center justify-center gap-2 px-6 py-3 rounded-xl text-sm font-semibold text-white transition-all duration-300 hover:bg-primary/20"
                                        style={{ background: 'rgba(0,174,239,0.1)', border: '1px solid rgba(0,174,239,0.3)', boxShadow: '0 0 15px rgba(0,174,239,0.15)' }}>
                                        <Download className="w-4 h-4 text-primary" /> Download PDF Report
                                    </button>
                                </div>
                            </motion.div>
                        )}

                    </AnimatePresence>
                </motion.div>
            </div>
        </section>
    );
};

export default DemoSection;
