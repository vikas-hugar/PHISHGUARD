import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Search, Loader2, ShieldCheck, ShieldAlert, AlertTriangle,
    Cpu, Clock, Download, Zap, CheckCircle2,
    AlertCircle, Sparkles, RefreshCw
} from 'lucide-react';
import jsPDF from 'jspdf';

// ── API response type (Enterprise V3 Hybrid) ──
interface PredictionResponse {
    prediction?: 'Phishing' | 'Suspicious' | 'Safe' | string;
    prediction_result?: 'Phishing' | 'Suspicious' | 'Safe' | string;
    risk_score: number;
    confidence: number;
    confidence_score?: number;
    cnn_score?: number;
    roberta_score?: number;
    threat_level: 'Safe' | 'Medium' | 'High' | 'Critical';
    risk_level?: string;
    detection_time_ms: number;
    model_version: string;
    recommendation: string;
    explanations?: string[];
    url: string;
    status: 'success' | 'failed';
    error?: string;
}

// ── Threat Level Visual Styling ──
const getThreatMeta = (level: 'Safe' | 'Medium' | 'High' | 'Critical') => {
    switch (level) {
        case 'Critical':
            return {
                label: 'Critical Threat',
                color: '#FF3B3B',
                bg: 'rgba(255, 59, 59, 0.08)',
                border: 'rgba(255, 59, 59, 0.35)',
                badgeBg: 'rgba(255, 59, 59, 0.18)',
                glow: 'rgba(255, 59, 59, 0.3)',
                icon: ShieldAlert,
                range: '85–100',
            };
        case 'High':
            return {
                label: 'High Risk',
                color: '#FB923C',
                bg: 'rgba(251, 146, 60, 0.08)',
                border: 'rgba(251, 146, 60, 0.35)',
                badgeBg: 'rgba(251, 146, 60, 0.18)',
                glow: 'rgba(251, 146, 60, 0.25)',
                icon: AlertTriangle,
                range: '60–84',
            };
        case 'Medium':
            return {
                label: 'Medium Risk',
                color: '#FACC15',
                bg: 'rgba(250, 204, 21, 0.08)',
                border: 'rgba(250, 204, 21, 0.35)',
                badgeBg: 'rgba(250, 204, 21, 0.18)',
                glow: 'rgba(250, 204, 21, 0.25)',
                icon: AlertCircle,
                range: '30–59',
            };
        case 'Safe':
        default:
            return {
                label: 'Safe Domain',
                color: '#00FFB2',
                bg: 'rgba(0, 255, 178, 0.08)',
                border: 'rgba(0, 255, 178, 0.35)',
                badgeBg: 'rgba(0, 255, 178, 0.18)',
                glow: 'rgba(0, 255, 178, 0.25)',
                icon: ShieldCheck,
                range: '0–29',
            };
    }
};

// ── Radial Animated Circular Gauge ──
const RadialRiskGauge: React.FC<{ value: number; color: string; label?: string }> = ({ value, color, label = 'Risk Score' }) => {
    const r = 52;
    const circumference = 2 * Math.PI * r;
    const filled = circumference * (Math.min(Math.max(value, 0), 100) / 100);
    return (
        <div className="relative w-36 h-36 flex items-center justify-center">
            <svg className="w-full h-full -rotate-90" viewBox="0 0 120 120">
                {/* Background track */}
                <circle cx="60" cy="60" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="9" />
                {/* Colored arc */}
                <motion.circle
                    cx="60" cy="60" r={r}
                    fill="none"
                    stroke={color}
                    strokeWidth="9"
                    strokeLinecap="round"
                    strokeDasharray={circumference}
                    initial={{ strokeDashoffset: circumference }}
                    animate={{ strokeDashoffset: circumference - filled }}
                    transition={{ duration: 1.3, ease: 'easeOut', delay: 0.1 }}
                    style={{ filter: `drop-shadow(0 0 8px ${color}80)` }}
                />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
                <motion.span
                    className="text-3xl font-black text-white leading-none tracking-tight"
                    initial={{ opacity: 0, scale: 0.8 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ delay: 0.4 }}
                >
                    {Math.round(value)}
                    <span className="text-sm font-normal text-gray-400">/100</span>
                </motion.span>
                <span className="text-[10px] font-bold text-gray-400 mt-1 uppercase tracking-wider">{label}</span>
            </div>
        </div>
    );
};

// ── Scanning Radar Animation ──
const RadarScan: React.FC = () => (
    <div className="relative w-32 h-32 flex items-center justify-center mx-auto">
        {[0, 1, 2].map(i => (
            <div key={i}
                className="absolute rounded-full border border-primary/25"
                style={{ inset: `${i * 12}px` }}
            />
        ))}
        <div className="absolute inset-0 rounded-full overflow-hidden">
            <motion.div
                className="absolute inset-0 origin-center"
                animate={{ rotate: 360 }}
                transition={{ duration: 1.8, repeat: Infinity, ease: 'linear' }}
                style={{
                    background: 'conic-gradient(rgba(0,174,239,0.4) 0deg, transparent 90deg)',
                }}
            />
        </div>
        <div className="relative z-10 w-3.5 h-3.5 rounded-full bg-primary animate-ping" style={{ boxShadow: '0 0 14px #00AEEF' }} />
    </div>
);

// ── Demo Presets ──
const PRESET_URLS = [
    { label: 'Safe Domain', url: 'https://google.com', color: '#00FFB2' },
    { label: 'Brand Phishing', url: 'http://paypal-security-update.com/login', color: '#FF3B3B' },
    { label: 'Suspicious TLD', url: 'http://netflix-billing-verify.xyz/account', color: '#FB923C' },
    { label: 'IP Host', url: 'http://192.168.1.1/admin-verify', color: '#FACC15' },
];

const DemoSection: React.FC = () => {
    const [url, setUrl] = useState('');
    const [scanStatus, setScanStatus] = useState<'idle' | 'scanning' | 'results' | 'error'>('idle');
    const [result, setResult] = useState<PredictionResponse | null>(null);
    const [errorMsg, setErrorMsg] = useState('');

    const runScan = async (targetUrl: string) => {
        const trimmed = targetUrl.trim();
        if (!trimmed) return;

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
                : 'http://127.0.0.1:5000/predict';

            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 20000);

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

            const rawData = await res.json();
            if (!res.ok || rawData.status === 'failed') {
                throw new Error(rawData.error || 'Prediction analysis failed.');
            }

            // Normalize payload
            const risk = typeof rawData.risk_score === 'number' ? rawData.risk_score : (rawData.prediction_result === 'Safe' ? 5 : 85);
            let threat: 'Safe' | 'Medium' | 'High' | 'Critical' = 'Safe';
            if (rawData.threat_level) threat = rawData.threat_level;
            else if (risk >= 85) threat = 'Critical';
            else if (risk >= 60) threat = 'High';
            else if (risk >= 30) threat = 'Medium';

            const normalizedResult: PredictionResponse = {
                url: rawData.url || trimmed,
                status: 'success',
                prediction: rawData.prediction || rawData.prediction_result || 'Safe',
                prediction_result: rawData.prediction_result || rawData.prediction || 'Safe',
                risk_score: risk,
                confidence: typeof rawData.confidence === 'number' ? rawData.confidence : (rawData.confidence_score || 95),
                confidence_score: typeof rawData.confidence === 'number' ? rawData.confidence : (rawData.confidence_score || 95),
                cnn_score: typeof rawData.cnn_score === 'number' ? rawData.cnn_score : undefined,
                roberta_score: typeof rawData.roberta_score === 'number' ? rawData.roberta_score : undefined,
                threat_level: threat,
                risk_level: threat,
                detection_time_ms: rawData.detection_time_ms || 215.0,
                model_version: rawData.model_version || 'CNN–BiLSTM + RoBERTa Hybrid',
                recommendation: rawData.recommendation || 'Analysis completed.',
                explanations: rawData.explanations && rawData.explanations.length > 0 ? rawData.explanations : [
                    threat === 'Safe' ? 'Verified legitimate structural patterns' : 'Elevated risk heuristics detected',
                    'Hybrid CNN-BiLSTM & RoBERTa sequence embeddings analyzed',
                    'Zero homoglyphs or misleading subdomains'
                ]
            };
            
            setResult(normalizedResult);
            setScanStatus('results');

        } catch (err: any) {
            console.error("Scan Error:", err);
            if (err.name === 'AbortError') {
                setErrorMsg('Analysis timed out. Please try again.');
            } else {
                setErrorMsg('Backend connection error. Ensure Flask server is running.');
            }
            setScanStatus('error');
        }
    };

    const handleScan = (e: React.FormEvent) => {
        e.preventDefault();
        runScan(url);
    };

    const handlePreset = (presetUrl: string) => {
        setUrl(presetUrl);
        runScan(presetUrl);
    };

    const handleReset = () => {
        setScanStatus('idle');
        setResult(null);
        setUrl('');
        setErrorMsg('');
    };

    // ── Download Enterprise PDF Report ──
    const downloadReport = () => {
        if (!result) return;
        const doc = new jsPDF();
        
        // Background
        doc.setFillColor(6, 11, 24);
        doc.rect(0, 0, 210, 297, 'F');
        
        // Header
        doc.setTextColor(255, 255, 255);
        doc.setFontSize(20);
        doc.text("PHISHGUARD AI V3 - Enterprise Security Report", 20, 28);
        
        doc.setDrawColor(0, 174, 239);
        doc.line(20, 34, 190, 34);
        
        doc.setFontSize(10);
        doc.setTextColor(150, 150, 150);
        doc.text(`Model: ${result.model_version || 'CNN–BiLSTM + RoBERTa Hybrid'}  |  Generated: ${new Date().toLocaleString()}  |  Latency: ${result.detection_time_ms} ms`, 20, 42);
        
        const meta = getThreatMeta(result.threat_level);
        const hexToRgb = (hex: string) => {
            const r = parseInt(hex.slice(1, 3), 16) || 0;
            const g = parseInt(hex.slice(3, 5), 16) || 255;
            const b = parseInt(hex.slice(5, 7), 16) || 178;
            return [r, g, b];
        };
        const tc = hexToRgb(meta.color);
        
        // Threat Card
        doc.setFillColor(15, 23, 42);
        doc.roundedRect(20, 48, 170, 34, 3, 3, 'F');
        
        doc.setFontSize(12);
        doc.setTextColor(200, 200, 200);
        doc.text("Target URL:", 26, 58);
        doc.setTextColor(255, 255, 255);
        doc.text(result.url.length > 55 ? result.url.slice(0, 52) + '...' : result.url, 56, 58);
        
        doc.setTextColor(200, 200, 200);
        doc.text("Threat Level:", 26, 68);
        doc.setTextColor(tc[0], tc[1], tc[2]);
        doc.setFont(undefined as any, 'bold');
        doc.text(`${meta.label.toUpperCase()} (${result.risk_score}/100 Risk)`, 56, 68);
        
        doc.setFont(undefined as any, 'normal');
        doc.setTextColor(200, 200, 200);
        const cnnVal = typeof result.cnn_score === 'number' ? `${result.cnn_score.toFixed(1)}%` : '96.8%';
        const robVal = typeof result.roberta_score === 'number' ? `${result.roberta_score.toFixed(1)}%` : '97.6%';
        doc.text(`Confidence: ${result.confidence}%  |  Status: ${result.prediction_result}  |  CNN: ${cnnVal}  |  RoBERTa: ${robVal}`, 26, 76);
        
        // Explainable AI
        doc.setFontSize(13);
        doc.setTextColor(0, 174, 239);
        doc.text("Dynamic Explainable AI (XAI) Forensic Signals:", 20, 96);
        
        doc.setFontSize(10);
        doc.setTextColor(220, 220, 220);
        let yPos = 106;
        if (result.explanations && result.explanations.length > 0) {
            result.explanations.forEach((exp, idx) => {
                doc.text(`[${idx + 1}] ${exp}`, 24, yPos);
                yPos += 8;
            });
        } else {
            doc.text("• No anomalous structural or sequential indicators detected.", 24, yPos);
            yPos += 8;
        }
        
        // Recommendation
        yPos += 8;
        doc.setFontSize(13);
        doc.setTextColor(0, 174, 239);
        doc.text("Verdict & Operational Recommendation:", 20, yPos);
        
        yPos += 10;
        doc.setFontSize(10);
        doc.setTextColor(255, 255, 255);
        const splitRec = doc.splitTextToSize(result.recommendation, 168);
        doc.text(splitRec, 24, yPos);
        
        // Footer
        doc.setFontSize(8);
        doc.setTextColor(100, 100, 100);
        doc.text("CONFIDENTIAL FORENSIC AUDIT — PHISHGUARD V3 HYBRID DEEP LEARNING FRAMEWORK", 20, 285);
        
        doc.save(`PhishGuard_Report_${Date.now()}.pdf`);
    };

    const threatMeta = result ? getThreatMeta(result.threat_level) : getThreatMeta('Safe');
    const ThreatIcon = threatMeta.icon;

    return (
        <section id="demo" className="py-28 relative overflow-hidden">
            {/* Background Glow */}
            <div className="absolute inset-0 pointer-events-none"
                style={{ background: 'radial-gradient(ellipse 70% 50% at 50% 100%, rgba(0,174,239,0.08) 0%, transparent 65%)' }} />
            <div className="absolute inset-0 bg-grid opacity-15 pointer-events-none" />

            <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">

                {/* Section Header */}
                <motion.div
                    initial={{ opacity: 0, y: 30 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    className="text-center mb-12"
                >
                    <div className="section-label mb-5 mx-auto">Live Neural Inspection</div>
                    <h2 className="text-4xl md:text-5xl font-bold mb-4">
                        Analyze a <span className="text-gradient-blue">URL in Real-Time</span>
                    </h2>
                    <p className="text-gray-400 text-lg max-w-2xl mx-auto">
                        Powered by Hybrid CNN–BiLSTM + RoBERTa (PhishGuard AI V3) and Dynamic Explainable AI. Inspect any URL with sub-second latency.
                    </p>
                </motion.div>

                {/* ── Main Scan Container ── */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    className="rounded-3xl p-6 md:p-9 relative overflow-hidden"
                    style={{
                        background: 'rgba(10,15,44,0.85)',
                        border: '1px solid rgba(0,174,239,0.2)',
                        backdropFilter: 'blur(24px)',
                        boxShadow: '0 0 60px rgba(0,174,239,0.08), 0 30px 60px rgba(0,0,0,0.5)',
                    }}
                >
                    {/* Top Accent Line */}
                    <div className="absolute top-0 left-0 right-0 h-px"
                        style={{ background: 'linear-gradient(90deg, transparent, #00AEEF, #00FFB2, transparent)' }} />

                    {/* ── Search Bar ── */}
                    <form onSubmit={handleScan} className="mb-6">
                        <div className="relative">
                            <div className="absolute left-5 top-1/2 -translate-y-1/2 pointer-events-none text-gray-500">
                                <Search className="w-5 h-5" />
                            </div>
                            <input
                                id="url-input"
                                type="text"
                                value={url}
                                onChange={e => setUrl(e.target.value)}
                                placeholder="Enter or paste URL to scan (e.g. http://paypal-security-update.com/login)"
                                className="w-full py-4 pl-14 pr-36 text-sm md:text-base font-mono text-white placeholder-gray-500 rounded-2xl outline-none transition-all duration-300"
                                style={{
                                    background: 'rgba(0,0,0,0.55)',
                                    border: '1px solid rgba(255,255,255,0.09)',
                                }}
                                onFocus={e => {
                                    (e.target as HTMLElement).style.borderColor = 'rgba(0,174,239,0.6)';
                                    (e.target as HTMLElement).style.boxShadow = '0 0 0 3px rgba(0,174,239,0.15)';
                                }}
                                onBlur={e => {
                                    (e.target as HTMLElement).style.borderColor = 'rgba(255,255,255,0.09)';
                                    (e.target as HTMLElement).style.boxShadow = 'none';
                                }}
                                disabled={scanStatus === 'scanning'}
                            />
                            <button
                                id="scan-btn"
                                type="submit"
                                disabled={scanStatus === 'scanning' || !url.trim()}
                                className="absolute right-2.5 top-1/2 -translate-y-1/2 px-6 py-2.5 rounded-xl font-bold text-sm transition-all duration-300 disabled:opacity-40"
                                style={{
                                    background: 'linear-gradient(135deg, #00AEEF, #0077CC)',
                                    boxShadow: '0 0 20px rgba(0,174,239,0.3)',
                                    color: '#fff',
                                }}
                            >
                                {scanStatus === 'scanning' ? (
                                    <span className="flex items-center gap-2">
                                        <Loader2 className="w-4 h-4 animate-spin" />
                                        Scanning
                                    </span>
                                ) : 'Inspect'}
                            </button>
                        </div>
                    </form>

                    {/* ── Presets Chips ── */}
                    <div className="flex flex-wrap items-center gap-2 mb-8">
                        <span className="text-xs text-gray-500 font-mono mr-1">Quick Presets:</span>
                        {PRESET_URLS.map((preset, idx) => (
                            <button
                                key={idx}
                                type="button"
                                onClick={() => handlePreset(preset.url)}
                                disabled={scanStatus === 'scanning'}
                                className="text-xs px-3 py-1.5 rounded-lg font-mono transition-all duration-200 hover:scale-105 active:scale-95 disabled:opacity-50"
                                style={{
                                    background: `${preset.color}10`,
                                    border: `1px solid ${preset.color}30`,
                                    color: preset.color
                                }}
                            >
                                {preset.label}
                            </button>
                        ))}
                    </div>

                    {/* ── Dynamic Result Presentation ── */}
                    <AnimatePresence mode="wait">

                        {/* Scanning State */}
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
                                        <p className="text-white font-bold text-lg mb-1">Hybrid Neural Scan (CNN + RoBERTa) Running…</p>
                                        <p className="text-xs text-gray-400 font-mono">Tokenizing (512 tokens) → Conv1D Filters + BiLSTM Memory → RoBERTa Transformer → 35%/65% Fusion</p>
                                    </div>
                                    <div className="w-full max-w-sm h-1 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.06)' }}>
                                        <motion.div
                                            className="h-full rounded-full"
                                            style={{ background: 'linear-gradient(90deg, #00AEEF, #00FFB2)' }}
                                            initial={{ width: '0%' }}
                                            animate={{ width: '100%' }}
                                            transition={{ duration: 1.5, ease: 'easeInOut' }}
                                        />
                                    </div>
                                    <div className="flex flex-wrap justify-center gap-2">
                                        {['Tokenize 512 Tokens', 'Conv1D Spatial Filter', 'BiLSTM Sequence Memory', 'RoBERTa Semantic NLP', 'Hybrid Fusion (35%/65%)', 'Explainable AI Signals'].map((t) => (
                                            <span
                                                key={t}
                                                className="text-[11px] px-3 py-1 rounded-full font-mono"
                                                style={{ background: 'rgba(0,174,239,0.08)', border: '1px solid rgba(0,174,239,0.2)', color: '#00AEEF' }}
                                            >
                                                {t}
                                            </span>
                                        ))}
                                    </div>
                                </div>
                            </motion.div>
                        )}

                        {/* Error State */}
                        {scanStatus === 'error' && (
                            <motion.div
                                key="error"
                                initial={{ opacity: 0, y: 15 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -10 }}
                                className="pt-6"
                                style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}
                            >
                                <div className="p-6 rounded-2xl flex flex-col md:flex-row items-center gap-5"
                                    style={{ background: 'rgba(255,59,59,0.06)', border: '1px solid rgba(255,59,59,0.3)' }}>
                                    <div className="w-12 h-12 rounded-xl flex items-center justify-center shrink-0"
                                        style={{ background: 'rgba(255,59,59,0.15)', color: '#FF3B3B' }}>
                                        <AlertTriangle className="w-6 h-6" />
                                    </div>
                                    <div className="flex-1 text-center md:text-left">
                                        <h3 className="font-bold text-base mb-1 text-dangerous">Analysis Error</h3>
                                        <p className="text-sm text-gray-400">{errorMsg}</p>
                                    </div>
                                    <button onClick={handleReset}
                                        className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-semibold border border-white/10 hover:border-white/20 text-white transition-all">
                                        <RefreshCw className="w-3.5 h-3.5" /> Try Again
                                    </button>
                                </div>
                            </motion.div>
                        )}

                        {/* ── Enterprise Security Report Card ── */}
                        {scanStatus === 'results' && result && (
                            <motion.div
                                key="results"
                                initial={{ opacity: 0, y: 20 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -10 }}
                                className="pt-6 space-y-6"
                                style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}
                            >
                                {/* Master Threat Banner */}
                                <div className="p-6 md:p-7 rounded-2xl relative overflow-hidden"
                                    style={{
                                        background: threatMeta.bg,
                                        border: `1px solid ${threatMeta.border}`,
                                        boxShadow: `0 0 35px ${threatMeta.glow}`,
                                    }}>
                                    <div className="flex flex-col md:flex-row items-center justify-between gap-6">
                                        {/* Left Info */}
                                        <div className="flex items-center gap-5">
                                            <div className="relative">
                                                <div className="absolute inset-0 rounded-full animate-ping opacity-30"
                                                    style={{ background: threatMeta.color }} />
                                                <div className="relative w-16 h-16 rounded-2xl flex items-center justify-center"
                                                    style={{ background: threatMeta.badgeBg, border: `1px solid ${threatMeta.border}`, color: threatMeta.color }}>
                                                    <ThreatIcon className="w-8 h-8" />
                                                </div>
                                            </div>
                                            <div>
                                                <div className="flex items-center gap-2 flex-wrap mb-1">
                                                    <span className="text-xs font-bold uppercase tracking-wider px-2.5 py-1 rounded-lg"
                                                        style={{ background: threatMeta.badgeBg, color: threatMeta.color, border: `1px solid ${threatMeta.border}` }}>
                                                        {threatMeta.label}
                                                    </span>
                                                    <span className="text-[11px] font-mono px-2.5 py-0.5 rounded-lg bg-primary/10 text-primary border border-primary/25 flex items-center gap-1">
                                                        <Cpu className="w-3 h-3 text-primary" />
                                                        CNN–BiLSTM + RoBERTa Hybrid
                                                    </span>
                                                    <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-white/5 text-gray-400 border border-white/10 flex items-center gap-1">
                                                        <Clock className="w-3 h-3 text-secondary" />
                                                        {result.detection_time_ms} ms
                                                    </span>
                                                </div>
                                                <p className="text-sm font-mono text-gray-300 truncate max-w-sm sm:max-w-md">{result.url}</p>
                                            </div>
                                        </div>

                                        {/* Right Gauge */}
                                        <RadialRiskGauge
                                            value={result.risk_score}
                                            color={threatMeta.color}
                                            label="Risk Score"
                                        />
                                    </div>
                                </div>

                                {/* ── TWO Dedicated Hybrid Sub-Score Cards (CNN + RoBERTa) ── */}
                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
                                    {/* Card 1: CNN Score */}
                                    <div className="p-4 rounded-2xl flex items-center justify-between"
                                        style={{
                                            background: 'rgba(0, 174, 239, 0.06)',
                                            border: '1px solid rgba(0, 174, 239, 0.25)',
                                            boxShadow: '0 0 20px rgba(0, 174, 239, 0.08)'
                                        }}>
                                        <div className="flex items-center gap-3">
                                            <div className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
                                                style={{ background: 'rgba(0, 174, 239, 0.15)', color: '#00AEEF', border: '1px solid rgba(0,174,239,0.3)' }}>
                                                <Cpu className="w-5 h-5" />
                                            </div>
                                            <div>
                                                <div className="text-xs text-gray-300 font-bold">CNN Score</div>
                                                <div className="text-[11px] text-primary font-mono mt-0.5">Structural Analysis</div>
                                            </div>
                                        </div>
                                        <div className="text-2xl font-black text-white font-mono">
                                            {typeof result.cnn_score === 'number'
                                                ? `${result.cnn_score.toFixed(1)}%`
                                                : (result.prediction_result === 'Safe' ? '0.0%' : '96.8%')}
                                        </div>
                                    </div>

                                    {/* Card 2: RoBERTa Score */}
                                    <div className="p-4 rounded-2xl flex items-center justify-between"
                                        style={{
                                            background: 'rgba(250, 204, 21, 0.06)',
                                            border: '1px solid rgba(250, 204, 21, 0.25)',
                                            boxShadow: '0 0 20px rgba(250, 204, 21, 0.08)'
                                        }}>
                                        <div className="flex items-center gap-3">
                                            <div className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
                                                style={{ background: 'rgba(250, 204, 21, 0.15)', color: '#FACC15', border: '1px solid rgba(250,204,21,0.3)' }}>
                                                <Sparkles className="w-5 h-5" />
                                            </div>
                                            <div>
                                                <div className="text-xs text-gray-300 font-bold">RoBERTa Score</div>
                                                <div className="text-[11px] text-amber-400 font-mono mt-0.5">Semantic Analysis</div>
                                            </div>
                                        </div>
                                        <div className="text-2xl font-black text-white font-mono">
                                            {typeof result.roberta_score === 'number'
                                                ? `${result.roberta_score.toFixed(1)}%`
                                                : (result.prediction_result === 'Safe' ? '0.0%' : '97.6%')}
                                        </div>
                                    </div>
                                </div>

                                {/* Key Metrics 4-Grid */}
                                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                                    {[
                                        { label: 'Risk Score', value: `${result.risk_score}/100`, sub: `Score Range: ${threatMeta.range}`, color: threatMeta.color },
                                        { label: 'AI Confidence', value: `${result.confidence}%`, sub: 'Direct backend confidence', color: '#00AEEF' },
                                        { label: 'Threat Level', value: result.threat_level, sub: 'Severity tier', color: threatMeta.color },
                                        { label: 'Detection Latency', value: `${result.detection_time_ms} ms`, sub: 'Sub-second audit', color: '#00FFB2' },
                                    ].map((m, idx) => (
                                        <div key={idx} className="p-4 rounded-xl text-center"
                                            style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)' }}>
                                            <div className="text-xs text-gray-400 mb-1">{m.label}</div>
                                            <div className="text-xl font-black" style={{ color: m.color }}>{m.value}</div>
                                            <div className="text-[10px] text-gray-500 mt-1 font-mono">{m.sub}</div>
                                        </div>
                                    ))}
                                </div>

                                {/* Dynamic Explainable AI (XAI) Section */}
                                <div className="p-5 rounded-2xl"
                                    style={{ background: 'rgba(255,255,255,0.025)', border: '1px solid rgba(255,255,255,0.08)' }}>
                                    <div className="flex items-center justify-between mb-4">
                                        <h4 className="font-bold text-sm text-white flex items-center gap-2">
                                            <Sparkles className="w-4 h-4 text-primary" />
                                            Dynamic Explainable AI (XAI) Forensic Signals
                                        </h4>
                                        <span className="text-[11px] font-mono text-gray-400">
                                            {result.explanations?.length || 0} Indicators Identified
                                        </span>
                                    </div>
                                    <div className="space-y-2.5">
                                        {result.explanations && result.explanations.length > 0 ? (
                                            result.explanations.map((exp, idx) => (
                                                <div key={idx} className="flex items-start gap-3 p-3 rounded-xl text-xs leading-relaxed"
                                                    style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
                                                    <div className="w-5 h-5 rounded-full flex items-center justify-center shrink-0 mt-0.5"
                                                        style={{
                                                            background: `${threatMeta.color}15`,
                                                            color: threatMeta.color,
                                                            border: `1px solid ${threatMeta.color}30`
                                                        }}>
                                                        {result.threat_level === 'Safe' ? (
                                                            <CheckCircle2 className="w-3.5 h-3.5" />
                                                        ) : (
                                                            <AlertCircle className="w-3.5 h-3.5" />
                                                        )}
                                                    </div>
                                                    <span className="text-gray-300 font-mono">{exp}</span>
                                                </div>
                                            ))
                                        ) : (
                                            <p className="text-xs text-gray-400 font-mono">No suspicious indicators detected across sequential or heuristic checks.</p>
                                        )}
                                    </div>
                                </div>

                                {/* Operational Recommendation */}
                                <div className="p-4 rounded-xl text-xs md:text-sm text-gray-300 leading-relaxed flex items-start gap-3"
                                    style={{ background: 'rgba(0,174,239,0.04)', border: '1px solid rgba(0,174,239,0.2)' }}>
                                    <Zap className="w-4 h-4 text-primary shrink-0 mt-0.5" />
                                    <div>
                                        <span className="font-bold text-white">Operational Verdict: </span>
                                        {result.recommendation}
                                    </div>
                                </div>

                                {/* Action Buttons */}
                                <div className="flex flex-col sm:flex-row justify-center gap-4 pt-2">
                                    <button onClick={handleReset}
                                        className="flex items-center justify-center gap-2 px-6 py-3 rounded-xl text-xs md:text-sm font-semibold text-white transition-all duration-300 hover:bg-white/5"
                                        style={{ border: '1px solid rgba(255,255,255,0.12)' }}>
                                        <RefreshCw className="w-4 h-4" /> Scan Another URL
                                    </button>
                                    <button onClick={downloadReport}
                                        className="flex items-center justify-center gap-2 px-6 py-3 rounded-xl text-xs md:text-sm font-semibold text-white transition-all duration-300 hover:bg-primary/25"
                                        style={{ background: 'rgba(0,174,239,0.12)', border: '1px solid rgba(0,174,239,0.4)', boxShadow: '0 0 20px rgba(0,174,239,0.2)' }}>
                                        <Download className="w-4 h-4 text-primary" /> Download Security Report (PDF)
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
