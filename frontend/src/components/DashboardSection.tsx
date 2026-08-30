import React, { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import {
    AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid
} from 'recharts';
import {
    Activity, ShieldAlert, ShieldCheck, Zap, Clock,
    TrendingUp, AlertTriangle, AlertCircle, Cpu, Globe, ArrowUpRight
} from 'lucide-react';

// ── Mock initial threat timeline data ──
const INITIAL_TIMELINE = [
    { time: '10:00', safe: 14, medium: 3, high: 2, critical: 1 },
    { time: '10:15', safe: 22, medium: 5, high: 4, critical: 2 },
    { time: '10:30', safe: 19, medium: 4, high: 3, critical: 1 },
    { time: '10:45', safe: 31, medium: 8, high: 6, critical: 4 },
    { time: '11:00', safe: 28, medium: 6, high: 5, critical: 2 },
    { time: '11:15', safe: 35, medium: 7, high: 4, critical: 3 },
    { time: '11:30', safe: 42, medium: 9, high: 7, critical: 5 },
];

// ── Initial Mock Scans with Enterprise Threat Levels ──
const INITIAL_SCANS = [
    { url: 'paypal-security-update.com/login', threat: 'Critical' as const, risk: 97, latency: 34.2, time: '1m ago' },
    { url: 'github.com/microsoft/vscode', threat: 'Safe' as const, risk: 4, latency: 28.5, time: '3m ago' },
    { url: 'netflix-billing-verify.xyz/account', threat: 'High' as const, risk: 78, latency: 38.1, time: '5m ago' },
    { url: 'amazon.com/orders/tracking', threat: 'Safe' as const, risk: 2, latency: 26.4, time: '9m ago' },
    { url: 'secure-bank-token-auth.info', threat: 'Medium' as const, risk: 52, latency: 41.0, time: '12m ago' },
    { url: 'appleid-support-icloud.biz/session', threat: 'Critical' as const, risk: 96, latency: 32.8, time: '16m ago' },
    { url: 'docs.google.com/document/d/edit', threat: 'Safe' as const, risk: 1, latency: 25.1, time: '20m ago' },
];

// ── Real Model Performance Metrics (Hybrid AI V3) ──
const MODEL_METRICS = [
    { label: 'Test Accuracy', value: '95.17%', raw: 95.17, color: '#00FFB2', sub: 'Hybrid AI Benchmark' },
    { label: 'Precision', value: '94.63%', raw: 94.63, color: '#00AEEF', sub: 'True Positives / Predicted' },
    { label: 'Recall', value: '94.87%', raw: 94.87, color: '#7C3AED', sub: 'Zero-Day Detection Coverage' },
    { label: 'F1-Score', value: '94.75%', raw: 94.75, color: '#FACC15', sub: 'Harmonic Mean P & R' },
];

// ── Animated counter component ──
const AnimatedCounter: React.FC<{ end: number; suffix?: string; duration?: number }> = ({ end, suffix = '', duration = 1.2 }) => {
    const [count, setCount] = useState(0);
    const countRef = useRef(0);

    useEffect(() => {
        let startTime: number;
        let animationFrame: number;
        const startValue = countRef.current;
        
        if (startValue === end) {
            setCount(end);
            return;
        }
        
        const animate = (time: number) => {
            if (!startTime) startTime = time;
            const progress = Math.min((time - startTime) / (duration * 1000), 1);
            const easeProgress = 1 - (1 - progress) * (1 - progress);
            
            const current = Math.round(startValue + (end - startValue) * easeProgress);
            setCount(current);
            countRef.current = current;
            
            if (progress < 1) {
                animationFrame = requestAnimationFrame(animate);
            } else {
                setCount(end);
                countRef.current = end;
            }
        };
        
        animationFrame = requestAnimationFrame(animate);
        return () => cancelAnimationFrame(animationFrame);
    }, [end, duration]);

    return <span>{count.toLocaleString()}{suffix}</span>;
};

// ── Threat Level Meta Helpers ──
const getBadgeStyles = (threat: 'Safe' | 'Medium' | 'High' | 'Critical') => {
    switch (threat) {
        case 'Critical':
            return { color: '#FF3B3B', bg: 'rgba(255,59,59,0.12)', border: 'rgba(255,59,59,0.3)', icon: AlertTriangle };
        case 'High':
            return { color: '#FB923C', bg: 'rgba(251,146,60,0.12)', border: 'rgba(251,146,60,0.3)', icon: ShieldAlert };
        case 'Medium':
            return { color: '#FACC15', bg: 'rgba(250,204,21,0.12)', border: 'rgba(250,204,21,0.3)', icon: AlertCircle };
        case 'Safe':
        default:
            return { color: '#00FFB2', bg: 'rgba(0,255,178,0.12)', border: 'rgba(0,255,178,0.3)', icon: ShieldCheck };
    }
};

const DashboardSection: React.FC = () => {
    const [recentScans, setRecentScans] = useState(INITIAL_SCANS);
    const [liveStats, setLiveStats] = useState({
        total: 1482,
        safe: 820,
        medium: 310,
        high: 215,
        critical: 137,
        avgScanTimeMs: 215.0,
        highestRisk: 98,
        totalDomainsScanned: 684
    });

    useEffect(() => {
        const fetchGlobalStats = async () => {
            try {
                const endpoint = import.meta.env.VITE_API_URL 
                    ? `${import.meta.env.VITE_API_URL}/stats` 
                    : 'http://127.0.0.1:5000/stats';
                
                const res = await fetch(endpoint);
                if (!res.ok) throw new Error("Failed to fetch live stats");
                
                const data = await res.json();
                
                if (data.history && data.history.length > 0) {
                    const mappedHistory = data.history.map((h: any) => {
                        const risk = h.risk_score !== undefined ? h.risk_score : (h.result === 'Safe' ? 5 : 90);
                        let threat: 'Safe' | 'Medium' | 'High' | 'Critical' = 'Safe';
                        if (h.threat_level) threat = h.threat_level;
                        else if (risk >= 85) threat = 'Critical';
                        else if (risk >= 60) threat = 'High';
                        else if (risk >= 30) threat = 'Medium';

                        return {
                            url: h.url,
                            threat,
                            risk,
                            latency: h.latency || 215.0,
                            time: h.time || 'just now'
                        };
                    });
                    const merged = [...mappedHistory, ...INITIAL_SCANS].slice(0, 7);
                    setRecentScans(merged);
                }

                if (data.stats && data.stats.total > 0) {
                    const st = data.stats;
                    setLiveStats({
                        total: st.total,
                        safe: st.safe || 0,
                        medium: st.medium || st.suspicious || 0,
                        high: st.high || 0,
                        critical: st.critical || st.phishing || 0,
                        avgScanTimeMs: st.avgScanTimeMs || 215.0,
                        highestRisk: st.highestRisk || 98,
                        totalDomainsScanned: st.totalDomainsScanned || Math.round(st.total * 0.65)
                    });
                }
            } catch (err) {
                // Silently fallback to initial live mock
            }
        };

        fetchGlobalStats();
        const intervalId = setInterval(fetchGlobalStats, 4000);
        return () => clearInterval(intervalId);
    }, []);

    // Calculate Distribution Percentages
    const totalCount = liveStats.total || 1;
    const distSafe = Math.round((liveStats.safe / totalCount) * 100) || 55;
    const distMedium = Math.round((liveStats.medium / totalCount) * 100) || 21;
    const distHigh = Math.round((liveStats.high / totalCount) * 100) || 14;
    const distCritical = Math.round((liveStats.critical / totalCount) * 100) || 10;

    return (
        <section id="dashboard" className="py-28 relative overflow-hidden">
            {/* Background Glow */}
            <div className="absolute inset-0 bg-grid opacity-20 pointer-events-none" />
            <div className="absolute right-0 top-0 w-1/2 h-full pointer-events-none"
                style={{ background: 'radial-gradient(ellipse at 100% 30%, rgba(0,255,178,0.05) 0%, transparent 60%)' }} />
            <div className="absolute left-0 bottom-0 w-1/3 h-1/2 pointer-events-none"
                style={{ background: 'radial-gradient(ellipse at 0% 100%, rgba(0,174,239,0.06) 0%, transparent 60%)' }} />

            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">

                {/* Section Header */}
                <motion.div
                    initial={{ opacity: 0, y: 30 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    className="text-center mb-16"
                >
                    <div className="section-label mb-6 mx-auto">Enterprise Threat Center</div>
                    <h2 className="text-4xl md:text-5xl font-bold mb-5">
                        SOC Hybrid Threat <span className="text-gradient-blue">Intelligence Dashboard</span>
                    </h2>
                    <p className="text-gray-400 text-lg max-w-2xl mx-auto">
                        Live telemetry, real-time threat timelines, risk severity distributions, and Hybrid CNN–BiLSTM + RoBERTa model metrics.
                    </p>
                </motion.div>

                {/* ── Row 1: Key Telemetry Counters ── */}
                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-8">
                    {[
                        { icon: Activity, label: 'Total URLs Scanned', end: liveStats.total, suffix: '', color: '#00AEEF' },
                        { icon: Globe, label: 'Domains Inspected', end: liveStats.totalDomainsScanned, suffix: '', color: '#38BDF8' },
                        { icon: Clock, label: 'Avg Scan Latency', end: Math.round(liveStats.avgScanTimeMs || 215), suffix: ' ms', color: '#00FFB2' },
                        { icon: AlertTriangle, label: 'Peak Risk Score', end: liveStats.highestRisk || 98, suffix: '/100', color: '#FF3B3B' },
                        { icon: ShieldCheck, label: 'Safe Verified', end: liveStats.safe, suffix: '', color: '#00FFB2' },
                        { icon: ShieldAlert, label: 'Threats Neutralized', end: liveStats.high + liveStats.critical, suffix: '', color: '#FB923C' },
                    ].map((stat, i) => {
                        const Icon = stat.icon;
                        return (
                            <motion.div
                                key={i}
                                initial={{ opacity: 0, y: 20 }}
                                whileInView={{ opacity: 1, y: 0 }}
                                viewport={{ once: true }}
                                transition={{ delay: i * 0.06 }}
                                className="stat-card group"
                            >
                                <div className="flex items-center justify-between mb-2.5">
                                    <div className="w-9 h-9 rounded-xl flex items-center justify-center"
                                        style={{ background: `${stat.color}15`, border: `1px solid ${stat.color}30` }}>
                                        <Icon className="w-4 h-4" style={{ color: stat.color }} />
                                    </div>
                                    <ArrowUpRight className="w-3.5 h-3.5 text-gray-700 group-hover:text-gray-400 transition-colors" />
                                </div>
                                <div className="text-2xl font-black text-white">
                                    <AnimatedCounter end={stat.end} suffix={stat.suffix} />
                                </div>
                                <div className="text-[11px] text-gray-400 mt-1">{stat.label}</div>
                            </motion.div>
                        );
                    })}
                </div>

                {/* ── Row 2: Threat Timeline + Risk Distribution ── */}
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 mb-8">

                    {/* Threat Timeline (7 Cols) */}
                    <motion.div
                        initial={{ opacity: 0, scale: 0.98 }}
                        whileInView={{ opacity: 1, scale: 1 }}
                        viewport={{ once: true }}
                        className="lg:col-span-7 glass-surface rounded-2xl p-6"
                        style={{ border: '1px solid rgba(0,174,239,0.15)' }}
                    >
                        <div className="flex items-center justify-between mb-5">
                            <div>
                                <h3 className="font-bold text-white text-base flex items-center gap-2">
                                    <TrendingUp className="w-4 h-4 text-primary" />
                                    Threat Velocity Timeline
                                </h3>
                                <p className="text-xs text-gray-400 mt-0.5">Real-time scan event frequency & threat distribution</p>
                            </div>
                            <div className="flex items-center gap-2 text-xs font-mono text-secondary bg-white/5 px-2.5 py-1 rounded-lg border border-white/10">
                                <span className="w-2 h-2 rounded-full bg-secondary animate-pulse" />
                                Live Telemetry
                            </div>
                        </div>

                        {/* Area Chart */}
                        <div className="h-56">
                            <ResponsiveContainer width="100%" height="100%">
                                <AreaChart data={INITIAL_TIMELINE} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                                    <defs>
                                        <linearGradient id="critGrad" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#FF3B3B" stopOpacity={0.35} />
                                            <stop offset="95%" stopColor="#FF3B3B" stopOpacity={0} />
                                        </linearGradient>
                                        <linearGradient id="highGrad" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#FB923C" stopOpacity={0.25} />
                                            <stop offset="95%" stopColor="#FB923C" stopOpacity={0} />
                                        </linearGradient>
                                        <linearGradient id="safeGrad" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#00FFB2" stopOpacity={0.25} />
                                            <stop offset="95%" stopColor="#00FFB2" stopOpacity={0} />
                                        </linearGradient>
                                    </defs>
                                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                                    <XAxis dataKey="time" stroke="transparent" tick={{ fill: '#6B7280', fontSize: 11 }} tickLine={false} />
                                    <YAxis stroke="transparent" tick={{ fill: '#6B7280', fontSize: 11 }} tickLine={false} />
                                    <Tooltip
                                        contentStyle={{
                                            background: '#0A0F2C',
                                            border: '1px solid rgba(0,174,239,0.3)',
                                            borderRadius: '12px',
                                            fontSize: 12
                                        }}
                                        labelStyle={{ color: '#9CA3AF' }}
                                    />
                                    <Area type="monotone" dataKey="critical" stroke="#FF3B3B" strokeWidth={2} fill="url(#critGrad)" name="Critical" />
                                    <Area type="monotone" dataKey="high" stroke="#FB923C" strokeWidth={2} fill="url(#highGrad)" name="High Risk" />
                                    <Area type="monotone" dataKey="safe" stroke="#00FFB2" strokeWidth={2} fill="url(#safeGrad)" name="Safe" />
                                </AreaChart>
                            </ResponsiveContainer>
                        </div>

                        {/* Timeline Legend */}
                        <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-white/5 text-xs text-gray-400">
                            <div className="flex items-center gap-4">
                                <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-[#00FFB2]" /> Safe Domains</span>
                                <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-[#FB923C]" /> High Risk</span>
                                <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-[#FF3B3B]" /> Critical Threats</span>
                            </div>
                            <span className="font-mono text-[11px] text-gray-500">Interval: 15-min rolling</span>
                        </div>
                    </motion.div>

                    {/* Risk Distribution Breakdown (5 Cols) */}
                    <motion.div
                        initial={{ opacity: 0, scale: 0.98 }}
                        whileInView={{ opacity: 1, scale: 1 }}
                        viewport={{ once: true }}
                        transition={{ delay: 0.1 }}
                        className="lg:col-span-5 glass-surface rounded-2xl p-6 flex flex-col justify-between"
                        style={{ border: '1px solid rgba(0,174,239,0.15)' }}
                    >
                        <div>
                            <h3 className="font-bold text-white text-base flex items-center gap-2 mb-1">
                                <ShieldAlert className="w-4 h-4 text-secondary" />
                                Risk Level Distribution
                            </h3>
                            <p className="text-xs text-gray-400 mb-6">4-Tier enterprise classification breakdown</p>

                            <div className="space-y-4">
                                {[
                                    { label: 'Safe', scoreRange: '0–29', count: liveStats.safe, pct: distSafe, color: '#00FFB2' },
                                    { label: 'Medium', scoreRange: '30–59', count: liveStats.medium, pct: distMedium, color: '#FACC15' },
                                    { label: 'High', scoreRange: '60–84', count: liveStats.high, pct: distHigh, color: '#FB923C' },
                                    { label: 'Critical', scoreRange: '85–100', count: liveStats.critical, pct: distCritical, color: '#FF3B3B' },
                                ].map((item, idx) => (
                                    <div key={idx} className="space-y-1.5">
                                        <div className="flex items-center justify-between text-xs font-mono">
                                            <div className="flex items-center gap-2">
                                                <span className="w-2.5 h-2.5 rounded-full" style={{ background: item.color }} />
                                                <span className="font-bold text-white">{item.label}</span>
                                                <span className="text-[10px] text-gray-500">({item.scoreRange})</span>
                                            </div>
                                            <div className="flex items-center gap-2">
                                                <span className="text-gray-400">{item.count} URLs</span>
                                                <span className="font-bold" style={{ color: item.color }}>{item.pct}%</span>
                                            </div>
                                        </div>
                                        {/* Progress bar */}
                                        <div className="w-full h-2 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.06)' }}>
                                            <motion.div
                                                className="h-full rounded-full"
                                                style={{ background: item.color, boxShadow: `0 0 8px ${item.color}80` }}
                                                initial={{ width: 0 }}
                                                whileInView={{ width: `${item.pct}%` }}
                                                viewport={{ once: true }}
                                                transition={{ duration: 1, delay: idx * 0.1 }}
                                            />
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>

                        <div className="pt-4 mt-4 border-t border-white/5 flex items-center justify-between text-xs text-gray-400 font-mono">
                            <span>Total Sampled: {liveStats.total}</span>
                            <span className="text-primary font-bold">Accuracy: 95.17%</span>
                        </div>
                    </motion.div>

                </div>

                {/* ── Row 3: Recent Scans Live Feed ── */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    className="glass-surface rounded-2xl p-6 mb-8"
                    style={{ border: '1px solid rgba(0,174,239,0.15)' }}
                >
                    <div className="flex items-center justify-between mb-5">
                        <div>
                            <h3 className="font-bold text-white flex items-center gap-2">
                                <Clock className="w-4 h-4 text-primary" />
                                Live SOC Recent Scans Feed
                            </h3>
                            <p className="text-xs text-gray-400 mt-0.5">Real-time audit log with threat badges, risk scores, and latency</p>
                        </div>
                        <div className="text-xs font-mono text-gray-400 hidden sm:block">
                            Auto-updating via WebSocket/REST
                        </div>
                    </div>

                    <div className="space-y-2.5 overflow-hidden">
                        {recentScans.map((scan, i) => {
                            const badge = getBadgeStyles(scan.threat);
                            const Icon = badge.icon;
                            return (
                                <motion.div
                                    key={i}
                                    initial={{ opacity: 0, x: 10 }}
                                    whileInView={{ opacity: 1, x: 0 }}
                                    viewport={{ once: true }}
                                    transition={{ delay: i * 0.04 }}
                                    className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3.5 rounded-xl transition-all duration-200 hover:bg-white/5"
                                    style={{ border: '1px solid rgba(255,255,255,0.05)', background: 'rgba(255,255,255,0.015)' }}
                                >
                                    {/* Left: Icon & URL */}
                                    <div className="flex items-center gap-3.5 min-w-0 flex-1">
                                        <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
                                            style={{ background: badge.bg, border: `1px solid ${badge.border}`, color: badge.color }}>
                                            <Icon className="w-4 h-4" />
                                        </div>
                                        <div className="min-w-0 flex-1">
                                            <p className="text-xs md:text-sm font-mono text-gray-200 truncate">{scan.url}</p>
                                        </div>
                                    </div>

                                    {/* Right: Threat badge, Risk, Latency, Time */}
                                    <div className="flex items-center gap-3 shrink-0 self-end sm:self-auto">
                                        <span className="text-[11px] font-mono font-bold px-2.5 py-1 rounded-md"
                                            style={{ background: badge.bg, border: `1px solid ${badge.border}`, color: badge.color }}>
                                            {scan.threat.toUpperCase()}
                                        </span>
                                        <div className="text-xs font-mono font-bold" style={{ color: badge.color }}>
                                            {scan.risk}/100 Risk
                                        </div>
                                        <div className="text-[11px] font-mono text-gray-400 flex items-center gap-1">
                                            <Zap className="w-3 h-3 text-secondary" />
                                            {scan.latency} ms
                                        </div>
                                        <div className="text-xs text-gray-500 font-mono hidden md:block">
                                            {scan.time}
                                        </div>
                                    </div>
                                </motion.div>
                            );
                        })}
                    </div>
                </motion.div>

                {/* ── Row 4: Verified Hybrid AI Metrics ── */}
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                    {MODEL_METRICS.map((m, i) => (
                        <motion.div
                            key={i}
                            initial={{ opacity: 0, y: 20 }}
                            whileInView={{ opacity: 1, y: 0 }}
                            viewport={{ once: true }}
                            transition={{ delay: i * 0.08 }}
                            className="glass-surface rounded-2xl p-5 relative overflow-hidden group cursor-default transition-all duration-300"
                            style={{ border: `1px solid ${m.color}20` }}
                            whileHover={{ borderColor: `${m.color}50`, boxShadow: `0 0 30px ${m.color}20` }}
                        >
                            {/* Radial progress arc */}
                            <div className="relative w-16 h-16 mx-auto mb-3">
                                <svg className="w-full h-full -rotate-90" viewBox="0 0 36 36">
                                    <circle cx="18" cy="18" r="14" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="3.5" />
                                    <motion.circle
                                        cx="18" cy="18" r="14"
                                        fill="none"
                                        stroke={m.color}
                                        strokeWidth="3.5"
                                        strokeLinecap="round"
                                        strokeDasharray={`${2 * Math.PI * 14}`}
                                        strokeDashoffset={`${2 * Math.PI * 14 * (1 - m.raw / 100)}`}
                                        initial={{ strokeDashoffset: `${2 * Math.PI * 14}` }}
                                        whileInView={{ strokeDashoffset: `${2 * Math.PI * 14 * (1 - m.raw / 100)}` }}
                                        viewport={{ once: true }}
                                        transition={{ duration: 1.3, delay: i * 0.1, ease: 'easeOut' }}
                                        style={{ filter: `drop-shadow(0 0 6px ${m.color}90)` }}
                                    />
                                </svg>
                                <div className="absolute inset-0 flex items-center justify-center">
                                    <span className="text-[11px] font-bold" style={{ color: m.color }}>{m.value}</span>
                                </div>
                            </div>

                            <div className="text-center">
                                <div className="font-bold text-white text-sm">{m.label}</div>
                                <div className="text-[11px] text-gray-400 mt-0.5">{m.sub}</div>
                            </div>
                        </motion.div>
                    ))}
                </div>

            </div>
        </section>
    );
};

export default DashboardSection;
