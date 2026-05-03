import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { Activity, ShieldAlert, ShieldCheck, Zap, Clock, BarChart2, TrendingUp, AlertTriangle } from 'lucide-react';

// ── Mock data for demo dashboard ──
const INITIAL_PIE_DATA = [
    { name: 'Phishing', value: 42, color: '#FF3B3B' },
    { name: 'Safe', value: 51, color: '#00FFB2' },
    { name: 'Suspicious', value: 7, color: '#FFB347' },
];

const INITIAL_SCANS = [
    { url: 'paypal-account-update.com/login', result: 'Phishing', confidence: 97, time: '2min ago' },
    { url: 'github.com/microsoft/vscode', result: 'Safe', confidence: 99, time: '5min ago' },
    { url: 'apple-id-verify-secure.net', result: 'Phishing', confidence: 94, time: '8min ago' },
    { url: 'amazon.com/orders', result: 'Safe', confidence: 98, time: '12min ago' },
    { url: 'secure-bank-update.info', result: 'Suspicious', confidence: 71, time: '15min ago' },
    { url: 'docs.google.com/spreadsheets', result: 'Safe', confidence: 99, time: '19min ago' },
    { url: 'netflix-payment-failed.xyz', result: 'Phishing', confidence: 99, time: '23min ago' },
];

const metrics = [
    { label: 'Accuracy', value: '99.8%', color: '#00FFB2', sub: 'Overall detection rate' },
    { label: 'Precision', value: '99.5%', color: '#00AEEF', sub: 'True positives / total predicted' },
    { label: 'Recall', value: '99.7%', color: '#7C3AED', sub: 'True positives / actual positives' },
    { label: 'F1-Score', value: '99.6%', color: '#FFB347', sub: 'Harmonic mean of P & R' },
];

// ── Animated counter ──
const AnimatedCounter: React.FC<{ end: number; suffix?: string; duration?: number }> = ({ end, suffix = '', duration = 1.5 }) => {
    const [count, setCount] = useState(0);
    const ref = useRef<HTMLSpanElement>(null);
    const started = useRef(false);

    useEffect(() => {
        const observer = new IntersectionObserver(entries => {
            if (entries[0].isIntersecting && !started.current) {
                started.current = true;
                const stepTime = (duration * 1000) / end;
                let current = 0;
                const timer = setInterval(() => {
                    current += Math.ceil(end / (duration * 30));
                    if (current >= end) { setCount(end); clearInterval(timer); }
                    else setCount(current);
                }, stepTime);
            }
        });
        if (ref.current) observer.observe(ref.current);
        return () => observer.disconnect();
    }, [end, duration]);

    return <span ref={ref}>{count.toLocaleString()}{suffix}</span>;
};

// ── Custom donut chart label ──
const RADIAN = Math.PI / 180;
const renderCustomLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent, name }: any) => {
    const r = innerRadius + (outerRadius - innerRadius) * 0.5;
    const x = cx + r * Math.cos(-midAngle * RADIAN);
    const y = cy + r * Math.sin(-midAngle * RADIAN);
    return (
        <text x={x} y={y} fill="white" textAnchor="middle" dominantBaseline="central" fontSize={11} fontWeight="bold">
            {`${(percent * 100).toFixed(0)}%`}
        </text>
    );
};

// ─────────────────────────────────────────────────
const DashboardSection: React.FC = () => {
    const [pieData, setPieData] = useState(INITIAL_PIE_DATA);
    const [recentScans, setRecentScans] = useState(INITIAL_SCANS);
    const [liveStats, setLiveStats] = useState({ total: 24817, phishing: 10423, safe: 12650, avgConf: 94 });

    useEffect(() => {
        const updateFromHistory = () => {
            const historyStr = localStorage.getItem('phishguard_history');
            if (historyStr) {
                try {
                    const history = JSON.parse(historyStr);
                    if (history.length > 0) {
                        setRecentScans([...history, ...INITIAL_SCANS].slice(0, 7));
                        let phishCount = 0, safeCount = 0, suspCount = 0, confSum = 0;
                        history.forEach((h: any) => {
                            if (h.result === 'Phishing') phishCount++;
                            else if (h.result === 'Safe') safeCount++;
                            else suspCount++;
                            confSum += h.confidence;
                        });
                        const total = history.length;
                        setPieData([
                            { name: 'Phishing', value: Math.round((phishCount/total)*100), color: '#FF3B3B' },
                            { name: 'Safe', value: Math.round((safeCount/total)*100), color: '#00FFB2' },
                            { name: 'Suspicious', value: Math.round((suspCount/total)*100), color: '#FFB347' },
                        ]);
                        setLiveStats({
                            total: 24817 + total,
                            phishing: 10423 + phishCount,
                            safe: 12650 + safeCount,
                            avgConf: Math.round(confSum / total)
                        });
                    }
                } catch (e) {
                    console.error("Failed to parse history", e);
                }
            }
        };

        updateFromHistory();
        window.addEventListener('scan-history-update', updateFromHistory);
        return () => window.removeEventListener('scan-history-update', updateFromHistory);
    }, []);

    const resultColor = (r: string) => r === 'Phishing' ? '#FF3B3B' : r === 'Suspicious' ? '#FFB347' : '#00FFB2';
    const resultBadge = (r: string) => r === 'Phishing' ? 'badge-phishing' : r === 'Suspicious' ? 'badge-suspicious' : 'badge-safe';
    const resultIcon = (r: string) => r === 'Phishing'
        ? <AlertTriangle className="w-3.5 h-3.5" />
        : r === 'Suspicious'
            ? <Zap className="w-3.5 h-3.5" />
            : <ShieldCheck className="w-3.5 h-3.5" />;

    return (
        <section id="dashboard" className="py-28 relative overflow-hidden">
            {/* BG decoration */}
            <div className="absolute inset-0 bg-grid opacity-20 pointer-events-none" />
            <div className="absolute right-0 top-0 w-1/2 h-full pointer-events-none"
                style={{ background: 'radial-gradient(ellipse at 100% 30%, rgba(0,255,178,0.05) 0%, transparent 60%)' }} />
            <div className="absolute left-0 bottom-0 w-1/3 h-1/2 pointer-events-none"
                style={{ background: 'radial-gradient(ellipse at 0% 100%, rgba(0,174,239,0.06) 0%, transparent 60%)' }} />

            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">

                {/* Header */}
                <motion.div
                    initial={{ opacity: 0, y: 30 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    className="text-center mb-16"
                >
                    <div className="section-label mb-6 mx-auto">Live Analytics</div>
                    <h2 className="text-4xl md:text-5xl font-bold mb-5">
                        Threat <span className="text-gradient-blue">Dashboard</span>
                    </h2>
                    <p className="text-gray-400 text-lg max-w-2xl mx-auto">
                        Real-time statistics, analysis history, and model performance metrics — all in one place.
                    </p>
                </motion.div>

                {/* ── Row 1: Stat counters ── */}
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
                    {[
                        { icon: Activity, label: 'URLs Analyzed', end: liveStats.total, suffix: '', color: '#00AEEF' },
                        { icon: AlertTriangle, label: 'Phishing Detected', end: liveStats.phishing, suffix: '', color: '#FF3B3B' },
                        { icon: ShieldCheck, label: 'Safe URLs', end: liveStats.safe, suffix: '', color: '#00FFB2' },
                        { icon: BarChart2, label: 'Avg. Confidence', end: liveStats.avgConf, suffix: '%', color: '#FFB347' },
                    ].map((stat, i) => {
                        const Icon = stat.icon;
                        return (
                            <motion.div
                                key={i}
                                initial={{ opacity: 0, y: 20 }}
                                whileInView={{ opacity: 1, y: 0 }}
                                viewport={{ once: true }}
                                transition={{ delay: i * 0.08 }}
                                className="stat-card group"
                            >
                                <div className="flex items-center justify-between mb-3">
                                    <div className="w-10 h-10 rounded-xl flex items-center justify-center"
                                        style={{ background: `${stat.color}15`, border: `1px solid ${stat.color}30` }}>
                                        <Icon className="w-5 h-5" style={{ color: stat.color }} />
                                    </div>
                                    <TrendingUp className="w-4 h-4 text-gray-700 group-hover:text-gray-500 transition-colors" />
                                </div>
                                <div className="text-2xl lg:text-3xl font-bold text-white mt-1">
                                    <AnimatedCounter end={stat.end} suffix={stat.suffix} />
                                </div>
                                <div className="text-xs text-gray-500 mt-1">{stat.label}</div>
                            </motion.div>
                        );
                    })}
                </div>

                {/* ── Row 2: Donut chart + Recent scans ── */}
                <div className="grid grid-cols-1 lg:grid-cols-5 gap-6 mb-8">

                    {/* Donut chart */}
                    <motion.div
                        initial={{ opacity: 0, scale: 0.95 }}
                        whileInView={{ opacity: 1, scale: 1 }}
                        viewport={{ once: true }}
                        className="lg:col-span-2 glass-surface rounded-2xl p-6"
                        style={{ border: '1px solid rgba(0,174,239,0.12)' }}
                    >
                        <h3 className="font-bold text-white mb-1 flex items-center gap-2">
                            <PieChart className="w-4 h-4 text-primary" />
                            URL Classification Split
                        </h3>
                        <p className="text-xs text-gray-500 mb-5">Of all URLs analyzed this session</p>

                        <div className="h-52">
                            <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                    <Pie
                                        data={pieData}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={55}
                                        outerRadius={85}
                                        paddingAngle={3}
                                        dataKey="value"
                                        labelLine={false}
                                        label={renderCustomLabel}
                                    >
                                        {pieData.map((entry, index) => (
                                            <Cell key={`cell-${index}`} fill={entry.color} stroke={entry.color + '30'} strokeWidth={1} />
                                        ))}
                                    </Pie>
                                    <Tooltip
                                        contentStyle={{
                                            background: '#0A0F2C',
                                            border: '1px solid rgba(0,174,239,0.2)',
                                            borderRadius: '12px',
                                            color: '#fff',
                                            fontSize: 12,
                                        }}
                                        formatter={(value: any, name: any) => [`${value}%`, name]}
                                    />
                                </PieChart>
                            </ResponsiveContainer>
                        </div>

                        {/* Legend */}
                        <div className="flex flex-col gap-2 mt-2">
                            {pieData.map(d => (
                                <div key={d.name} className="flex items-center justify-between text-sm">
                                    <div className="flex items-center gap-2">
                                        <div className="w-2.5 h-2.5 rounded-full" style={{ background: d.color }} />
                                        <span className="text-gray-400">{d.name}</span>
                                    </div>
                                    <span className="font-bold text-white">{d.value}%</span>
                                </div>
                            ))}
                        </div>
                    </motion.div>

                    {/* Recent scans table */}
                    <motion.div
                        initial={{ opacity: 0, x: 20 }}
                        whileInView={{ opacity: 1, x: 0 }}
                        viewport={{ once: true }}
                        transition={{ delay: 0.1 }}
                        className="lg:col-span-3 glass-surface rounded-2xl p-6"
                        style={{ border: '1px solid rgba(0,174,239,0.12)' }}
                    >
                        <div className="flex items-center justify-between mb-5">
                            <h3 className="font-bold text-white flex items-center gap-2">
                                <Clock className="w-4 h-4 text-primary" />
                                Recent Analysis History
                            </h3>
                            <div className="flex items-center gap-1.5 text-xs text-secondary px-2 py-1 rounded-lg"
                                style={{ background: 'rgba(0,255,178,0.08)', border: '1px solid rgba(0,255,178,0.2)' }}>
                                <span className="w-1.5 h-1.5 rounded-full bg-secondary animate-pulse" />
                                Live
                            </div>
                        </div>

                        <div className="space-y-2 overflow-hidden">
                            {recentScans.map((scan, i) => (
                                <motion.div
                                    key={i}
                                    initial={{ opacity: 0, x: 10 }}
                                    whileInView={{ opacity: 1, x: 0 }}
                                    viewport={{ once: true }}
                                    transition={{ delay: i * 0.05 }}
                                    className="flex items-center gap-3 p-3 rounded-xl transition-colors duration-200 hover:bg-white/3 cursor-default"
                                    style={{ border: '1px solid rgba(255,255,255,0.04)' }}
                                >
                                    {/* Status icon */}
                                    <div className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0"
                                        style={{
                                            background: `${resultColor(scan.result)}15`,
                                            color: resultColor(scan.result),
                                        }}>
                                        {resultIcon(scan.result)}
                                    </div>

                                    {/* URL */}
                                    <div className="flex-1 min-w-0">
                                        <p className="text-xs font-mono text-gray-400 truncate">{scan.url}</p>
                                    </div>

                                    {/* Badge */}
                                    <div className={resultBadge(scan.result)}>
                                        {scan.result}
                                    </div>

                                    {/* Confidence */}
                                    <div className="text-xs font-bold shrink-0" style={{ color: resultColor(scan.result) }}>
                                        {scan.confidence}%
                                    </div>

                                    {/* Time */}
                                    <div className="text-xs text-gray-600 shrink-0 hidden sm:block">{scan.time}</div>
                                </motion.div>
                            ))}
                        </div>
                    </motion.div>
                </div>

                {/* ── Row 3: Model performance metric cards ── */}
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                    {metrics.map((m, i) => (
                        <motion.div
                            key={i}
                            initial={{ opacity: 0, y: 20 }}
                            whileInView={{ opacity: 1, y: 0 }}
                            viewport={{ once: true }}
                            transition={{ delay: i * 0.08 }}
                            className="glass-surface rounded-2xl p-5 relative overflow-hidden group cursor-default transition-all duration-300"
                            style={{ border: `1px solid ${m.color}18` }}
                            whileHover={{ borderColor: `${m.color}40`, boxShadow: `0 0 30px ${m.color}15` }}
                        >
                            {/* Glow orb */}
                            <div className="absolute -top-6 -right-6 w-24 h-24 rounded-full blur-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"
                                style={{ background: `${m.color}20` }} />

                            {/* Radial progress arc (SVG) */}
                            <div className="relative w-16 h-16 mx-auto mb-4">
                                <svg className="w-full h-full -rotate-90" viewBox="0 0 36 36">
                                    <circle cx="18" cy="18" r="14" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="3" />
                                    <motion.circle
                                        cx="18" cy="18" r="14"
                                        fill="none"
                                        stroke={m.color}
                                        strokeWidth="3"
                                        strokeLinecap="round"
                                        strokeDasharray={`${2 * Math.PI * 14}`}
                                        strokeDashoffset={`${2 * Math.PI * 14 * (1 - parseFloat(m.value) / 100)}`}
                                        initial={{ strokeDashoffset: `${2 * Math.PI * 14}` }}
                                        whileInView={{ strokeDashoffset: `${2 * Math.PI * 14 * (1 - parseFloat(m.value) / 100)}` }}
                                        viewport={{ once: true }}
                                        transition={{ duration: 1.2, delay: i * 0.1, ease: 'easeOut' }}
                                        style={{ filter: `drop-shadow(0 0 4px ${m.color}80)` }}
                                    />
                                </svg>
                                <div className="absolute inset-0 flex items-center justify-center">
                                    <span className="text-xs font-bold" style={{ color: m.color }}>{m.value}</span>
                                </div>
                            </div>

                            <div className="text-center">
                                <div className="font-bold text-white text-sm">{m.label}</div>
                                <div className="text-xs text-gray-600 mt-0.5">{m.sub}</div>
                            </div>
                        </motion.div>
                    ))}
                </div>

            </div>
        </section>
    );
};

export default DashboardSection;
