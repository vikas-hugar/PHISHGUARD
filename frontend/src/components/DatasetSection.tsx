import React from 'react';
import { motion } from 'framer-motion';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { BarChart2, Database, Settings } from 'lucide-react';

// ── Training data (Hybrid Model Convergence) ──
const trainingData = [
    { epoch: 'Epoch 1', accuracy: 91.80, val_accuracy: 93.10, loss: 0.1850 },
    { epoch: 'Epoch 2', accuracy: 93.90, val_accuracy: 94.40, loss: 0.1280 },
    { epoch: 'Epoch 3', accuracy: 94.80, val_accuracy: 94.90, loss: 0.0960 },
    { epoch: 'Epoch 4*', accuracy: 95.40, val_accuracy: 95.17, loss: 0.0810 },
];

// ── Class distribution pie (1,532,239 URLs) ──
const classDist = [
    { name: 'Phishing URLs (720,618)', value: 47, color: '#FF3B3B' },
    { name: 'Legitimate URLs (811,621)', value: 53, color: '#00FFB2' },
];

const DatasetSection: React.FC = () => {
    return (
        <section className="py-28 relative overflow-hidden"
            style={{ background: 'rgba(6,11,24,0.98)' }}>
            {/* BG decoration */}
            <div className="absolute top-0 right-0 w-1/2 h-3/4 pointer-events-none"
                style={{ background: 'radial-gradient(ellipse at 100% 0%, rgba(0,174,239,0.06) 0%, transparent 60%)' }} />
            <div className="absolute bottom-0 left-0 w-64 h-64 pointer-events-none"
                style={{ background: 'radial-gradient(ellipse at 0% 100%, rgba(0,255,178,0.05) 0%, transparent 70%)' }} />
            <div className="absolute inset-0 bg-grid opacity-20 pointer-events-none" />

            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">

                {/* Header */}
                <motion.div
                    initial={{ opacity: 0, y: 30 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    className="text-center mb-16"
                >
                    <div className="section-label mb-6 mx-auto">Performance Analysis</div>
                    <h2 className="text-4xl md:text-5xl font-bold mb-5">
                        Training & <span className="text-gradient-blue">Performance</span>
                    </h2>
                    <p className="text-gray-400 text-lg max-w-2xl mx-auto">
                        Trained on 1,532,239 URLs combining PhishTank, OpenPhish, and verified legitimate corpuses — evaluated on Hybrid CNN–BiLSTM + RoBERTa (V3).
                    </p>
                </motion.div>

                <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">

                    {/* ── Left column: Metrics + dataset cards ── */}
                    <div className="lg:col-span-4 flex flex-col gap-5">

                        {/* Dataset overview */}
                        <motion.div
                            initial={{ opacity: 0, x: -20 }}
                            whileInView={{ opacity: 1, x: 0 }}
                            viewport={{ once: true }}
                            className="glass-surface rounded-2xl p-6"
                            style={{ border: '1px solid rgba(0,174,239,0.12)' }}
                        >
                            <h3 className="font-bold text-white mb-5 flex items-center gap-2 text-sm">
                                <Database className="w-4 h-4 text-primary" />
                                Dataset Overview
                            </h3>
                            {/* Mini pie */}
                            <div className="h-32 mb-5">
                                <ResponsiveContainer width="100%" height="100%">
                                    <PieChart>
                                        <Pie data={classDist} cx="50%" cy="50%" innerRadius={35} outerRadius={55}
                                            paddingAngle={3} dataKey="value">
                                            {classDist.map((entry, i) => (
                                                <Cell key={i} fill={entry.color} stroke={entry.color + '20'} />
                                            ))}
                                        </Pie>
                                        <Tooltip
                                            contentStyle={{ background: '#0A0F2C', border: '1px solid rgba(0,174,239,0.2)', borderRadius: 8, fontSize: 11 }}
                                            formatter={(v: any, n: any) => [`${v}%`, n]}
                                        />
                                    </PieChart>
                                </ResponsiveContainer>
                            </div>
                            <div className="space-y-3 text-sm">
                                {[
                                    { label: 'Total Samples', value: '1,532,239', color: '#fff' },
                                    { label: 'Legitimate URLs', value: '811,621', color: '#00FFB2' },
                                    { label: 'Phishing URLs', value: '720,618', color: '#FF3B3B' },
                                    { label: 'Train / Validation', value: '80% / 20%', color: '#00AEEF' },
                                    { label: 'Architecture', value: 'Hybrid V3', color: '#FFB347' },
                                ].map((row, i) => (
                                    <div key={i} className="flex justify-between py-2"
                                        style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                                        <span className="text-gray-500">{row.label}</span>
                                        <span className="font-bold font-mono" style={{ color: row.color }}>{row.value}</span>
                                    </div>
                                ))}
                            </div>
                        </motion.div>

                        {/* Model metrics grid */}
                        <motion.div
                            initial={{ opacity: 0, x: -20 }}
                            whileInView={{ opacity: 1, x: 0 }}
                            viewport={{ once: true }}
                            transition={{ delay: 0.15 }}
                            className="glass-surface rounded-2xl p-6"
                            style={{ border: '1px solid rgba(0,174,239,0.12)' }}
                        >
                            <h3 className="font-bold text-white mb-5 flex items-center gap-2 text-sm">
                                <Settings className="w-4 h-4 text-secondary" />
                                Model Metrics (Hybrid AI V3)
                            </h3>
                            <div className="grid grid-cols-2 gap-3">
                                {[
                                    { value: '95.17%', label: 'Accuracy', color: '#00FFB2' },
                                    { value: '94.63%', label: 'Precision', color: '#00AEEF' },
                                    { value: '94.87%', label: 'Recall', color: '#7C3AED' },
                                    { value: '94.75%', label: 'F1', color: '#FFB347' },
                                ].map((m, i) => (
                                    <motion.div
                                        key={i}
                                        initial={{ scale: 0.9, opacity: 0 }}
                                        whileInView={{ scale: 1, opacity: 1 }}
                                        viewport={{ once: true }}
                                        transition={{ delay: i * 0.07 }}
                                        className="p-4 rounded-xl text-center"
                                        style={{
                                            background: `${m.color}08`,
                                            border: `1px solid ${m.color}20`,
                                        }}
                                    >
                                        <div className="text-xl font-black" style={{ color: m.color }}>{m.value}</div>
                                        <div className="text-xs text-gray-500 mt-0.5">{m.label}</div>
                                    </motion.div>
                                ))}
                            </div>
                        </motion.div>
                    </div>

                    {/* ── Right column: Training charts ── */}
                    <motion.div
                        initial={{ opacity: 0, scale: 0.97 }}
                        whileInView={{ opacity: 1, scale: 1 }}
                        viewport={{ once: true }}
                        className="lg:col-span-8 glass-surface rounded-2xl p-7"
                        style={{ border: '1px solid rgba(0,174,239,0.12)' }}
                    >
                        <h3 className="font-bold text-white mb-2 flex items-center gap-2 text-sm">
                            <BarChart2 className="w-4 h-4 text-primary" />
                            Training & Convergence — Hybrid Model (V3)
                        </h3>
                        <p className="text-xs text-gray-400 mb-7 font-mono">accuracy vs val_accuracy · loss curve (95.17% target accuracy)</p>

                        {/* Accuracy chart */}
                        <div className="h-52 mb-3">
                            <ResponsiveContainer width="100%" height="100%">
                                <AreaChart data={trainingData} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
                                    <defs>
                                        <linearGradient id="accGrad" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#00FFB2" stopOpacity={0.25} />
                                            <stop offset="95%" stopColor="#00FFB2" stopOpacity={0} />
                                        </linearGradient>
                                        <linearGradient id="valAccGrad" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#00AEEF" stopOpacity={0.2} />
                                            <stop offset="95%" stopColor="#00AEEF" stopOpacity={0} />
                                        </linearGradient>
                                    </defs>
                                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                                    <XAxis dataKey="epoch" stroke="transparent" tick={{ fill: '#4B5563', fontSize: 11 }} tickLine={false} />
                                    <YAxis stroke="transparent" tick={{ fill: '#4B5563', fontSize: 11 }} tickLine={false} domain={[90, 100]} />
                                    <Tooltip
                                        contentStyle={{ background: '#0A0F2C', border: '1px solid rgba(0,174,239,0.25)', borderRadius: 10, fontSize: 12 }}
                                        labelStyle={{ color: '#9CA3AF' }}
                                        itemStyle={{ color: '#fff' }}
                                        formatter={(v: any) => [`${v}%`]}
                                    />
                                    <Area type="monotone" dataKey="accuracy" stroke="#00FFB2" strokeWidth={2.5}
                                        fill="url(#accGrad)" dot={false} name="Train Accuracy" />
                                    <Area type="monotone" dataKey="val_accuracy" stroke="#00AEEF" strokeWidth={2}
                                        fill="url(#valAccGrad)" dot={false} strokeDasharray="5 3" name="Val Accuracy" />
                                </AreaChart>
                            </ResponsiveContainer>
                        </div>

                        {/* Loss chart */}
                        <div className="h-32 mb-5">
                            <ResponsiveContainer width="100%" height="100%">
                                <AreaChart data={trainingData} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
                                    <defs>
                                        <linearGradient id="lossGrad" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#FF3B3B" stopOpacity={0.25} />
                                            <stop offset="95%" stopColor="#FF3B3B" stopOpacity={0} />
                                        </linearGradient>
                                    </defs>
                                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false} />
                                    <XAxis dataKey="epoch" stroke="transparent" tick={{ fill: '#4B5563', fontSize: 11 }} tickLine={false} />
                                    <YAxis stroke="transparent" tick={{ fill: '#4B5563', fontSize: 11 }} tickLine={false} />
                                    <Tooltip
                                        contentStyle={{ background: '#0A0F2C', border: '1px solid rgba(255,59,59,0.25)', borderRadius: 10, fontSize: 12 }}
                                        itemStyle={{ color: '#fff' }}
                                        formatter={(v: any) => [v]}
                                    />
                                    <Area type="monotone" dataKey="loss" stroke="#FF3B3B" strokeWidth={2.5}
                                        fill="url(#lossGrad)" dot={false} name="Validation Loss" />
                                </AreaChart>
                            </ResponsiveContainer>
                        </div>

                        {/* Legend */}
                        <div className="flex flex-wrap gap-5">
                            {[
                                { color: '#00FFB2', label: 'Train Accuracy' },
                                { color: '#00AEEF', label: 'Val Accuracy', dashed: true },
                                { color: '#FF3B3B', label: 'Loss' },
                            ].map((l, i) => (
                                <div key={i} className="flex items-center gap-2 text-xs text-gray-500">
                                    <div className="flex items-center gap-1">
                                        <div className="w-4 h-0.5 rounded" style={{
                                            background: l.color,
                                            borderTop: l.dashed ? `1.5px dashed ${l.color}` : 'none',
                                        }} />
                                        <div className="w-4 h-0.5 rounded" style={{ background: l.color }} />
                                    </div>
                                    {l.label}
                                </div>
                            ))}
                        </div>
                    </motion.div>
                </div>
            </div>
        </section>
    );
};

export default DatasetSection;
