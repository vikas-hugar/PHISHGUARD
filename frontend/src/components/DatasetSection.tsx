import React from 'react';
import { motion } from 'framer-motion';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { BarChart2, Database, Settings } from 'lucide-react';

// ── Training data ──
const trainingData = [
    { epoch: 1, accuracy: 65.4, val_accuracy: 62.1, loss: 1.2 },
    { epoch: 2, accuracy: 78.2, val_accuracy: 75.8, loss: 0.8 },
    { epoch: 3, accuracy: 85.6, val_accuracy: 83.2, loss: 0.5 },
    { epoch: 4, accuracy: 91.2, val_accuracy: 89.5, loss: 0.3 },
    { epoch: 5, accuracy: 94.5, val_accuracy: 93.1, loss: 0.2 },
    { epoch: 6, accuracy: 96.8, val_accuracy: 95.7, loss: 0.15 },
    { epoch: 7, accuracy: 98.2, val_accuracy: 97.6, loss: 0.1 },
    { epoch: 8, accuracy: 99.1, val_accuracy: 98.8, loss: 0.08 },
    { epoch: 9, accuracy: 99.5, val_accuracy: 99.2, loss: 0.05 },
    { epoch: 10, accuracy: 99.8, val_accuracy: 99.6, loss: 0.02 },
];

// ── Class distribution pie ──
const classDist = [
    { name: 'Phishing URLs', value: 50, color: '#FF3B3B' },
    { name: 'Legitimate URLs', value: 50, color: '#00FFB2' },
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
                        Trained on 1.45M+ URLs combining PhishTank, OpenPhish, and custom zero-day examples — achieving state-of-the-art detection accuracy.
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
                                    { label: 'Total Samples', value: '1,450,000+', color: '#fff' },
                                    { label: 'Phishing URLs', value: '725,000', color: '#FF3B3B' },
                                    { label: 'Legitimate URLs', value: '725,000', color: '#00FFB2' },
                                    { label: 'Train / Val Split', value: '80% / 20%', color: '#00AEEF' },
                                ].map((row, i) => (
                                    <div key={i} className="flex justify-between py-2"
                                        style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                                        <span className="text-gray-500">{row.label}</span>
                                        <span className="font-bold" style={{ color: row.color }}>{row.value}</span>
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
                                Model Metrics
                            </h3>
                            <div className="grid grid-cols-2 gap-3">
                                {[
                                    { value: '99.8%', label: 'Accuracy', color: '#00FFB2' },
                                    { value: '99.5%', label: 'Precision', color: '#00AEEF' },
                                    { value: '99.7%', label: 'Recall', color: '#7C3AED' },
                                    { value: '99.6%', label: 'F1-Score', color: '#FFB347' },
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
                            Training Progress — 10 Epochs
                        </h3>
                        <p className="text-xs text-gray-600 mb-7 font-mono">accuracy vs val_accuracy · loss curve</p>

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
                                    <YAxis stroke="transparent" tick={{ fill: '#4B5563', fontSize: 11 }} tickLine={false} domain={[55, 102]} />
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
