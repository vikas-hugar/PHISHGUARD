import React from 'react';
import { motion } from 'framer-motion';
import { Database, Cpu, Activity, LayoutGrid, ArrowDown, Layers, Binary } from 'lucide-react';

// ── Pipeline node data ──
const nodes = [
    {
        id: 'input',
        label: 'Input URL Data',
        sub: 'http://secure-login.paypal-update.com/auth',
        icon: Database,
        color: '#6B7280',
        border: 'rgba(107,114,128,0.3)',
        bg: 'rgba(107,114,128,0.06)',
    },
    {
        id: 'embed',
        label: 'Lexical Tokenization & Embedding',
        sub: 'Characters → dense vectors (dim=128)',
        icon: Binary,
        color: '#7C3AED',
        border: 'rgba(124,58,237,0.35)',
        bg: 'rgba(124,58,237,0.07)',
    },
    {
        id: 'cnn',
        label: 'Convolutional Layer (1D-CNN)',
        sub: 'Filters detect structural anomalies · outputs spatial feature maps',
        icon: LayoutGrid,
        color: '#00AEEF',
        border: 'rgba(0,174,239,0.35)',
        bg: 'rgba(0,174,239,0.07)',
    },
    {
        id: 'lstm',
        label: 'Bidirectional LSTM (BiLSTM)',
        sub: 'Processes CNN maps bidirectionally · captures long-range obfuscation patterns in both directions',
        icon: Activity,
        color: '#00FFB2',
        border: 'rgba(0,255,178,0.35)',
        bg: 'rgba(0,255,178,0.07)',
    },
    {
        id: 'reg',
        label: 'Regularization (Dropout)',
        sub: 'Prevents over-fitting — rate 0.4',
        icon: Layers,
        color: '#FFB347',
        border: 'rgba(255,179,71,0.3)',
        bg: 'rgba(255,179,71,0.06)',
    },
    {
        id: 'output',
        label: 'Dense → Sigmoid Output',
        sub: 'Safe / Suspicious / Phishing (Hybrid Decision Layer)',
        icon: Cpu,
        color: '#FF3B3B',
        gradient: 'linear-gradient(135deg, rgba(255,59,59,0.15), rgba(0,174,239,0.08))',
        border: 'rgba(255,59,59,0.35)',
        bg: 'rgba(255,59,59,0.07)',
    },
];

const ArchitectureSection: React.FC = () => {
    return (
        <section id="architecture" className="py-28 relative overflow-hidden">
            {/* Background */}
            <div className="absolute inset-0 bg-dots opacity-25 pointer-events-none" />
            <div className="absolute inset-0 pointer-events-none"
                style={{ background: 'radial-gradient(ellipse 60% 50% at 50% 50%, rgba(0,174,239,0.05) 0%, transparent 70%)' }} />

            <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">

                {/* Header */}
                <motion.div
                    initial={{ opacity: 0, y: 30 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    className="text-center mb-16"
                >
                    <div className="section-label mb-6 mx-auto">Deep Learning Pipeline</div>
                    <h2 className="text-4xl md:text-5xl font-bold mb-5">
                        Model <span className="text-gradient-blue">Architecture</span>
                    </h2>
                    <p className="text-gray-400 text-lg max-w-2xl mx-auto">
                        A hybrid CNN-BiLSTM pipeline that extracts spatial features and maintains sequential memory for highly accurate phishing detection.
                    </p>
                </motion.div>

                {/* Two-column layout: pipeline left, specs right */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-start">

                    {/* ── Left: Vertical pipeline ── */}
                    <div className="lg:col-span-2">
                        <div className="relative rounded-3xl p-8"
                            style={{
                                background: 'rgba(10,15,44,0.6)',
                                border: '1px solid rgba(0,174,239,0.15)',
                                backdropFilter: 'blur(20px)',
                            }}>
                            {/* Inner glow */}
                            <div className="absolute inset-0 rounded-3xl pointer-events-none"
                                style={{ background: 'radial-gradient(ellipse at 50% 0%, rgba(0,174,239,0.08) 0%, transparent 60%)' }} />

                            <div className="relative z-10 flex flex-col items-center space-y-3">
                                {nodes.map((node, i) => {
                                    const Icon = node.icon;
                                    return (
                                        <React.Fragment key={node.id}>
                                            <motion.div
                                                initial={{ opacity: 0, y: -20 }}
                                                whileInView={{ opacity: 1, y: 0 }}
                                                viewport={{ once: true }}
                                                transition={{ delay: i * 0.1 }}
                                                className="w-full max-w-lg rounded-2xl p-4 md:p-5"
                                                style={{
                                                    background: node.gradient || node.bg,
                                                    border: `1px solid ${node.border}`,
                                                    boxShadow: `0 0 20px ${node.border}`,
                                                }}
                                                whileHover={{ scale: 1.015 }}
                                            >
                                                <div className="flex items-start gap-4">
                                                    <div className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
                                                        style={{ background: `${node.color}20`, border: `1px solid ${node.color}40` }}>
                                                        <Icon className="w-5 h-5" style={{ color: node.color }} />
                                                    </div>
                                                    <div>
                                                        <h4 className="font-bold text-sm mb-1" style={{ color: node.color }}>{node.label}</h4>
                                                        <p className="text-xs text-gray-500 leading-relaxed font-mono">{node.sub}</p>
                                                    </div>
                                                </div>
                                            </motion.div>

                                            {/* Animated connector arrow */}
                                            {i < nodes.length - 1 && (
                                                <motion.div
                                                    initial={{ opacity: 0 }}
                                                    whileInView={{ opacity: 1 }}
                                                    viewport={{ once: true }}
                                                    transition={{ delay: i * 0.1 + 0.05 }}
                                                    className="flex flex-col items-center gap-0.5"
                                                >
                                                    <div className="w-px h-5 bg-gradient-to-b from-white/10 to-white/5" />
                                                    <motion.div
                                                        animate={{ y: [0, 4, 0] }}
                                                        transition={{ duration: 1.5, repeat: Infinity }}
                                                    >
                                                        <ArrowDown className="w-4 h-4 text-white/25" />
                                                    </motion.div>
                                                </motion.div>
                                            )}
                                        </React.Fragment>
                                    );
                                })}
                            </div>
                        </div>
                    </div>

                    {/* ── Right: Model specs cards ── */}
                    <div className="flex flex-col gap-5">
                        {/* Architecture summary */}
                        <motion.div
                            initial={{ opacity: 0, x: 20 }}
                            whileInView={{ opacity: 1, x: 0 }}
                            viewport={{ once: true }}
                            className="glass-surface rounded-2xl p-6"
                            style={{ border: '1px solid rgba(0,174,239,0.15)' }}
                        >
                            <h3 className="font-bold text-white mb-5 text-sm uppercase tracking-wider" style={{ color: '#00AEEF' }}>
                                Architecture Summary
                            </h3>
                            <div className="space-y-3">
                                {[
                                    { label: 'Embedding Dim', value: '128' },
                                    { label: 'CNN Filters', value: '128, kernel=5' },
                                    { label: 'BiLSTM Units', value: '64' },
                                    { label: 'Dropout Rate', value: '0.4' },
                                    { label: 'Dense Units', value: '64 → Sigmoid' },
                                    { label: 'Optimizer', value: 'Adam (lr=0.001)' },
                                    { label: 'Loss Function', value: 'Binary CE' },
                                    { label: 'Epochs', value: '10' },
                                ].map((item, i) => (
                                    <motion.div
                                        key={i}
                                        initial={{ opacity: 0 }}
                                        whileInView={{ opacity: 1 }}
                                        viewport={{ once: true }}
                                        transition={{ delay: i * 0.04 }}
                                        className="flex justify-between items-center text-xs py-2"
                                        style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}
                                    >
                                        <span className="text-gray-500">{item.label}</span>
                                        <span className="font-mono font-bold text-white">{item.value}</span>
                                    </motion.div>
                                ))}
                            </div>
                        </motion.div>

                        {/* Output classes */}
                        <motion.div
                            initial={{ opacity: 0, x: 20 }}
                            whileInView={{ opacity: 1, x: 0 }}
                            viewport={{ once: true }}
                            transition={{ delay: 0.2 }}
                            className="glass-surface rounded-2xl p-6"
                            style={{ border: '1px solid rgba(0,174,239,0.12)' }}
                        >
                            <h3 className="font-bold text-sm uppercase tracking-wider mb-4" style={{ color: '#00AEEF' }}>
                                Output Classes
                            </h3>
                            <div className="space-y-3">
                                {[
                                    { label: '✅ Safe', desc: 'Legitimate URL', color: '#00FFB2' },
                                    { label: '⚠️ Suspicious', desc: 'May be malicious', color: '#FFB347' },
                                    { label: '🚨 Phishing', desc: 'Confirmed phishing', color: '#FF3B3B' },
                                ].map((c, i) => (
                                    <div key={i} className="flex items-center justify-between text-xs p-2.5 rounded-xl"
                                        style={{ background: `${c.color}08`, border: `1px solid ${c.color}20` }}>
                                        <span className="font-bold" style={{ color: c.color }}>{c.label}</span>
                                        <span className="text-gray-500">{c.desc}</span>
                                    </div>
                                ))}
                            </div>
                        </motion.div>
                    </div>
                </div>

            </div>
        </section>
    );
};

export default ArchitectureSection;
