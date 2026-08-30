import React from 'react';
import { motion } from 'framer-motion';
import { Link2, Fingerprint, Cpu, BrainCircuit, Sparkles, ShieldCheck, ArrowRight, GitMerge } from 'lucide-react';

// ── Step data (6-Step Hybrid Architecture) ──
const steps = [
    {
        id: '01',
        icon: Link2,
        title: 'URL Input',
        description: 'Raw URL string is ingested from client request, security telemetry, or real-time network stream.',
        color: '#00AEEF',
        glow: 'rgba(0,174,239,0.2)',
        border: 'rgba(0,174,239,0.35)',
        bg: 'rgba(0,174,239,0.06)',
    },
    {
        id: '02',
        icon: Fingerprint,
        title: 'URL Normalization',
        description: 'Protocol resolution, domain extraction, punycode decoding, and structural entropy metric computation.',
        color: '#7C3AED',
        glow: 'rgba(124,58,237,0.2)',
        border: 'rgba(124,58,237,0.35)',
        bg: 'rgba(124,58,237,0.06)',
    },
    {
        id: '03',
        icon: Cpu,
        title: 'CNN Feature Extraction',
        description: '256 Conv1D spatial filters sweep character embeddings to extract localized n-gram anomalies and spoof patterns.',
        color: '#0077CC',
        glow: 'rgba(0,119,204,0.2)',
        border: 'rgba(0,119,204,0.35)',
        bg: 'rgba(0,119,204,0.06)',
    },
    {
        id: '04',
        icon: BrainCircuit,
        title: 'BiLSTM Context Analysis',
        description: '128-unit Bidirectional LSTM layers process sequential feature maps in both directions for long-range context.',
        color: '#00FFB2',
        glow: 'rgba(0,255,178,0.2)',
        border: 'rgba(0,255,178,0.35)',
        bg: 'rgba(0,255,178,0.06)',
    },
    {
        id: '05',
        icon: Sparkles,
        title: 'RoBERTa Semantic Analysis',
        description: 'Pretrained transformer encoder analyzes lexical brand semantics, urgency triggers, and obfuscated intent.',
        color: '#FACC15',
        glow: 'rgba(250,204,21,0.2)',
        border: 'rgba(250,204,21,0.35)',
        bg: 'rgba(250,204,21,0.06)',
    },
    {
        id: '06',
        icon: GitMerge,
        title: 'Hybrid Fusion & Prediction',
        description: 'Ensemble layer fuses CNN (35%) + RoBERTa (65%) probabilities with explainable AI heuristics for final verdict.',
        color: '#FF3B3B',
        glow: 'rgba(255,59,59,0.2)',
        border: 'rgba(255,59,59,0.35)',
        bg: 'rgba(255,59,59,0.06)',
    },
];

const HowItWorksSection: React.FC = () => {
    return (
        <section id="how-it-works" className="py-28 relative overflow-hidden">
            {/* Background decoration */}
            <div className="absolute inset-0 bg-dots opacity-30 pointer-events-none" />
            <div className="absolute left-0 top-0 w-1/2 h-full pointer-events-none"
                style={{ background: 'radial-gradient(ellipse at 0% 50%, rgba(0,174,239,0.06) 0%, transparent 60%)' }} />

            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">

                {/* Section header */}
                <motion.div
                    initial={{ opacity: 0, y: 30 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    transition={{ duration: 0.7 }}
                    className="text-center mb-20"
                >
                    <div className="section-label mb-6 mx-auto">
                        Hybrid CNN–BiLSTM + RoBERTa Pipeline
                    </div>
                    <h2 className="text-4xl md:text-5xl font-bold mb-5">
                        How <span className="text-gradient-blue">It Works</span>
                    </h2>
                    <p className="text-gray-400 text-lg max-w-2xl mx-auto leading-relaxed">
                        A step-by-step walkthrough of the 6-stage deep learning pipeline that processes raw URLs and generates real-time hybrid verdicts in 215ms.
                    </p>
                </motion.div>

                {/* ── Desktop: Horizontal flowchart ── */}
                <div className="hidden lg:block">
                    {/* Step cards row */}
                    <div className="grid grid-cols-6 gap-2 relative">
                        {/* Connector line behind cards */}
                        <div className="absolute top-[48px] left-[8%] right-[8%] h-px pointer-events-none"
                            style={{ background: 'linear-gradient(90deg, #00AEEF33, #7C3AED33, #0077CC33, #00FFB233, #FACC1533, #FF3B3B33)' }} />

                        {steps.map((step, i) => {
                            const Icon = step.icon;
                            return (
                                <div key={step.id} className="flex flex-col items-center px-1.5">
                                    {/* Numbered icon node */}
                                    <motion.div
                                        initial={{ scale: 0, opacity: 0 }}
                                        whileInView={{ scale: 1, opacity: 1 }}
                                        viewport={{ once: true }}
                                        transition={{ delay: i * 0.1, type: 'spring', stiffness: 200 }}
                                        className="w-[92px] h-[92px] rounded-2xl flex flex-col items-center justify-center mb-5 relative z-10 cursor-default"
                                        style={{
                                            background: step.bg,
                                            border: `1px solid ${step.border}`,
                                            boxShadow: `0 0 20px ${step.glow}`,
                                        }}
                                        whileHover={{ scale: 1.06, boxShadow: `0 0 35px ${step.glow}` }}
                                    >
                                        <Icon className="w-7 h-7 mb-1" style={{ color: step.color }} />
                                        <span className="text-xs font-mono font-bold" style={{ color: step.color }}>{step.id}</span>
                                    </motion.div>

                                    {/* Card */}
                                    <motion.div
                                        initial={{ opacity: 0, y: 20 }}
                                        whileInView={{ opacity: 1, y: 0 }}
                                        viewport={{ once: true }}
                                        transition={{ delay: i * 0.1 + 0.12 }}
                                        className="text-center"
                                    >
                                        <h3 className="font-bold text-xs sm:text-sm text-white mb-2" style={{ color: step.color }}>
                                            {step.title}
                                        </h3>
                                        <p className="text-[11px] text-gray-500 leading-relaxed">{step.description}</p>
                                    </motion.div>
                                </div>
                            );
                        })}
                    </div>

                    {/* Animated data packets travelling along connector */}
                    <div className="relative h-2 mt-0 -mb-8">
                        {[0, 1, 2].map(i => (
                            <motion.div
                                key={i}
                                className="absolute top-0 w-2 h-2 rounded-full"
                                style={{ background: '#00AEEF', boxShadow: '0 0 8px #00AEEF' }}
                                animate={{ x: ['8%', '92%'] }}
                                transition={{
                                    duration: 3.5,
                                    repeat: Infinity,
                                    ease: 'linear',
                                    delay: i * 1.1,
                                }}
                            />
                        ))}
                    </div>
                </div>

                {/* ── Mobile: Vertical timeline ── */}
                <div className="lg:hidden space-y-0">
                    {steps.map((step, i) => {
                        const Icon = step.icon;
                        return (
                            <div key={step.id} className="relative flex gap-5">
                                {/* Left node + vertical line */}
                                <div className="flex flex-col items-center">
                                    <motion.div
                                        initial={{ scale: 0 }}
                                        whileInView={{ scale: 1 }}
                                        viewport={{ once: true }}
                                        transition={{ delay: i * 0.1, type: 'spring' }}
                                        className="w-12 h-12 rounded-xl flex items-center justify-center shrink-0 z-10"
                                        style={{
                                            background: step.bg,
                                            border: `1px solid ${step.border}`,
                                            boxShadow: `0 0 20px ${step.glow}`,
                                        }}
                                    >
                                        <Icon className="w-5 h-5" style={{ color: step.color }} />
                                    </motion.div>
                                    {i < steps.length - 1 && (
                                        <div className="w-px flex-1 my-2" style={{ background: `${step.border}` }} />
                                    )}
                                </div>
                                {/* Content */}
                                <motion.div
                                    initial={{ opacity: 0, x: 20 }}
                                    whileInView={{ opacity: 1, x: 0 }}
                                    viewport={{ once: true }}
                                    transition={{ delay: i * 0.1 + 0.1 }}
                                    className="pb-8"
                                >
                                    <div className="text-xs font-mono mb-1" style={{ color: step.color }}>{step.id}</div>
                                    <h3 className="font-bold text-white mb-1">{step.title}</h3>
                                    <p className="text-sm text-gray-500 leading-relaxed">{step.description}</p>
                                </motion.div>
                            </div>
                        );
                    })}
                </div>

                {/* Bottom info row */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    transition={{ delay: 0.5 }}
                    className="mt-20 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6"
                >
                    {[
                        { label: 'Architecture', value: 'CNN + BiLSTM + RoBERTa', sub: 'Hybrid deep learning' },
                        { label: 'Optimizer', value: 'Adam (lr=0.001)', sub: 'With LR scheduler' },
                        { label: 'Inference', value: '215 ms', sub: 'End-to-end per URL' },
                        { label: 'Detection', value: '35% CNN + 65% RoBERTa', sub: 'Hybrid Decision Fusion' },
                    ].map((item, i) => (
                        <div key={i} className="glass-surface rounded-2xl p-5 flex flex-col gap-1"
                            style={{ border: '1px solid rgba(0,174,239,0.12)' }}>
                            <span className="text-xs text-gray-500 uppercase tracking-wider">{item.label}</span>
                            <span className="text-lg font-bold text-white">{item.value}</span>
                            <span className="text-xs text-gray-600">{item.sub}</span>
                        </div>
                    ))}
                </motion.div>

            </div>
        </section>
    );
};

export default HowItWorksSection;
