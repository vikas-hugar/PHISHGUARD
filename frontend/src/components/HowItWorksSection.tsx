import React from 'react';
import { motion } from 'framer-motion';
import { Link2, Fingerprint, Cpu, BrainCircuit, ShieldCheck, ArrowRight } from 'lucide-react';

// ── Step data ──
const steps = [
    {
        id: '01',
        icon: Link2,
        title: 'URL Input',
        description: 'Raw URL is received and normalised. Protocol, hostname, path and query parameters are separated for analysis.',
        color: '#00AEEF',
        glow: 'rgba(0,174,239,0.2)',
        border: 'rgba(0,174,239,0.35)',
        bg: 'rgba(0,174,239,0.06)',
    },
    {
        id: '02',
        icon: Fingerprint,
        title: 'Tokenization & Embedding',
        description: 'Characters and sub-word tokens are mapped to dense high-dimensional vectors using a trained tokenizer.',
        color: '#7C3AED',
        glow: 'rgba(124,58,237,0.2)',
        border: 'rgba(124,58,237,0.35)',
        bg: 'rgba(124,58,237,0.06)',
    },
    {
        id: '03',
        icon: Cpu,
        title: 'CNN Feature Extraction',
        description: '1D Convolutional filters sweep over the embedding matrix to detect local structural anomalies — unusual hyphens, suspicious TLDs, brand spoofing.',
        color: '#0077CC',
        glow: 'rgba(0,119,204,0.2)',
        border: 'rgba(0,119,204,0.35)',
        bg: 'rgba(0,119,204,0.06)',
    },
    {
        id: '04',
        icon: BrainCircuit,
        title: 'BiLSTM Context Analysis',
        description: 'Bidirectional LSTM layers process the CNN feature maps as a sequence in both directions, capturing long-range dependencies and identifying obfuscation patterns across the full URL.',
        color: '#00FFB2',
        glow: 'rgba(0,255,178,0.2)',
        border: 'rgba(0,255,178,0.35)',
        bg: 'rgba(0,255,178,0.06)',
    },
    {
        id: '05',
        icon: ShieldCheck,
        title: 'Prediction Output',
        description: 'A Dense + Sigmoid layer outputs a probability score. High confidence → 🚨 Phishing / ⚠️ Suspicious / ✅ Safe, with a detailed feature breakdown.',
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
                        CNN–BiLSTM Pipeline
                    </div>
                    <h2 className="text-4xl md:text-5xl font-bold mb-5">
                        How <span className="text-gradient-blue">It Works</span>
                    </h2>
                    <p className="text-gray-400 text-lg max-w-2xl mx-auto leading-relaxed">
                        A step-by-step walkthrough of the deep learning pipeline that takes a raw URL and produces a precise phishing verdict in under 100ms.
                    </p>
                </motion.div>

                {/* ── Desktop: Horizontal flowchart ── */}
                <div className="hidden lg:block">
                    {/* Step cards row */}
                    <div className="grid grid-cols-5 gap-0 relative">
                        {/* Connector line behind cards */}
                        <div className="absolute top-[52px] left-[10%] right-[10%] h-px pointer-events-none"
                            style={{ background: 'linear-gradient(90deg, #00AEEF33, #7C3AED33, #0077CC33, #00FFB233, #FF3B3B33)' }} />

                        {steps.map((step, i) => {
                            const Icon = step.icon;
                            return (
                                <div key={step.id} className="flex flex-col items-center px-2">
                                    {/* Numbered icon node */}
                                    <motion.div
                                        initial={{ scale: 0, opacity: 0 }}
                                        whileInView={{ scale: 1, opacity: 1 }}
                                        viewport={{ once: true }}
                                        transition={{ delay: i * 0.12, type: 'spring', stiffness: 200 }}
                                        className="w-[104px] h-[104px] rounded-2xl flex flex-col items-center justify-center mb-6 relative z-10 cursor-default"
                                        style={{
                                            background: step.bg,
                                            border: `1px solid ${step.border}`,
                                            boxShadow: `0 0 25px ${step.glow}`,
                                        }}
                                        whileHover={{ scale: 1.06, boxShadow: `0 0 40px ${step.glow}` }}
                                    >
                                        <Icon className="w-8 h-8 mb-1" style={{ color: step.color }} />
                                        <span className="text-xs font-mono font-bold" style={{ color: step.color }}>{step.id}</span>
                                    </motion.div>

                                    {/* Card */}
                                    <motion.div
                                        initial={{ opacity: 0, y: 20 }}
                                        whileInView={{ opacity: 1, y: 0 }}
                                        viewport={{ once: true }}
                                        transition={{ delay: i * 0.12 + 0.15 }}
                                        className="text-center"
                                    >
                                        <h3 className="font-bold text-sm text-white mb-2" style={{ color: step.color }}>
                                            {step.title}
                                        </h3>
                                        <p className="text-xs text-gray-500 leading-relaxed">{step.description}</p>
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
                                animate={{ x: ['10%', '90%'] }}
                                transition={{
                                    duration: 3,
                                    repeat: Infinity,
                                    ease: 'linear',
                                    delay: i * 1,
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
                        { label: 'Architecture', value: 'CNN + BiLSTM + Dense', sub: 'Hybrid deep learning' },
                        { label: 'Optimizer', value: 'Adam (lr=0.001)', sub: 'With LR scheduler' },
                        { label: 'Inference Time', value: '< 100ms', sub: 'End-to-end per URL' },
                        { label: 'Detection Method', value: 'Hybrid Detection', sub: 'Deep Learning + Rule-Based Verification' },
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
