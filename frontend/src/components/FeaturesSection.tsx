import React from 'react';
import { motion } from 'framer-motion';
import { Zap, Shield, Cpu, Eye, Globe, Lock, TrendingUp, BarChart2 } from 'lucide-react';

const features = [
    {
        icon: Zap,
        title: 'Zero-Day Adaptability',
        description: 'Unlike rule-based systems, our CNN-LSTM model generalizes to previously unseen phishing patterns — no blacklists needed.',
        color: '#00AEEF',
        gradient: 'linear-gradient(135deg, rgba(0,174,239,0.12), rgba(0,174,239,0.04))',
        border: 'rgba(0,174,239,0.2)',
        glow: 'rgba(0,174,239,0.15)',
    },
    {
        icon: Cpu,
        title: 'CNN Feature Extraction',
        description: '1D Convolutional filters detect spatial anomalies in URL character sequences — suspicious hyphens, long subdomain chains, unusual TLDs.',
        color: '#7C3AED',
        gradient: 'linear-gradient(135deg, rgba(124,58,237,0.12), rgba(124,58,237,0.04))',
        border: 'rgba(124,58,237,0.2)',
        glow: 'rgba(124,58,237,0.15)',
    },
    {
        icon: Eye,
        title: 'LSTM Sequence Memory',
        description: 'Long Short-Term Memory layers capture subtle long-range obfuscation patterns that span the full URL string.',
        color: '#00FFB2',
        gradient: 'linear-gradient(135deg, rgba(0,255,178,0.1), rgba(0,255,178,0.03))',
        border: 'rgba(0,255,178,0.2)',
        glow: 'rgba(0,255,178,0.12)',
    },
    {
        icon: Shield,
        title: 'Real-Time Detection',
        description: 'End-to-end inference completes in under 100ms — fast enough for browser extensions and live monitoring dashboards.',
        color: '#FF3B3B',
        gradient: 'linear-gradient(135deg, rgba(255,59,59,0.1), rgba(255,59,59,0.03))',
        border: 'rgba(255,59,59,0.2)',
        glow: 'rgba(255,59,59,0.12)',
    },
    {
        icon: Globe,
        title: 'Multilingual URL Support',
        description: 'Handles internationalized domain names (IDN), punycode, and Unicode homograph attacks used in sophisticated phishing campaigns.',
        color: '#FFB347',
        gradient: 'linear-gradient(135deg, rgba(255,179,71,0.1), rgba(255,179,71,0.03))',
        border: 'rgba(255,179,71,0.2)',
        glow: 'rgba(255,179,71,0.12)',
    },
    {
        icon: BarChart2,
        title: 'Dashboard Analytics',
        description: 'Live statistics dashboard tracks classification trends, confidence distributions, and model performance metrics in real time.',
        color: '#0077CC',
        gradient: 'linear-gradient(135deg, rgba(0,119,204,0.12), rgba(0,119,204,0.04))',
        border: 'rgba(0,119,204,0.2)',
        glow: 'rgba(0,119,204,0.12)',
    },
];

const FeaturesSection: React.FC = () => {
    return (
        <section id="features" className="py-28 relative overflow-hidden">
            <div className="absolute inset-0 bg-dots opacity-20 pointer-events-none" />

            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">

                {/* Header */}
                <motion.div
                    initial={{ opacity: 0, y: 30 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    className="text-center mb-16"
                >
                    <div className="section-label mb-6 mx-auto">Capabilities</div>
                    <h2 className="text-4xl md:text-5xl font-bold mb-5">
                        Why <span className="text-gradient-blue">PhishGuard AI?</span>
                    </h2>
                    <p className="text-gray-400 text-lg max-w-2xl mx-auto">
                        A production-grade deep learning pipeline built for real-world cybersecurity deployment — fast, accurate, and adaptive.
                    </p>
                </motion.div>

                {/* Feature cards grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
                    {features.map((feat, i) => {
                        const Icon = feat.icon;
                        return (
                            <motion.div
                                key={i}
                                initial={{ opacity: 0, y: 30 }}
                                whileInView={{ opacity: 1, y: 0 }}
                                viewport={{ once: true }}
                                transition={{ delay: i * 0.08 }}
                                className="feature-card group relative overflow-hidden"
                                style={{
                                    background: feat.gradient,
                                    border: `1px solid ${feat.border}`,
                                }}
                                whileHover={{
                                    borderColor: feat.color + '60',
                                    boxShadow: `0 0 30px ${feat.glow}, 0 12px 40px rgba(0,0,0,0.4)`,
                                    y: -5,
                                }}
                            >
                                {/* Corner glow on hover */}
                                <div className="absolute -top-10 -right-10 w-32 h-32 rounded-full blur-3xl opacity-0 group-hover:opacity-100 transition-all duration-500 pointer-events-none"
                                    style={{ background: `${feat.color}25` }} />

                                {/* Icon */}
                                <div className="w-12 h-12 rounded-xl flex items-center justify-center mb-5"
                                    style={{
                                        background: `${feat.color}15`,
                                        border: `1px solid ${feat.color}35`,
                                        boxShadow: `0 0 15px ${feat.color}25`,
                                    }}>
                                    <Icon className="w-6 h-6" style={{ color: feat.color }} />
                                </div>

                                <h3 className="font-bold text-white text-lg mb-3">{feat.title}</h3>
                                <p className="text-sm text-gray-500 leading-relaxed">{feat.description}</p>

                                {/* Bottom accent line (hidden until hover) */}
                                <div className="absolute bottom-0 left-0 right-0 h-px scale-x-0 group-hover:scale-x-100 transition-transform duration-500 origin-left"
                                    style={{ background: `linear-gradient(90deg, ${feat.color}, transparent)` }} />
                            </motion.div>
                        );
                    })}
                </div>

            </div>
        </section>
    );
};

export default FeaturesSection;
