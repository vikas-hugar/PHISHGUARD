import React from 'react';
import { motion } from 'framer-motion';
import { Lightbulb, TrendingUp, SearchCheck, Zap, BookOpen } from 'lucide-react';

const innovations = [
    {
        title: 'Spatial-Temporal Fusion',
        desc: 'We treat URLs as both spatial and sequential data simultaneously — CNN feature maps feed directly into LSTM input gates.',
        icon: Lightbulb,
        color: '#FFB347',
    },
    {
        title: 'Zero-Day Generalization',
        desc: 'Achieves 94%+ generalization on entirely unseen phishing campaigns without retraining — true zero-day adaptability.',
        icon: TrendingUp,
        color: '#00FFB2',
    },
    {
        title: 'Reduced False Positives',
        desc: 'Deep lexical context extraction reduced the false positive rate from the industry standard 3.2% down to 0.5%.',
        icon: SearchCheck,
        color: '#00AEEF',
    },
    {
        title: 'Sub-100ms Inference',
        desc: 'Post-training dropout pruning condensed model parameters — full inference in under 12ms per URL on standard CPU hardware.',
        icon: Zap,
        color: '#7C3AED',
    },
];

const ResearchSection: React.FC = () => {
    return (
        <section className="py-28 relative overflow-hidden">
            <div className="absolute inset-0 bg-dots opacity-20 pointer-events-none" />

            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-14 items-center">

                    {/* Left copy */}
                    <motion.div
                        initial={{ opacity: 0, x: -30 }}
                        whileInView={{ opacity: 1, x: 0 }}
                        viewport={{ once: true }}
                        className="flex flex-col gap-6"
                    >
                        <div className="section-label w-fit">Research Contributions</div>
                        <h2 className="text-4xl md:text-5xl font-bold">
                            Pushing the Bounds of{' '}
                            <span className="text-gradient-blue">Deep Learning</span>
                        </h2>
                        <p className="text-gray-400 text-lg leading-relaxed">
                            This project isn't just an implementation of existing models. We engineered a highly optimized spatial-temporal extraction pipeline tailored specifically for URL character sequence analysis — achieving results beyond the current state of the art.
                        </p>
                        <a href="#"
                            className="inline-flex items-center gap-2 w-fit px-6 py-3 rounded-xl text-sm font-bold text-white transition-all duration-300"
                            style={{
                                border: '1px solid rgba(0,174,239,0.3)',
                                background: 'rgba(0,174,239,0.06)',
                            }}
                            onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'rgba(0,174,239,0.12)'}
                            onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'rgba(0,174,239,0.06)'}
                        >
                            <BookOpen className="w-4 h-4 text-primary" />
                            <span style={{ color: '#00AEEF' }}>Read the Full Paper</span>
                        </a>
                    </motion.div>

                    {/* Right: 4 innovation cards */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        {innovations.map((item, i) => {
                            const Icon = item.icon;
                            return (
                                <motion.div
                                    key={i}
                                    initial={{ opacity: 0, y: 20 }}
                                    whileInView={{ opacity: 1, y: 0 }}
                                    viewport={{ once: true }}
                                    transition={{ delay: i * 0.1 }}
                                    className="p-6 rounded-2xl transition-all duration-300 group"
                                    style={{
                                        background: `${item.color}07`,
                                        border: `1px solid ${item.color}20`,
                                    }}
                                    whileHover={{
                                        borderColor: `${item.color}45`,
                                        boxShadow: `0 0 25px ${item.color}15`,
                                    }}
                                >
                                    <div className="w-10 h-10 rounded-xl flex items-center justify-center mb-4"
                                        style={{
                                            background: `${item.color}15`,
                                            border: `1px solid ${item.color}35`,
                                        }}>
                                        <Icon className="w-5 h-5" style={{ color: item.color }} />
                                    </div>
                                    <h4 className="text-white font-bold mb-2 text-sm">{item.title}</h4>
                                    <p className="text-xs text-gray-500 leading-relaxed">{item.desc}</p>
                                </motion.div>
                            );
                        })}
                    </div>
                </div>
            </div>
        </section>
    );
};

export default ResearchSection;
