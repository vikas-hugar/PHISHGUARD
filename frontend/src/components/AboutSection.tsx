import React from 'react';
import { motion } from 'framer-motion';
import { AlertTriangle, Network, Cpu, BookOpen, GraduationCap } from 'lucide-react';

const AboutSection: React.FC = () => {
    return (
        <section id="about" className="py-28 relative overflow-hidden">
            {/* Background */}
            <div className="absolute inset-0 bg-dots opacity-20 pointer-events-none" />
            <div className="absolute inset-0 pointer-events-none"
                style={{ background: 'radial-gradient(ellipse 50% 60% at 50% 100%, rgba(0,174,239,0.06) 0%, transparent 60%)' }} />

            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">

                {/* Header */}
                <motion.div
                    initial={{ opacity: 0, y: 30 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    className="text-center mb-16"
                >
                    <div className="section-label mb-6 mx-auto">Research Context</div>
                    <h2 className="text-4xl md:text-5xl font-bold mb-5">
                        The <span className="text-gradient-blue">Zero-Day</span> Problem
                    </h2>
                    <p className="text-gray-400 text-lg max-w-2xl mx-auto">
                        Traditional detection systems fail against previously unseen phishing attacks. Our research proposes an adaptable Hybrid CNN–BiLSTM + RoBERTa framework that learns patterns — not blacklists.
                    </p>
                </motion.div>

                {/* Cards */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-14">
                    {/* Problem card */}
                    <motion.div
                        initial={{ opacity: 0, y: 30 }}
                        whileInView={{ opacity: 1, y: 0 }}
                        viewport={{ once: true }}
                        transition={{ duration: 0.6 }}
                        className="group rounded-2xl p-8 transition-all duration-300 relative overflow-hidden"
                        style={{
                            background: 'rgba(255,59,59,0.04)',
                            border: '1px solid rgba(255,59,59,0.15)',
                        }}
                        whileHover={{ borderColor: 'rgba(255,59,59,0.35)', boxShadow: '0 0 30px rgba(255,59,59,0.1)' }}
                    >
                        <div className="absolute -top-10 -right-10 w-40 h-40 rounded-full blur-3xl opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"
                            style={{ background: 'rgba(255,59,59,0.12)' }} />

                        <div className="w-12 h-12 rounded-xl flex items-center justify-center mb-6"
                            style={{ background: 'rgba(255,59,59,0.12)', border: '1px solid rgba(255,59,59,0.3)' }}>
                            <AlertTriangle className="w-6 h-6 text-dangerous" />
                        </div>
                        <h3 className="text-xl font-bold mb-3 text-white">Why Traditional Methods Fail</h3>
                        <p className="text-gray-400 text-sm leading-relaxed mb-6">
                            Blocklists and heuristic systems operate reactively — they can only block URLs that have already been reported. Sophisticated attackers generate thousands of new obfuscated domains daily, creating a critical vulnerability window.
                        </p>
                        <ul className="space-y-3">
                            {[
                                'Blocklists are always one step behind attackers',
                                'Ad-hoc obfuscation bypasses simple regex detection',
                                'Manual feature engineering misses complex sequential patterns',
                                'New TLDs and IDN homograph attacks are ignored',
                            ].map((item, i) => (
                                <li key={i} className="flex items-start gap-3 text-sm text-gray-400">
                                    <div className="mt-1.5 w-1.5 h-1.5 rounded-full shrink-0" style={{ background: '#FF3B3B99' }} />
                                    {item}
                                </li>
                            ))}
                        </ul>
                    </motion.div>

                    {/* Solution card */}
                    <motion.div
                        initial={{ opacity: 0, y: 30 }}
                        whileInView={{ opacity: 1, y: 0 }}
                        viewport={{ once: true }}
                        transition={{ duration: 0.6, delay: 0.15 }}
                        className="group rounded-2xl p-8 transition-all duration-300 relative overflow-hidden"
                        style={{
                            background: 'rgba(0,174,239,0.04)',
                            border: '1px solid rgba(0,174,239,0.15)',
                        }}
                        whileHover={{ borderColor: 'rgba(0,174,239,0.35)', boxShadow: '0 0 30px rgba(0,174,239,0.1)' }}
                    >
                        <div className="absolute -top-10 -right-10 w-40 h-40 rounded-full blur-3xl opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"
                            style={{ background: 'rgba(0,174,239,0.12)' }} />

                        <div className="w-12 h-12 rounded-xl flex items-center justify-center mb-6"
                            style={{ background: 'rgba(0,174,239,0.12)', border: '1px solid rgba(0,174,239,0.3)' }}>
                            <Network className="w-6 h-6 text-primary" />
                        </div>
                        <h3 className="text-xl font-bold mb-3 text-white">Why Hybrid AI Wins</h3>
                        <p className="text-gray-400 text-sm leading-relaxed mb-6">
                            The hybrid architecture combines structural CNN features, BiLSTM sequential memory, and RoBERTa semantic understanding to detect sophisticated zero-day phishing URLs.
                        </p>
                        <ul className="space-y-3.5">
                            {[
                                { title: 'CNN extracts structural URL patterns', desc: 'Captures spatial character arrangements, anomalous subdomains, and obfuscated TLDs.' },
                                { title: 'BiLSTM captures long-range dependencies', desc: 'Maintains sequential context across extended URLs to detect split tokens.' },
                                { title: 'RoBERTa understands semantic phishing intent', desc: 'Transformer NLP analyzes brand impersonation, urgency cues, and context.' },
                                { title: 'Hybrid fusion reduces false positives', desc: 'Weighted 35% CNN + 65% RoBERTa decision engine yields reliable verdicts.' },
                            ].map((item, i) => (
                                <li key={i} className="flex items-start gap-3">
                                    <div className="mt-1.5 w-1.5 h-1.5 rounded-full shrink-0" style={{ background: '#00FFB2' }} />
                                    <div>
                                        <p className="text-sm font-bold text-white leading-snug">{item.title}</p>
                                        <p className="text-xs text-gray-500 mt-0.5">{item.desc}</p>
                                    </div>
                                </li>
                            ))}
                        </ul>
                    </motion.div>
                </div>

                {/* Research info strip */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    transition={{ delay: 0.2 }}
                    className="rounded-2xl p-7 flex flex-col md:flex-row items-center justify-between gap-8"
                    style={{
                        background: 'rgba(10,15,44,0.6)',
                        border: '1px solid rgba(0,174,239,0.15)',
                        backdropFilter: 'blur(16px)',
                    }}
                >
                    <div className="flex items-center gap-5">
                        <div className="w-14 h-14 rounded-2xl flex items-center justify-center shrink-0"
                            style={{ background: 'rgba(0,174,239,0.12)', border: '1px solid rgba(0,174,239,0.25)' }}>
                            <GraduationCap className="w-7 h-7 text-primary" />
                        </div>
                        <div>
                            <div className="text-xs text-gray-500 uppercase tracking-widest mb-1">Final Year Engineering Project (2025–2026)</div>
                            <h3 className="font-bold text-white text-lg">
                                PhishGuard AI V3
                            </h3>
                            <p className="text-sm text-gray-400 mt-0.5">Using a Hybrid CNN–BiLSTM + RoBERTa Deep Learning Framework</p>
                        </div>
                    </div>
                    <div className="flex flex-wrap gap-2.5 shrink-0">
                        {['Deep Learning', 'CNN', 'BiLSTM', 'RoBERTa', 'Cybersecurity', 'Flask API', 'React'].map(tag => (
                            <span key={tag} className="text-xs px-3 py-1.5 rounded-full font-semibold"
                                style={{
                                    background: 'rgba(0,174,239,0.08)',
                                    border: '1px solid rgba(0,174,239,0.2)',
                                    color: '#00AEEF',
                                }}>
                                {tag}
                            </span>
                        ))}
                    </div>
                </motion.div>

            </div>
        </section>
    );
};

export default AboutSection;
