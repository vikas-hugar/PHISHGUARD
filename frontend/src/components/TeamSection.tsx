import React from 'react';
import { motion } from 'framer-motion';
import { GraduationCap, User2, BookOpen } from 'lucide-react';

const TeamSection: React.FC = () => {
    return (
        <section id="team" className="py-28 relative overflow-hidden">
            <div className="absolute inset-0 bg-grid opacity-15 pointer-events-none" />
            <div className="absolute inset-0 pointer-events-none"
                style={{ background: 'radial-gradient(ellipse 70% 50% at 50% 50%, rgba(0,174,239,0.05) 0%, transparent 70%)' }} />

            <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">

                {/* Header */}
                <motion.div
                    initial={{ opacity: 0, y: 30 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    className="text-center mb-14"
                >
                    <div className="section-label mb-6 mx-auto">Project Presentation</div>
                    <h2 className="text-4xl md:text-5xl font-bold mb-3">
                        Academic <span className="text-gradient-blue">Context</span>
                    </h2>
                    <div className="flex items-center justify-center gap-2 mt-4 mb-2">
                        <GraduationCap className="w-5 h-5 text-primary" />
                        <span className="text-gray-300 font-medium text-sm">Final Year Engineering Project (2025–2026)</span>
                    </div>
                    <p className="text-gray-500 text-xs font-mono">Hybrid CNN–BiLSTM + RoBERTa Framework for Zero-Day Phishing Detection</p>
                </motion.div>

                {/* Cards */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

                    {/* Student card */}
                    <motion.div
                        initial={{ opacity: 0, x: -20 }}
                        whileInView={{ opacity: 1, x: 0 }}
                        viewport={{ once: true }}
                        className="rounded-2xl p-8 relative overflow-hidden group transition-all duration-300"
                        style={{
                            background: 'rgba(0,174,239,0.04)',
                            border: '1px solid rgba(0,174,239,0.15)',
                        }}
                        whileHover={{ borderColor: 'rgba(0,174,239,0.4)', boxShadow: '0 0 30px rgba(0,174,239,0.1)' }}
                    >
                        <div className="absolute -top-10 -right-10 w-40 h-40 rounded-full blur-3xl opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"
                            style={{ background: 'rgba(0,174,239,0.1)' }} />

                        <div className="w-12 h-12 rounded-xl flex items-center justify-center mb-6 text-primary"
                            style={{ background: 'rgba(0,174,239,0.12)', border: '1px solid rgba(0,174,239,0.25)' }}>
                            <User2 className="w-6 h-6" />
                        </div>
                        <p className="text-xs text-gray-600 uppercase tracking-widest font-bold mb-2">Developed By</p>
                        <h3 className="text-2xl font-bold text-white mb-1">[Your Name]</h3>
                        <p className="text-gray-500 text-sm mb-6">B.E. Computer Science & Engineering</p>
                        <div className="space-y-3">
                            {[
                                { label: 'USN / Roll No', value: '[Your USN]' },
                                { label: 'Role', value: 'Full Stack AI Developer' },
                                { label: 'Specialization', value: 'Deep Learning & Cybersecurity' },
                            ].map((r, i) => (
                                <div key={i} className="flex justify-between items-center py-2 text-sm"
                                    style={{ borderBottom: i < 2 ? '1px solid rgba(255,255,255,0.05)' : 'none' }}>
                                    <span className="text-gray-600">{r.label}</span>
                                    <span className="font-mono text-white text-xs">{r.value}</span>
                                </div>
                            ))}
                        </div>
                    </motion.div>

                    {/* Guide card */}
                    <motion.div
                        initial={{ opacity: 0, x: 20 }}
                        whileInView={{ opacity: 1, x: 0 }}
                        viewport={{ once: true }}
                        className="rounded-2xl p-8 relative overflow-hidden group transition-all duration-300"
                        style={{
                            background: 'rgba(0,255,178,0.03)',
                            border: '1px solid rgba(0,255,178,0.12)',
                        }}
                        whileHover={{ borderColor: 'rgba(0,255,178,0.35)', boxShadow: '0 0 30px rgba(0,255,178,0.08)' }}
                    >
                        <div className="absolute -top-10 -right-10 w-40 h-40 rounded-full blur-3xl opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"
                            style={{ background: 'rgba(0,255,178,0.08)' }} />

                        <div className="w-12 h-12 rounded-xl flex items-center justify-center mb-6 text-secondary"
                            style={{ background: 'rgba(0,255,178,0.1)', border: '1px solid rgba(0,255,178,0.25)' }}>
                            <BookOpen className="w-6 h-6" />
                        </div>
                        <p className="text-xs text-gray-600 uppercase tracking-widest font-bold mb-2">Under the Guidance Of</p>
                        <h3 className="text-2xl font-bold text-white mb-1">[Your Guide Name]</h3>
                        <p className="text-gray-500 text-sm mb-6">Professor, Dept of CSE</p>
                        <div className="space-y-3">
                            {[
                                { label: 'Institution', value: '[Your College]' },
                                { label: 'Academic Year', value: '2025 – 2026' },
                                { label: 'Degree', value: 'B.E. / B.Tech CSE' },
                            ].map((r, i) => (
                                <div key={i} className="flex justify-between items-center py-2 text-sm"
                                    style={{ borderBottom: i < 2 ? '1px solid rgba(255,255,255,0.05)' : 'none' }}>
                                    <span className="text-gray-600">{r.label}</span>
                                    <span className="font-mono text-white text-xs">{r.value}</span>
                                </div>
                            ))}
                        </div>
                    </motion.div>
                </div>

            </div>
        </section>
    );
};

export default TeamSection;
