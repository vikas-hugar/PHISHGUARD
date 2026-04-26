import React from 'react';
import { Shield, Github, Linkedin, Mail, ArrowRight, ExternalLink, ScanLine } from 'lucide-react';

const Footer: React.FC = () => {
    return (
        <footer className="relative overflow-hidden pt-20 pb-10"
            style={{
                background: '#040810',
                borderTop: '1px solid rgba(0,174,239,0.12)',
            }}>

            {/* Top glow */}
            <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[600px] h-px"
                style={{ background: 'linear-gradient(90deg, transparent, rgba(0,174,239,0.5), rgba(0,255,178,0.3), transparent)' }} />
            <div className="absolute top-0 left-1/2 -translate-x-1/2 w-96 h-32 pointer-events-none blur-3xl"
                style={{ background: 'rgba(0,174,239,0.07)' }} />

            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-12 mb-16">

                    {/* Brand col */}
                    <div className="lg:col-span-2">
                        <div className="flex items-center gap-2.5 mb-5">
                            <div className="w-9 h-9 rounded-xl flex items-center justify-center"
                                style={{ background: 'linear-gradient(135deg, #00AEEF, #0077CC)', boxShadow: '0 0 15px rgba(0,174,239,0.35)' }}>
                                <Shield className="w-5 h-5 text-white" />
                            </div>
                            <span className="text-lg font-bold text-white">
                                Phish<span style={{ color: '#00AEEF' }}>Guard</span>
                                <span className="text-xs ml-1 font-semibold px-1.5 py-0.5 rounded"
                                    style={{ background: 'rgba(0,174,239,0.15)', color: '#00AEEF', border: '1px solid rgba(0,174,239,0.3)' }}>AI</span>
                            </span>
                        </div>
                        <p className="text-gray-500 text-sm leading-relaxed max-w-sm mb-6">
                            A state-of-the-art CNN-LSTM deep learning model engineered to detect and prevent zero-day phishing attacks in real-time.
                            Final Year Engineering Project.
                        </p>
                        <div className="flex items-center gap-3 mb-6">
                            {[
                                { icon: Github, href: '#' },
                                { icon: Linkedin, href: '#' },
                                { icon: Mail, href: '#' },
                            ].map(({ icon: Icon, href }, i) => (
                                <a key={i} href={href}
                                    className="w-9 h-9 rounded-xl flex items-center justify-center text-gray-500 transition-all duration-200 hover:text-white"
                                    style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}
                                    onMouseEnter={e => (e.currentTarget as HTMLElement).style.borderColor = 'rgba(0,174,239,0.4)'}
                                    onMouseLeave={e => (e.currentTarget as HTMLElement).style.borderColor = 'rgba(255,255,255,0.08)'}
                                >
                                    <Icon className="w-4 h-4" />
                                </a>
                            ))}
                        </div>

                        {/* Quick scan CTA */}
                        <a href="#demo"
                            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-bold text-white transition-all duration-300"
                            style={{
                                background: 'linear-gradient(135deg, #00AEEF22, #00AEEF11)',
                                border: '1px solid rgba(0,174,239,0.3)',
                            }}
                            onMouseEnter={e => {
                                (e.currentTarget as HTMLElement).style.background = 'rgba(0,174,239,0.15)';
                                (e.currentTarget as HTMLElement).style.borderColor = 'rgba(0,174,239,0.5)';
                            }}
                            onMouseLeave={e => {
                                (e.currentTarget as HTMLElement).style.background = 'linear-gradient(135deg, #00AEEF22, #00AEEF11)';
                                (e.currentTarget as HTMLElement).style.borderColor = 'rgba(0,174,239,0.3)';
                            }}
                        >
                            <ScanLine className="w-4 h-4 text-primary" />
                            <span style={{ color: '#00AEEF' }}>Try URL Scanner</span>
                        </a>
                    </div>

                    {/* Quick links */}
                    <div>
                        <h3 className="text-white font-semibold mb-5 text-sm uppercase tracking-wider">Project Links</h3>
                        <ul className="space-y-3">
                            {[
                                'Research Paper',
                                'Documentation',
                                'Source Code (GitHub)',
                                'Model Architecture',
                                'Dataset Info',
                            ].map((label, i) => (
                                <li key={i}>
                                    <a href="#" className="flex items-center gap-2 text-sm text-gray-500 hover:text-primary transition-colors duration-200 group">
                                        <ExternalLink className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 transition-opacity" />
                                        {label}
                                    </a>
                                </li>
                            ))}
                        </ul>
                    </div>

                    {/* Contact form */}
                    <div>
                        <h3 className="text-white font-semibold mb-5 text-sm uppercase tracking-wider">Get in Touch</h3>
                        <form className="space-y-3" onSubmit={e => e.preventDefault()}>
                            <input
                                type="email"
                                placeholder="your@email.com"
                                className="w-full py-2.5 px-4 rounded-xl text-sm text-white placeholder-gray-600 outline-none transition-all duration-200 font-sans"
                                style={{
                                    background: 'rgba(255,255,255,0.04)',
                                    border: '1px solid rgba(255,255,255,0.08)',
                                }}
                                onFocus={e => (e.target as HTMLElement).style.borderColor = 'rgba(0,174,239,0.4)'}
                                onBlur={e => (e.target as HTMLElement).style.borderColor = 'rgba(255,255,255,0.08)'}
                            />
                            <textarea
                                placeholder="Your message…"
                                rows={3}
                                className="w-full py-2.5 px-4 rounded-xl text-sm text-white placeholder-gray-600 outline-none transition-all duration-200 resize-none font-sans"
                                style={{
                                    background: 'rgba(255,255,255,0.04)',
                                    border: '1px solid rgba(255,255,255,0.08)',
                                }}
                                onFocus={e => (e.target as HTMLElement).style.borderColor = 'rgba(0,174,239,0.4)'}
                                onBlur={e => (e.target as HTMLElement).style.borderColor = 'rgba(255,255,255,0.08)'}
                            />
                            <button
                                type="submit"
                                className="w-full py-2.5 rounded-xl text-sm font-bold text-white flex items-center justify-center gap-2 transition-all duration-300"
                                style={{ background: 'linear-gradient(135deg, #00AEEF, #0077CC)' }}
                            >
                                Send Message <ArrowRight className="w-4 h-4" />
                            </button>
                        </form>
                    </div>
                </div>

                {/* Bottom bar */}
                <div className="pt-8 flex flex-col md:flex-row justify-between items-center gap-4"
                    style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                    <p className="text-gray-600 text-xs font-mono">
                        © {new Date().getFullYear()} PhishGuard AI — Final Year Project · CNN-LSTM Phishing Detection
                    </p>
                    <div className="flex gap-6 text-xs text-gray-600">
                        <a href="#" className="hover:text-gray-400 transition-colors">Privacy</a>
                        <a href="#" className="hover:text-gray-400 transition-colors">Terms</a>
                        <a href="#" className="hover:text-gray-400 transition-colors">API Docs</a>
                    </div>
                </div>
            </div>
        </footer>
    );
};

export default Footer;
