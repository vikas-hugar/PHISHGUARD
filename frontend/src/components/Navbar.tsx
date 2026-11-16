import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Shield, Menu, X, ScanLine, BarChart2 } from 'lucide-react';

const navLinks = [
    { label: 'Home', href: '#' },
    { label: 'How It Works', href: '#how-it-works' },
    { label: 'Demo', href: '#demo' },
    { label: 'Dashboard', href: '#dashboard' },
    { label: 'Architecture', href: '#architecture' },
    { label: 'About', href: '#about' },
];

const Navbar: React.FC = () => {
    const [scrolled, setScrolled] = useState(false);
    const [mobileOpen, setMobileOpen] = useState(false);
    const [activeSection, setActiveSection] = useState('');

    useEffect(() => {
        const onScroll = () => setScrolled(window.scrollY > 30);
        window.addEventListener('scroll', onScroll);
        return () => window.removeEventListener('scroll', onScroll);
    }, []);

    return (
        <>
            <motion.nav
                initial={{ y: -80, opacity: 0 }}
                animate={{ y: 0, opacity: 1 }}
                transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
                className={`fixed top-0 left-0 right-0 z-50 transition-all duration-500 ${scrolled
                    ? 'py-3'
                    : 'py-5'
                    }`}
                style={{
                    background: scrolled
                        ? 'rgba(6,11,24,0.92)'
                        : 'rgba(6,11,24,0)',
                    backdropFilter: scrolled ? 'blur(24px)' : 'none',
                    borderBottom: scrolled ? '1px solid rgba(0,174,239,0.12)' : '1px solid transparent',
                    boxShadow: scrolled ? '0 4px 30px rgba(0,0,0,0.4)' : 'none',
                }}
            >
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex items-center justify-between">

                        {/* Logo */}
                        <a href="#" className="flex items-center gap-2.5 group">
                            <div className="w-9 h-9 rounded-xl flex items-center justify-center transition-all duration-300 group-hover:shadow-glow-blue"
                                style={{
                                    background: 'linear-gradient(135deg, #00AEEF, #0077CC)',
                                    boxShadow: '0 0 15px rgba(0,174,239,0.3)',
                                }}>
                                <Shield className="w-5 h-5 text-white" />
                            </div>
                            <span className="text-lg font-bold text-white">
                                Phish<span style={{ color: '#00AEEF' }}>Guard</span>
                                <span className="text-xs ml-1 font-semibold px-1.5 py-0.5 rounded"
                                    style={{ background: 'rgba(0,174,239,0.15)', color: '#00AEEF', border: '1px solid rgba(0,174,239,0.3)' }}>
                                    AI
                                </span>
                            </span>
                        </a>

                        {/* Desktop nav */}
                        <div className="hidden lg:flex items-center gap-1">
                            {navLinks.map((link) => (
                                <a
                                    key={link.label}
                                    href={link.href}
                                    className="px-4 py-2 text-sm font-medium rounded-lg transition-all duration-200 text-gray-400 hover:text-white hover:bg-white/5"
                                >
                                    {link.label}
                                </a>
                            ))}
                        </div>

                        {/* Right side actions */}
                        <div className="hidden lg:flex items-center gap-3">
                            <a
                                href="#demo"
                                className="flex items-center gap-2 px-5 py-2.5 text-sm font-bold text-white rounded-xl transition-all duration-300"
                                style={{
                                    background: 'linear-gradient(135deg, #00AEEF, #0077CC)',
                                    boxShadow: '0 0 20px rgba(0,174,239,0.3)',
                                }}
                                onMouseEnter={e => {
                                    (e.currentTarget as HTMLElement).style.boxShadow = '0 0 35px rgba(0,174,239,0.55)';
                                    (e.currentTarget as HTMLElement).style.transform = 'translateY(-1px)';
                                }}
                                onMouseLeave={e => {
                                    (e.currentTarget as HTMLElement).style.boxShadow = '0 0 20px rgba(0,174,239,0.3)';
                                    (e.currentTarget as HTMLElement).style.transform = 'translateY(0)';
                                }}
                            >
                                <ScanLine className="w-4 h-4" />
                                Scan URL
                            </a>
                        </div>

                        {/* Mobile hamburger */}
                        <button
                            className="lg:hidden p-2 rounded-lg text-gray-400 hover:text-white hover:bg-white/5 transition-all"
                            onClick={() => setMobileOpen(!mobileOpen)}
                            aria-label="Toggle menu"
                        >
                            {mobileOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
                        </button>
                    </div>
                </div>
            </motion.nav>

            {/* ── Mobile menu overlay ── */}
            <motion.div
                initial={false}
                animate={{ opacity: mobileOpen ? 1 : 0, pointerEvents: mobileOpen ? 'auto' : 'none' }}
                transition={{ duration: 0.3 }}
                className="fixed inset-0 z-40 lg:hidden"
                style={{ background: 'rgba(6,11,24,0.97)', backdropFilter: 'blur(20px)' }}
            >
                <div className="flex flex-col items-center justify-center h-full gap-6">
                    {navLinks.map((link, i) => (
                        <motion.a
                            key={link.label}
                            href={link.href}
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: mobileOpen ? 1 : 0, y: mobileOpen ? 0 : 20 }}
                            transition={{ delay: i * 0.05 }}
                            onClick={() => setMobileOpen(false)}
                            className="text-2xl font-bold text-gray-300 hover:text-white transition-colors"
                        >
                            {link.label}
                        </motion.a>
                    ))}
                    <motion.a
                        href="#demo"
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: mobileOpen ? 1 : 0, y: mobileOpen ? 0 : 20 }}
                        transition={{ delay: navLinks.length * 0.05 }}
                        onClick={() => setMobileOpen(false)}
                        className="mt-4 flex items-center gap-2 px-8 py-4 text-lg font-bold text-white rounded-xl"
                        style={{ background: 'linear-gradient(135deg, #00AEEF, #0077CC)' }}
                    >
                        <ScanLine className="w-5 h-5" />
                        Scan URL
                    </motion.a>
                </div>
            </motion.div>
        </>
    );
};

export default Navbar;
