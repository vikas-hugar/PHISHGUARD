import React, { useRef, useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { ShieldAlert, Activity, Lock, ScanLine, ChevronRight, Zap } from 'lucide-react';

// ── Particle network canvas animation ──
const ParticleCanvas: React.FC = () => {
    const canvasRef = useRef<HTMLCanvasElement>(null);
    const mouseRef = useRef({ x: 0, y: 0 });

    useEffect(() => {
        const canvas = canvasRef.current;
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        let animId: number;
        const particles: Array<{
            x: number; y: number; vx: number; vy: number; radius: number; opacity: number;
        }> = [];
        const ripples: Array<{
            x: number; y: number; radius: number; maxRadius: number; opacity: number; speed: number;
        }> = [];
        const PARTICLE_COUNT = 80;
        const CONNECTION_DIST = 130;
        const CONNECTION_DIST = 130;

        const resize = () => {
            canvas.width = canvas.offsetWidth;
            canvas.height = canvas.offsetHeight;
        };
        resize();
        window.addEventListener('resize', resize);

        const handleMouse = (e: MouseEvent) => {
            const rect = canvas.getBoundingClientRect();
            mouseRef.current = { x: e.clientX - rect.left, y: e.clientY - rect.top };
        };

        const handleClick = (e: MouseEvent) => {
            const rect = canvas.getBoundingClientRect();
            const clickX = e.clientX - rect.left;
            const clickY = e.clientY - rect.top;
            
            // Add visual ripple
            ripples.push({
                x: clickX, y: clickY, radius: 0, maxRadius: 150 + Math.random() * 50, opacity: 1, speed: 8 + Math.random() * 4
            });

            // Apply outward velocity to particles
            for (const p of particles) {
                const dx = p.x - clickX;
                const dy = p.y - clickY;
                const dist = Math.sqrt(dx * dx + dy * dy);
                
                if (dist < 200) {
                    const force = (200 - dist) / 200; // 0 to 1
                    const angle = Math.atan2(dy, dx);
                    p.vx += Math.cos(angle) * force * 15;
                    p.vy += Math.sin(angle) * force * 15;
                }
            }
        };

        window.addEventListener('mousemove', handleMouse);
        window.addEventListener('mousedown', handleClick);

        // Init particles
        for (let i = 0; i < PARTICLE_COUNT; i++) {
            particles.push({
                x: Math.random() * canvas.width,
                y: Math.random() * canvas.height,
                vx: (Math.random() - 0.5) * 0.4,
                vy: (Math.random() - 0.5) * 0.4,
                radius: Math.random() * 1.5 + 0.5,
                opacity: Math.random() * 0.5 + 0.2,
            });
        }

        const draw = () => {
            ctx.clearRect(0, 0, canvas.width, canvas.height);

            // Update & draw particles
            for (const p of particles) {
                // Apply friction to velocity so they slow back down after a ripple
                p.vx *= 0.98;
                p.vy *= 0.98;
                
                // Keep base movement if too slow
                if (Math.abs(p.vx) < 0.2) p.vx += (Math.random() - 0.5) * 0.05;
                if (Math.abs(p.vy) < 0.2) p.vy += (Math.random() - 0.5) * 0.05;

                // Max speed cap
                p.vx = Math.max(Math.min(p.vx, 5), -5);
                p.vy = Math.max(Math.min(p.vy, 5), -5);

                p.x += p.vx;
                p.y += p.vy;
                if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
                if (p.y < 0 || p.y > canvas.height) p.vy *= -1;

                ctx.beginPath();
                ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
                ctx.fillStyle = `rgba(0, 174, 239, ${p.opacity})`;
                ctx.fill();
            }

            // Draw ripples
            for (let i = ripples.length - 1; i >= 0; i--) {
                const r = ripples[i];
                r.radius += r.speed;
                r.opacity -= 0.02;
                
                if (r.opacity <= 0 || r.radius >= r.maxRadius) {
                    ripples.splice(i, 1);
                    continue;
                }
                
                ctx.beginPath();
                ctx.arc(r.x, r.y, r.radius, 0, Math.PI * 2);
                ctx.strokeStyle = `rgba(0, 255, 178, ${r.opacity})`;
                ctx.lineWidth = 2;
                ctx.stroke();
            }

            // Draw connections
            for (let i = 0; i < particles.length; i++) {
                for (let j = i + 1; j < particles.length; j++) {
                    const dx = particles[i].x - particles[j].x;
                    const dy = particles[i].y - particles[j].y;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    if (dist < CONNECTION_DIST) {
                        const alpha = (1 - dist / CONNECTION_DIST) * 0.25;
                        ctx.beginPath();
                        ctx.moveTo(particles[i].x, particles[i].y);
                        ctx.lineTo(particles[j].x, particles[j].y);
                        ctx.strokeStyle = `rgba(0, 174, 239, ${alpha})`;
                        ctx.lineWidth = 0.8;
                        ctx.stroke();
                    }
                }

                // Mouse interaction
                const mx = mouseRef.current.x;
                const my = mouseRef.current.y;
                const dx = particles[i].x - mx;
                const dy = particles[i].y - my;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < 120) {
                    const alpha = (1 - dist / 120) * 0.5;
                    ctx.beginPath();
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(mx, my);
                    ctx.strokeStyle = `rgba(0, 255, 178, ${alpha})`;
                    ctx.lineWidth = 1;
                    ctx.stroke();
                }
            }
            animId = requestAnimationFrame(draw);
        };
        draw();

        return () => {
            cancelAnimationFrame(animId);
            window.removeEventListener('resize', resize);
            window.removeEventListener('mousemove', handleMouse);
            window.removeEventListener('mousedown', handleClick);
        };
    }, []);

    return <canvas ref={canvasRef} className="absolute inset-0 w-full h-full" />;
};

// ─────────────────────────────────────────────────
const HeroSection = () => {
    return (
        <section className="relative min-h-screen pt-28 pb-20 flex items-center justify-center overflow-hidden">
            {/* Layered animated background */}
            <div className="absolute inset-0 z-0">
                {/* Particle network */}
                <ParticleCanvas />

                {/* Grid overlay */}
                <div className="absolute inset-0 bg-grid opacity-100 pointer-events-none" />

                {/* Radial hero glow from top */}
                <div className="absolute inset-0" style={{
                    background: 'radial-gradient(ellipse 80% 60% at 50% -10%, rgba(0,174,239,0.15) 0%, transparent 65%)'
                }} />

                {/* Animated orbs */}
                <div className="absolute top-1/4 -left-20 w-[500px] h-[500px] rounded-full animate-blob animation-delay-2000"
                    style={{ background: 'radial-gradient(circle, rgba(0,174,239,0.12) 0%, transparent 70%)' }} />
                <div className="absolute bottom-1/4 -right-20 w-[400px] h-[400px] rounded-full animate-blob animation-delay-4000"
                    style={{ background: 'radial-gradient(circle, rgba(0,255,178,0.1) 0%, transparent 70%)' }} />
            </div>

            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10 w-full">
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 lg:gap-10 items-center">

                    {/* ── Left: Copy ── */}
                    <motion.div
                        initial={{ opacity: 0, x: -50 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.9, ease: [0.16, 1, 0.3, 1] }}
                        className="flex flex-col gap-7"
                    >
                        {/* Animated badge */}
                        <motion.div
                            initial={{ opacity: 0, y: -10 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: 0.15, duration: 0.6 }}
                            className="inline-flex items-center gap-2.5 w-fit rounded-full px-4 py-2"
                            style={{
                                border: '1px solid rgba(0,174,239,0.4)',
                                background: 'rgba(0,174,239,0.08)',
                                boxShadow: '0 0 20px rgba(0,174,239,0.15)',
                            }}
                        >
                            <span className="relative flex h-2.5 w-2.5">
                                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75" />
                                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-primary" />
                            </span>
                            <span className="text-xs font-semibold tracking-widest uppercase text-primary">
                                AI-Powered · Zero-Day Detection
                            </span>
                        </motion.div>

                        {/* Headline */}
                        <motion.h1
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: 0.2, duration: 0.8 }}
                            className="text-5xl lg:text-[4.5rem] font-bold tracking-tight leading-[1.08]"
                        >
                            Detect Phishing<br />
                            <span className="bg-clip-text text-transparent"
                                style={{ backgroundImage: 'linear-gradient(135deg, #00AEEF 0%, #00FFB2 100%)' }}>
                                Before It Strikes
                            </span>
                        </motion.h1>

                        {/* Tagline */}
                        <motion.p
                            initial={{ opacity: 0, y: 15 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: 0.3, duration: 0.7 }}
                            className="text-lg text-gray-400 max-w-xl leading-relaxed"
                        >
                            Real-time phishing URL detection powered by an <span className="text-primary font-semibold">optimized CNN–BiLSTM</span> deep learning model. 
                            Adaptable to zero-day attacks with 97.2% accuracy.
                        </motion.p>

                        {/* CTA buttons */}
                        <motion.div
                            initial={{ opacity: 0, y: 15 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: 0.4, duration: 0.7 }}
                            className="flex flex-wrap items-center gap-4"
                        >
                            <a href="#demo" className="btn-primary text-base">
                                <ScanLine className="w-5 h-5" />
                                Analyze a URL
                            </a>
                            <a href="#how-it-works" className="btn-outline text-base">
                                How It Works
                                <ChevronRight className="w-5 h-5" />
                            </a>
                        </motion.div>

                        {/* Stats row */}
                        <motion.div
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            transition={{ delay: 0.6, duration: 0.8 }}
                            className="flex items-center gap-10 mt-4 pt-8"
                            style={{ borderTop: '1px solid rgba(255,255,255,0.08)' }}
                        >
                            {[
                                { value: '97.2%', label: 'Detection Accuracy' },
                                { value: '<1s', label: 'Avg Response Time' },
                                { value: '235K+', label: 'URLs Trained On' },
                            ].map((s, i) => (
                                <div key={i} className="flex flex-col">
                                    <span className="text-2xl font-bold text-white glow-text-blue">{s.value}</span>
                                    <span className="text-xs text-gray-500 mt-0.5">{s.label}</span>
                                </div>
                            ))}
                        </motion.div>
                    </motion.div>

                    {/* ── Right: Live threat dashboard mockup ── */}
                    <motion.div
                        initial={{ opacity: 0, scale: 0.88 }}
                        animate={{ opacity: 1, scale: 1 }}
                        transition={{ duration: 1, delay: 0.25, ease: [0.16, 1, 0.3, 1] }}
                        className="relative w-full flex items-center justify-center"
                    >
                        {/* Wrapper to allow badges to float outside the hidden overflow */}
                        <div className="relative w-full max-w-lg">
                            
                            <div className="relative w-full rounded-2xl p-6 overflow-hidden"
                                style={{
                                    background: 'rgba(10,15,44,0.75)',
                                    border: '1px solid rgba(0,174,239,0.25)',
                                    backdropFilter: 'blur(24px)',
                                    boxShadow: '0 0 60px rgba(0,174,239,0.12), 0 30px 60px rgba(0,0,0,0.5)',
                                }}>

                            {/* Top accent line */}
                            <div className="absolute top-0 left-0 w-full h-px"
                                style={{ background: 'linear-gradient(90deg, transparent, #00AEEF, #00FFB2, transparent)' }} />

                            {/* Header */}
                            <div className="flex justify-between items-center mb-6">
                                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                                    <Activity className="w-4 h-4 text-primary" />
                                    Live Threat Monitor
                                </h3>
                                <div className="flex items-center gap-2 text-xs font-semibold px-2.5 py-1 rounded-lg"
                                    style={{ background: 'rgba(0,255,178,0.1)', color: '#00FFB2', border: '1px solid rgba(0,255,178,0.2)' }}>
                                    <span className="w-1.5 h-1.5 rounded-full bg-secondary animate-pulse" />
                                    System Active
                                </div>
                            </div>

                            {/* URL scan items */}
                            <div className="space-y-3 mb-6 relative">
                                {/* Vertical connection line */}
                                <div className="absolute left-[22px] top-4 bottom-4 w-px bg-gradient-to-b from-primary/30 via-secondary/30 to-transparent" />
                                
                                {[
                                    { url: 'auth-apple-secure.verify-account.com', status: 'suspicious', prob: '74%', color: '#FFB347' },
                                    { url: 'paypal-transaction-issue.net/login', status: 'phishing', prob: '99%', color: '#FF3B3B' },
                                    { url: 'github.com/microsoft/vscode', status: 'safe', prob: '0.1%', color: '#00FFB2' },
                                ].map((item, i) => (
                                    <motion.div
                                        key={i}
                                        initial={{ x: 50, opacity: 0 }}
                                        animate={{ x: 0, opacity: 1 }}
                                        transition={{ delay: 0.5 + i * 0.2 }}
                                        className="relative p-3.5 rounded-xl flex justify-between items-center gap-3 bg-white/[0.02] hover:bg-white/[0.04] transition-colors group"
                                        style={{
                                            border: `1px solid ${item.color}15`,
                                        }}
                                    >
                                        <div className="flex items-center gap-4 min-w-0">
                                            <div className="relative flex items-center justify-center w-8 h-8 rounded-lg shrink-0"
                                                style={{ background: `${item.color}10`, border: `1px solid ${item.color}30` }}>
                                                {item.status === 'phishing'
                                                    ? <ShieldAlert className="w-4 h-4" style={{ color: item.color }} />
                                                    : item.status === 'safe'
                                                        ? <Lock className="w-4 h-4" style={{ color: item.color }} />
                                                        : <Zap className="w-4 h-4" style={{ color: item.color }} />}
                                            </div>
                                            <div className="flex flex-col">
                                                <span className="text-xs font-mono text-gray-300 truncate group-hover:text-white transition-colors">{item.url}</span>
                                                <span className="text-[10px] uppercase tracking-wider mt-0.5" style={{ color: item.color }}>{item.status}</span>
                                            </div>
                                        </div>
                                        <div className="flex flex-col items-end gap-1 shrink-0">
                                            <span className="text-sm font-black" style={{ color: item.color }}>{item.prob}</span>
                                            <div className="w-16 h-1 bg-white/5 rounded-full overflow-hidden">
                                                <motion.div
                                                    initial={{ width: 0 }}
                                                    animate={{ width: item.prob }}
                                                    transition={{ delay: 0.7 + i * 0.2, duration: 0.8 }}
                                                    className="h-full rounded-full"
                                                    style={{ background: item.color, boxShadow: `0 0 10px ${item.color}` }}
                                                />
                                            </div>
                                        </div>
                                    </motion.div>
                                ))}
                            </div>

                            {/* Mini radar chart decoration */}
                            <div className="flex items-center justify-between px-2 py-3 mt-4" style={{ borderTop: '1px solid rgba(255,255,255,0.05)' }}>
                                <div className="flex items-center gap-4">
                                    <div className="relative w-12 h-12 flex items-center justify-center">
                                        <div className="absolute inset-0 rounded-full border border-primary/20" />
                                        <div className="absolute inset-2 rounded-full border border-primary/10" />
                                        <div className="absolute inset-0 rounded-full border-2 border-t-primary animate-radar-spin"
                                            style={{
                                                background: 'conic-gradient(rgba(0,174,239,0.15) 0deg, transparent 90deg)',
                                            }} />
                                        <Activity className="w-4 h-4 text-primary relative z-10" />
                                    </div>
                                    <div>
                                        <div className="text-sm font-bold text-white flex items-center gap-2">
                                            CNN–BiLSTM
                                            <span className="text-[10px] px-1.5 py-0.5 rounded-sm bg-primary/20 text-primary border border-primary/30">Active</span>
                                        </div>
                                        <div className="text-xs text-gray-500 mt-0.5 font-mono">1D-CNN → LSTM → Dense</div>
                                    </div>
                                </div>
                                
                                <div className="text-right">
                                    <div className="text-[10px] text-gray-500 uppercase tracking-widest mb-1">Status</div>
                                    <div className="text-xs font-semibold text-secondary glow-text-green">Monitoring</div>
                                </div>
                            </div>

                            </div>

                            {/* Floating badges (now outside overflow-hidden) */}
                            <motion.div
                                animate={{ y: [0, -8, 0] }}
                                transition={{ repeat: Infinity, duration: 4, ease: 'easeInOut' }}
                                className="absolute -right-4 -top-4 px-3 py-2 rounded-xl text-xs font-bold z-20"
                                style={{
                                    background: 'rgba(10,15,44,0.9)',
                                    border: '1px solid rgba(0,174,239,0.35)',
                                    backdropFilter: 'blur(12px)',
                                    boxShadow: '0 0 20px rgba(0,174,239,0.2)',
                                    color: '#00AEEF',
                                }}
                            >
                                97.2% Accuracy
                            </motion.div>

                            <motion.div
                                animate={{ y: [0, 8, 0] }}
                                transition={{ repeat: Infinity, duration: 5, ease: 'easeInOut', delay: 1 }}
                                className="absolute -right-8 bottom-12 px-3 py-2 rounded-xl text-xs font-bold z-20"
                                style={{
                                    background: 'rgba(10,15,44,0.9)',
                                    border: '1px solid rgba(0,255,178,0.3)',
                                    backdropFilter: 'blur(12px)',
                                    boxShadow: '0 0 20px rgba(0,255,178,0.15)',
                                    color: '#00FFB2',
                                }}
                            >
                                <span className="flex items-center gap-1.5">
                                    <ShieldAlert className="w-3.5 h-3.5" />
                                    Zero-Day Ready
                                </span>
                            </motion.div>
                        </div>
                    </motion.div>

                </div>
            </div>

            {/* Bottom gradient fade */}
            <div className="absolute bottom-0 left-0 right-0 h-32 pointer-events-none"
                style={{ background: 'linear-gradient(to top, #060B18, transparent)' }} />
        </section>
    );
};

export default HeroSection;
