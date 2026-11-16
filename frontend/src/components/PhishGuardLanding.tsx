"use client";

import React, { useEffect, useRef, useState } from "react";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Cpu,
  Binary,
  Eye,
  Activity,
  ArrowRight,
  ExternalLink,
  Search,
  Lock,
  Layers,
  Sparkles,
  Terminal,
  CheckCircle2,
  ChevronRight,
  Database,
  Globe,
  Radio,
  Sliders,
} from "lucide-react";

// ─── Constants ────────────────────────────────────────────────────────────────
const BALL_SIZE = 380; // px — fixed diameter during Phase 1 travel per original component

interface PhishGuardLandingProps {
  onLaunchScanner: () => void;
  onExploreCapabilities?: () => void;
}

// ─── Root Landing Component ───────────────────────────────────────────────────
export default function PhishGuardLanding({ onLaunchScanner }: PhishGuardLandingProps) {
  const wrapperRef = useRef<HTMLDivElement>(null);
  const capabilitiesRef = useRef<HTMLDivElement>(null);

  const scrollToCapabilities = () => {
    if (capabilitiesRef.current) {
      capabilitiesRef.current.scrollIntoView({ behavior: "smooth" });
    }
  };

  return (
    <div className="bg-black text-white selection:bg-white selection:text-black font-sans min-h-screen">
      <LandingNavbar onLaunchScanner={onLaunchScanner} onScrollToSection={scrollToCapabilities} />

      {/* ── Section 1: Animated Inversion Circle Hero ── */}
      <InversionCircleHero
        wrapperRef={wrapperRef}
        onLaunchScanner={onLaunchScanner}
        onExplore={scrollToCapabilities}
      />

      {/* ── Section 2: Introduction (Scroll-revealed) ── */}
      <IntroductionSection />

      {/* ── Section 3: Protection Capabilities ── */}
      <div ref={capabilitiesRef}>
        <CapabilitiesSection onLaunchScanner={onLaunchScanner} />
      </div>

      {/* ── Section 4: Detection Workflow ── */}
      <WorkflowSection />

      {/* ── Section 5: Technology & Subsystems ── */}
      <TechnologySection />

      {/* ── Section 6: Final CTA ── */}
      <FinalCTASection onLaunchScanner={onLaunchScanner} />

      {/* ── Minimalist Monochrome Footer ── */}
      <MonochromeFooter onLaunchScanner={onLaunchScanner} />
    </div>
  );
}

// ─── Navbar ───────────────────────────────────────────────────────────────────
function LandingNavbar({
  onLaunchScanner,
  onScrollToSection,
}: {
  onLaunchScanner: () => void;
  onScrollToSection: () => void;
}) {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 40);
    };
    window.addEventListener("scroll", handleScroll, { passive: true });
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  return (
    <nav
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        scrolled
          ? "bg-black/90 backdrop-blur-md border-b border-[#1A1A1A] py-3.5"
          : "bg-transparent py-5"
      }`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center justify-between">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-white flex items-center justify-center text-black font-black text-sm">
            PG
          </div>
          <div className="flex items-center gap-2">
            <span className="font-extrabold tracking-tight text-white text-base">
              PHISHGUARD AI
            </span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#111111] text-[#808080] border border-[#1A1A1A]">
              V7.0
            </span>
          </div>
        </div>

        {/* Links */}
        <div className="hidden md:flex items-center gap-8 text-xs uppercase tracking-widest text-[#808080]">
          <button
            onClick={onScrollToSection}
            className="hover:text-white transition-colors cursor-pointer"
          >
            Capabilities
          </button>
          <a href="#workflow" className="hover:text-white transition-colors cursor-pointer">
            Workflow
          </a>
          <a href="#technology" className="hover:text-white transition-colors cursor-pointer">
            Technology
          </a>
          <a href="#soc" className="hover:text-white transition-colors cursor-pointer">
            Architecture
          </a>
        </div>

        {/* CTA */}
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={onLaunchScanner}
            className="px-4 py-2 text-xs font-semibold rounded bg-white text-black hover:opacity-90 transition-opacity cursor-pointer flex items-center gap-2"
          >
            <span>LAUNCH SCANNER</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </nav>
  );
}

// ─── Section 1: Inversion Circle Hero ─────────────────────────────────────────
/**
 * Exactly implements the original inversion-circle-scroll-animation mechanics:
 * - 300vh scroll track with sticky 100vh hero
 * - Phase 1 (0 -> viewH): Circle rises from below viewport to dead-centre (Power4 InOut)
 * - Phase 2 (viewH -> 2*viewH): Circle expands to cover screen (ease-in-squared)
 * - CSS clip-path mirrors circle position to invert text colors (black layer + white clipped layer)
 */
function InversionCircleHero({
  wrapperRef,
  onLaunchScanner,
  onExplore,
}: {
  wrapperRef: React.RefObject<HTMLDivElement | null>;
  onLaunchScanner: () => void;
  onExplore: () => void;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [scrollY, setScrollY] = useState(0);
  const [viewH, setViewH] = useState(800);
  const [viewW, setViewW] = useState(1200);

  useEffect(() => {
    const measure = () => {
      setViewH(window.innerHeight || 800);
      setViewW(window.innerWidth || 1200);
    };
    measure();

    const handleScroll = () => {
      if (containerRef.current) {
        const rect = containerRef.current.getBoundingClientRect();
        // scroll relative to top of track
        const currentScroll = -rect.top;
        setScrollY(Math.max(0, currentScroll));
      }
    };

    window.addEventListener("resize", measure);
    window.addEventListener("scroll", handleScroll, { passive: true });
    handleScroll();

    return () => {
      window.removeEventListener("resize", measure);
      window.removeEventListener("scroll", handleScroll);
    };
  }, []);

  // clamp helper
  const clamp = (v: number) => Math.min(1, Math.max(0, v));

  // Phase progress 0 -> 1
  const p1 = clamp(scrollY / viewH);
  const p2 = clamp((scrollY - viewH) / viewH);

  // Power4 InOut easing
  const p1e = p1 < 0.5 ? 8 * p1 ** 4 : 1 - (-2 * p1 + 2) ** 4 / 2;

  // Ease-in squared expansion
  const p2e = p2 * p2;

  // Geometry
  const yOff = (1 - p1e) * (viewH / 2 + BALL_SIZE / 2);
  const coverSize = Math.max(viewW, viewH) * 2.8;
  const ballSize = BALL_SIZE + p2e * (coverSize - BALL_SIZE);
  const clipX = viewW / 2;
  const clipY = viewH / 2 + yOff;
  const clipR = ballSize / 2;

  return (
    <div ref={containerRef} className="relative h-[300vh] bg-white">
      <div className="sticky top-0 h-screen w-full overflow-hidden bg-white select-none">
        {/* Expanding black circle */}
        <div
          className="absolute top-1/2 left-1/2 rounded-full bg-black pointer-events-none will-change-transform"
          style={{
            width: ballSize,
            height: ballSize,
            transform: `translate(-50%, calc(-50% + ${yOff}px))`,
          }}
        />

        {/* ── Dark Text Layer (Visible on White Background) ── */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center px-4 z-10 pointer-events-auto">
          <div className="max-w-4xl mx-auto space-y-6 text-black">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-black/20 bg-black/5 text-[11px] font-mono uppercase tracking-widest text-black/70">
              <span className="w-2 h-2 rounded-full bg-black animate-pulse" />
              HYBRID ZERO-DAY DETECTION ENGINE
            </div>

            <h1 className="text-5xl sm:text-7xl md:text-8xl font-black tracking-tighter leading-none text-black">
              PHISHGUARD AI
            </h1>

            <p className="text-xl sm:text-2xl md:text-3xl font-semibold tracking-tight text-black/90">
              Stay Ahead of Every Threat.
            </p>

            <p className="text-sm sm:text-base md:text-lg text-black/70 max-w-2xl mx-auto leading-relaxed">
              Advanced AI-powered phishing detection with intelligent threat analysis and isolated
              browser inspection.
            </p>

            <div className="flex flex-wrap items-center justify-center gap-4 pt-4">
              <button
                type="button"
                onClick={onExplore}
                className="px-6 py-3 rounded-md bg-black text-white text-xs sm:text-sm font-bold uppercase tracking-wider hover:opacity-90 transition-all cursor-pointer shadow-lg"
              >
                EXPLORE PHISHGUARD
              </button>

              <button
                type="button"
                onClick={onLaunchScanner}
                className="px-6 py-3 rounded-md border-2 border-black text-black text-xs sm:text-sm font-bold uppercase tracking-wider hover:bg-black hover:text-white transition-all cursor-pointer"
              >
                LAUNCH SCANNER
              </button>
            </div>

            <div className="pt-8 text-black/40 text-[11px] uppercase tracking-widest font-mono">
              Scroll down to reveal the architecture
            </div>
          </div>
        </div>

        {/* ── Light Text Layer (Clipped to Expanding Black Circle -> Color Inversion) ── */}
        <div
          className="absolute inset-0 flex flex-col items-center justify-center text-center px-4 z-20 pointer-events-auto will-change-[clip-path]"
          style={{
            clipPath: `circle(${clipR}px at ${clipX}px ${clipY}px)`,
          }}
        >
          <div className="max-w-4xl mx-auto space-y-6 text-white">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-white/20 bg-white/10 text-[11px] font-mono uppercase tracking-widest text-white/80">
              <span className="w-2 h-2 rounded-full bg-white animate-pulse" />
              HYBRID ZERO-DAY DETECTION ENGINE
            </div>

            <h1 className="text-5xl sm:text-7xl md:text-8xl font-black tracking-tighter leading-none text-white">
              PHISHGUARD AI
            </h1>

            <p className="text-xl sm:text-2xl md:text-3xl font-semibold tracking-tight text-white/95">
              Stay Ahead of Every Threat.
            </p>

            <p className="text-sm sm:text-base md:text-lg text-white/75 max-w-2xl mx-auto leading-relaxed">
              Advanced AI-powered phishing detection with intelligent threat analysis and isolated
              browser inspection.
            </p>

            <div className="flex flex-wrap items-center justify-center gap-4 pt-4">
              <button
                type="button"
                onClick={onExplore}
                className="px-6 py-3 rounded-md bg-white text-black text-xs sm:text-sm font-bold uppercase tracking-wider hover:opacity-90 transition-all cursor-pointer shadow-lg"
              >
                EXPLORE PHISHGUARD
              </button>

              <button
                type="button"
                onClick={onLaunchScanner}
                className="px-6 py-3 rounded-md border-2 border-white text-white text-xs sm:text-sm font-bold uppercase tracking-wider hover:bg-white hover:text-black transition-all cursor-pointer"
              >
                LAUNCH SCANNER
              </button>
            </div>

            <div className="pt-8 text-white/40 text-[11px] uppercase tracking-widest font-mono">
              Scroll down to reveal the architecture
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Section 2: Introduction ──────────────────────────────────────────────────
/**
 * Uses the original content-section reveal mechanics with IntersectionObserver
 * and smooth transition timing.
 */
function IntroductionSection() {
  const sectionRef = useRef<HTMLElement>(null);
  const [isInView, setIsInView] = useState(false);

  useEffect(() => {
    const el = sectionRef.current;
    if (!el) return;

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) setIsInView(true);
      },
      { threshold: 0.25 }
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  return (
    <section
      ref={sectionRef}
      className={`py-32 px-4 transition-colors duration-1000 ${
        isInView ? "bg-black text-white" : "bg-black text-white"
      }`}
    >
      <div className="max-w-4xl mx-auto text-center space-y-8">
        <span
          className={`text-xs uppercase tracking-[0.25em] font-mono text-[#808080] block transition-all duration-700 ${
            isInView ? "opacity-100 translate-y-0" : "opacity-0 translate-y-6"
          }`}
        >
          Introduction
        </span>

        <h2
          className={`text-4xl sm:text-6xl font-black tracking-tight leading-tight transition-all duration-700 delay-100 ${
            isInView ? "opacity-100 translate-y-0" : "opacity-0 translate-y-6"
          }`}
        >
          SECURITY THAT THINKS AHEAD.
        </h2>

        <p
          className={`text-lg sm:text-xl text-[#808080] max-w-2xl mx-auto leading-relaxed transition-all duration-700 delay-200 ${
            isInView ? "opacity-100 translate-y-0" : "opacity-0 translate-y-6"
          }`}
        >
          Traditional blacklists detect phishing only after victims have fallen. PhishGuard AI
          re-engineers zero-day defense through dual-stream spatial character convolutions,
          bidirectional memory networks, transformer semantic NLP, and isolated VirtualBox execution.
        </p>

        {/* 3 Metric Pills */}
        <div
          className={`grid grid-cols-1 sm:grid-cols-3 gap-4 pt-8 transition-all duration-700 delay-300 ${
            isInView ? "opacity-100 translate-y-0" : "opacity-0 translate-y-6"
          }`}
        >
          <div className="p-6 rounded-xl bg-[#111111] border border-[#1A1A1A] text-left">
            <span className="text-3xl font-extrabold text-white block">95.17%</span>
            <span className="text-xs font-mono text-[#808080] uppercase tracking-wider mt-1 block">
              Validation Accuracy
            </span>
          </div>

          <div className="p-6 rounded-xl bg-[#111111] border border-[#1A1A1A] text-left">
            <span className="text-3xl font-extrabold text-white block">&lt; 215ms</span>
            <span className="text-xs font-mono text-[#808080] uppercase tracking-wider mt-1 block">
              Inference Latency
            </span>
          </div>

          <div className="p-6 rounded-xl bg-[#111111] border border-[#1A1A1A] text-left">
            <span className="text-3xl font-extrabold text-white block">2.12M+</span>
            <span className="text-xs font-mono text-[#808080] uppercase tracking-wider mt-1 block">
              Threat Signatures
            </span>
          </div>
        </div>
      </div>
    </section>
  );
}

// ─── Section 3: Protection Capabilities ───────────────────────────────────────
function CapabilitiesSection({ onLaunchScanner }: { onLaunchScanner: () => void }) {
  const capabilities = [
    {
      id: "01",
      icon: Cpu,
      title: "AI-Powered Phishing Detection",
      subtitle: "Hybrid CNN-BiLSTM + RoBERTa Fusion",
      desc: "Combines 256 Conv1D spatial character filters with 128 BiLSTM sequential tokens and fine-tuned RoBERTa transformer attention for comprehensive structural and semantic analysis.",
      metric: "94.63% Precision",
    },
    {
      id: "02",
      icon: ShieldAlert,
      title: "Zero-Day Threat Analysis",
      subtitle: "Unseen Attack Signature Generalization",
      desc: "Identifies never-before-seen phishing patterns without relying on obsolete static blacklists, isolating adversarial permutations, punycode spoofing, and lexical obfuscations.",
      metric: "94.87% Zero-Day Recall",
    },
    {
      id: "03",
      icon: Activity,
      title: "Behavioral Intelligence",
      subtitle: "Dynamic DOM Mutation & Form Inspection",
      desc: "Deep inspection engine detects credential harvesting forms, deceptive redirects, homoglyph substitutions, Shannon entropy spikes, and illicit write operations.",
      metric: "18+ Security Heuristics",
    },
    {
      id: "04",
      icon: Eye,
      title: "Isolated Browser Sandbox",
      subtitle: "VirtualBox VM Execution Environment",
      desc: "Renders live untrusted targets in a secure VirtualBox VM sandbox with complete write blocking, allowing safe visual inspection and forensic screenshot capture.",
      metric: "Zero Client Risk",
    },
  ];

  return (
    <section id="capabilities" className="py-28 px-4 bg-[#000000] border-t border-[#1A1A1A]">
      <div className="max-w-7xl mx-auto">
        <div className="text-center max-w-3xl mx-auto mb-20 space-y-4">
          <span className="text-xs uppercase tracking-[0.25em] font-mono text-[#808080] block">
            Capabilities
          </span>
          <h2 className="text-4xl sm:text-5xl font-black tracking-tight text-white">
            FOUR PILLARS OF ZERO-DAY DEFENSE
          </h2>
          <p className="text-sm sm:text-base text-[#808080]">
            Engineered from ground up to inspect, analyze, and neutralize web threats in real time.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {capabilities.map((cap) => {
            const Icon = cap.icon;
            return (
              <div
                key={cap.id}
                className="p-8 rounded-2xl bg-[#111111] border border-[#1A1A1A] hover:border-[#808080] transition-all duration-300 group flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-6">
                    <div className="w-12 h-12 rounded-xl bg-black border border-[#1A1A1A] flex items-center justify-center text-white group-hover:bg-white group-hover:text-black transition-colors">
                      <Icon className="w-6 h-6" />
                    </div>
                    <span className="font-mono text-xs font-bold text-[#808080]">{cap.id}</span>
                  </div>

                  <h3 className="text-xl font-bold text-white mb-1.5">{cap.title}</h3>
                  <p className="text-xs font-mono text-[#808080] mb-4">{cap.subtitle}</p>
                  <p className="text-sm text-[#808080] leading-relaxed mb-6">{cap.desc}</p>
                </div>

                <div className="pt-4 border-t border-[#1A1A1A] flex items-center justify-between">
                  <span className="text-xs font-mono text-white font-semibold">{cap.metric}</span>
                  <button
                    onClick={onLaunchScanner}
                    className="text-xs font-mono text-[#808080] group-hover:text-white flex items-center gap-1 transition-colors cursor-pointer"
                  >
                    <span>Test in Sandbox</span>
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}

// ─── Section 4: Detection Workflow ───────────────────────────────────────────
function WorkflowSection() {
  const steps = [
    {
      num: "01",
      title: "URL Submission",
      desc: "User inputs target link or real-time network stream ingests suspicious URL.",
    },
    {
      num: "02",
      title: "Feature Extraction",
      desc: "Computes Shannon entropy, punycode resolution, token n-grams, and homoglyphs.",
    },
    {
      num: "03",
      title: "AI Analysis",
      desc: "Dual-stream CNN-BiLSTM structural extractor and RoBERTa semantic encoder compute scores.",
    },
    {
      num: "04",
      title: "Sandbox Inspection",
      desc: "Headless Chromium & VirtualBox VM sandbox loads DOM, executing read-only forensic probe.",
    },
    {
      num: "05",
      title: "Risk Assessment",
      desc: "Dynamic weighted fusion calibrates probability against 2.1M threat repository signatures.",
    },
    {
      num: "06",
      title: "Final Verdict",
      desc: "Generates instant monochrome classification (Safe, Suspicious, Malicious) with explanations.",
    },
  ];

  return (
    <section id="workflow" className="py-28 px-4 bg-[#0A0A0A] border-t border-[#1A1A1A]">
      <div className="max-w-7xl mx-auto">
        <div className="text-center max-w-3xl mx-auto mb-20 space-y-4">
          <span className="text-xs uppercase tracking-[0.25em] font-mono text-[#808080] block">
            Pipeline Architecture
          </span>
          <h2 className="text-4xl sm:text-5xl font-black tracking-tight text-white">
            DETECTION WORKFLOW
          </h2>
          <p className="text-sm sm:text-base text-[#808080]">
            From raw input to isolated forensic verdict in under 215 milliseconds.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {steps.map((s) => (
            <div
              key={s.num}
              className="p-6 rounded-xl bg-[#111111] border border-[#1A1A1A] hover:border-white/40 transition-all flex flex-col justify-between"
            >
              <div>
                <span className="text-xs font-mono font-bold text-white bg-black border border-[#1A1A1A] px-2.5 py-1 rounded inline-block mb-4">
                  STAGE {s.num}
                </span>
                <h3 className="text-lg font-bold text-white mb-2">{s.title}</h3>
                <p className="text-xs text-[#808080] leading-relaxed">{s.desc}</p>
              </div>

              <div className="mt-6 pt-3 border-t border-[#1A1A1A] flex items-center justify-between text-[11px] font-mono text-[#808080]">
                <span>Status: Automated</span>
                <span className="text-white">Active</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

// ─── Section 5: Technology ────────────────────────────────────────────────────
function TechnologySection() {
  const techs = [
    {
      name: "CNN-BiLSTM",
      role: "Structural Feature Extraction",
      desc: "256 Conv1D spatial filters + 128 Bidirectional LSTM units capturing sequence n-grams.",
    },
    {
      name: "RoBERTa",
      role: "Transformer Semantic NLP",
      desc: "768-dimensional language model fine-tuned on phishing semantics and deceptive brand context.",
    },
    {
      name: "Entropy Analysis",
      role: "Obfuscation Metric",
      desc: "Shannon entropy calculation detecting randomized subdomains and algorithmically generated domains.",
    },
    {
      name: "Typosquatting Engine",
      role: "Lexical Proximity Matching",
      desc: "Levenshtein distance verification mapping against 1,024 recognized global enterprise brands.",
    },
    {
      name: "Homoglyph Engine",
      role: "Punycode & Unicode Attack Guard",
      desc: "Cyrillic, Greek, and Latin character substitution detector preventing visual deception.",
    },
    {
      name: "DOM Intelligence",
      role: "Behavioral Sandbox Telemetry",
      desc: "Real-time inspection of forms, password fields, script injections, and iframe hijacking.",
    },
    {
      name: "VirtualBox Sandbox",
      role: "Hardware-Isolated Analysis",
      desc: "Dedicated virtual machine guest (192.168.56.101:8765) executing suspicious websites with total client isolation.",
    },
  ];

  return (
    <section id="technology" className="py-28 px-4 bg-[#000000] border-t border-[#1A1A1A]">
      <div className="max-w-7xl mx-auto">
        <div className="text-center max-w-3xl mx-auto mb-20 space-y-4">
          <span className="text-xs uppercase tracking-[0.25em] font-mono text-[#808080] block">
            Subsystems
          </span>
          <h2 className="text-4xl sm:text-5xl font-black tracking-tight text-white">
            PROVEN ENGINEERING STACK
          </h2>
          <p className="text-sm sm:text-base text-[#808080]">
            The verified deep learning, lexical, and virtualization engines running inside PhishGuard AI.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {techs.map((t) => (
            <div
              key={t.name}
              className="p-6 rounded-xl bg-[#111111] border border-[#1A1A1A] hover:border-[#808080] transition-all"
            >
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-base font-bold text-white">{t.name}</h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-black border border-[#1A1A1A] text-[#808080]">
                  Verified
                </span>
              </div>
              <p className="text-xs font-mono text-[#808080] mb-3">{t.role}</p>
              <p className="text-xs text-[#808080] leading-relaxed">{t.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

// ─── Section 6: Final CTA ─────────────────────────────────────────────────────
function FinalCTASection({ onLaunchScanner }: { onLaunchScanner: () => void }) {
  return (
    <section className="py-32 px-4 bg-white text-black text-center border-t border-black">
      <div className="max-w-4xl mx-auto space-y-8">
        <span className="text-xs uppercase tracking-[0.25em] font-mono text-black/60 block">
          Ready to verify?
        </span>

        <h2 className="text-4xl sm:text-6xl md:text-7xl font-black tracking-tighter leading-tight text-black">
          DON&apos;T TRUST EVERY LINK.
          <br />
          VERIFY IT.
        </h2>

        <p className="text-base sm:text-lg text-black/70 max-w-xl mx-auto leading-relaxed">
          Experience real-time zero-day phishing protection powered by Hybrid AI and isolated
          sandbox inspection.
        </p>

        <div className="pt-4">
          <button
            type="button"
            onClick={onLaunchScanner}
            className="px-8 py-4 rounded-md bg-black text-white text-sm font-bold uppercase tracking-widest hover:opacity-90 transition-all cursor-pointer shadow-2xl inline-flex items-center gap-3"
          >
            <span>START SCANNING</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </section>
  );
}

// ─── Footer ───────────────────────────────────────────────────────────────────
function MonochromeFooter({ onLaunchScanner }: { onLaunchScanner: () => void }) {
  return (
    <footer className="py-16 px-4 bg-black border-t border-[#1A1A1A] text-[#808080] text-xs font-mono">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-6">
        <div className="flex items-center gap-3 text-white">
          <div className="w-6 h-6 rounded bg-white text-black font-black flex items-center justify-center text-xs">
            PG
          </div>
          <span className="font-bold tracking-tight">PHISHGUARD AI V7.0</span>
          <span className="text-[#808080]">· Black & White Monochrome Edition</span>
        </div>

        <div className="flex items-center gap-6">
          <a href="#capabilities" className="hover:text-white transition-colors">
            Capabilities
          </a>
          <a href="#workflow" className="hover:text-white transition-colors">
            Workflow
          </a>
          <a href="#technology" className="hover:text-white transition-colors">
            Technology
          </a>
          <button onClick={onLaunchScanner} className="hover:text-white transition-colors cursor-pointer">
            Scanner Workspace
          </button>
        </div>

        <p>© {new Date().getFullYear()} PhishGuard AI. Strict Monochrome Security Operations.</p>
      </div>
    </footer>
  );
}
