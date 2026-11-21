"use client";

import { createRimRenderer } from "./rimRenderer";
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
  const capabilitiesRef = useRef<HTMLDivElement>(null);

  const scrollToCapabilities = () => {
    if (capabilitiesRef.current) {
      capabilitiesRef.current.scrollIntoView({ behavior: "smooth" });
    }
  };

  return (
    <div className="phishguard-landing bg-black text-white selection:bg-white selection:text-black font-sans min-h-screen">
      {/* ── Section 1: Animated Inversion Circle Hero ── */}
      <InversionCircleHero
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
  revealComplete,
  onLaunchScanner,
  onScrollToSection,
}: {
  revealComplete: boolean;
  onLaunchScanner: () => void;
  onScrollToSection: () => void;
}) {
  return (
    <nav
      className={`fixed top-0 left-0 right-0 z-50 border-b text-white ${
        revealComplete
          ? "bg-black border-[#1A1A1A] py-3.5"
          : "bg-transparent mix-blend-difference border-transparent py-5"
      }`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center justify-between">
        {/* Brand */}
        <div className="flex items-center gap-3.5">
          <img
            src="/phishguard-wordmark-white.png"
            alt="PhishGuard AI"
            className="block h-auto w-[164px] sm:w-[218px]"
          />
        </div>

        {/* Links */}
        <div className="hidden md:flex items-center gap-8 text-xs uppercase tracking-widest">
          <button
            onClick={onScrollToSection}
            className="opacity-75 hover:opacity-100 transition-opacity cursor-pointer"
          >
            Capabilities
          </button>
          <a href="#workflow" className="opacity-75 hover:opacity-100 transition-opacity cursor-pointer">
            Workflow
          </a>
          <a href="#technology" className="opacity-75 hover:opacity-100 transition-opacity cursor-pointer">
            Technology
          </a>
          <a href="#soc" className="opacity-75 hover:opacity-100 transition-opacity cursor-pointer">
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
  onLaunchScanner,
  onExplore,
}: {
  onLaunchScanner: () => void;
  onExplore: () => void;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const revealRef = useRef<HTMLDivElement>(null);
  const mapRef = useRef<SVGFEImageElement>(null);
  const bendRef = useRef<SVGFEFuncAElement>(null);
  const contentRef = useRef<HTMLDivElement>(null);
  const reflectionRef = useRef<HTMLDivElement>(null);
  const glassRef = useRef<HTMLImageElement>(null);
  const [revealComplete, setRevealComplete] = useState(false);

  useEffect(() => {
    const track = containerRef.current;
    const layer = revealRef.current;
    const glass = glassRef.current;
    if (!track || !layer || !glass) return;

    const reflection = reflectionRef.current;
    const contentLayer = contentRef.current;
    if (!reflection || !contentLayer) return;
    let disposed = false;

    // Cache glyphs at their laid-out positions, including wrapped lines and button labels.
    const glyphs = document.createElement("canvas");
    const atlas = glyphs.getContext("2d");
    const fallbackCanvas = document.createElement("canvas");
    const gpuCanvas = document.createElement("canvas");
    for (const canvas of [gpuCanvas, fallbackCanvas]) {
      canvas.width = canvas.height = BALL_SIZE * 2;
      canvas.style.width = canvas.style.height = "100%";
    }
    const renderer = createRimRenderer(gpuCanvas);
    reflection.replaceChildren(renderer ? gpuCanvas : fallbackCanvas);
    const surface = fallbackCanvas.getContext("2d");
    const wordBounds: { left: number; right: number; top: number; bottom: number }[] = [];
    const cacheGlyphs = () => {
      if (disposed || !atlas) return;
      const bounds = contentLayer.getBoundingClientRect();
      wordBounds.length = 0;
      glyphs.width = Math.ceil(bounds.width);
      glyphs.height = Math.ceil(bounds.height);
      atlas.fillStyle = "#dcf4ff";
      atlas.textBaseline = "middle";
      const nodes = document.createTreeWalker(contentLayer, NodeFilter.SHOW_TEXT);
      const range = document.createRange();
      while (nodes.nextNode()) {
        const node = nodes.currentNode;
        if (!node.textContent?.trim() || !node.parentElement) continue;
        const style = getComputedStyle(node.parentElement);
        atlas.font = `${style.fontWeight} ${style.fontSize} ${style.fontFamily}`;
        atlas.letterSpacing = style.letterSpacing === "normal" ? "0px" : style.letterSpacing;
        for (const word of node.textContent.matchAll(/\S+/g)) {
          const start = word.index!;
          range.setStart(node, start);
          range.setEnd(node, start + word[0].length);
          const rect = range.getBoundingClientRect();
          wordBounds.push({ left: rect.left - bounds.left, right: rect.right - bounds.left,
            top: rect.top - bounds.top, bottom: rect.bottom - bounds.top });
          const text = style.textTransform === "uppercase" ? word[0].toUpperCase() : word[0];
          atlas.fillText(text, rect.left - bounds.left,
            rect.top - bounds.top + rect.height / 2, rect.width);
        }
      }
      renderer?.upload(glyphs);
    };

    const paintReflection = (cy: number, width: number, height: number) => {
      if (renderer?.draw(cy, width, height)) {
        if (reflection.firstChild !== gpuCanvas) reflection.replaceChildren(gpuCanvas);
        return;
      }
      if (reflection.firstChild !== fallbackCanvas) reflection.replaceChildren(fallbackCanvas);
      if (!surface || !glyphs.width) return;
      const diameter = fallbackCanvas.width;
      surface.clearRect(0, 0, diameter, diameter);
      const radius = diameter * 0.454;
      const slices = 84;
      const arc = 2 * Math.PI / slices;
      const strip = radius * arc + 1;
      const depth = diameter * 0.045;
      for (let i = 0; i < slices; i++) {
        const angle = i * arc;
        const x = Math.sin(angle);
        const y = -Math.cos(angle);
        const rimFraction = radius / diameter;
        const sx = glyphs.width / 2 + x * width * rimFraction;
        const sy = cy + y * height * rimFraction;
        const tangentX = -y * width;
        const tangentY = x * height;
        const sourceWidth = strip / diameter * Math.hypot(tangentX, tangentY);
        const sourceHeight = height * 0.135;
        const span = Math.hypot(sourceWidth, sourceHeight);
        const half = span / 2 + 2;
        if (!wordBounds.some(word => word.left < sx + half && word.right > sx - half &&
          word.top < sy + half && word.bottom > sy - half)) continue;
        // Reflect across the local tangent. Only nearby glyphs enter this part of the rim.
        surface.save();
        surface.translate(diameter / 2 + x * radius, diameter / 2 + y * radius);
        surface.rotate(angle);
        surface.beginPath();
        surface.rect(-strip / 2, -depth / 2, strip, depth);
        surface.clip();
        surface.scale(strip / sourceWidth, -depth / sourceHeight);
        surface.rotate(-Math.atan2(tangentY, tangentX));
        surface.drawImage(glyphs, sx - span / 2, sy - span / 2, span, span,
          -span / 2, -span / 2, span, span);
        surface.restore();
      }
    };
    let viewWidth = 1;
    let trackTop = 0;
    let viewH = 1;
    let coverSize = 0;
    let lastScroll = -1;
    let complete = false;
    let frame = 0;
    let settleTimer = 0;
    let stretch = 0;
    let velocity = 0;
    let lastTime = 0;
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

    const draw = (time: number) => {
      frame = 0;
      // scroll relative to top of track
      const targetScroll = Math.min(2 * viewH, Math.max(0, window.scrollY - trackTop));
      const elapsed = Math.max(0, time - lastTime);
      const distance = targetScroll - lastScroll;
      // Interpolate coarse wheel ticks, but snap restored positions and long navigation jumps.
      const immediate = lastScroll < 0 || reducedMotion.matches || Math.abs(distance) >= viewH;
      const scrollY = immediate || Math.abs(distance) < 0.35 ? targetScroll
        : lastScroll + distance * (1 - Math.exp(-Math.min(elapsed, 32) / 23));
      const delta = lastScroll < 0 ? 0 : scrollY - lastScroll;
      if (scrollY === lastScroll && !stretch && !velocity) return;
      const step = Math.min(1.5, (time - lastTime) / 16.67);
      lastTime = time;
      velocity += Math.max(-0.035, Math.min(0.035, delta / viewH));
      velocity = (velocity - stretch * 0.13 * step) * 0.79 ** step;
      stretch = Math.max(-0.18, Math.min(0.18, stretch + velocity * step));
      if (reducedMotion.matches || scrollY === 0 || scrollY === 2 * viewH ||
          (Math.abs(stretch) < 0.001 && Math.abs(velocity) < 0.001)) {
        stretch = velocity = 0;
      }
      lastScroll = scrollY;

      // Phase progress 0 -> 1
      const p1 = Math.min(1, scrollY / viewH);
      const p2 = Math.max(0, scrollY / viewH - 1);
      // Power4 InOut easing
      const rise = p1 < 0.5 ? 8 * p1 ** 4 : 1 - (-2 * p1 + 2) ** 4 / 2;
      // Ease-in squared expansion
      const diameter = BALL_SIZE + p2 * p2 * (coverSize - BALL_SIZE);
      // Geometry
      const centerY = viewH / 2 + (1 - rise) * (viewH + BALL_SIZE) / 2;
      const aspect = 1 + 0.045 * (1 - p2);
      const height = diameter * (1 + stretch) / aspect;
      const width = diameter * aspect / (1 + stretch);
      const transform = `translate3d(-50%, ${centerY - BALL_SIZE / 2}px, 0) scale(${width / BALL_SIZE}, ${height / BALL_SIZE})`;
      layer.style.transform = transform;
      const strength = Math.min(1, scrollY / 80) * Math.min(1, (1 - p2) * 4);
      // The baked surface includes a 10px shadow margin on every side.
      glass.style.transform = `translate3d(-50%, ${centerY - (BALL_SIZE + 20) / 2}px, 0) scale(${width / BALL_SIZE}, ${height / BALL_SIZE})`;
      glass.style.opacity = String(strength);
      reflection.style.transform = transform;
      reflection.style.opacity = String(strength * 0.52);
      if (strength > 0 && !reducedMotion.matches) paintReflection(centerY, width, height);


      // Keep the costly glyph filter off the scroll path. Render it once at rest.
      clearTimeout(settleTimer);
      const content = contentRef.current;
      if (content?.style.filter) content.style.filter = "";
      if (scrollY === targetScroll && strength > 0 && !reducedMotion.matches && !stretch && !velocity && content) {
        settleTimer = window.setTimeout(() => {
          const map = mapRef.current;
          if (!map || !bendRef.current) return;
          map.setAttribute("x", String((viewWidth - width) / 2));
          map.setAttribute("y", String(centerY - height / 2));
          map.setAttribute("width", String(width));
          map.setAttribute("height", String(height));
          bendRef.current.setAttribute("slope", String(strength));
          content.style.filter = "url(#hero-rim-bend)";
        }, 120);
      }
      if (stretch || velocity || scrollY !== targetScroll) frame = requestAnimationFrame(draw);
      if (complete !== (p2 === 1)) {
        complete = p2 === 1;
        setRevealComplete(complete);
      }
    };

    const scheduleDraw = () => {
      if (!frame) frame = requestAnimationFrame(draw);
    };
    const measure = () => {
      cacheGlyphs();
      trackTop = track.getBoundingClientRect().top + window.scrollY;
      viewWidth = track.clientWidth;
      viewH = Math.max(1, track.clientHeight / 3);
      coverSize = Math.hypot(track.clientWidth, viewH) + 4;
      lastScroll = -1;
      scheduleDraw();
    };
    measure();
    void document.fonts.ready.then(() => { if (!disposed) measure(); });
    window.addEventListener("resize", measure);
    window.addEventListener("scroll", scheduleDraw, { passive: true });
    return () => {
      disposed = true;
      renderer?.dispose();
      reflection.replaceChildren();
      clearTimeout(settleTimer);
      cancelAnimationFrame(frame);
      window.removeEventListener("resize", measure);
      window.removeEventListener("scroll", scheduleDraw);
    };
  }, []);

  return (
    <div ref={containerRef} className="relative h-[300vh] bg-white">
      <LandingNavbar
        revealComplete={revealComplete}
        onLaunchScanner={onLaunchScanner}
        onScrollToSection={onExplore}
      />
      <div className="sticky isolate top-0 h-screen w-full overflow-hidden bg-white select-none">
        {/* ── Dark Text Layer (Visible on White Background) ── */}
        <svg width="0" height="0" aria-hidden="true" className="absolute pointer-events-none">
          <defs>
            <filter id="hero-rim-bend" x="0%" y="0%" width="100%" height="100%"
              primitiveUnits="userSpaceOnUse" colorInterpolationFilters="sRGB">
              <feFlood floodColor="#808080" result="neutral" />
              <feImage ref={mapRef} href="/droplet-displacement.png" preserveAspectRatio="none" result="rim" />
              <feComponentTransfer in="rim" result="fadedRim">
                <feFuncA ref={bendRef} type="linear" slope="1" />
              </feComponentTransfer>
              <feMerge result="offsets">
                <feMergeNode in="neutral" /><feMergeNode in="fadedRim" />
              </feMerge>
              {/* Interpolate adjacent glyph samples so a fractional bend preserves edge coverage. */}
              {(["x", "y"] as const).map(axis => {
                const source = axis === "x" ? "SourceGraphic" : "xBent";
                const channel = axis === "x" ? "2 0" : "0 2";
                const opposite = axis === "x" ? "-2 0" : "0 -2";
                return (
                  <React.Fragment key={axis}>
                    <feColorMatrix in="offsets" values={`0 0 0 0 0  0 0 0 0 0  0 0 0 0 0  ${channel} 0 0 -1.00392`} result="positive" />
                    <feColorMatrix in="offsets" values={`0 0 0 0 0  0 0 0 0 0  0 0 0 0 0  ${opposite} 0 0 1.00392`} result="negative" />
                    <feOffset in={source} dx={axis === "x" ? -1 : 0} dy={axis === "y" ? -1 : 0} />
                    <feComposite in2="positive" operator="in" result="forward" />
                    <feOffset in={source} dx={axis === "x" ? 1 : 0} dy={axis === "y" ? 1 : 0} />
                    <feComposite in2="negative" operator="in" result="backward" />
                    <feComposite in="positive" in2="negative" operator="over" result="weight" />
                    <feComposite in={source} in2="weight" operator="out" />
                    <feComposite in2="forward" operator="arithmetic" k2="1" k3="1" />
                    <feComposite in2="backward" operator="arithmetic" k2="1" k3="1" result={axis + "Bent"} />
                  </React.Fragment>
                );
              })}
            </filter>
          </defs>
        </svg>
        <div ref={contentRef} className="absolute inset-0 flex flex-col items-center justify-center text-center px-4 z-10 pointer-events-auto">
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
        <img aria-hidden="true" alt="" draggable={false} src="/droplet-surface.webp" ref={glassRef} className="hero-scroll-glass"
          style={{ width: BALL_SIZE + 20, height: BALL_SIZE + 20 }} />
        <div aria-hidden="true" ref={reflectionRef} className="hero-droplet-reflection"
          style={{ width: BALL_SIZE, height: BALL_SIZE }} />
        <div aria-hidden="true" ref={revealRef}
          className="absolute top-0 left-1/2 z-20 rounded-full bg-white mix-blend-difference pointer-events-none will-change-transform"
          style={{ width: BALL_SIZE, height: BALL_SIZE, transform: "scale(0)" }} />
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
        <div className="flex items-center gap-3.5 text-white">
          <img
            src="/phishguard-wordmark-white.png"
            alt="PhishGuard AI"
            className="block h-auto w-[164px] sm:w-[218px]"
          />
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
