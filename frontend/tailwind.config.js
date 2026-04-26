/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    darkMode: 'class',
    theme: {
        extend: {
            colors: {
                // Core dark backgrounds
                background: '#060B18',
                surface: '#0A0F2C',
                'surface-light': '#0F1640',
                // Brand accents
                primary: '#00AEEF',       // Electric blue
                secondary: '#00FFB2',     // Cyan-green neon
                accent: '#0077CC',        // Deep blue accent
                // Status colors
                dangerous: '#FF3B3B',
                warning: '#FFB347',
                success: '#00FFB2',
                // Utility
                'border-glow': '#00AEEF33',
            },
            fontFamily: {
                sans: ['Space Grotesk', 'Inter', 'system-ui', 'sans-serif'],
                mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
            },
            boxShadow: {
                'glow-blue': '0 0 20px rgba(0, 174, 239, 0.35), 0 0 60px rgba(0, 174, 239, 0.1)',
                'glow-green': '0 0 20px rgba(0, 255, 178, 0.35), 0 0 60px rgba(0, 255, 178, 0.1)',
                'glow-red': '0 0 20px rgba(255, 59, 59, 0.35), 0 0 60px rgba(255, 59, 59, 0.1)',
                'glow-amber': '0 0 20px rgba(255, 179, 71, 0.35), 0 0 60px rgba(255, 179, 71, 0.1)',
                'card': '0 4px 24px 0 rgba(0,0,0,0.5)',
            },
            backgroundImage: {
                'grid-pattern': "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='60' height='60'%3E%3Cpath d='M 60 0 L 0 0 0 60' fill='none' stroke='%2300AEEF' stroke-width='0.3' stroke-opacity='0.12'/%3E%3C/svg%3E\")",
                'radial-navy': 'radial-gradient(ellipse at center, #0A0F2C 0%, #060B18 70%)',
                'hero-gradient': 'radial-gradient(ellipse 80% 60% at 50% -20%, rgba(0,174,239,0.18) 0%, transparent 60%)',
            },
            animation: {
                'blob': 'blob 8s ease-in-out infinite',
                'pulse-slow': 'pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                'data-stream': 'dataStream 3s linear infinite',
                'scan-line': 'scanLine 2s linear infinite',
                'float': 'float 6s ease-in-out infinite',
                'float-delayed': 'float 6s ease-in-out infinite 2s',
                'glow-pulse': 'glowPulse 2s ease-in-out infinite',
                'radar-spin': 'radarSpin 2s linear infinite',
                'count-up': 'countUp 0.8s ease-out forwards',
                'slide-in-right': 'slideInRight 0.5s ease-out forwards',
                'fade-up': 'fadeUp 0.6s ease-out forwards',
                'draw-line': 'drawLine 1.5s ease-out forwards',
                'dot-travel': 'dotTravel 2s linear infinite',
            },
            keyframes: {
                blob: {
                    '0%, 100%': { transform: 'translate(0, 0) scale(1)' },
                    '33%': { transform: 'translate(30px, -30px) scale(1.1)' },
                    '66%': { transform: 'translate(-20px, 20px) scale(0.9)' },
                },
                float: {
                    '0%, 100%': { transform: 'translateY(0px)' },
                    '50%': { transform: 'translateY(-16px)' },
                },
                glowPulse: {
                    '0%, 100%': { opacity: '1', boxShadow: '0 0 20px rgba(0,174,239,0.4)' },
                    '50%': { opacity: '0.7', boxShadow: '0 0 40px rgba(0,174,239,0.8), 0 0 80px rgba(0,174,239,0.3)' },
                },
                radarSpin: {
                    '0%': { transform: 'rotate(0deg)' },
                    '100%': { transform: 'rotate(360deg)' },
                },
                dataStream: {
                    '0%': { strokeDashoffset: '400' },
                    '100%': { strokeDashoffset: '0' },
                },
                scanLine: {
                    '0%': { transform: 'translateY(-100%)' },
                    '100%': { transform: 'translateY(100vh)' },
                },
                fadeUp: {
                    '0%': { opacity: '0', transform: 'translateY(20px)' },
                    '100%': { opacity: '1', transform: 'translateY(0)' },
                },
                slideInRight: {
                    '0%': { opacity: '0', transform: 'translateX(40px)' },
                    '100%': { opacity: '1', transform: 'translateX(0)' },
                },
                drawLine: {
                    '0%': { strokeDashoffset: '500' },
                    '100%': { strokeDashoffset: '0' },
                },
                dotTravel: {
                    '0%': { offsetDistance: '0%', opacity: '0' },
                    '10%': { opacity: '1' },
                    '90%': { opacity: '1' },
                    '100%': { offsetDistance: '100%', opacity: '0' },
                },
            },
        },
    },
    plugins: [],
}
