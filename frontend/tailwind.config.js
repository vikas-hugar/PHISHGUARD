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
                // Strict Black and White Design System
                black: '#000000',
                white: '#FFFFFF',
                'mono-black': '#000000',
                'mono-soft': '#111111',
                'mono-dark': '#1A1A1A',
                'mono-gray': '#808080',
                'mono-light': '#E5E5E5',
                'mono-white': '#FFFFFF',

                // Application role mapping
                background: '#000000',
                surface: '#111111',
                'surface-light': '#1A1A1A',
                primary: '#FFFFFF',
                secondary: '#E5E5E5',
                accent: '#808080',
                'border-glow': 'rgba(255, 255, 255, 0.15)',
            },
            fontFamily: {
                sans: ['Inter', 'Space Grotesk', 'system-ui', 'sans-serif'],
                mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
            },
            boxShadow: {
                'mono-sm': '0 1px 2px 0 rgba(0, 0, 0, 0.5)',
                'mono-md': '0 4px 6px -1px rgba(0, 0, 0, 0.4), 0 2px 4px -1px rgba(0, 0, 0, 0.3)',
                'mono-lg': '0 10px 15px -3px rgba(0, 0, 0, 0.4), 0 4px 6px -2px rgba(0, 0, 0, 0.2)',
                'mono-border': '0 0 0 1px #1A1A1A',
                'mono-glow': '0 0 20px rgba(255, 255, 255, 0.1)',
                'card': '0 4px 24px 0 rgba(0,0,0,0.8)',
            },
            backgroundImage: {
                'grid-pattern': "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='60' height='60'%3E%3Cpath d='M 60 0 L 0 0 0 60' fill='none' stroke='%23333333' stroke-width='0.5' stroke-opacity='0.25'/%3E%3C/svg%3E\")",
            },
            animation: {
                'pulse-slow': 'pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                'radar-spin': 'radarSpin 2s linear infinite',
                'count-up': 'countUp 0.8s ease-out forwards',
                'fade-up': 'fadeUp 0.6s ease-out forwards',
            },
            keyframes: {
                radarSpin: {
                    '0%': { transform: 'rotate(0deg)' },
                    '100%': { transform: 'rotate(360deg)' },
                },
                countUp: {
                    '0%': { opacity: '0', transform: 'translateY(10px)' },
                    '100%': { opacity: '1', transform: 'translateY(0)' },
                },
                fadeUp: {
                    '0%': { opacity: '0', transform: 'translateY(20px)' },
                    '100%': { opacity: '1', transform: 'translateY(0)' },
                },
            },
        },
    },
    plugins: [],
}
