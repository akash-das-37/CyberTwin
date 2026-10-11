/** @type {import('tailwindcss').Config} */
export default {
  content: ['./popup.html', './options.html', './dashboard.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        cyber: {
          black: '#0a0a0f',
          darker: '#0f0f18',
          dark: '#14141f',
          card: 'rgba(20, 20, 31, 0.72)',
          red: '#dc2626',
          'red-glow': '#ef4444',
          'red-deep': '#991b1b',
          orange: '#f97316',
          green: '#22c55e',
          muted: '#71717a',
          border: 'rgba(6, 182, 212, 0.25)',
          cyan: '#06b6d4',
          'cyan-glow': '#22d3ee',
          blue: '#2563eb',
          'blue-glow': '#3b82f6',
          'blue-deep': '#1d4ed8',
        },
      },
      fontFamily: {
        cyber: ['Inter', 'Segoe UI', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      boxShadow: {
        glow: '0 0 20px rgba(6, 182, 212, 0.35)',
        'glow-lg': '0 0 40px rgba(6, 182, 212, 0.45)',
        'glow-blue': '0 0 20px rgba(37, 99, 235, 0.35)',
        'glow-green': '0 0 20px rgba(34, 197, 94, 0.35)',
        'glow-orange': '0 0 20px rgba(249, 115, 22, 0.35)',
        glass: '0 8px 32px rgba(0, 0, 0, 0.45)',
      },
      animation: {
        'pulse-glow': 'pulseGlow 2s ease-in-out infinite',
        'fade-in': 'fadeIn 0.4s ease-out',
        'slide-up': 'slideUp 0.35s ease-out',
      },
      keyframes: {
        pulseGlow: {
          '0%, 100%': { boxShadow: '0 0 15px rgba(220, 38, 38, 0.3)' },
          '50%': { boxShadow: '0 0 30px rgba(220, 38, 38, 0.6)' },
        },
        fadeIn: {
          from: { opacity: '0' },
          to: { opacity: '1' },
        },
        slideUp: {
          from: { opacity: '0', transform: 'translateY(12px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
      },
      backgroundImage: {
        'cyber-grid':
          'linear-gradient(rgba(6,182,212,0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(6,182,212,0.04) 1px, transparent 1px)',
      },
      backgroundSize: {
        grid: '24px 24px',
      },
    },
  },
  plugins: [],
};
