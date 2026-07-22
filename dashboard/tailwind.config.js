/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        bg: {
          main: '#f9fafb',
          sidebar: '#ffffff',
          card: '#ffffff',
        },
        border: '#e5e7eb',
        text: {
          main: '#111827',
          muted: '#6b7280',
        },
        brand: {
          primary: '#0f172a',
          primaryGlow: '#f1f5f9',
          success: '#16a34a',
          successGlow: '#f0fdf4',
          warning: '#ca8a04',
          warningGlow: '#fef9c3',
          danger: '#dc2626',
          dangerGlow: '#fef2f2',
        }
      },
      fontFamily: {
        sans: ['Plus Jakarta Sans', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      }
    },
  },
  plugins: [],
}
