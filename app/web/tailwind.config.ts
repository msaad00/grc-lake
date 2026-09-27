import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        ink: "rgb(var(--rgb-ink) / <alpha-value>)",
        muted: "rgb(var(--rgb-muted) / <alpha-value>)",
        line: "rgb(var(--rgb-line) / <alpha-value>)",
        panel: "rgb(var(--rgb-panel) / <alpha-value>)",
        rail: {
          DEFAULT: "rgb(var(--rgb-rail) / <alpha-value>)",
          line: "rgb(var(--rgb-rail-line) / <alpha-value>)",
          hover: "#152030",
          active: "#172436",
          "active-line": "#31435c",
          text: "#c6d1df",
          heading: "#8a9ab0",
          "heading-hover": "#bcc8d8",
          chip: "#1d2b3d",
          "chip-icon": "#9cc2ff",
          "chip-active": "#eff6ff",
          "chip-active-icon": "#1d4ed8",
        },
        surface: "rgb(var(--rgb-surface) / <alpha-value>)",
        surfaceMuted: "rgb(var(--rgb-surface-muted) / <alpha-value>)",
        brand: {
          DEFAULT: "#4f7cff",
          cyan: "#30c7d2",
          green: "#059669",
          red: "#dc2626",
          orange: "#d97706",
          purple: "#7a35ff",
        },
      },
      fontFamily: {
        sans: [
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "sans-serif",
        ],
        mono: [
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "monospace",
        ],
      },
      boxShadow: {
        card: "var(--shadow-card)",
        hero: "var(--shadow-hero)",
      },
      borderRadius: {
        sm: "var(--radius-sm)",
        md: "var(--radius-md)",
        lg: "var(--radius-lg)",
        xl: "var(--radius-xl)",
      },
      transitionDuration: {
        fast: "var(--motion-fast)",
        base: "var(--motion-base)",
        slow: "var(--motion-slow)",
      },
    },
  },
  plugins: [],
};

export default config;
