import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        ink: "rgb(var(--rgb-ink) / <alpha-value>)",
        muted: "rgb(var(--rgb-muted) / <alpha-value>)",
        line: {
          DEFAULT: "rgb(var(--rgb-line) / <alpha-value>)",
          strong: "rgb(var(--rgb-line-strong) / <alpha-value>)",
        },
        panel: "rgb(var(--rgb-panel) / <alpha-value>)",
        rail: {
          DEFAULT: "rgb(var(--rgb-rail) / <alpha-value>)",
          line: "rgb(var(--rgb-rail-line) / <alpha-value>)",
          hover: "rgb(var(--rgb-rail-hover) / <alpha-value>)",
          active: "rgb(var(--rgb-rail-active) / <alpha-value>)",
          text: "rgb(var(--rgb-rail-text) / <alpha-value>)",
          heading: "rgb(var(--rgb-rail-heading) / <alpha-value>)",
        },
        surface: "rgb(var(--rgb-surface) / <alpha-value>)",
        surfaceMuted: "rgb(var(--rgb-surface-muted) / <alpha-value>)",
        brand: "rgb(var(--rgb-brand) / <alpha-value>)",
        onBrand: "rgb(var(--rgb-on-brand) / <alpha-value>)",
        success: {
          DEFAULT: "rgb(var(--rgb-success) / <alpha-value>)",
          fg: "rgb(var(--rgb-success-fg) / <alpha-value>)",
          bg: "rgb(var(--rgb-success-bg) / <alpha-value>)",
        },
        warning: {
          DEFAULT: "rgb(var(--rgb-warning) / <alpha-value>)",
          fg: "rgb(var(--rgb-warning-fg) / <alpha-value>)",
          bg: "rgb(var(--rgb-warning-bg) / <alpha-value>)",
        },
        serious: {
          DEFAULT: "rgb(var(--rgb-serious) / <alpha-value>)",
          fg: "rgb(var(--rgb-serious-fg) / <alpha-value>)",
          bg: "rgb(var(--rgb-serious-bg) / <alpha-value>)",
        },
        danger: {
          DEFAULT: "rgb(var(--rgb-danger) / <alpha-value>)",
          fg: "rgb(var(--rgb-danger-fg) / <alpha-value>)",
          bg: "rgb(var(--rgb-danger-bg) / <alpha-value>)",
        },
        info: {
          DEFAULT: "rgb(var(--rgb-info) / <alpha-value>)",
          fg: "rgb(var(--rgb-info-fg) / <alpha-value>)",
          bg: "rgb(var(--rgb-info-bg) / <alpha-value>)",
        },
        code: {
          DEFAULT: "rgb(var(--rgb-code) / <alpha-value>)",
          fg: "rgb(var(--rgb-code-fg) / <alpha-value>)",
        },
        neutral: {
          fg: "rgb(var(--rgb-neutral-fg) / <alpha-value>)",
          bg: "rgb(var(--rgb-neutral-bg) / <alpha-value>)",
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
