import { cn } from "@/lib/utils";
import { BRAND } from "@/lib/brand";

const SIZES = {
  xs: "h-5 w-5 rounded-[5px]",
  sm: "h-6 w-6 rounded-md",
  md: "h-8 w-8 rounded-lg",
  lg: "h-10 w-10 rounded-xl",
  xl: "h-12 w-12 rounded-xl",
} as const;

type Size = keyof typeof SIZES;

const WAVES =
  "M10 35c7-4.8 14-4.8 22 0s14 4.8 22 0M10 44c7-4.8 14-4.8 22 0s14 4.8 22 0M10 53c7-4.8 14-4.8 22 0s14 4.8 22 0";

/**
 * At 40px and below the four source glyphs blur into specks, so those sizes
 * draw the evidence-lake waves alone, centred and heavier.
 */
const SIMPLE_SIZES: ReadonlySet<Size> = new Set(["xs", "sm", "md", "lg"]);

interface Props {
  size?: Size;
  className?: string;
  gradientId?: string;
  /** `auto` picks the waves-only mark at 40px and below. */
  variant?: "auto" | "full" | "simple";
}

export function TrustOpsMark({
  size = "md",
  className,
  gradientId = "trustops-mark-gradient",
  variant = "auto",
}: Props) {
  const simple =
    variant === "simple" || (variant === "auto" && SIMPLE_SIZES.has(size));
  return (
    <svg
      viewBox="0 0 64 64"
      role="img"
      aria-label={BRAND.name}
      data-variant={simple ? "simple" : "full"}
      className={cn("flex-none", SIZES[size], className)}
    >
      <title>{BRAND.name}</title>
      <defs>
        <linearGradient
          id={gradientId}
          gradientUnits="userSpaceOnUse"
          x1="4"
          y1="7"
          x2="55"
          y2="58"
        >
          <stop stopColor="#4f7cff" />
          <stop offset="1" stopColor="#42dfcf" />
        </linearGradient>
      </defs>
      <g>
        <rect width="64" height="64" rx="15" fill="#0b1b2c" />
        <g
          fill="none"
          stroke={`url(#${gradientId})`}
          color="#5b9aff"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          {simple ? (
            <g strokeWidth="3.6" transform="translate(0 -12)">
              <path d={WAVES} />
            </g>
          ) : (
            <>
              <g strokeWidth="1.8">
                <g transform="translate(4 10) scale(.66)">
                  <path d="M3 14h12a4 4 0 0 0 0-8 5.5 5.5 0 0 0-10.4-1.7A4.5 4.5 0 0 0 3 14Z" />
                </g>
                <g transform="translate(18.5 10) scale(.66)">
                  <circle cx="9" cy="4.5" r="3" />
                  <path d="M3 16v-2a6 6 0 0 1 12 0v2" />
                </g>
                <g transform="translate(33 10) scale(.66)">
                  <rect x="2" y="5" width="14" height="11" rx="3" />
                  <path d="M9 5V1M0 9v4M18 9v4" />
                  <circle cx="6" cy="10" r=".9" fill="currentColor" />
                  <circle cx="12" cy="10" r=".9" fill="currentColor" />
                </g>
                <g transform="translate(47.5 10) scale(.66)">
                  <rect x="3" y="1" width="12" height="16" rx="2" />
                  <path d="M6 5h6M6 9h6M6 13h4" />
                </g>
              </g>
              <g strokeWidth="2.4">
                <path d={WAVES} />
              </g>
            </>
          )}
        </g>
      </g>
    </svg>
  );
}
