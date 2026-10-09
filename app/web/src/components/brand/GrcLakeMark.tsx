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
  "M12 40c6-3 12-3 20 0s14 3 20 0M12 47c6-3 12-3 20 0s14 3 20 0M12 54c6-3 12-3 20 0s14 3 20 0";

/**
 * At 40px and below the monogram competes with the waves, so those sizes
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

export function GrcLakeMark({
  size = "md",
  className,
  gradientId = "grc-lake-mark-gradient",
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
            <g strokeWidth="3.6" transform="translate(0 -15)">
              <path d={WAVES} />
            </g>
          ) : (
            <>
              <path d="M42 17a14 14 0 1 0 2 20V27H32" strokeWidth="4" />
              <g strokeWidth="2.6">
                <path d={WAVES} />
              </g>
            </>
          )}
        </g>
      </g>
    </svg>
  );
}
