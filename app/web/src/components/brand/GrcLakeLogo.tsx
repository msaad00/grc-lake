import Link from "next/link";
import { cn } from "@/lib/utils";
import { BRAND } from "@/lib/brand";
import { GrcLakeMark } from "./GrcLakeMark";

interface Props {
  /** Show wordmark text beside the evidence-lake mark. */
  showWordmark?: boolean;
  /** Optional subtitle under the wordmark (e.g. "Console"). */
  subtitle?: string;
  /** Link target; omit for static branding (no link). */
  href?: string;
  markSize?: "xs" | "sm" | "md" | "lg" | "xl";
  className?: string;
  /** Light text for dark headers (TopBar). */
  inverted?: boolean;
  gradientId?: string;
  wordmarkClassName?: string;
}

export function GrcLakeLogo({
  showWordmark = true,
  subtitle,
  href,
  markSize = "md",
  className,
  inverted = false,
  gradientId,
  wordmarkClassName,
}: Props) {
  const content = (
    <>
      <GrcLakeMark size={markSize} gradientId={gradientId} />
      {showWordmark && (
        <span className={cn("min-w-0 leading-tight", wordmarkClassName)}>
          <span
            className={cn(
              "block truncate font-semibold tracking-tight",
              inverted ? "text-code-fg" : "text-ink",
              markSize === "sm" || markSize === "xs" ? "text-sm" : "text-lg",
            )}
          >
            {BRAND.name}
          </span>
          {subtitle && (
            <span
              className={cn(
                "block truncate text-[11px] font-semibold uppercase tracking-wide",
                inverted ? "text-code-fg/70" : "text-muted",
              )}
            >
              {subtitle}
            </span>
          )}
        </span>
      )}
    </>
  );

  const classes = cn("inline-flex min-w-0 items-center gap-2", className);

  if (href) {
    return (
      <Link href={href} className={cn(classes, "hover:opacity-90")}>
        {content}
      </Link>
    );
  }

  return <div className={classes}>{content}</div>;
}
