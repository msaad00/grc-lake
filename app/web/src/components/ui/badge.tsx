import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

// Status tones carry meaning (tinted fill + strong text, AA in both themes);
// `default` and `info` stay neutral so status is the only colour in a row.
const badgeVariants = cva(
  "inline-flex max-w-full min-w-0 items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium leading-4",
  {
    variants: {
      tone: {
        default: "bg-neutral-bg text-neutral-fg",
        info: "bg-neutral-bg text-neutral-fg",
        brand: "bg-brand/10 text-brand",
        outline:
          "bg-transparent text-muted ring-1 ring-inset ring-line-strong/60",
        ready: "bg-success-bg text-success-fg",
        attention: "bg-warning-bg text-warning-fg",
        serious: "bg-serious-bg text-serious-fg",
        critical: "bg-danger-bg text-danger-fg",
      },
    },
    defaultVariants: { tone: "default" },
  },
);

export interface BadgeProps
  extends
    React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, tone, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ tone, className }))} {...props} />;
}
