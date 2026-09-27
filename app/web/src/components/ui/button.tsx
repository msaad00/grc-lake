"use client";

import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-lg text-sm font-extrabold ring-offset-surface transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        default: "border border-line bg-surface text-ink hover:bg-surfaceMuted",
        primary:
          "border border-transparent bg-gradient-to-br from-[#315dff] to-[#0e7490] text-white hover:opacity-95",
        dark: "border border-slate-900 bg-slate-900 text-white hover:bg-slate-950 dark:border-slate-200 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-white",
        ghost:
          "border border-transparent bg-transparent text-ink hover:bg-surfaceMuted",
      },
      size: {
        default: "h-10 px-3.5 py-2.5",
        sm: "h-8 rounded-md px-3",
        lg: "h-11 rounded-lg px-5",
        icon: "h-9 w-9",
      },
    },
    defaultVariants: { variant: "default", size: "default" },
  },
);

export interface ButtonProps
  extends
    React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return (
      <Comp
        ref={ref}
        className={cn(buttonVariants({ variant, size, className }))}
        {...props}
      />
    );
  },
);
Button.displayName = "Button";

export { buttonVariants };
