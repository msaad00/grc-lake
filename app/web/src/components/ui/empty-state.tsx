import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * The one empty state: an icon, one sentence, and an optional next step.
 * Use it wherever a list or panel has nothing to show yet.
 */
export function EmptyState({
  icon: Icon,
  children,
  action,
  className,
}: {
  icon: LucideIcon;
  /** One sentence: what is missing and, if there is no action, what to do. */
  children: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex flex-col items-center gap-3 rounded-lg border border-dashed border-line bg-surface px-4 py-6 text-center",
        className,
      )}
    >
      <span className="grid h-9 w-9 place-items-center rounded-full bg-neutral-bg text-neutral-fg">
        <Icon aria-hidden="true" className="h-4 w-4" />
      </span>
      <p className="max-w-md text-sm leading-6 text-muted">{children}</p>
      {action ? (
        <div className="flex flex-wrap justify-center gap-2">{action}</div>
      ) : null}
    </div>
  );
}
