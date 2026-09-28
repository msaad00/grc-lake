import { cn } from "@/lib/utils";

/** A neutral pulsing placeholder shown while a query is loading. */
export function Skeleton({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("animate-pulse rounded-md bg-line", className)}
      {...props}
    />
  );
}
