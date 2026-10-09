"use client";

import { X } from "lucide-react";
import type { Tag } from "@/lib/api/types";

interface TagChipProps {
  tag: Tag;
  onRemove?: (tagId: string) => void;
  size?: "sm" | "md";
}

/**
 * A neutral pill for a single tag. The tag's own colour is a dot, so the text
 * stays AA-legible whatever colour a user picked. Pass `onRemove` to show an x.
 */
export function TagChip({ tag, onRemove, size = "sm" }: TagChipProps) {
  const dot = tag.color || "var(--color-brand)";
  const padding = size === "sm" ? "px-2 py-0.5" : "px-2.5 py-1";
  const textSize = size === "sm" ? "text-[11px]" : "text-xs";

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border border-line bg-neutral-bg font-medium text-neutral-fg ${padding} ${textSize}`}
    >
      <span
        aria-hidden="true"
        className="h-2 w-2 shrink-0 rounded-full"
        style={{ backgroundColor: dot }}
      />
      {tag.name}
      {onRemove && (
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onRemove(tag.id);
          }}
          className="rounded-full opacity-70 hover:opacity-100 focus:outline-none"
          aria-label={`Remove tag ${tag.name}`}
        >
          <X className="h-2.5 w-2.5" />
        </button>
      )}
    </span>
  );
}
