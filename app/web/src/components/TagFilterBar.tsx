"use client";

import { Tag as TagIcon, X } from "lucide-react";
import { TagChip } from "@/components/TagChip";
import type { Tag } from "@/lib/api/types";

export function TagFilterBar({
  tags,
  activeTagId,
  onSelect,
  onClear,
}: {
  tags: Tag[];
  activeTagId: string | null;
  onSelect: (tagId: string | null) => void;
  onClear: () => void;
}) {
  if (tags.length === 0) return null;

  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="flex items-center gap-1 text-[11px] font-semibold uppercase tracking-wide text-muted">
        <TagIcon className="h-3 w-3" />
        Tags
      </span>
      {tags.map((tag) => (
        <button
          key={tag.id}
          type="button"
          onClick={() => onSelect(activeTagId === tag.id ? null : tag.id)}
          className={`rounded-full outline-none ring-offset-1 focus:ring-2 focus:ring-brand ${
            activeTagId === tag.id ? "ring-2 ring-brand ring-offset-1" : ""
          }`}
        >
          <TagChip tag={tag} />
        </button>
      ))}
      {activeTagId && (
        <button
          type="button"
          onClick={onClear}
          className="flex items-center gap-1 text-[11px] text-muted hover:text-ink"
        >
          <X className="h-3 w-3" />
          clear
        </button>
      )}
    </div>
  );
}
