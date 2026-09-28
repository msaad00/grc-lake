"use client";

import { useState } from "react";
import { Bookmark, BookmarkCheck, X } from "lucide-react";
import { notify } from "@/lib/toast";
import {
  useCreateSavedViewMutation,
  useDeleteSavedViewMutation,
  useSavedViews,
} from "@/lib/api/hooks";

interface SavedViewsBarProps {
  surface: string;
  filters: Record<string, unknown>;
  onApply: (filters: Record<string, unknown>) => void;
}

export function SavedViewsBar({
  surface,
  filters,
  onApply,
}: SavedViewsBarProps) {
  const savedViewsQuery = useSavedViews(surface);
  const createView = useCreateSavedViewMutation();
  const deleteView = useDeleteSavedViewMutation();
  const [saveViewName, setSaveViewName] = useState("");
  const [showSavePanel, setShowSavePanel] = useState(false);

  const savedViews = savedViewsQuery.data ?? [];

  function handleSaveView() {
    if (!saveViewName.trim()) return;
    createView.mutate(
      {
        surface,
        name: saveViewName.trim(),
        filters,
      },
      {
        onSuccess: () => {
          setSaveViewName("");
          setShowSavePanel(false);
          notify.success("View saved");
        },
      },
    );
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="flex items-center gap-1 text-[11px] font-semibold uppercase tracking-wide text-muted">
        <Bookmark className="h-3 w-3" />
        Saved views
      </span>
      {savedViews.map((view) => (
        <div key={view.id} className="flex items-center gap-0.5">
          <button
            type="button"
            onClick={() => onApply(view.filters)}
            className="rounded-md border border-line bg-surface px-2 py-0.5 text-[11px] font-medium text-ink hover:bg-surfaceMuted"
          >
            {view.name}
          </button>
          <button
            type="button"
            onClick={() =>
              deleteView.mutate(
                { viewId: view.id, surface },
                { onSuccess: () => notify.success("View deleted") },
              )
            }
            className="rounded p-0.5 text-muted hover:text-ink"
            aria-label="Delete saved view"
          >
            <X className="h-3 w-3" />
          </button>
        </div>
      ))}
      <button
        type="button"
        onClick={() => setShowSavePanel(!showSavePanel)}
        className="flex items-center gap-1 rounded-md border border-line bg-surface px-2 py-0.5 text-[11px] font-medium text-muted hover:text-ink"
      >
        <BookmarkCheck className="h-3 w-3" />
        Save current
      </button>
      {showSavePanel && (
        <div className="flex items-center gap-1">
          <input
            value={saveViewName}
            onChange={(e) => setSaveViewName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSaveView()}
            placeholder="View name…"
            className="rounded border border-line px-2 py-0.5 text-[11px] focus:outline-none focus:ring-2 focus:ring-brand"
          />
          <button
            type="button"
            onClick={handleSaveView}
            className="rounded bg-info-bg px-2 py-0.5 text-[11px] font-medium text-info-fg hover:bg-info"
          >
            Save
          </button>
        </div>
      )}
    </div>
  );
}
