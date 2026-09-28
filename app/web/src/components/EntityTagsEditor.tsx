"use client";

import { useState } from "react";
import { Plus } from "lucide-react";
import { TagChip } from "@/components/TagChip";
import { notify } from "@/lib/toast";
import {
  useAttachTagMutation,
  useDetachTagMutation,
  useTags,
  useTagsForEntity,
} from "@/lib/api/hooks";

export function EntityTagsEditor({
  entityType,
  entityId,
}: {
  entityType: string;
  entityId: string;
}) {
  const allTags = useTags();
  const entityTags = useTagsForEntity(entityType, entityId);
  const attach = useAttachTagMutation();
  const detach = useDetachTagMutation();
  const [pickId, setPickId] = useState("");

  const attached = entityTags.data ?? [];
  const available = (allTags.data ?? []).filter(
    (tag) => !attached.some((row) => row.id === tag.id),
  );

  return (
    <div className="rounded-xl border border-line bg-surfaceMuted p-3">
      <div className="text-[11px] font-semibold uppercase tracking-wide text-muted">
        Tags
      </div>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {attached.map((tag) => (
          <TagChip
            key={tag.id}
            tag={tag}
            onRemove={(tagId) =>
              detach.mutate(
                { tag_id: tagId, entity_type: entityType, entity_id: entityId },
                { onSuccess: () => notify.success("Tag removed") },
              )
            }
          />
        ))}
        {attached.length === 0 && (
          <span className="text-xs text-muted">No tags on this record.</span>
        )}
      </div>
      {available.length > 0 && (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <select
            value={pickId}
            onChange={(e) => setPickId(e.target.value)}
            className="rounded-lg border border-line bg-surface px-2 py-1 text-xs font-semibold"
          >
            <option value="">Add tag…</option>
            {available.map((tag) => (
              <option key={tag.id} value={tag.id}>
                {tag.name}
              </option>
            ))}
          </select>
          <button
            type="button"
            disabled={!pickId || attach.isPending}
            onClick={() => {
              if (!pickId) return;
              attach.mutate(
                {
                  tag_id: pickId,
                  entity_type: entityType,
                  entity_id: entityId,
                },
                {
                  onSuccess: () => {
                    setPickId("");
                    notify.success("Tag added");
                  },
                },
              );
            }}
            className="inline-flex items-center gap-1 rounded-lg border border-line bg-surface px-2 py-1 text-xs font-semibold hover:border-brand disabled:opacity-50"
          >
            <Plus className="h-3 w-3" />
            Add
          </button>
        </div>
      )}
    </div>
  );
}
