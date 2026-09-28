"use client";

import { useState } from "react";
import {
  ArrowRight,
  Cpu,
  GitFork,
  LayoutTemplate,
  Shield,
  X,
  Zap,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Modal } from "@/components/ui/modal";
import {
  WORKFLOW_TEMPLATES,
  type WorkflowTemplate,
} from "@/lib/workflow/templates";
import { cn } from "@/lib/utils";
import type { ActionKind } from "@/lib/api/types";

// ---------------------------------------------------------------------------
// Mini node chip for the template flow preview
// ---------------------------------------------------------------------------

const KIND_CHIP: Record<
  ActionKind,
  { bg: string; fg: string; Icon: React.ElementType }
> = {
  trigger: {
    bg: "bg-info-bg",
    fg: "text-brand",
    Icon: Zap,
  },
  check: {
    bg: "bg-warning-bg",
    fg: "text-warning-fg",
    Icon: GitFork,
  },
  gate: {
    bg: "bg-info-bg",
    fg: "text-brand",
    Icon: Shield,
  },
  action: {
    bg: "bg-success-bg",
    fg: "text-success-fg",
    Icon: Cpu,
  },
};

function guessKind(node_type: string): ActionKind {
  if (node_type.startsWith("trigger.")) return "trigger";
  if (node_type.startsWith("check.")) return "check";
  if (node_type.startsWith("gate.")) return "gate";
  return "action";
}

function FlowPreview({ template }: { template: WorkflowTemplate }) {
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {template.nodes.map((node, idx) => {
        const kind = guessKind(node.node_type);
        const chip = KIND_CHIP[kind];
        const Icon = chip.Icon;
        const edgeAfter = template.edges.find((e) => e.source === node.id);
        return (
          <span key={node.id} className="flex items-center gap-1.5">
            <span
              className={cn(
                "flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-semibold",
                chip.bg,
                chip.fg,
                "border-transparent",
              )}
            >
              <Icon className="h-2.5 w-2.5" aria-hidden />
              {node.node_type.split(".").slice(1).join(".")}
            </span>
            {idx < template.nodes.length - 1 && edgeAfter && (
              <span className="flex items-center gap-0.5 text-[9px] text-muted">
                <ArrowRight className="h-3 w-3" />
                {edgeAfter.condition && edgeAfter.condition !== "always" && (
                  <span className="rounded bg-surfaceMuted px-1 py-px font-mono">
                    {edgeAfter.condition}
                  </span>
                )}
              </span>
            )}
          </span>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Props + component
// ---------------------------------------------------------------------------

interface Props {
  open: boolean;
  onClose: () => void;
  onPick: (template: WorkflowTemplate) => void;
}

export function TemplateGallery({ open, onClose, onPick }: Props) {
  const [selected, setSelected] = useState<string>(
    WORKFLOW_TEMPLATES[0]?.id ?? "",
  );
  const active =
    WORKFLOW_TEMPLATES.find((t) => t.id === selected) ?? WORKFLOW_TEMPLATES[0];

  return (
    <Modal
      open={open}
      onOpenChange={(o) => !o && onClose()}
      title="Workflow templates"
      description="Start from a vetted story instead of an empty canvas. Each template is fully editable after loading."
      size="lg"
      footer={
        <div className="flex items-center justify-end gap-2">
          <Button variant="default" onClick={onClose}>
            <X className="h-4 w-4" /> Cancel
          </Button>
          {active && (
            <Button
              variant="primary"
              onClick={() => {
                onPick(active);
                onClose();
              }}
            >
              <LayoutTemplate className="h-4 w-4" /> Load &quot;{active.name}
              &quot;
            </Button>
          )}
        </div>
      }
    >
      <div className="grid min-w-0 gap-3 md:grid-cols-[200px_minmax(0,1fr)]">
        {/* Sidebar list */}
        <nav
          aria-label="Template list"
          className="grid max-h-[220px] gap-1.5 overflow-auto md:max-h-none"
        >
          {WORKFLOW_TEMPLATES.map((template) => (
            <button
              key={template.id}
              type="button"
              onClick={() => setSelected(template.id)}
              className={cn(
                "rounded-lg border px-3 py-2 text-left text-xs font-semibold transition-colors",
                template.id === selected
                  ? "border-ink bg-ink text-surface"
                  : "border-line bg-surface text-ink hover:border-brand",
              )}
            >
              {template.name}
            </button>
          ))}
        </nav>

        {/* Detail panel */}
        {active && (
          <div className="grid min-w-0 gap-4 rounded-xl border border-line bg-surfaceMuted p-4 text-sm">
            <div>
              <div className="text-xs font-semibold uppercase tracking-wide text-muted">
                Name
              </div>
              <div className="mt-0.5 font-semibold text-ink">{active.name}</div>
            </div>

            <div>
              <div className="text-xs font-semibold uppercase tracking-wide text-muted">
                Description
              </div>
              <div className="mt-0.5 text-xs text-ink">
                {active.description}
              </div>
            </div>

            <div className="flex flex-wrap gap-1.5">
              {active.tags.map((tag) => (
                <Badge key={tag}>{tag}</Badge>
              ))}
            </div>

            <div>
              <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">
                Flow preview
              </div>
              <div className="rounded-lg border border-line bg-surface p-3">
                <FlowPreview template={active} />
              </div>
            </div>

            <div>
              <div className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
                Composition
              </div>
              <div className="grid max-h-[220px] gap-1 overflow-auto font-mono text-[11px] text-ink">
                {active.nodes.map((node) => (
                  <div
                    key={node.id}
                    className="rounded border border-line bg-surface px-2 py-1"
                  >
                    <span className="text-muted">{node.id}</span>{" "}
                    <span className="text-muted">&rarr;</span> {node.node_type}
                  </div>
                ))}
                {active.edges.map((edge, idx) => (
                  <div
                    key={idx}
                    className="rounded border border-line bg-surface px-2 py-1 text-muted"
                  >
                    {edge.source} &mdash;{edge.condition ?? "always"}
                    &mdash;&rarr; {edge.target}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
}
