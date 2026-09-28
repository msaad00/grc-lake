"use client";

import { useEffect, useState } from "react";
import {
  CheckCircle2,
  ChevronRight,
  Loader2,
  Play,
  ShieldAlert,
  Trash2,
  X,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useTestAction } from "@/lib/api/hooks";
import type { ActionSchemaField, ActionSpec } from "@/lib/api/types";
import type { FlowNode } from "./WorkflowCanvas";
import { displayLabel } from "@/lib/display";

interface Props {
  node: FlowNode | null;
  spec: ActionSpec | null;
  /** Per-node result from the last workflow run, if any. */
  lastResult?: {
    result: "ok" | "error" | "skipped";
    output?: Record<string, unknown>;
    error?: string;
  } | null;
  onClose: () => void;
  onUpdateParams: (id: string, params: Record<string, unknown>) => void;
  onDelete: (id: string) => void;
}

function coerce(
  value: string,
  field: ActionSchemaField,
): string | number | boolean {
  if (field.type === "number") {
    const n = Number(value);
    return Number.isFinite(n) ? n : 0;
  }
  if (field.type === "boolean") return value === "true";
  return value;
}

export function NodeConfigPanel({
  node,
  spec,
  lastResult,
  onClose,
  onUpdateParams,
  onDelete,
}: Props) {
  const test = useTestAction();
  const [params, setParams] = useState<Record<string, unknown>>({});
  const [testResult, setTestResult] = useState<Record<string, unknown> | null>(
    null,
  );
  const [testError, setTestError] = useState<string | null>(null);

  useEffect(() => {
    setParams(node?.data.params ?? {});
    setTestResult(null);
    setTestError(null);
  }, [node?.id, node?.data.params]);

  if (!node || !spec) {
    return (
      <aside className="grid min-h-[160px] w-full xl:col-span-2 2xl:col-span-1 place-items-center rounded-2xl border border-line bg-surface text-xs text-muted 2xl:min-h-[560px] 2xl:w-[340px] 2xl:rounded-none 2xl:border-y-0 2xl:border-r-0">
        <div className="px-6 text-center">
          <ChevronRight className="mx-auto mb-2 h-4 w-4 text-muted" />
          Select a node in the canvas to inspect and edit it here.
        </div>
      </aside>
    );
  }

  const fields = Object.entries(spec.input_schema);

  const persist = (next: Record<string, unknown>) => {
    setParams(next);
    onUpdateParams(node.id, next);
  };

  const runTest = async () => {
    setTestError(null);
    setTestResult(null);
    try {
      const out = await test.mutateAsync({ node_type: spec.node_type, params });
      setTestResult(out.output);
    } catch (err) {
      setTestError((err as Error).message);
    }
  };

  return (
    <aside className="grid max-h-[min(760px,calc(100dvh-245px))] min-h-[560px] w-full xl:col-span-2 2xl:col-span-1 grid-rows-[auto_minmax(0,1fr)_auto] overflow-hidden rounded-2xl border border-line bg-surface 2xl:w-[340px] 2xl:rounded-none 2xl:border-y-0 2xl:border-r-0">
      <header className="flex items-start justify-between gap-3 border-b border-line p-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <Badge tone="info">{displayLabel(spec.kind)}</Badge>
            <code className="truncate text-xs text-ink">{spec.node_type}</code>
          </div>
          <div className="mt-1 text-sm font-semibold text-ink">
            {spec.label}
          </div>
          <div className="text-xs text-muted">{spec.description}</div>
        </div>
        <button
          type="button"
          aria-label="Deselect node"
          onClick={onClose}
          className="grid h-7 w-7 place-items-center rounded-md text-muted hover:bg-surfaceMuted"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </header>

      <div className="overflow-auto p-4">
        {lastResult && (
          <section
            className={[
              "mb-4 rounded-xl border p-3 text-xs",
              lastResult.result === "ok"
                ? "border-success/40 bg-success-bg text-success-fg"
                : "border-danger/40 bg-danger-bg text-danger-fg",
            ].join(" ")}
          >
            <div className="flex items-center gap-2 font-semibold">
              {lastResult.result === "ok" ? (
                <>
                  <CheckCircle2 className="h-4 w-4" /> Last run output
                </>
              ) : (
                <>
                  <ShieldAlert className="h-4 w-4" /> Last run errored
                </>
              )}
            </div>
            <pre className="mt-2 overflow-auto rounded bg-surface p-2 font-mono text-[11px] text-ink">
              {lastResult.error ?? JSON.stringify(lastResult.output, null, 2)}
            </pre>
          </section>
        )}

        <section className="grid gap-3">
          <div className="text-xs font-semibold uppercase tracking-wide text-muted">
            Parameters
          </div>
          {fields.length === 0 ? (
            <div className="rounded-lg border border-dashed border-line p-3 text-xs text-muted">
              This action takes no parameters.
            </div>
          ) : (
            fields.map(([name, field]) => {
              const value = params[name];
              const inputValue =
                value === undefined || value === null ? "" : String(value);
              return (
                <label
                  key={name}
                  className="grid gap-1 text-xs font-semibold uppercase tracking-wide text-muted"
                >
                  <span>
                    {field.label}
                    {field.required && (
                      <span className="text-danger-fg"> *</span>
                    )}
                  </span>
                  <input
                    value={inputValue}
                    placeholder={
                      field.default !== undefined
                        ? String(field.default)
                        : "supports {{nodeId.output.field}} refs"
                    }
                    onChange={(e) => {
                      const next = {
                        ...params,
                        [name]: coerce(e.target.value, field),
                      };
                      persist(next);
                    }}
                    className="rounded-lg border border-line bg-surface px-3 py-2 text-sm normal-case text-ink focus:outline-none focus:ring-1 focus:ring-brand"
                  />
                </label>
              );
            })
          )}
        </section>

        <section className="mt-4 rounded-xl border border-line bg-surfaceMuted p-3">
          <div className="text-xs font-semibold uppercase tracking-wide text-muted">
            Output keys (downstream nodes can read)
          </div>
          <div className="mt-2 grid gap-1 text-[11px]">
            {Object.entries(spec.output_schema).map(([key, kind]) => (
              <div
                key={key}
                className="flex items-center justify-between rounded border border-line bg-surface px-2 py-1"
              >
                <code className="text-ink">
                  &#123;&#123;{node.id}.output.{key}&#125;&#125;
                </code>
                <span className="text-muted">{kind}</span>
              </div>
            ))}
          </div>
        </section>

        {(testResult || testError) && (
          <section
            className={[
              "mt-4 rounded-xl border p-3 text-xs",
              testError
                ? "border-danger/40 bg-danger-bg text-danger-fg"
                : "border-success/40 bg-success-bg text-success-fg",
            ].join(" ")}
          >
            <div className="font-semibold">
              {testError ? "Test action errored" : "Test action returned"}
            </div>
            <pre className="mt-2 overflow-auto rounded bg-surface p-2 font-mono text-[11px] text-ink">
              {testError ?? JSON.stringify(testResult, null, 2)}
            </pre>
          </section>
        )}
      </div>

      <footer className="flex items-center justify-between gap-2 border-t border-line p-3">
        <Button
          variant="default"
          size="sm"
          onClick={() => {
            onDelete(node.id);
            onClose();
          }}
        >
          <Trash2 className="h-4 w-4" /> Remove
        </Button>
        <Button
          variant="primary"
          size="sm"
          onClick={runTest}
          disabled={test.isPending}
        >
          {test.isPending ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Play className="h-4 w-4" />
          )}{" "}
          Test action
        </Button>
      </footer>
    </aside>
  );
}
