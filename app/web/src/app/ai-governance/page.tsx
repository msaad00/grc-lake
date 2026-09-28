"use client";

import Link from "next/link";
import { BrainCircuit } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { PageHeader } from "@/components/PageHeader";
import { QueryState } from "@/components/QueryState";
import { AiGovernanceStrip } from "@/components/audit-room/AiGovernanceStrip";
import { useAiInventory, usePlatformStream } from "@/lib/api/hooks";
import { ROUTE_LABELS } from "@/lib/console-copy";
import { assetLabel } from "@/lib/format";

export default function AiGovernancePage() {
  const inventory = useAiInventory(50);
  const { connected } = usePlatformStream();

  return (
    <div className="page-shell grid gap-6">
      <PageHeader
        title={ROUTE_LABELS["/ai-governance"]}
        description="Model inventory, lineage, runtime signals, and framework mapping for NIST AI RMF, ISO 42001, and EU AI Act evidence loops."
        actions={
          <Badge tone={connected ? "ready" : "attention"}>
            {connected ? "live stream" : "polling"}
          </Badge>
        }
      />

      <AiGovernanceStrip />

      <QueryState queries={[inventory]} label="AI inventory">
        {inventory.data && (
          <Card>
            <CardContent className="grid gap-3 p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <BrainCircuit className="h-4 w-4 text-brand" />
                  <span className="text-sm font-semibold text-ink">
                    Full inventory
                  </span>
                </div>
                <Link
                  href="/controls?domain=ai-governance"
                  className="text-xs font-semibold text-brand hover:underline"
                >
                  AI controls
                </Link>
              </div>
              {inventory.data.length === 0 ? (
                <div className="rounded-lg border border-dashed border-line px-4 py-8 text-center text-sm font-semibold text-muted">
                  No AI assets in the lake yet.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[640px] text-left text-xs">
                    <thead>
                      <tr className="border-b border-line text-muted">
                        <th className="px-2 py-2 font-semibold">Asset</th>
                        <th className="px-2 py-2 font-semibold">Type</th>
                        <th className="px-2 py-2 font-semibold">Owner</th>
                        <th className="px-2 py-2 font-semibold">Signals</th>
                      </tr>
                    </thead>
                    <tbody>
                      {inventory.data.map((item) => (
                        <tr
                          key={item.asset_id}
                          className="border-b border-line/70"
                        >
                          <td
                            className="px-2 py-2 font-semibold text-ink"
                            title={item.asset_id}
                          >
                            {assetLabel(item)}
                          </td>
                          <td className="px-2 py-2 text-muted">
                            {item.asset_type}
                          </td>
                          <td className="px-2 py-2 text-muted">
                            {item.owner || "unowned"}
                          </td>
                          <td className="px-2 py-2">
                            <div className="flex flex-wrap gap-1">
                              {item.model_card ? (
                                <Badge tone="ready">model card</Badge>
                              ) : null}
                              {item.lineage_complete ||
                              item.event_types.includes("model.lineage") ? (
                                <Badge tone="ready">lineage</Badge>
                              ) : null}
                              {item.event_types.includes(
                                "runtime.tool_call",
                              ) ? (
                                <Badge tone="attention">runtime</Badge>
                              ) : null}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>
        )}
      </QueryState>
    </div>
  );
}
