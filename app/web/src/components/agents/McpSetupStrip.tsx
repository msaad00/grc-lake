"use client";

import Link from "next/link";
import { ClipboardCopy, GitBranch, KeyRound, Terminal } from "lucide-react";
import { TrustOpsLogo } from "@/components/brand/TrustOpsLogo";
import { TrustOpsMark } from "@/components/brand/TrustOpsMark";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { BRAND } from "@/lib/brand";
import { docsUrl } from "@/lib/format";
import { notify } from "@/lib/toast";

const MCP_TOOLS = [
  "get_posture",
  "list_controls",
  "list_evidence",
  "list_violations",
  "get_audit_readiness",
  "create_agent_run",
  "approve_agent_decision",
  "reject_agent_decision",
  "create_snapshot",
  "run_workflow",
] as const;

const CURSOR_CONFIG = `{
  "mcpServers": {
    "trustops": {
      "command": "trustops-mcp",
      "env": {
        "TRUSTOPS_API_URL": "http://127.0.0.1:8787",
        "TRUSTOPS_API_KEY": "tops_..."
      }
    }
  }
}`;

// Mirrors docs/playbooks/CI_POSTURE_GATE.md; keep inputs in sync with
// .github/actions/posture-gate/action.yml.
const CI_GATE_STEP = `- name: TrustOps posture gate
  uses: ./.github/actions/posture-gate
  with:
    trustops-url: \${{ secrets.TRUSTOPS_URL }}
    api-token: \${{ secrets.TRUSTOPS_API_TOKEN }}
    correlation-id: pr-\${{ github.event.pull_request.number }}-\${{ github.run_id }}
    min-score: "70"
    max-critical-violations: "0"
    max-failing-control-tests: "0"`;

export function McpSetupStrip() {
  const copy = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      notify.success(`${label} copied`);
    } catch {
      notify.error("Clipboard unavailable");
    }
  };

  return (
    <section className="grid gap-4 rounded-2xl border border-line bg-surface p-4 shadow-sm sm:p-5">
      <div className="flex min-w-0 flex-wrap items-start justify-between gap-4">
        <TrustOpsLogo markSize="lg" subtitle="MCP Server" />
        <Badge tone="info">stdio · {MCP_TOOLS.length}+ tools</Badge>
      </div>
      <p className="max-w-3xl text-sm leading-6 text-muted">
        Connect {BRAND.name} to Cursor, Claude Desktop, or any MCP host. Each
        tool advertises the {BRAND.name} mark in clients that support MCP icons
        — the same headless surface as this console and{" "}
        <code className="text-ink">/api/v1</code>.
      </p>
      <div className="grid gap-3 lg:grid-cols-2">
        <div className="grid gap-2 rounded-xl border border-line bg-surfaceMuted p-3">
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-semibold uppercase tracking-wide text-muted">
              Install
            </span>
            <Button
              variant="ghost"
              size="sm"
              onClick={() =>
                copy(
                  "pip install 'trustops-security-data-lake[mcp]'",
                  "Install command",
                )
              }
            >
              <ClipboardCopy className="h-3.5 w-3.5" />
              Copy
            </Button>
          </div>
          <pre className="overflow-x-auto rounded-lg bg-code p-3 text-xs text-code-fg">
            pip install &apos;trustops-security-data-lake[mcp]&apos;
          </pre>
        </div>
        <div className="grid gap-2 rounded-xl border border-line bg-surfaceMuted p-3">
          <div className="flex items-center justify-between gap-2">
            <span className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
              <Terminal className="h-3.5 w-3.5" />
              Cursor / MCP host
            </span>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => copy(CURSOR_CONFIG, "MCP config")}
            >
              <ClipboardCopy className="h-3.5 w-3.5" />
              Copy
            </Button>
          </div>
          <pre
            className="max-h-36 overflow-auto rounded-lg bg-code p-3 text-xs text-slate-100"
            tabIndex={0}
          >
            {CURSOR_CONFIG}
          </pre>
          <p className="flex flex-wrap items-center gap-x-2 text-xs text-muted">
            Replace <code className="text-ink">tops_...</code> with an API key.
            <Link
              href="/auth/#api-keys"
              className="inline-flex items-center gap-1 font-semibold text-brand hover:underline"
            >
              <KeyRound className="h-3.5 w-3.5" />
              Create key
            </Link>
          </p>
        </div>
      </div>
      <div className="grid min-w-0 gap-2 rounded-xl border border-line bg-surfaceMuted p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
            <GitBranch className="h-3.5 w-3.5" />
            GitHub Actions posture gate
          </span>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => copy(CI_GATE_STEP, "CI step")}
          >
            <ClipboardCopy className="h-3.5 w-3.5" />
            Copy
          </Button>
        </div>
        <p className="text-xs leading-5 text-muted">
          Fail a pull request when posture drops below your thresholds. Store
          the server URL and a read-only API key as repository secrets.{" "}
          <a
            href={docsUrl("playbooks/CI_POSTURE_GATE.md")}
            target="_blank"
            rel="noopener noreferrer"
            className="font-semibold text-brand hover:underline"
          >
            CI gate guide
          </a>
        </p>
        <pre
          className="max-h-48 overflow-auto rounded-lg bg-code p-3 text-xs text-slate-100"
          tabIndex={0}
        >
          {CI_GATE_STEP}
        </pre>
      </div>
      <div className="flex min-w-0 flex-wrap gap-2">
        {MCP_TOOLS.map((tool) => (
          <span
            key={tool}
            className="inline-flex items-center gap-1.5 rounded-full border border-line bg-panel px-2.5 py-1 text-[11px] font-semibold text-ink"
          >
            <TrustOpsMark size="xs" gradientId={`trustops-mcp-tool-${tool}`} />
            {tool}
          </span>
        ))}
      </div>
      <details className="text-xs leading-5 text-muted">
        <summary className="w-fit cursor-pointer font-semibold hover:text-ink">
          Details
        </summary>
        <div className="mt-1 grid gap-1">
          <p>
            Example config:{" "}
            <code className="text-ink">examples/mcp/mcp.json.example</code> in
            the repo. Set <code className="text-ink">TRUSTOPS_PUBLIC_URL</code>{" "}
            on hosted servers so remote MCP clients fetch the logo from{" "}
            <code className="text-ink">/brand/trustops-mark.svg</code>.
          </p>
          <p>
            Skill bundles and their routes:{" "}
            <a
              href={docsUrl("api/AGENT_SKILLS.md")}
              target="_blank"
              rel="noopener noreferrer"
              className="font-semibold text-brand hover:underline"
            >
              AGENT_SKILLS.md
            </a>
          </p>
        </div>
      </details>
    </section>
  );
}
