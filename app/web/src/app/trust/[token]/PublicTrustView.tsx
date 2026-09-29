"use client";

import { useEffect, useState } from "react";
import { Lock, Loader2, ShieldAlert } from "lucide-react";
import { TrustOpsLogo } from "@/components/brand/TrustOpsLogo";
import { Badge } from "@/components/ui/badge";
import { formatDate, plural } from "@/lib/format";

type FrameworkRow = {
  framework: string | null;
  score: number | null;
  state: string | null;
  control_count: number | null;
  failing_control_count?: number | null;
  stale_control_count?: number | null;
};

// Violation and stale-control counts are only present on detailed (auditor)
// shares; the server omits them for customer-facing public summaries.
type PublicTrust = {
  schema_version: string;
  data_residency: string;
  issued_by: string | null;
  scope: string | null;
  role: string | null;
  detail_level?: "summary" | "detailed";
  expires_at: string | null;
  evaluated_at: string | null;
  posture: {
    score: number | null;
    state: string | null;
    framework_count: number | null;
    control_count: number | null;
    open_violation_count?: number | null;
    critical_violation_count?: number | null;
    high_violation_count?: number | null;
    stale_control_count?: number | null;
  };
  frameworks: FrameworkRow[];
};

function tokenFromPath(): string {
  if (typeof window === "undefined") return "";
  const parts = window.location.pathname.replace(/\/$/, "").split("/");
  return parts[parts.length - 1] ?? "";
}

// External reviewers see readiness, not internal triage severity.
function readiness(state: string | null): {
  label: string;
  tone: "ready" | "info";
} {
  if (state === "ready") return { label: "Ready", tone: "ready" };
  if (state === "not_evaluated") return { label: "Not assessed", tone: "info" };
  return { label: "In progress", tone: "info" };
}

function roundScore(score: number | null | undefined): string {
  return typeof score === "number" && Number.isFinite(score)
    ? String(Math.round(score))
    : "—";
}

function ResidencyBanner() {
  return (
    <div className="flex items-start gap-3 rounded-xl border border-info/40 bg-info-bg p-4 text-info-fg">
      <Lock className="mt-0.5 h-5 w-5 shrink-0 text-info-fg" />
      <div className="min-w-0">
        <p className="text-sm font-semibold">
          Evidence stays with the issuing organization — only this summary is
          shared.
        </p>
        <p className="mt-1 text-xs leading-5 text-info-fg">
          This is a read-only posture summary issued for an external reviewer.
          Owners, notes, raw evidence, and asset details are not included.
        </p>
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="min-w-0">
      <dt className="text-muted">{label}</dt>
      <dd className="font-semibold text-ink">{value}</dd>
    </div>
  );
}

export default function PublicTrustView() {
  const [data, setData] = useState<PublicTrust | null>(null);
  const [status, setStatus] = useState<"loading" | "ok" | "invalid">("loading");

  useEffect(() => {
    const token = tokenFromPath();
    if (!token || token === "share") {
      setStatus("invalid");
      return;
    }
    let cancelled = false;
    fetch(`/api/public/trust/${encodeURIComponent(token)}`, {
      cache: "no-store",
    })
      .then(async (res) => {
        if (!res.ok) throw new Error(String(res.status));
        return (await res.json()) as PublicTrust;
      })
      .then((body) => {
        if (cancelled) return;
        setData(body);
        setStatus("ok");
      })
      .catch(() => {
        if (cancelled) return;
        setStatus("invalid");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const overall = readiness(data?.posture.state ?? null);
  const openViolations = data?.posture.open_violation_count;
  const staleControls = data?.posture.stale_control_count;

  return (
    <section className="grid min-h-screen place-items-center bg-panel p-4 sm:p-6">
      <div className="w-full min-w-0 max-w-[860px]">
        <header className="mb-6 flex flex-wrap items-center gap-4">
          <TrustOpsLogo
            showWordmark
            subtitle="Trust Center"
            markSize="lg"
            gradientId="trustops-trust-gradient"
          />
          <p className="min-w-0 flex-1 text-sm leading-6 text-muted">
            Shared, read-only verification for external reviewers.
          </p>
        </header>

        <div className="mb-6">
          <ResidencyBanner />
        </div>

        {status === "loading" && (
          <div className="flex items-center gap-3 rounded-xl border border-line bg-surface p-8 text-muted">
            <Loader2 className="h-5 w-5 animate-spin text-brand" />
            Loading shared posture…
          </div>
        )}

        {status === "invalid" && (
          <div className="rounded-xl border border-danger/40 bg-danger-bg p-8 text-danger-fg">
            <div className="flex items-center gap-3">
              <ShieldAlert className="h-6 w-6 shrink-0 text-danger-fg" />
              <h2 className="text-lg font-semibold">
                This trust link is invalid or has expired.
              </h2>
            </div>
            <p className="mt-3 text-sm leading-6 text-danger-fg">
              The link may have been revoked, reached its expiry, or was never
              issued. Ask the issuing organization for a fresh link.
            </p>
          </div>
        )}

        {status === "ok" && data && (
          <div className="grid gap-4">
            <div
              data-testid="trust-posture-card"
              className="rounded-xl border border-line bg-surface p-6 text-ink shadow-sm"
            >
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div className="min-w-0">
                  <p className="text-xs uppercase tracking-wide text-muted">
                    Overall posture
                  </p>
                  <p className="mt-1 text-5xl font-semibold">
                    {data.posture.state === "not_evaluated"
                      ? "—"
                      : roundScore(data.posture.score)}
                    <span className="ml-1 text-xl text-muted">/ 100</span>
                  </p>
                </div>
                <Badge tone={overall.tone}>{overall.label}</Badge>
              </div>
              <dl className="mt-6 grid grid-cols-2 gap-4 text-sm sm:grid-cols-4">
                <Stat
                  label="Frameworks"
                  value={data.posture.framework_count ?? 0}
                />
                <Stat
                  label="Controls"
                  value={data.posture.control_count ?? 0}
                />
                {typeof openViolations === "number" && (
                  <Stat label="Open violations" value={openViolations} />
                )}
                {typeof staleControls === "number" && (
                  <Stat label="Stale controls" value={staleControls} />
                )}
              </dl>
            </div>

            <div className="rounded-xl border border-line bg-surface p-4 text-ink shadow-sm sm:p-6">
              <h2 className="mb-4 text-sm font-semibold uppercase tracking-wide text-muted">
                Framework readiness
              </h2>
              <div className="grid gap-2">
                {data.frameworks.length === 0 && (
                  <p className="text-sm text-muted">
                    No framework readiness to report.
                  </p>
                )}
                {data.frameworks.map((row, index) => {
                  const state = readiness(row.state);
                  const detail = [plural(row.control_count ?? 0, "control")];
                  if (typeof row.failing_control_count === "number") {
                    detail.push(`${row.failing_control_count} failing`);
                  }
                  if (typeof row.stale_control_count === "number") {
                    detail.push(`${row.stale_control_count} stale`);
                  }
                  return (
                    <div
                      key={row.framework ?? `framework-${index}`}
                      className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 rounded-lg border border-line bg-surfaceMuted px-4 py-3"
                    >
                      <div className="min-w-0 flex-1">
                        <p className="font-semibold [overflow-wrap:anywhere]">
                          {row.framework ?? "—"}
                        </p>
                        <p className="text-xs text-muted">
                          {detail.join(" · ")}
                        </p>
                      </div>
                      <div
                        data-testid="framework-score"
                        className="flex shrink-0 items-center gap-3"
                      >
                        <span className="text-lg font-semibold">
                          {roundScore(row.score)}
                        </span>
                        <Badge tone={state.tone}>{state.label}</Badge>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            <footer className="rounded-xl border border-line bg-surface px-6 py-4 text-xs text-muted">
              Issued by{" "}
              <span className="font-semibold text-ink">
                {data.issued_by ?? "the data owner"}
              </span>
              {data.evaluated_at && (
                <> · Last verified {formatDate(data.evaluated_at)}</>
              )}
              {data.expires_at && (
                <> · Link expires {formatDate(data.expires_at)}</>
              )}
            </footer>
          </div>
        )}
      </div>
    </section>
  );
}
