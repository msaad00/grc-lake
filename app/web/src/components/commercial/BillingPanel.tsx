"use client";

import { useEffect, useMemo } from "react";
import { CreditCard, ExternalLink, Loader2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { QueryState } from "@/components/QueryState";
import {
  useAuthWhoami,
  useBilling,
  useBillingCheckoutMutation,
  useBillingPortalMutation,
} from "@/lib/api/hooks";
import type { BillingStatus } from "@/lib/api/types";
import { notify } from "@/lib/toast";
import { formatWhen } from "@/lib/utils";

const ACCESS_COPY: Record<
  BillingStatus["access"],
  { label: string; tone: "ready" | "attention" | "critical" }
> = {
  active: { label: "Active", tone: "ready" },
  grace: { label: "Payment due", tone: "attention" },
  read_only: { label: "Read-only", tone: "critical" },
};

function isNotImplemented(error: unknown): boolean {
  return String((error as Error | null)?.message ?? "").includes("501");
}

function titleCase(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function graceDeadline(status: BillingStatus): string {
  if (!status.past_due_since) return "soon";
  const deadline = new Date(status.past_due_since);
  if (Number.isNaN(deadline.getTime())) return "soon";
  deadline.setDate(deadline.getDate() + status.grace_days);
  return deadline.toLocaleDateString();
}

export function BillingPanel() {
  const whoami = useAuthWhoami();
  const isAdmin = useMemo(
    () => Boolean(whoami.data?.role === "admin"),
    [whoami.data],
  );
  const billing = useBilling({ enabled: Boolean(whoami.data) });
  const checkout = useBillingCheckoutMutation();
  const portal = useBillingPortalMutation();

  useEffect(() => {
    if (typeof window === "undefined") return;
    const result = new URLSearchParams(window.location.search).get("billing");
    if (result === "success") {
      notify.success("Payment received — your plan updates in a moment.");
    } else if (result === "cancel") {
      notify.error("Checkout was cancelled; nothing was charged.");
    }
  }, []);

  if (!whoami.data || (billing.isError && isNotImplemented(billing.error))) {
    return null;
  }

  const go = async (action: () => Promise<{ url: string }>) => {
    try {
      const { url } = await action();
      window.location.assign(url);
    } catch (err) {
      notify.error(String((err as Error).message));
    }
  };

  const status = billing.data;
  const access = status ? ACCESS_COPY[status.access] : null;

  return (
    <Card>
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
        <div className="min-w-[16rem] flex-1">
          <CardTitle className="flex items-center gap-2">
            <CreditCard className="h-5 w-5 text-brand" />
            Billing
          </CardTitle>
          <CardDescription>
            Plans are paid and changed through Stripe; card details never reach
            TrustOps.
          </CardDescription>
        </div>
        {isAdmin && status?.customer_linked ? (
          <Button
            size="sm"
            variant="default"
            className="shrink-0"
            disabled={portal.isPending}
            onClick={() => go(() => portal.mutateAsync())}
          >
            {portal.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <ExternalLink className="h-4 w-4" />
            )}
            Manage billing
          </Button>
        ) : null}
      </CardHeader>
      <CardContent className="grid gap-3">
        <QueryState queries={[billing]} label="billing">
          {status && access ? (
            <>
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm font-semibold text-ink">
                  {titleCase(status.plan_tier ?? "starter")} plan
                </span>
                <Badge tone={access.tone}>{access.label}</Badge>
                {status.subscription_status ? (
                  <Badge tone="default">{status.subscription_status}</Badge>
                ) : null}
              </div>
              {status.current_period_end ? (
                <p className="text-xs text-muted">
                  {status.cancel_at_period_end ? "Ends" : "Renews"}{" "}
                  {formatWhen(status.current_period_end)}
                </p>
              ) : null}
              {status.access === "grace" ? (
                <p className="rounded-lg border border-line bg-surfaceMuted p-3 text-sm text-ink">
                  A payment failed. The workspace stays fully available until{" "}
                  {graceDeadline(status)}, then becomes read-only until payment
                  is updated.
                </p>
              ) : null}
              {status.access === "read_only" ? (
                <p className="rounded-lg border border-line bg-surfaceMuted p-3 text-sm text-ink">
                  This workspace is read-only: all data and reports remain
                  available, but changes are paused until billing is resolved.
                </p>
              ) : null}
              {isAdmin && !status.customer_linked ? (
                status.self_serve_plans.length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {status.self_serve_plans.map((plan) => (
                      <Button
                        key={plan}
                        size="sm"
                        variant={plan === "team" ? "primary" : "default"}
                        disabled={checkout.isPending}
                        onClick={() => go(() => checkout.mutateAsync(plan))}
                      >
                        Subscribe to {titleCase(plan)}
                      </Button>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-muted">
                    No self-serve plans are configured. Contact sales for a
                    subscription.
                  </p>
                )
              ) : null}
            </>
          ) : null}
        </QueryState>
      </CardContent>
    </Card>
  );
}
