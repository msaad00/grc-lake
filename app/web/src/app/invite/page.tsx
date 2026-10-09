"use client";

import { Suspense, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Loader2, MailCheck } from "lucide-react";
import { TrustOpsLogo } from "@/components/brand/TrustOpsLogo";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { api } from "@/lib/api/client";
import { notify } from "@/lib/toast";

function InviteAcceptForm() {
  const params = useSearchParams();
  const router = useRouter();
  const token = params.get("token") ?? "";
  const [displayName, setDisplayName] = useState("");
  const [pending, setPending] = useState(false);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!token) {
      notify.error("Invite token is required");
      return;
    }
    setPending(true);
    try {
      await api.acceptInvite({ token, display_name: displayName });
      notify.success("Invite accepted — sign in to continue");
      router.replace("/login/");
    } catch (err) {
      notify.error(String((err as Error).message));
    } finally {
      setPending(false);
    }
  };

  return (
    <Card className="w-full">
      <CardHeader>
        <TrustOpsLogo className="mb-3 h-8 w-auto" />
        <h1 className="flex items-center gap-2 text-lg font-semibold leading-tight text-ink">
          <MailCheck aria-hidden="true" className="h-5 w-5 text-brand" />
          Accept invite
        </h1>
      </CardHeader>
      <CardContent>
        {!token ? (
          <p className="text-sm text-muted">
            Paste the invite link from your email or open the URL with a{" "}
            <code>?token=</code> query parameter.
          </p>
        ) : (
          <form className="grid gap-3" onSubmit={submit}>
            <label className="grid gap-1 text-sm">
              <span className="font-semibold text-ink">Display name</span>
              <input
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                className="rounded-lg border border-line px-3 py-2"
                placeholder="Your name"
              />
            </label>
            <Button type="submit" variant="primary" disabled={pending}>
              {pending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                "Join workspace"
              )}
            </Button>
          </form>
        )}
        <p className="mt-4 text-sm text-muted">
          <Link href="/login" className="font-semibold text-brand underline">
            Back to sign in
          </Link>
        </p>
      </CardContent>
    </Card>
  );
}

export default function InvitePage() {
  return (
    <div className="mx-auto grid min-h-screen max-w-lg place-items-center px-4 py-10">
      <Suspense
        fallback={<div className="text-sm text-muted">Loading invite…</div>}
      >
        <InviteAcceptForm />
      </Suspense>
    </div>
  );
}
