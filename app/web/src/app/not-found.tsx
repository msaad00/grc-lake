import Link from "next/link";

export default function NotFound() {
  return (
    <main className="mx-auto grid min-h-[60vh] max-w-xl content-center gap-4 px-6 py-16">
      <p className="text-xs font-semibold uppercase tracking-widest text-brand">
        TrustOps · 404
      </p>
      <h1 className="text-3xl font-semibold tracking-tight text-ink">
        This page is not available
      </h1>
      <p className="text-sm leading-6 text-muted">
        The link may have changed. Return to your overview to find controls,
        evidence, and open work.
      </p>
      <Link
        className="w-fit rounded-lg bg-brand px-4 py-2 text-sm font-semibold text-onBrand focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-4"
        href="/dashboard"
      >
        Return to overview
      </Link>
    </main>
  );
}
