import type { Metadata } from "next";
import { ReactNode } from "react";
import { Toaster } from "sonner";
import { Providers } from "./providers";
import { Shell } from "@/components/shell/Shell";
import { BRAND } from "@/lib/brand";
// Canvas styles load with the global sheet: imported per canvas, webpack split
// them into a chunk that several routes preloaded without applying.
import "@xyflow/react/dist/style.css";
import "./globals.css";

const metadataBase = new URL(
  process.env.NEXT_PUBLIC_APP_URL ?? "http://localhost:8787",
);

export const metadata: Metadata = {
  metadataBase,
  description: BRAND.description,
  applicationName: BRAND.name,
  openGraph: {
    title: BRAND.consoleName,
    description: BRAND.description,
    siteName: BRAND.name,
    type: "website",
    images: [
      {
        url: "/console/og/trustops-share.svg",
        width: 1200,
        height: 630,
        alt: `${BRAND.name} — ${BRAND.category}`,
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: BRAND.consoleName,
    description: BRAND.description,
  },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body>
        <Providers>
          <Shell>{children}</Shell>
        </Providers>
        <Toaster
          position="bottom-center"
          richColors
          closeButton
          toastOptions={{ duration: 4200 }}
        />
        <script
          id="app-data"
          type="application/json"
          // dashboard.py replaces this with the live assessment payload when
          // generating a static console.html for offline/audit distribution.
          dangerouslySetInnerHTML={{ __html: "{}" }}
        />
      </body>
    </html>
  );
}
