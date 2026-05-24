import type { Metadata, Viewport } from "next";

import { Providers } from "@/components/console/Providers";
import { THEME_INIT_INLINE_SCRIPT } from "@/lib/theme-init-inline";

import "./globals.css";

export const metadata: Metadata = {
  title: "AWS Audit Platform",
  description:
    "Security-first and cost-aware AWS account audits with actionable remediation.",
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#f2f3f3" },
    { media: "(prefers-color-scheme: dark)", color: "#0f172a" },
  ],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="antialiased min-h-[100dvh] min-w-0 touch-manipulation" suppressHydrationWarning>
        <script
          suppressHydrationWarning
          dangerouslySetInnerHTML={{ __html: THEME_INIT_INLINE_SCRIPT }}
        />
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
