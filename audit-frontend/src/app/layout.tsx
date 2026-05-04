import type { Metadata } from "next";

import { Providers } from "@/components/console/Providers";

import "./globals.css";

export const metadata: Metadata = {
  title: "AWS Audit Platform",
  description:
    "Security-first and cost-aware AWS account audits with actionable remediation.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="antialiased" suppressHydrationWarning>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
