"use client";

import { applyMode, Mode } from "@cloudscape-design/global-styles";
import { ThemeProvider, useTheme } from "next-themes";
import { useLayoutEffect } from "react";
import { Toaster } from "sonner";

const STORAGE_KEY = "audit-ui-theme";

function CloudscapeModeSync() {
  const { resolvedTheme } = useTheme();

  useLayoutEffect(() => {
    const resolved =
      resolvedTheme ??
      (globalThis.window?.matchMedia("(prefers-color-scheme: light)")?.matches
        ? "light"
        : "dark");
    const mode = resolved === "light" ? Mode.Light : Mode.Dark;
    applyMode(mode, document.body);
  }, [resolvedTheme]);

  return null;
}

export function Providers({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <ThemeProvider
      attribute="class"
      defaultTheme="dark"
      enableSystem
      storageKey={STORAGE_KEY}
    >
      <CloudscapeModeSync />
      <Toaster richColors closeButton />
      {children}
    </ThemeProvider>
  );
}
