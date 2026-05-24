"use client";

import { applyMode, Mode } from "@cloudscape-design/global-styles";
import {
  AUDIT_THEME_DEFAULT,
  AUDIT_THEME_ENABLE_SYSTEM,
  AUDIT_THEME_STORAGE_KEY,
} from "@/lib/theme-config";
import { ThemeProvider, useTheme } from "next-themes";
import { useLayoutEffect } from "react";
import { Toaster } from "sonner";

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
      defaultTheme={AUDIT_THEME_DEFAULT}
      enableSystem={AUDIT_THEME_ENABLE_SYSTEM}
      storageKey={AUDIT_THEME_STORAGE_KEY}
      disableTransitionOnChange
    >
      <CloudscapeModeSync />
      <Toaster richColors closeButton />
      {children}
    </ThemeProvider>
  );
}
