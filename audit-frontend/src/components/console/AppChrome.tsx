"use client";

import AppLayout from "@cloudscape-design/components/app-layout";
import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import FormField from "@cloudscape-design/components/form-field";
import Popover from "@cloudscape-design/components/popover";
import SideNavigation from "@cloudscape-design/components/side-navigation";
import type { SideNavigationProps } from "@cloudscape-design/components/side-navigation";
import TopNavigation from "@cloudscape-design/components/top-navigation";
import Toggle from "@cloudscape-design/components/toggle";
import { usePathname, useRouter } from "next/navigation";
import { useTheme } from "next-themes";
import { useCallback, useEffect, useMemo, useState } from "react";

const AWS_LOGO =
  "https://upload.wikimedia.org/wikipedia/commons/9/93/Amazon_Web_Services_Logo.svg";

const HEADER_HEIGHT = 56;

const SIDE_ITEMS: ReadonlyArray<SideNavigationProps.Item> = [
  {
    type: "section",
    text: "Overview",
    items: [{ type: "link", text: "Welcome", href: "/" }],
  },
  {
    type: "section",
    text: "Account",
    items: [{ type: "link", text: "Onboard AWS account", href: "/onboarding" }],
  },
  {
    type: "section",
    text: "Audits",
    items: [{ type: "link", text: "Operations dashboard", href: "/dashboard" }],
  },
];

export function AppChrome({ children }: { children: React.ReactNode }) {
  const pathname = usePathname() ?? "/";
  const router = useRouter();
  const { setTheme, resolvedTheme } = useTheme();
  const [navOpen, setNavOpen] = useState(true);

  useEffect(() => {
    if (typeof window === "undefined") return;
    if (!window.matchMedia("(max-width: 1023px)").matches) return;
    queueMicrotask(() => {
      setNavOpen(false);
    });
  }, []);

  const activeNavHref = useMemo(() => {
    if (pathname === "/") return "/";
    if (pathname.startsWith("/onboarding")) return "/onboarding";
    if (pathname.startsWith("/dashboard")) return "/dashboard";
    return pathname;
  }, [pathname]);

  const identityFollow = useCallback(
    (event: CustomEvent) => {
      event.preventDefault();
      router.push("/");
    },
    [router],
  );

  const navFollow = useCallback(
    (event: CustomEvent) => {
      event.preventDefault();
      const href = (event.detail as { href?: string } | undefined)?.href;
      if (href) router.push(href);
    },
    [router],
  );

  const isDarkChrome = resolvedTheme !== "light";

  const preferencesContent = useMemo(
    () => (
      <Box padding={{ horizontal: "l", vertical: "m" }}>
        <FormField
          label="Color scheme"
          description="Saved in this browser. Applies to the whole console."
          stretch
        >
          <Toggle
            checked={isDarkChrome}
            onChange={({ detail }) =>
              setTheme(detail.checked ? "dark" : "light")
            }
          >
            Dark mode
          </Toggle>
        </FormField>
      </Box>
    ),
    [isDarkChrome, setTheme],
  );

  return (
    <div className="flex h-[100dvh] min-h-0 min-w-0 flex-col overflow-x-hidden">
      <div
        id="audit-app-header"
        className="audit-app-header fixed top-0 left-0 right-0 z-[1000]"
      >
        <TopNavigation
          identity={{
            href: "/",
            title: "AWS Audit Platform",
            logo: { src: AWS_LOGO, alt: "AWS" },
            onFollow: identityFollow,
          }}
          utilities={[]}
        />
        <div className="pointer-events-none absolute inset-0 left-auto flex w-[min(72px,20vw)] items-center justify-center pr-4">
          <div className="pointer-events-auto">
            <Popover
              size="large"
              fixedWidth
              position="bottom"
              triggerType="custom"
              header="Preferences"
              dismissAriaLabel="Close preferences"
              renderWithPortal
              content={preferencesContent}
            >
              <Button
                variant="icon"
                iconName="settings"
                ariaLabel="Open preferences"
                formAction="none"
              />
            </Popover>
          </div>
        </div>
      </div>

      <div className="flex min-h-0 min-w-0 flex-1 flex-col" style={{ paddingTop: HEADER_HEIGHT }}>
        <AppLayout
          headerSelector="#audit-app-header"
          navigation={
            <SideNavigation
              activeHref={activeNavHref}
              items={SIDE_ITEMS}
              onFollow={navFollow}
            />
          }
          navigationOpen={navOpen}
          onNavigationChange={({ detail }) => setNavOpen(detail.open)}
          toolsHide
          content={
            <div className="audit-console-main-scroll min-h-0 min-w-0 flex-1 overflow-y-auto overflow-x-hidden px-3 py-3 sm:px-4 sm:py-4 md:px-6 md:py-5">
              {children}
            </div>
          }
          ariaLabels={{
            navigation: "Side navigation",
            navigationClose: "Close side navigation",
            navigationToggle: "Open side navigation",
            notifications: "Notifications",
            tools: "Tools",
            toolsClose: "Close tools",
            toolsToggle: "Open tools",
          }}
        />
      </div>
    </div>
  );
}
