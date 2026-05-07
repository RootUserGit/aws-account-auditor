import { AppChrome } from "@/components/console/AppChrome";

export default function ConsoleLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return <AppChrome>{children}</AppChrome>;
}
