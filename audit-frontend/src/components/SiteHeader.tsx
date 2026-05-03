import Image from "next/image";
import Link from "next/link";

type NavItem = { href: string; label: string };

export function SiteHeader({
  nav,
}: {
  nav?: NavItem[];
}) {
  return (
    <header className="border-b border-[var(--border)] bg-[var(--panel)]/80 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 py-3 flex flex-wrap items-center justify-between gap-4">
        <Link href="/" className="flex items-center gap-3 group">
          <span className="relative h-9 w-9 shrink-0 rounded-lg bg-white/95 p-1.5 shadow-lg shadow-black/20 ring-1 ring-white/10">
            <Image
              src="https://upload.wikimedia.org/wikipedia/commons/9/93/Amazon_Web_Services_Logo.svg"
              alt="AWS"
              width={36}
              height={36}
              className="object-contain"
              priority
            />
          </span>
          <span className="flex flex-col leading-tight">
            <span className="text-sm font-semibold tracking-tight text-white group-hover:text-aws-orange transition-colors">
              Audit Platform
            </span>
            <span className="text-[10px] uppercase tracking-widest text-slate-500">
              Security · Cost · WAR-aligned
            </span>
          </span>
        </Link>
        {nav && nav.length > 0 && (
          <nav className="flex flex-wrap gap-1">
            {nav.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className="text-xs sm:text-sm px-3 py-1.5 rounded-md text-slate-400 hover:text-white hover:bg-white/5 transition-colors"
              >
                {item.label}
              </Link>
            ))}
          </nav>
        )}
      </div>
    </header>
  );
}
