"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Icon, type IconName } from "@/components/icon";
import { ArgusMark } from "@/components/argus-mark";

const nav: { label: string; href: string; icon: IconName; dot?: boolean }[] = [
  { label: "Overview", href: "/", icon: "grid" },
  { label: "Assets", href: "/assets", icon: "server" },
  { label: "Network", href: "/network", icon: "network" },
  { label: "Vulns", href: "/vulns", icon: "alert", dot: true },
  { label: "Risk", href: "/risk", icon: "activity" },
  { label: "Settings", href: "/settings", icon: "sliders" },
];

export function Sidebar() {
  const pathname = usePathname();
  const isActive = (href: string) =>
    href === "/" ? pathname === "/" : pathname.startsWith(href);

  return (
    <aside className="hidden w-[88px] shrink-0 flex-col items-center bg-sidebar py-4 md:flex">
      {/* brand mark */}
      <Link href="/" className="mb-5 flex flex-col items-center gap-1.5">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-[#3b82f6] to-[#1e3a8a] text-white shadow-lg shadow-black/40 ring-1 ring-white/15">
          <ArgusMark size={24} />
        </div>
        <span className="text-[10px] font-semibold tracking-[0.2em] text-sidebar-fg">
          ARGUS
        </span>
      </Link>

      {/* nav rail */}
      <nav className="flex flex-1 flex-col items-center gap-1.5">
        {nav.map((it) => {
          const active = isActive(it.href);
          return (
            <Link
              key={it.label}
              href={it.href}
              className={`group relative flex w-16 flex-col items-center gap-1.5 rounded-xl px-2 py-2.5 text-[10px] font-medium transition-colors ${
                active
                  ? "bg-sidebar-2 text-white"
                  : "text-sidebar-fg hover:bg-sidebar-2/60 hover:text-white"
              }`}
            >
              {active && (
                <span className="absolute left-[-8px] top-1/2 h-7 w-[3px] -translate-y-1/2 rounded-r bg-accent" />
              )}
              <span
                className={
                  active
                    ? "text-white"
                    : "text-[color:var(--color-sidebar-icon)] group-hover:text-white"
                }
              >
                <Icon name={it.icon} size={20} />
              </span>
              <span>{it.label}</span>
              {it.dot && (
                <span className="absolute right-2.5 top-2 h-2 w-2 rounded-full bg-accent ring-2 ring-[color:var(--color-sidebar)]" />
              )}
            </Link>
          );
        })}
      </nav>

      {/* help bubble */}
      <button
        type="button"
        aria-label="Help"
        className="mt-3 flex h-11 w-11 items-center justify-center rounded-full bg-accent text-white shadow-lg shadow-black/40 transition-transform hover:scale-105"
      >
        <Icon name="chat" size={20} />
      </button>
    </aside>
  );
}
