"use client";

// Labeled navy sidebar. Static rail at md+; slide-over with backdrop below md.
// Open state lives in AppShell; every nav-link click, Escape, the backdrop
// and the close button call onClose.

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useRef } from "react";
import { Icon, type IconName } from "@/components/icon";
import { BrandTile } from "@/components/argus-mark";

interface NavItem {
  label: string;
  href: string;
  icon: IconName;
}

interface NavSection {
  label: string;
  items: NavItem[];
}

const sections: NavSection[] = [
  {
    label: "Monitor",
    items: [
      { label: "Overview", href: "/", icon: "grid" },
      { label: "Assets", href: "/assets", icon: "server" },
      { label: "Network", href: "/network", icon: "network" },
    ],
  },
  {
    label: "Analyze",
    items: [
      { label: "Vulnerabilities", href: "/vulns", icon: "bug" },
      { label: "Risk", href: "/risk", icon: "gauge" },
      { label: "Segmentation", href: "/policy", icon: "shield" },
      { label: "Reports", href: "/reports", icon: "file" },
    ],
  },
  {
    label: "Manage",
    items: [{ label: "Settings", href: "/settings", icon: "sliders" }],
  },
];

export function Sidebar({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const pathname = usePathname();
  const isActive = (href: string) =>
    href === "/" ? pathname === "/" : pathname.startsWith(href);
  const closeButtonRef = useRef<HTMLButtonElement>(null);

  // While the mobile slide-over is open it behaves like a modal: Escape
  // closes it, focus moves to the close button on open and returns to the
  // previously focused element (the hamburger) on close.
  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    closeButtonRef.current?.focus();
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      previous?.focus();
    };
  }, [open, onClose]);

  return (
    <>
      {/* mobile backdrop */}
      {open ? (
        <div
          className="fixed inset-0 z-40 bg-sidebar/50 md:hidden"
          onClick={onClose}
          aria-hidden="true"
        />
      ) : null}

      <aside
        role={open ? "dialog" : undefined}
        aria-modal={open ? true : undefined}
        aria-label={open ? "Navigation" : undefined}
        className={`fixed inset-y-0 left-0 z-50 flex w-[232px] flex-col bg-sidebar transition-[transform,visibility] duration-200 ease-out md:static md:z-auto md:visible md:shrink-0 md:translate-x-0 md:transition-none ${
          open ? "visible translate-x-0" : "invisible -translate-x-full"
        }`}
      >
        {/* brand lockup */}
        <div className="relative px-4 pb-2 pt-5">
          <Link
            href="/"
            onClick={onClose}
            className="flex items-center gap-3 rounded-lg px-1.5 py-1 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
          >
            <BrandTile size={36} markSize={22} />
            <div className="leading-tight">
              <span className="block text-sm font-semibold tracking-[0.18em] text-white">
                ARGUS
              </span>
              <span className="block text-[10px] font-medium tracking-wide text-sidebar-icon">
                Exposure Console
              </span>
            </div>
          </Link>
          {/* mobile close */}
          <button
            ref={closeButtonRef}
            type="button"
            onClick={onClose}
            aria-label="Close navigation"
            className="absolute right-3 top-5 flex h-8 w-8 items-center justify-center rounded-lg text-sidebar-fg transition-colors hover:bg-sidebar-2/60 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 md:hidden"
          >
            <Icon name="x" size={17} />
          </button>
        </div>

        {/* navigation */}
        <nav className="flex-1 space-y-5 overflow-y-auto px-3 py-4">
          {sections.map((section) => (
            <div key={section.label}>
              <p className="px-3 pb-1.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-sidebar-icon">
                {section.label}
              </p>
              <div className="space-y-0.5">
                {section.items.map((item) => {
                  const active = isActive(item.href);
                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      onClick={onClose}
                      aria-current={active ? "page" : undefined}
                      className={`group relative flex items-center gap-2.5 rounded-lg px-3 py-2 text-[13px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 ${
                        active
                          ? "bg-sidebar-2 text-white"
                          : "text-sidebar-fg hover:bg-sidebar-2/50 hover:text-white"
                      }`}
                    >
                      {active ? (
                        <span className="absolute left-0 top-1/2 h-5 w-0.5 -translate-y-1/2 rounded-full bg-accent" />
                      ) : null}
                      <span
                        className={
                          active
                            ? "text-white"
                            : "text-sidebar-icon transition-colors group-hover:text-white"
                        }
                      >
                        <Icon name={item.icon} size={17} />
                      </span>
                      {item.label}
                    </Link>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* footer */}
        <div className="border-t border-white/10 px-5 py-4">
          <p className="text-[11px] leading-relaxed text-sidebar-icon">
            Argus — open source CAASM
          </p>
        </div>
      </aside>
    </>
  );
}
