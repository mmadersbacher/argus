"use client";

// Top chrome: mobile nav trigger, functional asset search, live indicator
// and the account menu.

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { Icon } from "@/components/icon";
import { Badge } from "@/components/ui";
import { useAuth } from "@/lib/auth";

export function TopBar({ onMenuClick }: { onMenuClick: () => void }) {
  const router = useRouter();
  const { session, logout } = useAuth();
  const [query, setQuery] = useState("");
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const accountTriggerRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!menuOpen) return;
    const close = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
      }
    };
    const escape = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setMenuOpen(false);
        accountTriggerRef.current?.focus();
      }
    };
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", escape);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", escape);
    };
  }, [menuOpen]);

  const submitSearch = (e: React.FormEvent) => {
    e.preventDefault();
    const q = query.trim();
    router.push(q ? `/assets?q=${encodeURIComponent(q)}` : "/assets");
  };

  const initial = session?.email?.charAt(0).toUpperCase() ?? "?";

  return (
    <header className="flex h-16 items-center gap-3 border-b border-line bg-surface px-4 sm:px-6">
      {/* mobile nav trigger */}
      <button
        type="button"
        onClick={onMenuClick}
        aria-label="Open navigation"
        className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-fg-2 transition-colors hover:bg-surface-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 md:hidden"
      >
        <Icon name="menu" size={18} />
      </button>

      {/* search */}
      <form
        role="search"
        onSubmit={submitSearch}
        className="relative w-full max-w-md"
      >
        <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint">
          <Icon name="search" size={16} />
        </span>
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search assets, IPs, vendors…"
          aria-label="Search assets"
          className="h-9 w-full rounded-lg border border-line bg-surface-2 pl-9 pr-3 text-sm text-fg transition-colors placeholder:text-faint focus:border-accent focus:bg-surface focus:outline-none focus:ring-2 focus:ring-accent/20"
        />
      </form>

      <div className="ml-auto flex items-center gap-3">
        {/* live indicator */}
        <span className="hidden items-center gap-1.5 rounded-full border border-line px-2.5 py-1 text-xs font-medium text-muted sm:inline-flex">
          <span className="argus-pulse h-1.5 w-1.5 rounded-full bg-ok" />
          Live
        </span>

        {/* account menu */}
        <div className="relative" ref={menuRef}>
          <button
            ref={accountTriggerRef}
            type="button"
            aria-label="Account"
            aria-expanded={menuOpen}
            onClick={() => setMenuOpen((open) => !open)}
            className="flex h-9 w-9 items-center justify-center rounded-full bg-accent text-sm font-semibold text-white transition-colors hover:bg-accent-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
          >
            {initial}
          </button>
          {menuOpen ? (
            <div className="argus-rise absolute right-0 top-11 z-30 w-64 rounded-xl border border-line bg-surface p-1.5 shadow-lg">
              <div className="px-3 py-2.5">
                <p className="truncate text-sm font-medium text-fg">
                  {session?.email}
                </p>
                <div className="mt-1.5">
                  <Badge tone="neutral">
                    <span className="capitalize">{session?.role}</span>
                  </Badge>
                </div>
              </div>
              <div className="my-1 border-t border-line" />
              <button
                type="button"
                onClick={logout}
                className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-sm text-fg-2 transition-colors hover:bg-surface-2 hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
              >
                <Icon name="logout" size={16} />
                Sign out
              </button>
            </div>
          ) : null}
        </div>
      </div>
    </header>
  );
}
