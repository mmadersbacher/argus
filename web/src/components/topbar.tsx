"use client";

// Top chrome: mobile nav trigger, functional asset search, live indicator,
// theme toggle and the account menu (now backed by the Menu primitive).

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Icon } from "@/components/icon";
import { ThemeToggle } from "@/components/theme";
import { Badge, Menu } from "@/components/ui";
import { useAuth } from "@/lib/auth";

export function TopBar({ onMenuClick }: { onMenuClick: () => void }) {
  const router = useRouter();
  const { session, logout } = useAuth();
  const [query, setQuery] = useState("");

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

      <div className="ml-auto flex items-center gap-2">
        {/* live indicator */}
        <span className="hidden items-center gap-1.5 rounded-full border border-line px-2.5 py-1 text-xs font-medium text-muted sm:inline-flex">
          <span className="argus-pulse h-1.5 w-1.5 rounded-full bg-ok" />
          Live
        </span>

        {/* theme toggle */}
        <ThemeToggle />

        {/* account menu — email + role as non-interactive header, then sign-out */}
        <Menu
          align="end"
          triggerClassName="flex h-9 w-9 items-center justify-center rounded-full bg-accent text-sm font-semibold text-on-accent transition-colors hover:bg-accent-2"
          trigger={initial}
          header={
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
          }
          items={[
            {
              label: "Sign out",
              icon: "logout",
              onSelect: logout,
            },
          ]}
        />
      </div>
    </header>
  );
}
