"use client";

// Authenticated application frame. Renders /login bare; everything else is
// gated on a session and wrapped in the sidebar + topbar chrome. Owns the
// mobile navigation state: the topbar opens the sidebar slide-over; the
// backdrop, close button, Escape and every nav-link click close it.

import { usePathname, useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { Sidebar } from "@/components/sidebar";
import { TopBar } from "@/components/topbar";
import { useAuth } from "@/lib/auth";
import { CommandPalette } from "@/components/command-palette";

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { session, ready } = useAuth();
  const isLogin = pathname === "/login";
  // Plain boolean: every nav-link click in the sidebar calls onClose, so no
  // pathname effect (and no remembered route) is needed.
  const [navOpen, setNavOpen] = useState(false);
  const openNav = useCallback(() => setNavOpen(true), []);
  const closeNav = useCallback(() => setNavOpen(false), []);

  // Command palette state
  const [paletteOpen, setPaletteOpen] = useState(false);
  const closePalette = useCallback(() => setPaletteOpen(false), []);

  // Global Cmd+K / Ctrl+K hotkey — toggles the command palette
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setPaletteOpen((prev) => !prev);
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  useEffect(() => {
    if (ready && !session && !isLogin) router.replace("/login");
  }, [ready, session, isLogin, router]);

  if (isLogin) return <>{children}</>;
  // Until hydration finishes (or while redirecting) render nothing rather
  // than flashing the protected console.
  if (!ready || !session) return null;

  return (
    <div className="flex min-h-screen">
      <Sidebar open={navOpen} onClose={closeNav} />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar onMenuClick={openNav} />
        <main className="flex-1 p-6 lg:p-8">{children}</main>
      </div>
      <CommandPalette open={paletteOpen} onClose={closePalette} />
    </div>
  );
}
