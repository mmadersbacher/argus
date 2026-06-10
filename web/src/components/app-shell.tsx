"use client";

// Authenticated application frame. Renders /login bare; everything else is
// gated on a session and wrapped in the sidebar + topbar chrome.

import { usePathname, useRouter } from "next/navigation";
import { useEffect } from "react";
import { Sidebar } from "@/components/sidebar";
import { TopBar } from "@/components/topbar";
import { useAuth } from "@/lib/auth";

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { session, ready } = useAuth();
  const isLogin = pathname === "/login";

  useEffect(() => {
    if (ready && !session && !isLogin) router.replace("/login");
  }, [ready, session, isLogin, router]);

  if (isLogin) return <>{children}</>;
  // Until hydration finishes (or while redirecting) render nothing rather
  // than flashing the protected console.
  if (!ready || !session) return null;

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar />
        <main className="flex-1 p-6 lg:p-8">{children}</main>
      </div>
    </div>
  );
}
