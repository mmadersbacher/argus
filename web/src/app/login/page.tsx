"use client";

// Sign-in / organization signup. The only unauthenticated page.

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { ArgusMark } from "@/components/argus-mark";
import { useAuth } from "@/lib/auth";

type Mode = "login" | "register";

export default function LoginPage() {
  const router = useRouter();
  const { session, ready, login, register } = useAuth();
  const [mode, setMode] = useState<Mode>("login");
  const [organization, setOrganization] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (ready && session) router.replace("/");
  }, [ready, session, router]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (mode === "login") {
        await login(email, password);
      } else {
        await register(organization, email, password);
      }
      router.replace("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "request failed");
    } finally {
      setBusy(false);
    }
  };

  const tab = (m: Mode, label: string) => (
    <button
      type="button"
      onClick={() => {
        setMode(m);
        setError(null);
      }}
      className={`flex-1 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
        mode === m
          ? "bg-surface text-fg shadow-sm"
          : "text-muted hover:text-fg"
      }`}
    >
      {label}
    </button>
  );

  const field =
    "w-full rounded-lg border border-line bg-surface px-3 py-2.5 text-sm text-fg outline-none transition-colors placeholder:text-muted focus:border-accent";

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg p-6">
      <div className="argus-rise w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center gap-2">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br from-[#3b82f6] to-[#1e3a8a] text-white shadow-lg shadow-black/20 ring-1 ring-white/15">
            <ArgusMark size={28} />
          </div>
          <h1 className="text-lg font-semibold tracking-tight">
            Argus Console
          </h1>
          <p className="text-sm text-muted">
            Cyber exposure &amp; asset intelligence
          </p>
        </div>

        <div className="rounded-2xl border border-line bg-surface p-5 shadow-sm">
          <div className="mb-4 flex gap-1 rounded-xl bg-surface-2 p-1">
            {tab("login", "Sign in")}
            {tab("register", "Create organization")}
          </div>

          <form onSubmit={submit} className="flex flex-col gap-3">
            {mode === "register" && (
              <input
                className={field}
                placeholder="Organization name"
                value={organization}
                onChange={(e) => setOrganization(e.target.value)}
                required
                autoFocus
              />
            )}
            <input
              className={field}
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoComplete="email"
            />
            <input
              className={field}
              type="password"
              placeholder={
                mode === "register" ? "Password (min 10 chars)" : "Password"
              }
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={mode === "register" ? 10 : undefined}
              autoComplete={
                mode === "register" ? "new-password" : "current-password"
              }
            />

            {error && (
              <p className="rounded-lg border border-crit/30 bg-crit/5 px-3 py-2 text-sm text-crit">
                {error}
              </p>
            )}

            <button
              type="submit"
              disabled={busy}
              className="mt-1 rounded-lg bg-accent px-3 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-accent-2 disabled:opacity-60"
            >
              {busy
                ? "Working…"
                : mode === "login"
                  ? "Sign in"
                  : "Create organization"}
            </button>
          </form>
        </div>

        <p className="mt-4 text-center text-xs text-muted">
          First run? The bootstrap admin credentials are printed in the
          argus-api log.
        </p>
      </div>
    </div>
  );
}
