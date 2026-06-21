"use client";

// Sign-in / organization signup. The only unauthenticated page.

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { BrandTile } from "@/components/argus-mark";
import { Button, Field, FormError, Input, Tabs, TabPanel } from "@/components/ui";
import { useAuth } from "@/lib/auth";

type Mode = "login" | "register";

const LOGIN_TABS = [
  { id: "login", label: "Sign in" },
  { id: "register", label: "Create organization" },
];

const ERROR_ID = "login-form-error";

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

  const handleModeChange = (id: string) => {
    setMode(id as Mode);
    setError(null);
  };

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

  const inputErrorProps = error
    ? { "aria-invalid": true as const, "aria-describedby": ERROR_ID }
    : {};

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg p-6">
      <div className="argus-rise w-full max-w-sm">
        {/* brand lockup */}
        <div className="mb-6 flex flex-col items-center gap-3">
          <BrandTile size={48} markSize={28} />
          <div className="text-center leading-tight">
            <p className="text-base font-semibold tracking-[0.18em] text-fg">
              ARGUS
            </p>
            <p className="mt-1 text-sm text-muted">Exposure Console</p>
          </div>
        </div>

        <div className="rounded-xl border border-line bg-surface p-6 shadow-[0_1px_2px_rgba(16,24,40,0.05)]">
          {/* mode switch */}
          <div className="mb-5">
            <Tabs
              tabs={LOGIN_TABS}
              active={mode}
              onChange={handleModeChange}
            />
          </div>

          <form onSubmit={submit} className="space-y-4">
            <TabPanel when="register" active={mode}>
              <div className="space-y-4">
                <Field label="Organization name">
                  <Input
                    placeholder="Acme Corp"
                    value={organization}
                    onChange={(e) => setOrganization(e.target.value)}
                    required
                    autoFocus
                    {...inputErrorProps}
                  />
                </Field>
              </div>
            </TabPanel>

            <Field label="Email">
              <Input
                type="email"
                placeholder="you@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoComplete="email"
                {...inputErrorProps}
              />
            </Field>
            <Field
              label="Password"
              hint={mode === "register" ? "At least 10 characters." : undefined}
            >
              <Input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={mode === "register" ? 10 : undefined}
                autoComplete={
                  mode === "register" ? "new-password" : "current-password"
                }
                {...inputErrorProps}
              />
            </Field>

            {error && <FormError id={ERROR_ID}>{error}</FormError>}

            <Button type="submit" disabled={busy} className="w-full">
              {busy
                ? "Working…"
                : mode === "login"
                  ? "Sign in"
                  : "Create organization"}
            </Button>
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
