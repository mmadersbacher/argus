"use client";

// Tenant settings: continuous monitoring (visible to every role, editable by
// analyst+) plus users and API keys (admin-only; other roles get a read-only
// notice). Connector configuration remains on the roadmap.

import { useCallback, useEffect, useRef, useState } from "react";
import {
  createApiKey,
  createUser,
  deleteApiKey,
  fetchMonitor,
  listApiKeys,
  listUsers,
  saveMonitor,
  type ApiKeySummary,
  type MonitorConfig,
  type Role,
  type UserSummary,
} from "@/lib/api";
import { timeAgo } from "@/lib/ui";
import { useAuth } from "@/lib/auth";

const field =
  "rounded-lg border border-line bg-surface px-3 py-2 text-sm text-fg outline-none transition-colors placeholder:text-muted focus:border-accent";
const primaryBtn =
  "rounded-lg bg-accent px-3 py-2 text-sm font-semibold text-white transition-colors hover:bg-accent-2 disabled:opacity-60";

function Section({
  title,
  note,
  children,
}: {
  title: string;
  note: string;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-xl border border-line bg-surface p-5">
      <h2 className="font-semibold text-fg">{title}</h2>
      <p className="mt-0.5 text-sm text-muted">{note}</p>
      <div className="mt-4">{children}</div>
    </section>
  );
}

const intervals: { minutes: number; label: string }[] = [
  { minutes: 5, label: "Every 5 min" },
  { minutes: 15, label: "Every 15 min" },
  { minutes: 30, label: "Every 30 min" },
  { minutes: 60, label: "Every hour" },
  { minutes: 240, label: "Every 4 hours" },
  { minutes: 1440, label: "Every 24 hours" },
];

/** Continuous-monitoring card. Read-only for viewers; analyst+ can save. */
function MonitoringSection({ canEdit }: { canEdit: boolean }) {
  const [target, setTarget] = useState("");
  const [intervalMin, setIntervalMin] = useState(15);
  const [enabled, setEnabled] = useState(false);
  const [deep, setDeep] = useState(false);
  const [lastRunAt, setLastRunAt] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);

  const mounted = useRef(true);
  // Monotonic request id. Each issued request takes the next number; a response
  // is only adopted if nothing newer has already won, so a slow mount GET can
  // never clobber a freshly-saved (later) value or current user input.
  const seq = useRef(0);
  const adoptedSeq = useRef(-1);

  const adopt = useCallback((cfg: MonitorConfig, requestSeq: number) => {
    // Drop a stale response: a newer request has already updated the form.
    if (!mounted.current || requestSeq < adoptedSeq.current) return;
    adoptedSeq.current = requestSeq;
    if (!cfg.configured) return;
    setTarget(cfg.target);
    setIntervalMin(cfg.interval_minutes);
    setEnabled(cfg.enabled);
    setDeep(cfg.deep);
    setLastRunAt(cfg.last_run_at);
  }, []);

  const reload = useCallback(async () => {
    const requestSeq = ++seq.current;
    try {
      const cfg = await fetchMonitor();
      adopt(cfg, requestSeq);
      if (mounted.current) setError(null);
    } catch (e) {
      if (mounted.current) {
        setError(
          e instanceof Error ? e.message : "failed to load monitor config",
        );
      }
    } finally {
      if (mounted.current) setLoading(false);
    }
  }, [adopt]);

  useEffect(() => {
    mounted.current = true;
    // reload() is async data fetching — every setState in it happens after an
    // await, never synchronously in the effect body.
    void reload();
    return () => {
      mounted.current = false;
    };
  }, [reload]);

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    // Claim a sequence newer than any in-flight mount GET so this save's
    // result wins even if that older GET resolves afterwards.
    const requestSeq = ++seq.current;
    setBusy(true);
    setSaved(false);
    try {
      const cfg = await saveMonitor({
        target: target.trim(),
        interval_minutes: intervalMin,
        enabled,
        deep,
      });
      adopt(cfg, requestSeq);
      if (mounted.current) {
        setError(null);
        setSaved(true);
      }
    } catch (err) {
      if (mounted.current) {
        setError(
          err instanceof Error ? err.message : "failed to save monitor config",
        );
      }
    } finally {
      if (mounted.current) setBusy(false);
    }
  };

  // Keep the form disabled until the first GET resolves so a slow load never
  // presents never-configured defaults as editable values.
  const formDisabled = !canEdit || loading;

  return (
    <Section
      title="Continuous monitoring"
      note="Re-scan a target on a schedule; differences show up as events in the activity feed."
    >
      {error && (
        <p className="mb-3 rounded-lg border border-crit/30 bg-crit/5 px-3 py-2 text-sm text-crit">
          {error}
        </p>
      )}
      <form onSubmit={save} className="space-y-4">
        <label className="flex w-fit cursor-pointer items-center gap-3 text-sm font-medium text-fg">
          <button
            type="button"
            role="switch"
            aria-checked={enabled}
            aria-label="Enable monitoring"
            disabled={formDisabled}
            onClick={() => setEnabled((v) => !v)}
            className={`relative h-6 w-11 shrink-0 rounded-full transition-colors disabled:opacity-60 ${
              enabled ? "bg-accent" : "bg-surface-2 ring-1 ring-inset ring-line"
            }`}
          >
            <span
              className={`absolute left-0.5 top-0.5 h-5 w-5 rounded-full bg-white shadow ring-1 ring-line transition-transform ${
                enabled ? "translate-x-5" : ""
              }`}
            />
          </button>
          Enable monitoring
        </label>

        <div className="flex flex-wrap gap-2">
          <input
            className={`${field} min-w-52 flex-1 font-mono disabled:opacity-60`}
            placeholder="192.168.1.0/24"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            disabled={formDisabled}
            aria-label="Monitor target"
            required
          />
          <select
            className={`${field} disabled:opacity-60`}
            value={intervalMin}
            onChange={(e) => setIntervalMin(Number(e.target.value))}
            disabled={formDisabled}
            aria-label="Scan interval"
          >
            {!intervals.some((i) => i.minutes === intervalMin) && (
              <option value={intervalMin}>Every {intervalMin} min</option>
            )}
            {intervals.map((i) => (
              <option key={i.minutes} value={i.minutes}>
                {i.label}
              </option>
            ))}
          </select>
        </div>

        <label className="flex w-fit cursor-pointer items-center gap-2 text-sm text-fg">
          <input
            type="checkbox"
            className="h-4 w-4 accent-accent disabled:opacity-60"
            checked={deep}
            onChange={(e) => setDeep(e.target.checked)}
            disabled={formDisabled}
          />
          Deep scan
          <span className="text-xs text-muted">requires root</span>
        </label>

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="submit"
            disabled={busy || formDisabled}
            className={primaryBtn}
          >
            Save
          </button>
          {saved && (
            <span className="text-xs font-medium text-emerald-600">Saved.</span>
          )}
          {lastRunAt && (
            <span className="text-xs text-muted">
              Last run {timeAgo(lastRunAt)}
            </span>
          )}
          {!canEdit && (
            <span className="ml-auto text-xs text-muted">
              Editing requires the <b>analyst</b> role or higher.
            </span>
          )}
        </div>
      </form>
    </Section>
  );
}

export default function Page() {
  const { session } = useAuth();
  const isAdmin = session?.role === "admin";
  const canEditMonitor =
    session?.role === "analyst" || session?.role === "admin";

  const [users, setUsers] = useState<UserSummary[]>([]);
  const [keys, setKeys] = useState<ApiKeySummary[]>([]);
  const [error, setError] = useState<string | null>(null);

  const [newEmail, setNewEmail] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState<Role>("analyst");
  const [newKeyName, setNewKeyName] = useState("");
  const [newKeyRole, setNewKeyRole] = useState<Role>("analyst");
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const reload = useCallback(async () => {
    try {
      const [u, k] = await Promise.all([listUsers(), listApiKeys()]);
      setUsers(u);
      setKeys(k);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to load settings");
    }
  }, []);

  useEffect(() => {
    // False positive: reload() is async data fetching — every setState in it
    // happens after an await, never synchronously in the effect body.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (isAdmin) void reload();
  }, [isAdmin, reload]);

  const addUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await createUser(newEmail, newPassword, newRole);
      setNewEmail("");
      setNewPassword("");
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to create user");
    } finally {
      setBusy(false);
    }
  };

  const addKey = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    // Drop any previously shown secret before creating the next one, so a
    // failed create never leaves a stale key banner on screen.
    setCreatedKey(null);
    try {
      const created = await createApiKey(newKeyName, newKeyRole);
      setCreatedKey(created.key);
      setNewKeyName("");
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to create key");
    } finally {
      setBusy(false);
    }
  };

  const revokeKey = async (id: string) => {
    try {
      await deleteApiKey(id);
      // Clear the one-time banner so a revoked key's plaintext isn't left on screen.
      setCreatedKey(null);
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to revoke key");
    }
  };

  const roleSelect = (value: Role, onChange: (r: Role) => void) => (
    <select
      className={field}
      value={value}
      onChange={(e) => onChange(e.target.value as Role)}
    >
      <option value="viewer">viewer</option>
      <option value="analyst">analyst</option>
      <option value="admin">admin</option>
    </select>
  );

  return (
    <div className="argus-rise space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="mt-1 text-sm text-muted">
          Continuous monitoring, users and machine credentials for your
          organization.
        </p>
      </div>

      <MonitoringSection canEdit={canEditMonitor} />

      {!isAdmin ? (
        <p className="max-w-md rounded-xl border border-line bg-surface p-5 text-sm text-muted">
          User and API-key management requires the <b>admin</b> role. Ask your
          tenant administrator for access.
        </p>
      ) : (
        <>
          {error && (
            <p className="rounded-lg border border-crit/30 bg-crit/5 px-3 py-2 text-sm text-crit">
              {error}
            </p>
          )}

          <Section
            title="Users"
            note="Members of your organization. Emails are global logins."
          >
            <table className="w-full text-sm">
              <tbody>
                {users.map((u) => (
                  <tr key={u.id} className="border-t border-line">
                    <td className="py-2.5 text-fg">{u.email}</td>
                    <td className="py-2.5 text-right capitalize text-muted">
                      {u.role}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <form onSubmit={addUser} className="mt-4 flex flex-wrap gap-2">
              <input
                className={`${field} min-w-52 flex-1`}
                type="email"
                placeholder="email@company.com"
                value={newEmail}
                onChange={(e) => setNewEmail(e.target.value)}
                required
              />
              <input
                className={`${field} min-w-44`}
                type="password"
                placeholder="Initial password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                minLength={10}
                required
              />
              {roleSelect(newRole, setNewRole)}
              <button type="submit" disabled={busy} className={primaryBtn}>
                Add user
              </button>
            </form>
          </Section>

          <Section
            title="API keys"
            note="Machine credentials for CI importers and integrations. Sent via the x-api-key header."
          >
            {createdKey && (
              <p className="mb-3 break-all rounded-lg border border-accent/30 bg-accent/5 px-3 py-2 font-mono text-xs text-fg">
                New key (copy now — it is shown only once):{" "}
                <b className="select-all">{createdKey}</b>
              </p>
            )}
            <table className="w-full text-sm">
              <tbody>
                {keys.map((k) => (
                  <tr key={k.id} className="border-t border-line">
                    <td className="py-2.5 text-fg">{k.name}</td>
                    <td className="py-2.5 capitalize text-muted">{k.role}</td>
                    <td className="py-2.5 text-right">
                      <button
                        type="button"
                        onClick={() => void revokeKey(k.id)}
                        className="text-sm text-crit transition-colors hover:underline"
                      >
                        Revoke
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <form onSubmit={addKey} className="mt-4 flex flex-wrap gap-2">
              <input
                className={`${field} min-w-52 flex-1`}
                placeholder="Key name (e.g. ci-importer)"
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
                required
              />
              {roleSelect(newKeyRole, setNewKeyRole)}
              <button type="submit" disabled={busy} className={primaryBtn}>
                Create key
              </button>
            </form>
          </Section>
        </>
      )}
    </div>
  );
}
