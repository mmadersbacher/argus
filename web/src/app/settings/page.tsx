"use client";

// Tenant administration: users and API keys. Admin-only; other roles get a
// read-only notice. Connector configuration remains on the roadmap.

import { useCallback, useEffect, useState } from "react";
import {
  createApiKey,
  createUser,
  deleteApiKey,
  listApiKeys,
  listUsers,
  type ApiKeySummary,
  type Role,
  type UserSummary,
} from "@/lib/api";
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

export default function Page() {
  const { session } = useAuth();
  const isAdmin = session?.role === "admin";

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

  if (!isAdmin) {
    return (
      <div className="argus-rise">
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="mt-4 max-w-md rounded-xl border border-line bg-surface p-5 text-sm text-muted">
          User and API-key management requires the <b>admin</b> role. Ask your
          tenant administrator for access.
        </p>
      </div>
    );
  }

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
          Manage your organization&apos;s users and machine credentials.
        </p>
      </div>

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
    </div>
  );
}
