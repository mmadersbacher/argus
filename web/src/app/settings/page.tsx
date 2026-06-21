"use client";

// Tenant settings: account identity (read-only), continuous monitoring
// (visible to every role, editable by analyst+) plus users and API keys
// (admin-only; other roles get a read-only notice). Connector configuration
// remains on the roadmap.

import { useCallback, useEffect, useRef, useState } from "react";
import {
  createApiKey,
  createUser,
  deleteApiKey,
  deleteWebhook,
  fetchMonitor,
  fetchWebhook,
  listApiKeys,
  listUsers,
  saveMonitor,
  saveWebhook,
  type ApiKeySummary,
  type MonitorConfig,
  type Role,
  type UserSummary,
  type WebhookConfig,
} from "@/lib/api";
import {
  Badge,
  Button,
  ConfirmDialog,
  Field,
  FormError,
  Input,
  PageHeader,
  Panel,
  Select,
  Toggle,
} from "@/components/ui";
import { Icon } from "@/components/icon";
import { timeAgo } from "@/lib/ui";
import { useAuth } from "@/lib/auth";
import { useToast } from "@/components/ui/toast";

function RoleBadge({ role }: { role: Role }) {
  return (
    <Badge tone="neutral">
      <span className="capitalize">{role}</span>
    </Badge>
  );
}

/** Read-only identity card sourced from the client session. */
function AccountPanel() {
  const { session } = useAuth();
  return (
    <Panel title="Account" description="Your identity in this organization.">
      <dl className="grid gap-x-6 gap-y-5 sm:grid-cols-3">
        <div className="min-w-0">
          <dt className="text-[11px] font-medium uppercase tracking-[0.08em] text-muted">
            Email
          </dt>
          <dd className="mt-1.5 truncate text-sm text-fg">
            {session?.email ?? "—"}
          </dd>
        </div>
        <div>
          <dt className="text-[11px] font-medium uppercase tracking-[0.08em] text-muted">
            Role
          </dt>
          <dd className="mt-1.5">
            {session ? (
              <RoleBadge role={session.role} />
            ) : (
              <span className="text-sm text-muted">—</span>
            )}
          </dd>
        </div>
        <div className="min-w-0">
          <dt className="text-[11px] font-medium uppercase tracking-[0.08em] text-muted">
            Tenant ID
          </dt>
          <dd className="mt-1.5 break-all font-mono text-xs text-fg-2">
            {session?.tenant_id ?? "—"}
          </dd>
        </div>
      </dl>
    </Panel>
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
function MonitoringPanel({ canEdit }: { canEdit: boolean }) {
  const [target, setTarget] = useState("");
  const [intervalMin, setIntervalMin] = useState(15);
  const [enabled, setEnabled] = useState(false);
  const [deep, setDeep] = useState(false);
  const [lastRunAt, setLastRunAt] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);

  const { toast } = useToast();
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
        toast({ title: "Monitoring saved.", tone: "ok" });
      }
    } catch (err) {
      if (mounted.current) {
        const msg = err instanceof Error ? err.message : "failed to save monitor config";
        setError(msg);
        toast({ title: "Failed to save monitoring.", description: msg, tone: "danger" });
      }
    } finally {
      if (mounted.current) setBusy(false);
    }
  };

  // Keep the form disabled until the first GET resolves so a slow load never
  // presents never-configured defaults as editable values.
  const formDisabled = !canEdit || loading;

  return (
    <Panel
      title="Continuous monitoring"
      description="Re-scan a target on a schedule; differences show up as events in the activity feed."
    >
      <form onSubmit={save} className="space-y-4">
        {error && (
          <FormError id="monitor-error">{error}</FormError>
        )}

        <Toggle
          checked={enabled}
          onChange={setEnabled}
          disabled={formDisabled}
          label="Enable monitoring"
        />

        <div className="flex flex-wrap gap-3">
          <div className="min-w-52 flex-1">
            <Field label="Target">
              <Input
                className="font-mono"
                placeholder="192.168.1.0/24"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={formDisabled}
                aria-label="Monitor target"
                aria-invalid={!!error}
                aria-describedby={error ? "monitor-error" : undefined}
                required
              />
            </Field>
          </div>
          <div className="w-44">
            <Field label="Interval">
              <Select
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
              </Select>
            </Field>
          </div>
        </div>

        <div className="flex w-fit items-center gap-2">
          <Toggle
            checked={deep}
            onChange={setDeep}
            disabled={formDisabled}
            label="Deep scan"
          />
          <span className="text-xs text-muted">requires root</span>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" disabled={busy || formDisabled}>
            Save
          </Button>
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
    </Panel>
  );
}

function WebhookPanel() {
  const [url, setUrl] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [secret, setSecret] = useState<string | null>(null);
  const [configured, setConfigured] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [confirmDeleteOpen, setConfirmDeleteOpen] = useState(false);

  const { toast } = useToast();
  const mounted = useRef(true);
  // Same monotonic request-id guard as MonitoringPanel: a slow mount GET must
  // never overwrite a freshly-saved value or current input.
  const seq = useRef(0);
  const adoptedSeq = useRef(-1);

  const adopt = useCallback((cfg: WebhookConfig, requestSeq: number) => {
    if (!mounted.current || requestSeq < adoptedSeq.current) return;
    adoptedSeq.current = requestSeq;
    setConfigured(cfg.configured);
    if (cfg.configured) {
      setUrl(cfg.url);
      setEnabled(cfg.enabled);
      setSecret(cfg.secret);
    } else {
      setSecret(null);
    }
  }, []);

  const reload = useCallback(async () => {
    const requestSeq = ++seq.current;
    try {
      adopt(await fetchWebhook(), requestSeq);
      if (mounted.current) setError(null);
    } catch (e) {
      if (mounted.current) {
        setError(e instanceof Error ? e.message : "failed to load webhook config");
      }
    } finally {
      if (mounted.current) setLoading(false);
    }
  }, [adopt]);

  useEffect(() => {
    mounted.current = true;
    void reload();
    return () => {
      mounted.current = false;
    };
  }, [reload]);

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    const requestSeq = ++seq.current;
    setBusy(true);
    try {
      adopt(await saveWebhook(url.trim(), enabled), requestSeq);
      if (mounted.current) {
        setError(null);
        toast({ title: "Webhook saved.", tone: "ok" });
      }
    } catch (err) {
      if (mounted.current) {
        const msg = err instanceof Error ? err.message : "failed to save webhook";
        setError(msg);
        toast({ title: "Failed to save webhook.", description: msg, tone: "danger" });
      }
    } finally {
      if (mounted.current) setBusy(false);
    }
  };

  const remove = async () => {
    const requestSeq = ++seq.current;
    setBusy(true);
    setConfirmDeleteOpen(false);
    try {
      await deleteWebhook();
      adopt({ configured: false }, requestSeq);
      if (mounted.current) {
        setUrl("");
        setEnabled(true);
        setError(null);
        toast({ title: "Webhook removed.", tone: "ok" });
      }
    } catch (err) {
      if (mounted.current) {
        const msg = err instanceof Error ? err.message : "failed to delete webhook";
        setError(msg);
        toast({ title: "Failed to remove webhook.", description: msg, tone: "danger" });
      }
    } finally {
      if (mounted.current) setBusy(false);
    }
  };

  const copySecret = () => {
    if (!secret) return;
    if (!navigator.clipboard) {
      toast({ title: "Copy failed", tone: "danger" });
      return;
    }
    void navigator.clipboard.writeText(secret).then(() => {
      toast({ title: "Secret copied to clipboard.", tone: "ok" });
    }).catch(() => {
      toast({ title: "Failed to copy secret.", tone: "danger" });
    });
  };

  return (
    <Panel
      title="Webhook"
      description="POST change events to a URL after each scan, HMAC-SHA256-signed (x-argus-signature). Must be a public http(s) endpoint."
    >
      <ConfirmDialog
        open={confirmDeleteOpen}
        onConfirm={() => void remove()}
        onCancel={() => setConfirmDeleteOpen(false)}
        title="Remove webhook?"
        body="This will permanently delete the webhook and its signing secret. Deliveries will stop immediately."
        confirmLabel="Remove"
        tone="danger"
        busy={busy}
      />
      <form onSubmit={save} className="space-y-4">
        {error && (
          <FormError id="webhook-error">{error}</FormError>
        )}

        <Toggle
          checked={enabled}
          onChange={setEnabled}
          disabled={loading}
          label="Enable delivery"
        />

        <Field label="Endpoint URL">
          <Input
            className="font-mono"
            type="url"
            placeholder="https://example.com/hooks/argus"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={loading}
            aria-label="Webhook URL"
            aria-invalid={!!error}
            aria-describedby={error ? "webhook-error" : undefined}
            required
          />
        </Field>

        {secret && (
          <Field label="Signing secret (verify x-argus-signature with this)">
            <div className="flex items-center gap-2">
              <Input
                className="font-mono"
                value={secret}
                readOnly
                aria-label="Webhook signing secret"
              />
              <Button
                type="button"
                variant="ghost"
                size="sm"
                aria-label="Copy signing secret"
                onClick={copySecret}
              >
                <Icon name="copy" size={15} />
              </Button>
            </div>
          </Field>
        )}

        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" disabled={busy || loading}>
            Save
          </Button>
          {configured && (
            <Button
              type="button"
              variant="danger"
              disabled={busy || loading}
              onClick={() => setConfirmDeleteOpen(true)}
            >
              Remove
            </Button>
          )}
        </div>
      </form>
    </Panel>
  );
}

export default function Page() {
  const { session } = useAuth();
  const isAdmin = session?.role === "admin";
  const canEditMonitor =
    session?.role === "analyst" || session?.role === "admin";

  const [users, setUsers] = useState<UserSummary[]>([]);
  const [keys, setKeys] = useState<ApiKeySummary[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [newEmail, setNewEmail] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState<Role>("analyst");
  const [newKeyName, setNewKeyName] = useState("");
  const [newKeyRole, setNewKeyRole] = useState<Role>("analyst");
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const [pendingRevokeId, setPendingRevokeId] = useState<string | null>(null);

  const { toast } = useToast();

  const reload = useCallback(async () => {
    try {
      const [u, k] = await Promise.all([listUsers(), listApiKeys()]);
      setUsers(u);
      setKeys(k);
      setLoaded(true);
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
      setError(null);
      await reload();
      toast({ title: "User created.", tone: "ok" });
    } catch (err) {
      const msg = err instanceof Error ? err.message : "failed to create user";
      setError(msg);
      toast({ title: "Failed to create user.", description: msg, tone: "danger" });
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
      setError(null);
      await reload();
      toast({ title: "API key created.", tone: "ok" });
    } catch (err) {
      const msg = err instanceof Error ? err.message : "failed to create key";
      setError(msg);
      toast({ title: "Failed to create API key.", description: msg, tone: "danger" });
    } finally {
      setBusy(false);
    }
  };

  const revokeKey = async (id: string) => {
    setPendingRevokeId(null);
    setRevoking(true);
    try {
      await deleteApiKey(id);
      // Clear the one-time banner so a revoked key's plaintext isn't left on screen.
      setCreatedKey(null);
      await reload();
      toast({ title: "API key revoked.", tone: "ok" });
    } catch (err) {
      const msg = err instanceof Error ? err.message : "failed to revoke key";
      setError(msg);
      toast({ title: "Failed to revoke API key.", description: msg, tone: "danger" });
    } finally {
      setRevoking(false);
    }
  };

  const copyCreatedKey = () => {
    if (!createdKey) return;
    if (!navigator.clipboard) {
      toast({ title: "Copy failed", tone: "danger" });
      return;
    }
    void navigator.clipboard.writeText(createdKey).then(() => {
      toast({ title: "API key copied to clipboard.", tone: "ok" });
    }).catch(() => {
      toast({ title: "Failed to copy API key.", tone: "danger" });
    });
  };

  const roleSelect = (
    value: Role,
    onChange: (r: Role) => void,
    ariaLabel: string,
  ) => (
    <div className="w-36">
      <Select
        value={value}
        onChange={(e) => onChange(e.target.value as Role)}
        aria-label={ariaLabel}
      >
        <option value="viewer">viewer</option>
        <option value="analyst">analyst</option>
        <option value="admin">admin</option>
      </Select>
    </div>
  );

  const theadRow =
    "border-b border-line bg-surface-2/60 text-left text-xs text-muted";
  // No hover treatment: these rows are not clickable, so the hover affordance
  // used by the asset/vuln tables would be misleading here.
  const bodyRow = "border-b border-line last:border-0";

  return (
    <div className="argus-rise">
      <PageHeader
        title="Settings"
        description="Continuous monitoring, users and machine credentials for your organization."
      />

      <ConfirmDialog
        open={pendingRevokeId !== null}
        onConfirm={() => { if (pendingRevokeId) void revokeKey(pendingRevokeId); }}
        onCancel={() => setPendingRevokeId(null)}
        title="Revoke API key?"
        body="This key will stop working immediately. Any integrations using it will break."
        confirmLabel="Revoke"
        tone="danger"
        busy={revoking}
      />

      <div className="space-y-6">
        <AccountPanel />

        <MonitoringPanel canEdit={canEditMonitor} />

        {!isAdmin ? (
          <Panel>
            <p className="text-sm text-muted">
              User and API-key management requires the <b>admin</b> role. Ask
              your tenant administrator for access.
            </p>
          </Panel>
        ) : (
          <>
            {error && (
              <FormError id="admin-error">{error}</FormError>
            )}

            <WebhookPanel />

            <Panel
              title="Users"
              description="Members of your organization. Emails are global logins."
              bodyClassName="p-0"
            >
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className={theadRow}>
                      <th className="px-4 py-3 font-medium">Email</th>
                      <th className="px-4 py-3 font-medium">Role</th>
                    </tr>
                  </thead>
                  <tbody>
                    {loaded && users.length === 0 ? (
                      <tr className={bodyRow}>
                        <td
                          colSpan={2}
                          className="px-4 py-3 text-sm text-muted"
                        >
                          No users yet.
                        </td>
                      </tr>
                    ) : (
                      users.map((u) => (
                        <tr key={u.id} className={bodyRow}>
                          <td className="px-4 py-3 text-fg">{u.email}</td>
                          <td className="px-4 py-3">
                            <RoleBadge role={u.role} />
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
              <form
                onSubmit={addUser}
                className="flex flex-wrap items-center gap-2 border-t border-line px-4 py-3"
              >
                <div className="min-w-52 flex-1">
                  <Input
                    type="email"
                    placeholder="email@company.com"
                    aria-label="New user email"
                    aria-invalid={!!error}
                    aria-describedby={error ? "admin-error" : undefined}
                    value={newEmail}
                    onChange={(e) => setNewEmail(e.target.value)}
                    required
                  />
                </div>
                <div className="w-44">
                  <Input
                    type="password"
                    placeholder="Initial password"
                    aria-label="Initial password"
                    aria-invalid={!!error}
                    aria-describedby={error ? "admin-error" : undefined}
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    minLength={10}
                    required
                  />
                </div>
                {roleSelect(newRole, setNewRole, "New user role")}
                <Button type="submit" size="sm" disabled={busy}>
                  Add user
                </Button>
              </form>
            </Panel>

            <Panel
              title="API keys"
              description="Machine credentials for CI importers and integrations. Sent via the x-api-key header."
              bodyClassName="p-0"
            >
              {createdKey && (
                <div className="border-b border-line bg-accent-soft px-4 py-3">
                  <p className="text-xs font-medium text-accent">
                    New key — copy now, it is shown only once:
                  </p>
                  <div className="mt-1 flex items-center gap-2">
                    <p className="select-all break-all font-mono text-xs text-fg">
                      {createdKey}
                    </p>
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      aria-label="Copy API key"
                      onClick={copyCreatedKey}
                    >
                      <Icon name="copy" size={15} />
                    </Button>
                  </div>
                </div>
              )}
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className={theadRow}>
                      <th className="px-4 py-3 font-medium">Name</th>
                      <th className="px-4 py-3 font-medium">Role</th>
                      <th className="px-4 py-3 font-medium">
                        <span className="sr-only">Actions</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {loaded && keys.length === 0 ? (
                      <tr className={bodyRow}>
                        <td
                          colSpan={3}
                          className="px-4 py-3 text-sm text-muted"
                        >
                          No API keys yet.
                        </td>
                      </tr>
                    ) : (
                      keys.map((k) => (
                        <tr key={k.id} className={bodyRow}>
                          <td className="px-4 py-3 text-fg">{k.name}</td>
                          <td className="px-4 py-3">
                            <RoleBadge role={k.role} />
                          </td>
                          <td className="px-4 py-2 text-right">
                            <Button
                              type="button"
                              variant="danger"
                              size="sm"
                              onClick={() => setPendingRevokeId(k.id)}
                            >
                              Revoke
                            </Button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
              <form
                onSubmit={addKey}
                className="flex flex-wrap items-center gap-2 border-t border-line px-4 py-3"
              >
                <div className="min-w-52 flex-1">
                  <Input
                    placeholder="Key name (e.g. ci-importer)"
                    aria-label="Key name"
                    aria-invalid={!!error}
                    aria-describedby={error ? "admin-error" : undefined}
                    value={newKeyName}
                    onChange={(e) => setNewKeyName(e.target.value)}
                    required
                  />
                </div>
                {roleSelect(newKeyRole, setNewKeyRole, "New key role")}
                <Button type="submit" size="sm" disabled={busy}>
                  Create key
                </Button>
              </form>
            </Panel>
          </>
        )}
      </div>
    </div>
  );
}
