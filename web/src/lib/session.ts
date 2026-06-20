// Client-side session persistence, exposed as a tiny external store so React
// can subscribe via useSyncExternalStore. Holds only the display identity
// (email/role/tenant); the JWT itself lives in an HttpOnly cookie the browser
// sends automatically and JS can never read. Shared by the API client and the
// auth context.

export type Role = "viewer" | "analyst" | "admin";

export interface Session {
  email: string;
  role: Role;
  tenant_id: string;
}

const KEY = "argus.session";

// undefined = localStorage not read yet; null = signed out.
let cached: Session | null | undefined;
const listeners = new Set<() => void>();

function emit(): void {
  for (const listener of listeners) listener();
}

function read(): Session | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Session;
    // The session's authority is the HttpOnly cookie; this record is just the
    // display identity. A malformed one is dropped — the server (401) is the
    // real arbiter of whether the cookie is still valid.
    if (!parsed.email || !parsed.role || !parsed.tenant_id) {
      window.localStorage.removeItem(KEY);
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export function loadSession(): Session | null {
  if (cached === undefined) cached = read();
  return cached;
}

export function storeSession(session: Session): void {
  window.localStorage.setItem(KEY, JSON.stringify(session));
  cached = session;
  emit();
}

export function clearSession(): void {
  window.localStorage.removeItem(KEY);
  cached = null;
  emit();
}

export function subscribeSession(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

// Cross-tab sync: when another tab logs in/out (or localStorage is cleared),
// re-read and notify so this tab's guard re-evaluates instead of serving a
// stale cached session.
if (typeof window !== "undefined") {
  window.addEventListener("storage", (e) => {
    if (e.key === KEY || e.key === null) {
      cached = read();
      emit();
    }
  });
}

/** Server snapshot: there is never a session during SSR. */
export function serverSession(): Session | null {
  return null;
}
