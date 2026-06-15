// Client-side session persistence, exposed as a tiny external store so React
// can subscribe via useSyncExternalStore. Single source of truth for the
// stored token, shared by the API client and the auth context.

export type Role = "viewer" | "analyst" | "admin";

export interface Session {
  token: string;
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

// Decode a JWT's `exp` (unix seconds) WITHOUT verifying the signature — the
// server stays the authority. This only avoids treating an obviously-expired
// token as a live session (and the flash of protected chrome that causes).
function tokenExpired(token: string): boolean {
  const payload = token.split(".")[1];
  if (!payload) return false;
  try {
    const claims = JSON.parse(
      atob(payload.replace(/-/g, "+").replace(/_/g, "/")),
    ) as { exp?: number };
    return typeof claims.exp === "number" && Date.now() >= claims.exp * 1000;
  } catch {
    // Unparseable → let the server decide (it returns 401); don't force a logout.
    return false;
  }
}

function read(): Session | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Session;
    if (!parsed.token || tokenExpired(parsed.token)) {
      // Blank or expired token is not a session — drop it so it isn't re-sent.
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
