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

function read(): Session | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Session;
    return parsed.token ? parsed : null;
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

/** Server snapshot: there is never a session during SSR. */
export function serverSession(): Session | null {
  return null;
}
