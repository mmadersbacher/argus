"use client";

// Auth context: subscribes to the session store (localStorage-backed) and
// exposes login/register/logout. `ready` flips to true after hydration so
// guards don't redirect before the client has read the stored session.

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useSyncExternalStore,
} from "react";
import * as api from "./api";
import {
  clearSession,
  loadSession,
  serverSession,
  storeSession,
  subscribeSession,
  type Session,
} from "./session";

interface AuthValue {
  /** Current session, or null when signed out. */
  session: Session | null;
  /** False during SSR/hydration (avoids redirect flicker). */
  ready: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (
    organization: string,
    email: string,
    password: string,
  ) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthValue | null>(null);

const noopSubscribe = () => () => {};

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const session = useSyncExternalStore(
    subscribeSession,
    loadSession,
    serverSession,
  );
  // Standard SSR-safe "hydrated" probe: false on the server, true on the
  // client — flips exactly when the session snapshot becomes trustworthy.
  const ready = useSyncExternalStore(
    noopSubscribe,
    () => true,
    () => false,
  );

  const adopt = useCallback((res: api.SessionResponse) => {
    storeSession({
      token: res.token,
      email: res.email,
      role: res.role,
      tenant_id: res.tenant_id,
    });
  }, []);

  const login = useCallback(
    async (email: string, password: string) =>
      adopt(await api.login(email, password)),
    [adopt],
  );

  const register = useCallback(
    async (organization: string, email: string, password: string) =>
      adopt(await api.register(organization, email, password)),
    [adopt],
  );

  const logout = useCallback(() => {
    clearSession();
    // Hard-navigate so no protected view lingers on a stale render. The
    // AppShell guard effect would also catch this, but logout must not depend
    // on it firing.
    if (typeof window !== "undefined") window.location.href = "/login";
  }, []);

  const value = useMemo(
    () => ({ session, ready, login, register, logout }),
    [session, ready, login, register, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}
