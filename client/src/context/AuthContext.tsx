// Who is logged in, and what they may do. The session itself is an httpOnly
// cookie the browser manages; this context only mirrors GET /api/auth/me.
import { createContext, type ReactNode, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { setUnauthorizedHandler } from '../api/client';
import { api } from '../api';
import type { Session } from '../types/api';

interface AuthContextValue {
  session: Session | null;
  /** True until we know whether a session exists (first page load). */
  checking: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  /** ADMIN and ANALYST can change things; VIEWER is read-only. */
  canEdit: boolean;
  isAdmin: boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    api.auth
      .me()
      .then(setSession)
      .catch(() => setSession(null))
      .finally(() => setChecking(false));
    // Any 401 later (expired session) sends the analyst back to the login page.
    setUnauthorizedHandler(() => setSession(null));
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    await api.auth.login(email, password);
    setSession(await api.auth.me());
  }, []);

  const logout = useCallback(async () => {
    await api.auth.logout().catch(() => undefined);
    setSession(null);
  }, []);

  const value = useMemo<AuthContextValue>(() => {
    const role = session?.user.role;
    return {
      session,
      checking,
      login,
      logout,
      canEdit: role === 'ADMIN' || role === 'ANALYST',
      isAdmin: role === 'ADMIN',
    };
  }, [session, checking, login, logout]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used inside <AuthProvider>');
  return context;
}

/** For components that only render inside the authenticated app. */
export function useSession(): Session {
  const { session } = useAuth();
  if (!session) throw new Error('useSession called without a session');
  return session;
}
