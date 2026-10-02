// Test helpers: render a component inside the real app providers.
// Test files mock the API module with vi.mock('../api') (path relative to them).
import { render } from '@testing-library/react';
import type { ReactElement, ReactNode } from 'react';
import { MemoryRouter } from 'react-router';
import { vi } from 'vitest';
import { api } from '../api';
import { AuthProvider, useAuth } from '../context/AuthContext';
import { ToastProvider } from '../context/ToastContext';
import type { Role, Session } from '../types/api';

export function sessionFor(role: Role, features: Partial<Session['features']> = {}): Session {
  return {
    user: { id: 2, email: `${role.toLowerCase()}@minisoc.local`, name: `Test ${role.toLowerCase()}`, role },
    features: { simulation: true, aiAssistant: false, ...features },
  };
}

/** Renders children only once the (mocked) session has loaded. */
function SessionGate({ children }: { children: ReactNode }) {
  const { session } = useAuth();
  return session ? children : null;
}

export function renderWithProviders(
  ui: ReactElement,
  { role = 'ANALYST' as Role, route = '/', features = {} as Partial<Session['features']> } = {},
) {
  vi.mocked(api.auth.me).mockResolvedValue(sessionFor(role, features));
  return render(
    <MemoryRouter initialEntries={[route]}>
      <AuthProvider>
        <ToastProvider>
          <SessionGate>{ui}</SessionGate>
        </ToastProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}
