import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api';
import { ApiError } from '../api/client';
import { AuthProvider } from '../context/AuthContext';
import { sessionFor } from '../test/utils';
import LoginPage from './LoginPage';

vi.mock('../api');

function renderLogin() {
  render(
    <MemoryRouter initialEntries={['/login']}>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/dashboard" element={<p>Dashboard</p>} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  // No session yet: GET /api/auth/me answers 401.
  vi.mocked(api.auth.me).mockRejectedValue(new ApiError(401, 'Authentication required'));
});

describe('login page', () => {
  it('signs in and continues to the dashboard', async () => {
    vi.mocked(api.auth.login).mockResolvedValue({ user: sessionFor('ANALYST').user });
    renderLogin();

    const submit = await screen.findByRole('button', { name: 'Sign in' });
    expect(submit).toBeDisabled();

    await userEvent.type(screen.getByLabelText('Email'), 'analyst@minisoc.local');
    await userEvent.type(screen.getByLabelText('Password'), 'correct-password');
    vi.mocked(api.auth.me).mockResolvedValue(sessionFor('ANALYST'));
    await userEvent.click(submit);

    expect(api.auth.login).toHaveBeenCalledWith('analyst@minisoc.local', 'correct-password');
    expect(await screen.findByText('Dashboard')).toBeInTheDocument();
  });

  it('shows the server error for bad credentials and stays on the page', async () => {
    vi.mocked(api.auth.login).mockRejectedValue(new ApiError(401, 'Invalid email or password'));
    renderLogin();

    await userEvent.type(await screen.findByLabelText('Email'), 'analyst@minisoc.local');
    await userEvent.type(screen.getByLabelText('Password'), 'wrong');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid email or password');
    expect(screen.queryByText('Dashboard')).not.toBeInTheDocument();
  });
});
