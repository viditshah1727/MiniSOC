import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Route, Routes } from 'react-router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api';
import { alertDetail } from '../test/fixtures';
import { renderWithProviders } from '../test/utils';
import AlertDetailPage from './AlertDetailPage';

vi.mock('../api');

function renderPage(role: 'ANALYST' | 'VIEWER' = 'ANALYST', aiAssistant = false) {
  renderWithProviders(
    <Routes>
      <Route path="/alerts/:id" element={<AlertDetailPage />} />
    </Routes>,
    { role, route: '/alerts/21', features: { aiAssistant } },
  );
}

beforeEach(() => {
  vi.mocked(api.alerts.get).mockResolvedValue(alertDetail);
  vi.mocked(api.users.list).mockResolvedValue([]);
});

describe('alert investigation page', () => {
  it('explains why the alert fired, how it was scored and what to do next', async () => {
    renderPage();

    expect(await screen.findByRole('heading', { name: alertDetail.title })).toBeInTheDocument();
    expect(api.alerts.get).toHaveBeenCalledWith(21, expect.any(AbortSignal));

    // Why: the rule's own explanation plus the evidence it measured
    expect(screen.getByText(alertDetail.description)).toBeInTheDocument();
    expect(screen.getByText('Failed attempts before')).toBeInTheDocument();
    expect(screen.getByText('root, admin')).toBeInTheDocument();
    // Score breakdown
    expect(screen.getByText('Base score for CRITICAL severity')).toBeInTheDocument();
    expect(screen.getByText('+90')).toBeInTheDocument();
    // ATT&CK, threat intel, playbook
    expect(screen.getByRole('link', { name: /T1110 Brute Force/ })).toHaveAttribute('href', 'https://attack.mitre.org/techniques/T1110/');
    expect(screen.getByText('SSH brute-force botnet node')).toBeInTheDocument();
    expect(screen.getByText('Treat the account as compromised until proven otherwise.')).toBeInTheDocument();
    // Timeline folds the three failed logins
    expect(screen.getByText('3 × Login failure from 203.0.113.45 on web-01')).toBeInTheDocument();
  });

  it('lets an analyst start investigating', async () => {
    vi.mocked(api.alerts.update).mockResolvedValue({ ...alertDetail, status: 'INVESTIGATING' });
    renderPage();

    await userEvent.click(await screen.findByRole('button', { name: 'Investigate' }));

    expect(api.alerts.update).toHaveBeenCalledWith(21, { status: 'INVESTIGATING' });
    expect(await screen.findByText('Alert marked as investigating')).toBeInTheDocument();
  });

  it('requires a justification before marking a false positive', async () => {
    vi.mocked(api.alerts.update).mockResolvedValue({ ...alertDetail, status: 'FALSE_POSITIVE' });
    renderPage();

    await userEvent.click(await screen.findByRole('button', { name: 'False positive' }));
    const dialog = await screen.findByRole('dialog', { name: 'Mark as false positive' });
    const submit = within(dialog).getByRole('button', { name: 'Mark false positive' });
    expect(submit).toBeDisabled();

    await userEvent.type(within(dialog).getByLabelText(/Note/), 'Authorised penetration test (CHG-4411).');
    await userEvent.click(submit);

    expect(api.alerts.update).toHaveBeenCalledWith(21, {
      status: 'FALSE_POSITIVE',
      note: 'Authorised penetration test (CHG-4411).',
    });
  });

  it('hides the optional AI assistant unless the server enables it', async () => {
    renderPage();
    await screen.findByRole('heading', { name: alertDetail.title });
    expect(screen.queryByRole('button', { name: 'Analyze with AI' })).not.toBeInTheDocument();
  });

  it('shows the AI analysis as advice when the assistant is enabled', async () => {
    vi.mocked(api.alerts.analyze).mockResolvedValue({
      summary: 'jsmith was compromised through password guessing.',
      explanation: 'Three failures then a success from the same malicious IP.',
      likelyAttackBehavior: 'The attacker will try to escalate privileges next.',
      mitreTechnique: { id: 'T1110', name: 'Brute Force', rationale: 'Repeated guesses.' },
      investigationSteps: ['Reset the jsmith password.'],
      confidence: 'HIGH',
      model: 'claude-opus-5',
      generatedAt: '2026-09-22T10:10:00.000Z',
    });
    renderPage('ANALYST', true);

    await userEvent.click(await screen.findByRole('button', { name: 'Analyze with AI' }));

    expect(api.alerts.analyze).toHaveBeenCalledWith(21);
    expect(await screen.findByText('jsmith was compromised through password guessing.')).toBeInTheDocument();
    expect(screen.getByText('Reset the jsmith password.')).toBeInTheDocument();
    expect(screen.getByText(/verify it against the evidence before acting/)).toBeInTheDocument();
    expect(api.alerts.update).not.toHaveBeenCalled(); // advice only: nothing changes
  });

  it('shows no triage actions to a read-only viewer', async () => {
    renderPage('VIEWER');

    expect(await screen.findByText(/Read-only access/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Investigate' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Create incident' })).not.toBeInTheDocument();
  });
});
