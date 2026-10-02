import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api';
import { makeDashboard } from '../test/fixtures';
import { renderWithProviders } from '../test/utils';
import DashboardPage from './DashboardPage';

vi.mock('../api');

beforeEach(() => {
  vi.mocked(api.dashboard.stats).mockResolvedValue(makeDashboard());
});

describe('dashboard', () => {
  it('shows the headline numbers from the API', async () => {
    renderWithProviders(<DashboardPage />);

    const risk = await screen.findByRole('region', { name: 'Overall risk score' });
    expect(within(risk).getByText('79')).toBeInTheDocument();
    expect(within(risk).getByText('High')).toBeInTheDocument();
    expect(within(risk).getByText(/Average risk of 9 open alerts/)).toBeInTheDocument();

    expect(screen.getByText('1,013')).toBeInTheDocument(); // total events
    expect(screen.getByText('151 in the last 24 hours')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Critical alerts/ })).toHaveAttribute('href', '/alerts?severity=CRITICAL');
  });

  it('renders the four charts and the work queues', async () => {
    renderWithProviders(<DashboardPage />);

    for (const title of ['Security events over time', 'Alerts by severity', 'Top source IPs', 'Detections by rule']) {
      expect(await screen.findByRole('heading', { name: title })).toBeInTheDocument();
    }
    expect(screen.getByRole('link', { name: /^203\.0\.113\.45/ })).toHaveAttribute('href', '/alerts?sourceIp=203.0.113.45');
    expect(screen.getByRole('heading', { name: 'Recent high-priority alerts' })).toBeInTheDocument();
    expect(screen.getByText('No active incidents')).toBeInTheDocument();
  });

  it('offers every chart as a table (accessible alternative)', async () => {
    renderWithProviders(<DashboardPage />);

    const card = (await screen.findByRole('heading', { name: 'Alerts by severity' })).closest('section')!;
    await userEvent.click(within(card).getByRole('button', { name: 'Table' }));

    const table = within(card).getByRole('table');
    expect(within(table).getByRole('row', { name: 'Critical 3' })).toBeInTheDocument();
    expect(within(table).getByRole('row', { name: 'High 4' })).toBeInTheDocument();
  });

  it('reloads everything for the selected time range', async () => {
    renderWithProviders(<DashboardPage />);
    await screen.findByRole('heading', { name: 'Security overview' });

    await userEvent.click(screen.getByRole('button', { name: 'Last 7 days' }));

    expect(api.dashboard.stats).toHaveBeenLastCalledWith('7d', expect.any(AbortSignal));
  });
});
