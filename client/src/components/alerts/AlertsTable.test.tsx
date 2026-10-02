import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router';
import { describe, expect, it } from 'vitest';
import { alertListItem } from '../../test/fixtures';
import { AlertsTable } from './AlertsTable';

function renderTable(compact = false) {
  render(
    <MemoryRouter initialEntries={['/alerts']}>
      <Routes>
        <Route path="/alerts" element={<AlertsTable alerts={[alertListItem]} compact={compact} />} />
        <Route path="/alerts/:id" element={<p>Alert detail page</p>} />
      </Routes>
    </MemoryRouter>,
  );
}

describe('AlertsTable', () => {
  it('renders every triage column, with severity and status as text (not colour alone)', () => {
    renderTable();
    const row = screen.getAllByRole('row')[1]!;

    expect(within(row).getByText('Critical')).toBeInTheDocument();
    expect(within(row).getByText('Open')).toBeInTheDocument();
    expect(within(row).getByRole('link', { name: alertListItem.title })).toHaveAttribute('href', '/alerts/21');
    expect(within(row).getByText('ALR-21')).toBeInTheDocument();
    expect(within(row).getByText('R005')).toBeInTheDocument();
    expect(within(row).getByText('203.0.113.45')).toBeInTheDocument();
    expect(within(row).getByRole('img', { name: 'Threat intel: Malicious' })).toBeInTheDocument();
    expect(within(row).getByRole('meter', { name: 'Risk 100 of 100 (Critical)' })).toBeInTheDocument();
    expect(within(row).getByText('T1110')).toBeInTheDocument();
  });

  it('hides the source, target and MITRE columns in compact mode', () => {
    renderTable(true);
    expect(screen.queryByRole('columnheader', { name: 'Source' })).not.toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: 'Risk' })).toBeInTheDocument();
  });

  it('opens the investigation page when a row is clicked', async () => {
    renderTable();
    await userEvent.click(screen.getByText('bastion-01'));
    expect(screen.getByText('Alert detail page')).toBeInTheDocument();
  });
});
