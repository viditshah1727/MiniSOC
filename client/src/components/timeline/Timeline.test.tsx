import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router';
import { describe, expect, it } from 'vitest';
import { makeEvent } from '../../test/fixtures';
import { Timeline, type TimelineEntry } from './Timeline';

const burst: TimelineEntry[] = [1, 2, 3, 4, 5].map((id) => {
  const event = makeEvent({ id, timestamp: `2026-09-22T10:0${id}:00.000Z` });
  return { kind: 'event', at: event.timestamp, event };
});

describe('Timeline', () => {
  it('folds a burst of identical events into one expandable entry', async () => {
    render(
      <MemoryRouter>
        <Timeline entries={burst} />
      </MemoryRouter>,
    );

    expect(screen.getByText('5 × Login failure from 203.0.113.45 on web-01')).toBeInTheDocument();
    await userEvent.click(screen.getByText('Show 5 events'));
    expect(screen.getAllByText(/Failed password for root/)).toHaveLength(5);
  });

  it('keeps the trigger event separate and interleaves analyst activity in time order', () => {
    const success = makeEvent({ id: 9, timestamp: '2026-09-22T10:06:00.000Z', eventType: 'AUTH_SUCCESS', message: 'Accepted password' });
    render(
      <MemoryRouter>
        <Timeline
          entries={[
            ...burst,
            { kind: 'event', at: success.timestamp, event: success, isTrigger: true },
            {
              kind: 'activity',
              at: '2026-09-22T10:30:00.000Z',
              activity: { id: 1, type: 'NOTE', message: 'Password reset for jsmith.', createdAt: '2026-09-22T10:30:00.000Z', user: { id: 2, name: 'Jordan Lee' } },
            },
          ]}
        />
      </MemoryRouter>,
    );

    // Top-level timeline rows only (a folded burst has its own nested list).
    const items = screen.getAllByRole('listitem').filter((item) => item.parentElement?.tagName === 'OL');
    expect(items).toHaveLength(3);
    expect(items[1]).toHaveTextContent('Trigger event');
    expect(items[2]).toHaveTextContent('Jordan Lee');
    expect(items[2]).toHaveTextContent('Password reset for jsmith.');
  });
});
