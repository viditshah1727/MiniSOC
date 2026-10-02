// Status workflow and assignment for an incident:
//   OPEN -> INVESTIGATING -> RESOLVED -> CLOSED   (reopen at any time)
import { Check, CircleCheck, Lock, type LucideIcon, RotateCcw, Search } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { ApiError } from '../../api/client';
import { api } from '../../api';
import { useAuth } from '../../context/AuthContext';
import { useToast } from '../../context/ToastContext';
import { useApi } from '../../hooks/useApi';
import type { IncidentDetail, IncidentStatus } from '../../types/api';
import { cn } from '../../utils/cn';
import { INCIDENT_STATUS_LABEL, INCIDENT_STATUSES } from '../../utils/labels';
import { Button } from '../ui/Button';

const NEXT_STEP: Partial<Record<IncidentStatus, { status: IncidentStatus; label: string; icon: LucideIcon }>> = {
  OPEN: { status: 'INVESTIGATING', label: 'Start investigating', icon: Search },
  INVESTIGATING: { status: 'RESOLVED', label: 'Mark resolved', icon: CircleCheck },
  RESOLVED: { status: 'CLOSED', label: 'Close incident', icon: Lock },
};

export function IncidentControls({ incident, onUpdated }: { incident: IncidentDetail; onUpdated: (incident: IncidentDetail) => void }) {
  const { canEdit } = useAuth();
  const toast = useToast();
  const users = useApi((signal) => api.users.list(signal), []);
  const [saving, setSaving] = useState(false);

  async function update(body: { status?: IncidentStatus; assigneeId?: number | null }, message: string) {
    setSaving(true);
    try {
      onUpdated(await api.incidents.update(incident.id, body));
      toast({ tone: 'success', title: message });
    } catch (error) {
      toast({ tone: 'error', title: 'Update failed', description: error instanceof ApiError ? error.message : undefined });
    } finally {
      setSaving(false);
    }
  }

  const currentIndex = INCIDENT_STATUSES.indexOf(incident.status);
  const next = NEXT_STEP[incident.status];
  const isDone = incident.status === 'RESOLVED' || incident.status === 'CLOSED';

  return (
    <div className="flex flex-wrap items-center justify-between gap-4">
      <ol className="flex flex-wrap items-center gap-2 text-xs" aria-label="Incident progress">
        {INCIDENT_STATUSES.map((status, index) => (
          <li key={status} className="flex items-center gap-2">
            <span
              aria-current={index === currentIndex ? 'step' : undefined}
              className={cn(
                'flex items-center gap-1.5 rounded-full px-2.5 py-1 font-medium ring-1 ring-inset',
                index < currentIndex && 'text-muted ring-line-strong',
                index === currentIndex && 'bg-accent/15 text-fg ring-accent/50',
                index > currentIndex && 'text-faint ring-line',
              )}
            >
              {index < currentIndex && <Check aria-hidden className="size-3 text-state-good" />}
              {INCIDENT_STATUS_LABEL[status]}
            </span>
            {index < INCIDENT_STATUSES.length - 1 && <span aria-hidden className="h-px w-4 bg-line-strong" />}
          </li>
        ))}
      </ol>

      {canEdit && (
        <div className="flex flex-wrap items-center gap-2">
          <label htmlFor="assignee" className="text-xs text-muted">
            Assignee
          </label>
          <select
            id="assignee"
            value={incident.assignee?.id ?? ''}
            disabled={saving}
            onChange={(event) => {
              const value = event.target.value ? Number(event.target.value) : null;
              const name = users.data?.find((u) => u.id === value)?.name;
              void update({ assigneeId: value }, name ? `Assigned to ${name}` : 'Unassigned');
            }}
            className="field w-44 py-1.5"
          >
            <option value="">Unassigned</option>
            {(users.data ?? [])
              .filter((user) => user.role !== 'VIEWER')
              .map((user) => (
                <option key={user.id} value={user.id}>
                  {user.name}
                </option>
              ))}
          </select>
          {next && (
            <Button variant="primary" icon={next.icon} loading={saving} onClick={() => void update({ status: next.status }, `Incident ${INCIDENT_STATUS_LABEL[next.status].toLowerCase()}`)}>
              {next.label}
            </Button>
          )}
          {isDone && (
            <Button icon={RotateCcw} loading={saving} onClick={() => void update({ status: 'INVESTIGATING' }, 'Incident reopened')}>
              Reopen
            </Button>
          )}
        </div>
      )}
    </div>
  );
}

export function IncidentNoteForm({ incidentId, onAdded }: { incidentId: number; onAdded: () => void }) {
  const toast = useToast();
  const [content, setContent] = useState('');
  const [saving, setSaving] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    try {
      await api.incidents.addNote(incidentId, content.trim());
      setContent('');
      onAdded();
    } catch (error) {
      toast({ tone: 'error', title: 'Could not add the note', description: error instanceof ApiError ? error.message : undefined });
    } finally {
      setSaving(false);
    }
  }

  return (
    <form onSubmit={(event) => void handleSubmit(event)} className="space-y-2">
      <label htmlFor="incident-note" className="field-label">
        Add a note
      </label>
      <textarea
        id="incident-note"
        rows={3}
        maxLength={5000}
        value={content}
        onChange={(event) => setContent(event.target.value)}
        placeholder="Findings, containment steps, decisions..."
        className="field resize-y"
      />
      <div className="flex justify-end">
        <Button type="submit" size="sm" variant="primary" loading={saving} disabled={!content.trim()}>
          Add note
        </Button>
      </div>
    </form>
  );
}
