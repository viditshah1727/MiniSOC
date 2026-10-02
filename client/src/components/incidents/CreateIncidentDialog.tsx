// Escalates one alert into a new incident (POST /api/incidents).
import { type FormEvent, useEffect, useState } from 'react';
import { useNavigate } from 'react-router';
import { ApiError } from '../../api/client';
import { api } from '../../api';
import { useSession } from '../../context/AuthContext';
import { useToast } from '../../context/ToastContext';
import { useApi } from '../../hooks/useApi';
import type { AlertDetail, Severity } from '../../types/api';
import { incidentRef } from '../../utils/format';
import { SEVERITIES, SEVERITY_LABEL } from '../../utils/labels';
import { Button } from '../ui/Button';
import { Modal } from '../ui/Modal';

export function CreateIncidentDialog({ alert, open, onClose }: { alert: AlertDetail; open: boolean; onClose: () => void }) {
  const { user } = useSession();
  const navigate = useNavigate();
  const toast = useToast();
  const users = useApi((signal) => api.users.list(signal), []);

  const [title, setTitle] = useState(alert.title);
  const [severity, setSeverity] = useState<Severity>(alert.severity);
  const [assigneeId, setAssigneeId] = useState(String(user.id));
  const [description, setDescription] = useState(alert.description);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open) return;
    setTitle(alert.title);
    setSeverity(alert.severity);
    setAssigneeId(String(user.id));
    setDescription(alert.description);
    setError(null);
  }, [open, alert, user.id]);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    setError(null);
    try {
      const incident = await api.incidents.create({
        alertIds: [alert.id],
        title: title.trim(),
        severity,
        description: description.trim() || undefined,
        assigneeId: assigneeId ? Number(assigneeId) : null,
      });
      toast({ tone: 'success', title: `${incidentRef(incident.id)} created`, description: incident.title });
      navigate(`/incidents/${incident.id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not create the incident.');
      setSaving(false);
    }
  }

  const assignableUsers = (users.data ?? []).filter((candidate) => candidate.role !== 'VIEWER');

  return (
    <Modal open={open} onClose={onClose} title="Create incident" description="Escalate this alert into a tracked investigation.">
      <form onSubmit={(event) => void handleSubmit(event)} className="space-y-4">
        <div>
          <label htmlFor="incident-title" className="field-label">
            Title
          </label>
          <input id="incident-title" value={title} onChange={(e) => setTitle(e.target.value)} maxLength={200} required className="field" />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label htmlFor="incident-severity" className="field-label">
              Severity
            </label>
            <select id="incident-severity" value={severity} onChange={(e) => setSeverity(e.target.value as Severity)} className="field">
              {SEVERITIES.filter((s) => s !== 'INFO').map((s) => (
                <option key={s} value={s}>
                  {SEVERITY_LABEL[s]}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="incident-assignee" className="field-label">
              Assignee
            </label>
            <select id="incident-assignee" value={assigneeId} onChange={(e) => setAssigneeId(e.target.value)} className="field">
              <option value="">Unassigned</option>
              {assignableUsers.map((candidate) => (
                <option key={candidate.id} value={candidate.id}>
                  {candidate.name}
                  {candidate.id === user.id ? ' (me)' : ''}
                </option>
              ))}
            </select>
          </div>
        </div>
        <div>
          <label htmlFor="incident-description" className="field-label">
            Description
          </label>
          <textarea
            id="incident-description"
            rows={4}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            maxLength={5000}
            className="field resize-y"
          />
        </div>
        {error && (
          <p role="alert" className="text-sm text-sev-critical">
            {error}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" loading={saving} disabled={title.trim().length < 3}>
            Create incident
          </Button>
        </div>
      </form>
    </Modal>
  );
}
