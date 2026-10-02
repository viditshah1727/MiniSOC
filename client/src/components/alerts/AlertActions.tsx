// Analyst triage actions for one alert. What is offered depends on the
// alert's status; viewers see no actions at all (the API enforces this too).
import { Ban, Briefcase, CircleCheck, NotebookPen, RotateCcw, Search } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router';
import { ApiError } from '../../api/client';
import { api } from '../../api';
import { useAuth } from '../../context/AuthContext';
import { useToast } from '../../context/ToastContext';
import type { AlertDetail, AlertStatus } from '../../types/api';
import { incidentRef } from '../../utils/format';
import { ALERT_STATUS_LABEL } from '../../utils/labels';
import { CreateIncidentDialog } from '../incidents/CreateIncidentDialog';
import { Button } from '../ui/Button';
import { NoteDialog } from '../ui/NoteDialog';

type Dialog = 'resolve' | 'false-positive' | 'note' | 'incident' | null;

export function AlertActions({ alert, onUpdated }: { alert: AlertDetail; onUpdated: (alert: AlertDetail) => void }) {
  const { canEdit } = useAuth();
  const toast = useToast();
  const [dialog, setDialog] = useState<Dialog>(null);
  const [busy, setBusy] = useState(false);

  if (!canEdit) {
    return <p className="text-xs text-muted">Read-only access: ask an analyst to triage this alert.</p>;
  }

  const isOpen = alert.status === 'OPEN' || alert.status === 'INVESTIGATING';

  async function update(body: { status?: AlertStatus; note?: string }) {
    const updated = await api.alerts.update(alert.id, body);
    onUpdated(updated);
    toast({
      tone: 'success',
      title: body.status ? `Alert marked as ${ALERT_STATUS_LABEL[body.status].toLowerCase()}` : 'Note added',
    });
  }

  async function quickUpdate(status: AlertStatus) {
    setBusy(true);
    try {
      await update({ status });
    } catch (error) {
      toast({ tone: 'error', title: 'Update failed', description: error instanceof ApiError ? error.message : undefined });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      {alert.status === 'OPEN' && (
        <Button icon={Search} loading={busy} onClick={() => void quickUpdate('INVESTIGATING')}>
          Investigate
        </Button>
      )}
      {isOpen && (
        <>
          <Button icon={CircleCheck} onClick={() => setDialog('resolve')}>
            Resolve
          </Button>
          <Button icon={Ban} onClick={() => setDialog('false-positive')}>
            False positive
          </Button>
        </>
      )}
      {!isOpen && (
        <Button icon={RotateCcw} loading={busy} onClick={() => void quickUpdate('OPEN')}>
          Reopen
        </Button>
      )}
      <Button variant="ghost" icon={NotebookPen} onClick={() => setDialog('note')}>
        Add note
      </Button>
      {alert.incident ? (
        <Link
          to={`/incidents/${alert.incident.id}`}
          className="inline-flex h-9 items-center gap-2 rounded-md border border-accent/40 bg-accent/10 px-3.5 text-sm font-medium text-fg hover:bg-accent/20"
        >
          <Briefcase aria-hidden className="size-4 text-accent" />
          View {incidentRef(alert.incident.id)}
        </Link>
      ) : (
        <Button variant="primary" icon={Briefcase} onClick={() => setDialog('incident')}>
          Create incident
        </Button>
      )}

      <NoteDialog
        open={dialog === 'resolve'}
        onClose={() => setDialog(null)}
        title="Resolve alert"
        description="The threat was handled or turned out to be harmless."
        submitLabel="Resolve"
        placeholder="What was done? e.g. IP blocked at the firewall, password reset."
        required={false}
        onSubmit={(note) => update({ status: 'RESOLVED', note: note || undefined })}
      />
      <NoteDialog
        open={dialog === 'false-positive'}
        onClose={() => setDialog(null)}
        title="Mark as false positive"
        description="The rule fired on legitimate activity. A justification is required for the audit trail."
        submitLabel="Mark false positive"
        placeholder="Why is this benign? e.g. authorised scan, change ticket CHG-1234."
        onSubmit={(note) => update({ status: 'FALSE_POSITIVE', note })}
      />
      <NoteDialog
        open={dialog === 'note'}
        onClose={() => setDialog(null)}
        title="Add investigation note"
        submitLabel="Add note"
        placeholder="Findings, actions taken, next steps..."
        onSubmit={(note) => update({ note })}
      />
      <CreateIncidentDialog alert={alert} open={dialog === 'incident'} onClose={() => setDialog(null)} />
    </div>
  );
}
