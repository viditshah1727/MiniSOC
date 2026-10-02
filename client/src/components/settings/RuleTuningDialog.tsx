import { type FormEvent, useEffect, useState } from 'react';
import { ApiError } from '../../api/client';
import { api } from '../../api';
import type { DetectionRuleRow } from '../../types/api';
import { formatMinutes } from '../../utils/format';
import { Button } from '../ui/Button';
import { Modal } from '../ui/Modal';

/** Admin-only: change a rule's threshold and/or time window without a deploy. */
export function RuleTuningDialog({
  rule,
  onClose,
  onSaved,
}: {
  rule: DetectionRuleRow | null;
  onClose: () => void;
  onSaved: (rule: DetectionRuleRow) => void;
}) {
  const [threshold, setThreshold] = useState('');
  const [windowMinutes, setWindowMinutes] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!rule) return;
    setThreshold(rule.threshold === null ? '' : String(rule.threshold));
    setWindowMinutes(rule.windowMinutes === null ? '' : String(rule.windowMinutes));
    setError(null);
  }, [rule]);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (!rule) return;
    setSaving(true);
    setError(null);
    try {
      const updated = await api.rules.update(rule.id, {
        threshold: rule.tunable.threshold ? Number(threshold) : undefined,
        windowMinutes: rule.tunable.windowMinutes ? Number(windowMinutes) : undefined,
      });
      onSaved(updated);
      onClose();
    } catch (err) {
      setError(err instanceof ApiError ? [err.message, ...err.fieldErrors.map((f) => `${f.field}: ${f.message}`)].join(' · ') : 'Could not save.');
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal open={rule !== null} onClose={onClose} title={rule ? `Tune ${rule.code} ${rule.name}` : ''} description="Takes effect for the next event ingested.">
      {rule && (
        <form onSubmit={(event) => void handleSubmit(event)} className="space-y-4">
          {rule.tunable.threshold && (
            <div>
              <label htmlFor="rule-threshold" className="field-label">
                Threshold ({rule.thresholdLabel})
              </label>
              <input id="rule-threshold" type="number" min={1} max={1000} value={threshold} onChange={(e) => setThreshold(e.target.value)} className="field" />
            </div>
          )}
          {rule.tunable.windowMinutes && (
            <div>
              <label htmlFor="rule-window" className="field-label">
                Time window in minutes {windowMinutes && Number(windowMinutes) > 0 && `(${formatMinutes(Number(windowMinutes))})`}
              </label>
              <input id="rule-window" type="number" min={1} max={129600} value={windowMinutes} onChange={(e) => setWindowMinutes(e.target.value)} className="field" />
            </div>
          )}
          <p className="text-xs text-faint">Lower thresholds catch more attacks but raise more false positives. Every change is logged with your name.</p>
          {error && (
            <p role="alert" className="text-sm text-sev-critical">
              {error}
            </p>
          )}
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={saving}>
              Save
            </Button>
          </div>
        </form>
      )}
    </Modal>
  );
}
