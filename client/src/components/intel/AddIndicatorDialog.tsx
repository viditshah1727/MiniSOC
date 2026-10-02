import { type FormEvent, useEffect, useState } from 'react';
import { ApiError, type FieldError } from '../../api/client';
import { api } from '../../api';
import { useToast } from '../../context/ToastContext';
import type { IndicatorType, Reputation } from '../../types/api';
import { INDICATOR_TYPE_LABEL, REPUTATION_LABEL } from '../../utils/labels';
import { Button } from '../ui/Button';
import { Modal } from '../ui/Modal';

const PLACEHOLDER: Record<IndicatorType, string> = {
  IP: '203.0.113.99',
  DOMAIN: 'malicious-site.example',
  HASH: '64 hex characters (SHA-256)',
};

export function AddIndicatorDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: () => void }) {
  const toast = useToast();
  const [type, setType] = useState<IndicatorType>('IP');
  const [indicator, setIndicator] = useState('');
  const [reputation, setReputation] = useState<Reputation>('MALICIOUS');
  const [confidence, setConfidence] = useState(80);
  const [source, setSource] = useState('analyst');
  const [description, setDescription] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<FieldError[]>([]);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open) return;
    setIndicator('');
    setDescription('');
    setError(null);
    setFieldErrors([]);
  }, [open]);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    setError(null);
    setFieldErrors([]);
    try {
      const created = await api.threatIntel.create({
        type,
        indicator: indicator.trim(),
        reputation,
        confidence,
        source: source.trim(),
        description: description.trim() || undefined,
      });
      toast({ tone: 'success', title: 'Indicator added', description: created.indicator });
      onCreated();
      onClose();
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
        setFieldErrors(err.fieldErrors);
      } else {
        setError('Could not add the indicator.');
      }
    } finally {
      setSaving(false);
    }
  }

  const errorFor = (field: string) => fieldErrors.find((e) => e.field === field)?.message;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Add indicator"
      description="New indicators are used immediately to enrich alerts and by rule R006."
    >
      <form onSubmit={(event) => void handleSubmit(event)} className="space-y-4" noValidate>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label htmlFor="ioc-type" className="field-label">
              Type
            </label>
            <select id="ioc-type" value={type} onChange={(e) => setType(e.target.value as IndicatorType)} className="field">
              {(Object.keys(INDICATOR_TYPE_LABEL) as IndicatorType[]).map((t) => (
                <option key={t} value={t}>
                  {INDICATOR_TYPE_LABEL[t]}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="ioc-reputation" className="field-label">
              Reputation
            </label>
            <select id="ioc-reputation" value={reputation} onChange={(e) => setReputation(e.target.value as Reputation)} className="field">
              {(Object.keys(REPUTATION_LABEL) as Reputation[]).map((r) => (
                <option key={r} value={r}>
                  {REPUTATION_LABEL[r]}
                </option>
              ))}
            </select>
          </div>
        </div>
        <div>
          <label htmlFor="ioc-value" className="field-label">
            Indicator
          </label>
          <input
            id="ioc-value"
            value={indicator}
            onChange={(e) => setIndicator(e.target.value)}
            placeholder={PLACEHOLDER[type]}
            aria-invalid={Boolean(errorFor('indicator'))}
            aria-describedby="ioc-value-error"
            className="field font-mono"
            autoFocus
          />
          <p id="ioc-value-error" className="mt-1 text-xs text-sev-high">
            {errorFor('indicator')}
          </p>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label htmlFor="ioc-confidence" className="field-label">
              Confidence: {confidence}%
            </label>
            <input
              id="ioc-confidence"
              type="range"
              min={0}
              max={100}
              step={5}
              value={confidence}
              onChange={(e) => setConfidence(Number(e.target.value))}
              className="w-full accent-[var(--color-accent)]"
            />
          </div>
          <div>
            <label htmlFor="ioc-source" className="field-label">
              Source
            </label>
            <input id="ioc-source" value={source} onChange={(e) => setSource(e.target.value)} maxLength={100} className="field" />
          </div>
        </div>
        <div>
          <label htmlFor="ioc-description" className="field-label">
            Description (optional)
          </label>
          <input
            id="ioc-description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            maxLength={500}
            placeholder="e.g. Phishing kit hosting, seen in campaign X"
            className="field"
          />
        </div>
        {error && !errorFor('indicator') && (
          <p role="alert" className="text-sm text-sev-critical">
            {error}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" loading={saving} disabled={!indicator.trim() || !source.trim()}>
            Add indicator
          </Button>
        </div>
      </form>
    </Modal>
  );
}
