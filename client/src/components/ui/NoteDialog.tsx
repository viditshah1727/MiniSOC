// A dialog that asks for a note, used for "Add note", "Resolve" and
// "False positive" (where a justification is required).
import { type FormEvent, useEffect, useState } from 'react';
import { ApiError } from '../../api/client';
import { Button } from './Button';
import { Modal } from './Modal';

interface NoteDialogProps {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  submitLabel: string;
  placeholder?: string;
  /** When false, the note is optional. */
  required?: boolean;
  onSubmit: (note: string) => Promise<void>;
}

export function NoteDialog({ open, onClose, title, description, submitLabel, placeholder, required = true, onSubmit }: NoteDialogProps) {
  const [note, setNote] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (open) {
      setNote('');
      setError(null);
    }
  }, [open]);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    setError(null);
    try {
      await onSubmit(note.trim());
      onClose();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not save. Please try again.');
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal open={open} onClose={onClose} title={title} description={description}>
      <form onSubmit={(event) => void handleSubmit(event)} className="space-y-4">
        <div>
          <label htmlFor="note" className="field-label">
            Note {required ? '' : '(optional)'}
          </label>
          <textarea
            id="note"
            rows={4}
            maxLength={2000}
            value={note}
            onChange={(event) => setNote(event.target.value)}
            placeholder={placeholder}
            className="field resize-y"
            autoFocus
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
          <Button type="submit" variant="primary" loading={saving} disabled={required && !note.trim()}>
            {submitLabel}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
