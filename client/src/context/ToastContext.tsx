// Small, dependency-free toast notifications (announced to screen readers).
import { CircleCheck, CircleAlert, Info, Siren, X } from 'lucide-react';
import { createContext, type ReactNode, useCallback, useContext, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router';
import { cn } from '../utils/cn';

export type ToastTone = 'success' | 'error' | 'info' | 'alert';

export interface ToastInput {
  title: string;
  description?: string;
  tone?: ToastTone;
  /** Optional link, e.g. to the alert that was just raised. */
  href?: string;
}

interface Toast extends ToastInput {
  id: number;
  tone: ToastTone;
}

const MAX_VISIBLE = 4;
const DISMISS_AFTER_MS = 6000;

const ToastContext = createContext<((toast: ToastInput) => void) | null>(null);

const TONE_ICON = { success: CircleCheck, error: CircleAlert, info: Info, alert: Siren };
const TONE_COLOR = {
  success: 'text-state-good',
  error: 'text-sev-critical',
  info: 'text-accent',
  alert: 'text-sev-high',
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const nextId = useRef(1);

  const dismiss = useCallback((id: number) => setToasts((current) => current.filter((t) => t.id !== id)), []);

  const show = useCallback(
    (input: ToastInput) => {
      const id = nextId.current++;
      setToasts((current) => [...current, { ...input, id, tone: input.tone ?? 'info' }].slice(-MAX_VISIBLE));
      window.setTimeout(() => dismiss(id), DISMISS_AFTER_MS);
    },
    [dismiss],
  );

  const value = useMemo(() => show, [show]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div
        aria-live="polite"
        className="pointer-events-none fixed right-4 bottom-4 z-50 flex w-[min(24rem,calc(100vw-2rem))] flex-col gap-2"
      >
        {toasts.map((toast) => {
          const Icon = TONE_ICON[toast.tone];
          return (
            <div
              key={toast.id}
              role="status"
              className="pointer-events-auto flex gap-3 rounded-lg border border-line-strong bg-overlay p-3 shadow-lg shadow-black/40"
            >
              <Icon aria-hidden className={cn('mt-0.5 size-4 shrink-0', TONE_COLOR[toast.tone])} />
              <div className="min-w-0 flex-1 text-sm">
                <p className="font-medium text-fg">{toast.title}</p>
                {toast.description && <p className="mt-0.5 text-muted">{toast.description}</p>}
                {toast.href && (
                  <Link to={toast.href} className="mt-1 inline-block text-xs font-medium text-accent hover:underline">
                    Open
                  </Link>
                )}
              </div>
              <button
                type="button"
                onClick={() => dismiss(toast.id)}
                className="h-fit rounded p-0.5 text-faint hover:text-fg"
                aria-label="Dismiss notification"
              >
                <X className="size-4" />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) throw new Error('useToast must be used inside <ToastProvider>');
  return context;
}
