// Dialog built on the native <dialog> element: focus trapping, Esc to close
// and the backdrop come from the browser, not from extra code.
import { X } from 'lucide-react';
import { type ReactNode, useEffect, useId, useRef } from 'react';
import { cn } from '../../utils/cn';

interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: ReactNode;
  /** "drawer" slides in from the right, for detail panels. */
  variant?: 'center' | 'drawer';
}

export function Modal({ open, onClose, title, description, children, variant = 'center' }: ModalProps) {
  const dialog = useRef<HTMLDialogElement>(null);
  const titleId = useId();

  useEffect(() => {
    const element = dialog.current;
    if (!element) return;
    if (open && !element.open) element.showModal();
    if (!open && element.open) element.close();
  }, [open]);

  return (
    <dialog
      ref={dialog}
      onClose={onClose}
      onClick={(event) => {
        if (event.target === dialog.current) onClose(); // click on the backdrop
      }}
      aria-labelledby={titleId}
      className={cn(
        'border border-line-strong bg-surface p-0 text-fg shadow-2xl shadow-black/60 backdrop:bg-black/60',
        variant === 'center'
          ? 'm-auto w-[min(32rem,calc(100vw-2rem))] rounded-lg'
          : 'my-0 mr-0 ml-auto h-dvh max-h-dvh w-[min(40rem,100vw)] rounded-none border-y-0 border-r-0',
      )}
    >
      {open && (
        <div className="flex h-full flex-col">
          <header className="flex items-start justify-between gap-4 border-b border-line px-5 py-4">
            <div>
              <h2 id={titleId} className="text-base font-semibold">
                {title}
              </h2>
              {description && <p className="mt-0.5 text-sm text-muted">{description}</p>}
            </div>
            <button type="button" onClick={onClose} className="rounded p-1 text-faint hover:bg-raised hover:text-fg" aria-label="Close">
              <X className="size-4" />
            </button>
          </header>
          <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">{children}</div>
        </div>
      )}
    </dialog>
  );
}
