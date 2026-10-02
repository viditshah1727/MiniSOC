// Loading, error and empty states, so no page ever shows a blank area.
import { CircleAlert, Inbox, LoaderCircle, type LucideIcon, RefreshCw } from 'lucide-react';
import type { ReactNode } from 'react';
import type { ApiError } from '../../api/client';
import { cn } from '../../utils/cn';
import { Button } from './Button';

export function LoadingState({ label = 'Loading...', className }: { label?: string; className?: string }) {
  return (
    <div role="status" className={cn('flex items-center justify-center gap-2 py-12 text-sm text-muted', className)}>
      <LoaderCircle aria-hidden className="size-4 animate-spin" />
      {label}
    </div>
  );
}

export function ErrorState({ error, onRetry, className }: { error: ApiError; onRetry?: () => void; className?: string }) {
  return (
    <div role="alert" className={cn('flex flex-col items-center gap-3 py-12 text-center', className)}>
      <CircleAlert aria-hidden className="size-6 text-sev-critical" />
      <div>
        <p className="text-sm font-medium text-fg">{error.status === 404 ? 'Not found' : 'Could not load this data'}</p>
        <p className="mt-1 text-sm text-muted">{error.message}</p>
        {error.fieldErrors.map((fieldError) => (
          <p key={fieldError.field} className="mt-1 text-sm text-muted">
            <span className="font-mono text-fg">{fieldError.field}</span>: {fieldError.message}
          </p>
        ))}
      </div>
      {onRetry && error.status !== 404 && (
        <Button size="sm" icon={RefreshCw} onClick={onRetry}>
          Try again
        </Button>
      )}
    </div>
  );
}

interface EmptyStateProps {
  title: string;
  description?: ReactNode;
  icon?: LucideIcon;
  action?: ReactNode;
  className?: string;
}

export function EmptyState({ title, description, icon: Icon = Inbox, action, className }: EmptyStateProps) {
  return (
    <div className={cn('flex flex-col items-center gap-2 px-4 py-10 text-center', className)}>
      <Icon aria-hidden className="size-6 text-faint" />
      <p className="text-sm font-medium text-fg">{title}</p>
      {description && <p className="max-w-sm text-sm text-muted">{description}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}
