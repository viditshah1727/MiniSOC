// Small presentational building blocks shared by every page.
import type { ReactNode } from 'react';
import { cn } from '../../utils/cn';
import { formatDateTime, timeAgo } from '../../utils/format';

/** A timestamp: local time on screen, exact UTC on hover. */
export function Time({ iso, relative = false, className }: { iso: string; relative?: boolean; className?: string }) {
  return (
    <time dateTime={iso} title={new Date(iso).toUTCString()} className={cn('whitespace-nowrap', className)}>
      {relative ? timeAgo(iso) : formatDateTime(iso)}
    </time>
  );
}

/** Label/value pairs, e.g. an event's fields. */
export function KeyValueList({ items, className }: { items: [label: string, value: ReactNode][]; className?: string }) {
  return (
    <dl className={cn('grid grid-cols-[minmax(7rem,auto)_1fr] gap-x-4 gap-y-2 text-sm', className)}>
      {items.map(([label, value]) => (
        <div key={label} className="contents">
          <dt className="text-muted">{label}</dt>
          <dd className="min-w-0 break-words text-fg">{value ?? <span className="text-faint">—</span>}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Monospace text for machine values: IPs, hashes, commands, IDs. */
export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn('font-mono text-[13px]', className)}>{children}</span>;
}

interface PageHeaderProps {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  eyebrow?: ReactNode;
}

export function PageHeader({ title, description, actions, eyebrow }: PageHeaderProps) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        {eyebrow && <div className="mb-1 text-xs text-muted">{eyebrow}</div>}
        <h1 className="text-xl font-semibold text-fg">{title}</h1>
        {description && <p className="mt-1 text-sm text-muted">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

/** One labelled control in a filter bar. */
export function Field({ label, htmlFor, children, className }: { label: string; htmlFor: string; children: ReactNode; className?: string }) {
  return (
    <div className={className}>
      <label htmlFor={htmlFor} className="field-label">
        {label}
      </label>
      {children}
    </div>
  );
}
