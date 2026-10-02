// Controls for the filter bar above every list.
import { Search, X } from 'lucide-react';
import { type ReactNode, useEffect, useState } from 'react';
import { cn } from '../../utils/cn';
import { Button } from './Button';

/** Text input that reports its value after the user pauses typing (or presses Enter). */
export function DebouncedInput({
  id,
  value,
  onChange,
  placeholder,
  icon = false,
  className,
}: {
  id: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  icon?: boolean;
  className?: string;
}) {
  const [draft, setDraft] = useState(value);

  useEffect(() => setDraft(value), [value]);

  useEffect(() => {
    if (draft === value) return;
    const timer = window.setTimeout(() => onChange(draft.trim()), 400);
    return () => window.clearTimeout(timer);
  }, [draft, value, onChange]);

  return (
    <div className={cn('relative', className)}>
      {icon && <Search aria-hidden className="pointer-events-none absolute top-2.5 left-2.5 size-4 text-faint" />}
      <input
        id={id}
        type="search"
        value={draft}
        onChange={(event) => setDraft(event.target.value)}
        onKeyDown={(event) => event.key === 'Enter' && onChange(draft.trim())}
        placeholder={placeholder}
        className={cn('field', icon && 'pl-8')}
      />
    </div>
  );
}

export interface SelectOption {
  value: string;
  label: string;
}

export function SelectInput({
  id,
  value,
  onChange,
  options,
  allLabel = 'All',
}: {
  id: string;
  value: string;
  onChange: (value: string) => void;
  options: SelectOption[];
  allLabel?: string | null;
}) {
  return (
    <select id={id} value={value} onChange={(event) => onChange(event.target.value)} className="field pr-8">
      {allLabel !== null && <option value="">{allLabel}</option>}
      {options.map((option) => (
        <option key={option.value} value={option.value}>
          {option.label}
        </option>
      ))}
    </select>
  );
}

/** The single filter row above a list (filters scope everything below them). */
export function FilterBar({ children, onClear, hasFilters }: { children: ReactNode; onClear: () => void; hasFilters: boolean }) {
  return (
    <div className="mb-4 flex flex-wrap items-end gap-3 rounded-lg border border-line bg-surface p-3">
      {children}
      <Button variant="ghost" size="md" icon={X} onClick={onClear} disabled={!hasFilters} className="ml-auto">
        Clear filters
      </Button>
    </div>
  );
}
