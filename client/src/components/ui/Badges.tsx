// Every state in MiniSOC is shown as text + a colour cue, never colour alone.
import {
  Archive,
  Ban,
  CircleCheck,
  CircleDot,
  type LucideIcon,
  Search,
  ShieldAlert,
  ShieldCheck,
  TriangleAlert,
} from 'lucide-react';
import type { AlertStatus, IncidentStatus, Reputation, RiskLevel, Role, Severity } from '../../types/api';
import { cn } from '../../utils/cn';
import {
  ALERT_STATUS_LABEL,
  INCIDENT_STATUS_LABEL,
  REPUTATION_LABEL,
  ROLE_LABEL,
  SEVERITY_LABEL,
} from '../../utils/labels';

const SEVERITY_STYLE: Record<Severity, { pill: string; dot: string }> = {
  CRITICAL: { pill: 'bg-sev-critical/15 ring-sev-critical/45', dot: 'bg-sev-critical' },
  HIGH: { pill: 'bg-sev-high/12 ring-sev-high/40', dot: 'bg-sev-high' },
  MEDIUM: { pill: 'bg-sev-medium/10 ring-sev-medium/35', dot: 'bg-sev-medium' },
  LOW: { pill: 'bg-sev-low/10 ring-sev-low/30', dot: 'bg-sev-low' },
  INFO: { pill: 'bg-sev-info/15 ring-sev-info/40', dot: 'bg-sev-info' },
};

const pillBase = 'inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium whitespace-nowrap text-fg ring-1 ring-inset';

export function SeverityBadge({ severity, label }: { severity: Severity | RiskLevel; label?: string }) {
  const style = SEVERITY_STYLE[severity];
  return (
    <span className={cn(pillBase, style.pill)}>
      <span aria-hidden className={cn('size-1.5 rounded-full', style.dot)} />
      {label ?? SEVERITY_LABEL[severity]}
    </span>
  );
}

function IconPill({ icon: Icon, color, label }: { icon: LucideIcon; color: string; label: string }) {
  return (
    <span className={cn(pillBase, 'bg-raised ring-line-strong')}>
      <Icon aria-hidden className={cn('size-3.5', color)} />
      {label}
    </span>
  );
}

const ALERT_STATUS_ICON: Record<AlertStatus, { icon: LucideIcon; color: string }> = {
  OPEN: { icon: CircleDot, color: 'text-accent' },
  INVESTIGATING: { icon: Search, color: 'text-state-progress' },
  RESOLVED: { icon: CircleCheck, color: 'text-state-good' },
  FALSE_POSITIVE: { icon: Ban, color: 'text-muted' },
};

export function AlertStatusBadge({ status }: { status: AlertStatus }) {
  return <IconPill {...ALERT_STATUS_ICON[status]} label={ALERT_STATUS_LABEL[status]} />;
}

const INCIDENT_STATUS_ICON: Record<IncidentStatus, { icon: LucideIcon; color: string }> = {
  OPEN: { icon: CircleDot, color: 'text-accent' },
  INVESTIGATING: { icon: Search, color: 'text-state-progress' },
  RESOLVED: { icon: CircleCheck, color: 'text-state-good' },
  CLOSED: { icon: Archive, color: 'text-muted' },
};

export function IncidentStatusBadge({ status }: { status: IncidentStatus }) {
  return <IconPill {...INCIDENT_STATUS_ICON[status]} label={INCIDENT_STATUS_LABEL[status]} />;
}

const REPUTATION_ICON: Record<Reputation, { icon: LucideIcon; color: string }> = {
  MALICIOUS: { icon: ShieldAlert, color: 'text-sev-critical' },
  SUSPICIOUS: { icon: TriangleAlert, color: 'text-sev-medium' },
  BENIGN: { icon: ShieldCheck, color: 'text-state-good' },
};

export function ReputationBadge({ reputation }: { reputation: Reputation }) {
  return <IconPill {...REPUTATION_ICON[reputation]} label={REPUTATION_LABEL[reputation]} />;
}

/** Compact marker for tables: a coloured shield icon with an accessible label. */
export function ReputationIcon({ reputation }: { reputation: Reputation }) {
  const { icon: Icon, color } = REPUTATION_ICON[reputation];
  const label = `Threat intel: ${REPUTATION_LABEL[reputation]}`;
  return <Icon role="img" aria-label={label} className={cn('inline size-3.5 shrink-0', color)} />;
}

export function RoleBadge({ role }: { role: Role }) {
  return (
    <span className="rounded bg-raised px-1.5 py-0.5 text-[11px] font-medium tracking-wide text-muted uppercase ring-1 ring-line-strong ring-inset">
      {ROLE_LABEL[role]}
    </span>
  );
}

/** Rule code chip, e.g. "R001". */
export function RuleCode({ code }: { code: string }) {
  return <span className="rounded bg-raised px-1.5 py-0.5 font-mono text-[11px] text-muted ring-1 ring-line ring-inset">{code}</span>;
}
