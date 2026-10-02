import { SlidersHorizontal } from 'lucide-react';
import { useState } from 'react';
import { ApiError } from '../api/client';
import { api } from '../api';
import { RuleTuningDialog } from '../components/settings/RuleTuningDialog';
import { RoleBadge, RuleCode, SeverityBadge } from '../components/ui/Badges';
import { Button } from '../components/ui/Button';
import { Card, CardBody, CardHeader } from '../components/ui/Card';
import { KeyValueList, PageHeader } from '../components/ui/Primitives';
import { ErrorState, LoadingState } from '../components/ui/States';
import { useAuth, useSession } from '../context/AuthContext';
import { useLiveConnection } from '../context/LiveUpdatesContext';
import { useToast } from '../context/ToastContext';
import { useApi } from '../hooks/useApi';
import type { DetectionRuleRow, Role } from '../types/api';
import { cn } from '../utils/cn';
import { formatMinutes } from '../utils/format';

const ROLE_PERMISSIONS: Record<Role, string> = {
  ADMIN: 'Everything analysts can do, plus enabling, disabling and tuning detection rules.',
  ANALYST: 'Triage alerts, run incidents, ingest events and add threat intelligence.',
  VIEWER: 'Read-only access to every page.',
};

function Switch({ checked, onChange, disabled, label }: { checked: boolean; onChange: () => void; disabled?: boolean; label: string }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={onChange}
      className={cn(
        'relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors disabled:cursor-not-allowed disabled:opacity-50',
        checked ? 'bg-accent' : 'bg-line-strong',
      )}
    >
      <span className={cn('inline-block size-4 rounded-full bg-fg shadow transition-transform', checked ? 'translate-x-4.5' : 'translate-x-0.5')} />
    </button>
  );
}

function StatusDot({ on, onLabel, offLabel }: { on: boolean; onLabel: string; offLabel: string }) {
  return (
    <span className="flex items-center gap-2">
      <span aria-hidden className={cn('size-2 rounded-full', on ? 'bg-state-good' : 'bg-faint')} />
      {on ? onLabel : offLabel}
    </span>
  );
}

export default function SettingsPage() {
  const { user, features } = useSession();
  const { isAdmin } = useAuth();
  const live = useLiveConnection();
  const toast = useToast();
  const { data: rules, error, reload, setData } = useApi((signal) => api.rules.list(signal), []);
  const [tuning, setTuning] = useState<DetectionRuleRow | null>(null);
  const [toggling, setToggling] = useState<number | null>(null);

  function replaceRule(updated: DetectionRuleRow) {
    if (rules) setData(rules.map((rule) => (rule.id === updated.id ? updated : rule)));
  }

  async function toggle(rule: DetectionRuleRow) {
    setToggling(rule.id);
    try {
      replaceRule(await api.rules.update(rule.id, { enabled: !rule.enabled }));
      toast({ tone: 'success', title: `${rule.code} ${rule.enabled ? 'disabled' : 'enabled'}` });
    } catch (err) {
      toast({ tone: 'error', title: 'Could not change the rule', description: err instanceof ApiError ? err.message : undefined });
    } finally {
      setToggling(null);
    }
  }

  return (
    <>
      <PageHeader title="Settings" description="Detection rules, your account and platform status." />

      <Card className="mb-4">
        <CardHeader
          title="Detection rules"
          subtitle={
            isAdmin
              ? 'Rules are defined in code; their on/off state and thresholds live in the database and apply to the next event.'
              : 'Only admins can enable, disable or tune detection rules.'
          }
        />
        {error ? (
          <ErrorState error={error} onRetry={reload} />
        ) : !rules ? (
          <LoadingState />
        ) : (
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Severity</th>
                  <th>MITRE</th>
                  <th>Threshold</th>
                  <th>Window</th>
                  <th>Alerts</th>
                  <th>Enabled</th>
                  {isAdmin && <th aria-label="Actions" />}
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={rule.id} className={cn(!rule.enabled && 'opacity-60')}>
                    <td className="max-w-lg min-w-72">
                      <p className="flex items-center gap-2 font-medium text-fg">
                        <RuleCode code={rule.code} />
                        {rule.name}
                      </p>
                      <p className="mt-0.5 text-xs text-muted">{rule.description}</p>
                    </td>
                    <td>
                      <SeverityBadge severity={rule.severity} />
                    </td>
                    <td className="font-mono text-xs text-muted">{rule.techniques.map((t) => t.id).join(', ')}</td>
                    <td className="text-sm">
                      {rule.threshold === null ? (
                        <span className="text-faint">—</span>
                      ) : (
                        <>
                          <span className="tabular text-fg">{rule.threshold}</span>
                          {rule.thresholdLabel && <p className="text-xs text-faint">{rule.thresholdLabel}</p>}
                        </>
                      )}
                    </td>
                    <td className="whitespace-nowrap text-muted">{rule.windowMinutes === null ? '—' : formatMinutes(rule.windowMinutes)}</td>
                    <td className="tabular text-muted">{rule.alertCount}</td>
                    <td>
                      <Switch
                        checked={rule.enabled}
                        disabled={!isAdmin || toggling === rule.id}
                        onChange={() => void toggle(rule)}
                        label={`${rule.enabled ? 'Disable' : 'Enable'} ${rule.code} ${rule.name}`}
                      />
                    </td>
                    {isAdmin && (
                      <td>
                        {(rule.tunable.threshold || rule.tunable.windowMinutes) && (
                          <Button size="sm" variant="ghost" icon={SlidersHorizontal} onClick={() => setTuning(rule)}>
                            Tune
                          </Button>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="Your account" />
          <CardBody>
            <KeyValueList
              items={[
                ['Name', user.name],
                ['Email', user.email],
                ['Role', <RoleBadge key="role" role={user.role} />],
                ['Permissions', ROLE_PERMISSIONS[user.role]],
                ['Session', 'httpOnly cookie, expires after 8 hours'],
              ]}
            />
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Platform" />
          <CardBody>
            <KeyValueList
              items={[
                ['Real-time updates', <StatusDot key="live" on={live} onLabel="Connected (Server-Sent Events)" offLabel="Reconnecting" />],
                ['Attack simulator', <StatusDot key="sim" on={features.simulation} onLabel="Enabled (demo mode)" offLabel="Disabled" />],
                ['AI assistant', <StatusDot key="ai" on={features.aiAssistant} onLabel="Enabled" offLabel="Not configured (optional)" />],
                ['Detection engine', 'Deterministic rules, evaluated on every ingested event'],
              ]}
            />
          </CardBody>
        </Card>
      </div>

      <RuleTuningDialog rule={tuning} onClose={() => setTuning(null)} onSaved={replaceRule} />
    </>
  );
}
