import { ExternalLink, ShieldOff } from 'lucide-react';
import { Fragment } from 'react';
import { Link } from 'react-router';
import { api } from '../api';
import { RuleCode } from '../components/ui/Badges';
import { Card } from '../components/ui/Card';
import { Mono, PageHeader } from '../components/ui/Primitives';
import { ErrorState, LoadingState } from '../components/ui/States';
import { useApi } from '../hooks/useApi';
import type { MitreTechniqueRow } from '../types/api';

function CoverageTile({ label, value, caption }: { label: string; value: number; caption: string }) {
  return (
    <Card className="p-4">
      <p className="text-sm text-muted">{label}</p>
      <p className="mt-1 text-2xl font-semibold text-fg">{value}</p>
      <p className="mt-1 text-xs text-faint">{caption}</p>
    </Card>
  );
}

/** Groups techniques under their primary tactic, keeping the server's kill-chain order. */
function groupByTactic(techniques: MitreTechniqueRow[]) {
  const groups = new Map<string, MitreTechniqueRow[]>();
  for (const technique of techniques) {
    const tactic = technique.tactics[0] ?? 'Other';
    groups.set(tactic, [...(groups.get(tactic) ?? []), technique]);
  }
  return [...groups.entries()];
}

export default function MitrePage() {
  const { data: techniques, error, reload } = useApi((signal) => api.mitre.techniques(signal), []);

  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (!techniques) return <LoadingState />;

  const covered = techniques.filter((t) => t.rules.some((r) => r.enabled)).length;
  const observed = techniques.filter((t) => t.alertCount > 0).length;

  return (
    <>
      <PageHeader
        title="MITRE ATT&CK"
        description="The techniques relevant to what MiniSOC monitors, the rules that detect them, and how often they were seen. A focused local reference, not the full framework."
      />

      <div className="mb-4 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <CoverageTile label="Techniques in scope" value={techniques.length} caption="Local ATT&CK subset" />
        <CoverageTile label="Covered by a rule" value={covered} caption="At least one enabled detection rule" />
        <CoverageTile label="Seen in alerts" value={observed} caption="Mapped to at least one alert" />
        <CoverageTile label="Coverage gaps" value={techniques.length - covered} caption="No enabled rule detects these yet" />
      </div>

      <Card>
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Technique</th>
                <th>Tactics</th>
                <th>Detected by</th>
                <th>Alerts</th>
              </tr>
            </thead>
            <tbody>
              {groupByTactic(techniques).map(([tactic, group]) => (
                <Fragment key={tactic}>
                  <tr>
                    <td colSpan={4} className="bg-raised/60 py-1.5 text-xs font-semibold tracking-wide text-muted uppercase">
                      {tactic}
                    </td>
                  </tr>
                  {group.map((technique) => (
                    <tr key={technique.id}>
                      <td className="max-w-xl min-w-80">
                        <a
                          href={`https://attack.mitre.org/techniques/${technique.id.replace('.', '/')}/`}
                          target="_blank"
                          rel="noreferrer noopener"
                          className="group inline-flex items-center gap-2 font-medium text-fg hover:text-accent"
                        >
                          <Mono className="text-accent">{technique.id}</Mono>{' '}
                          {technique.name}
                          <ExternalLink aria-label="(opens attack.mitre.org)" className="size-3 text-faint group-hover:text-accent" />
                        </a>
                        <p className="mt-1 text-xs leading-relaxed text-muted">{technique.description}</p>
                      </td>
                      <td>
                        <div className="flex max-w-56 flex-wrap gap-1">
                          {technique.tactics.map((t) => (
                            <span key={t} className="rounded bg-raised px-1.5 py-0.5 text-[11px] whitespace-nowrap text-muted ring-1 ring-line ring-inset">
                              {t}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td>
                        {technique.rules.length === 0 ? (
                          <span className="inline-flex items-center gap-1.5 text-xs text-faint">
                            <ShieldOff aria-hidden className="size-3.5" />
                            No rule (gap)
                          </span>
                        ) : (
                          <ul className="space-y-1">
                            {technique.rules.map((rule) => (
                              <li key={rule.id} className="flex items-center gap-2 text-sm whitespace-nowrap">
                                <RuleCode code={rule.code} />
                                <span className={rule.enabled ? 'text-fg' : 'text-faint line-through'}>{rule.name}</span>
                                {!rule.enabled && <span className="text-xs text-faint">(disabled)</span>}
                              </li>
                            ))}
                          </ul>
                        )}
                      </td>
                      <td className="whitespace-nowrap">
                        {technique.alertCount > 0 ? (
                          <Link to={`/alerts?mitreTechniqueId=${technique.id}`} className="font-medium text-accent hover:underline">
                            <span className="tabular">{technique.alertCount}</span> alert{technique.alertCount === 1 ? '' : 's'}
                          </Link>
                        ) : (
                          <span className="text-faint">None</span>
                        )}
                        {technique.openAlertCount > 0 && (
                          <p className="text-xs text-muted">
                            <span className="tabular">{technique.openAlertCount}</span> open
                          </p>
                        )}
                      </td>
                    </tr>
                  ))}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}
