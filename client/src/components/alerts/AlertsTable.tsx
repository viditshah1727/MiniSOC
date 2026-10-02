import { Link, useNavigate } from 'react-router';
import type { AlertListItem } from '../../types/api';
import { alertRef } from '../../utils/format';
import { AlertStatusBadge, ReputationIcon, RuleCode, SeverityBadge } from '../ui/Badges';
import { Mono, Time } from '../ui/Primitives';
import { RiskMeter } from '../ui/RiskMeter';

/** Alert list used across the app. `compact` drops the source/target/MITRE columns. */
export function AlertsTable({ alerts, compact = false }: { alerts: AlertListItem[]; compact?: boolean }) {
  const navigate = useNavigate();

  return (
    <div className="overflow-x-auto">
      <table className="data-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Alert</th>
            <th>Risk</th>
            {!compact && <th>Source</th>}
            {!compact && <th>Target</th>}
            {!compact && <th>MITRE</th>}
            <th>Status</th>
            <th>Detected</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.id} className="row-link" onClick={() => navigate(`/alerts/${alert.id}`)}>
              <td>
                <SeverityBadge severity={alert.severity} />
              </td>
              <td className="max-w-md min-w-56">
                <Link to={`/alerts/${alert.id}`} onClick={(e) => e.stopPropagation()} className="font-medium text-fg hover:text-accent">
                  {alert.title}
                </Link>
                <div className="mt-0.5 flex items-center gap-2 text-xs text-faint">
                  <span className="font-mono">{alertRef(alert.id)}</span>
                  <RuleCode code={alert.rule.code} />
                  <span className="truncate">{alert.rule.name}</span>
                </div>
              </td>
              <td>
                <RiskMeter score={alert.riskScore} level={alert.riskLevel} />
              </td>
              {!compact && (
                <td>
                  {alert.sourceIp ? (
                    <span className="flex items-center gap-1.5">
                      <Mono>{alert.sourceIp}</Mono>
                      {alert.threatIntel && <ReputationIcon reputation={alert.threatIntel.reputation} />}
                    </span>
                  ) : (
                    <span className="text-faint">—</span>
                  )}
                </td>
              )}
              {!compact && (
                <td className="text-muted">
                  <div className="whitespace-nowrap">{alert.hostname ?? '—'}</div>
                  {alert.username && <div className="text-xs text-faint">{alert.username}</div>}
                </td>
              )}
              {!compact && (
                <td>
                  {alert.mitreTechnique ? (
                    <span title={alert.mitreTechnique.name} className="font-mono text-xs text-muted">
                      {alert.mitreTechnique.id}
                    </span>
                  ) : (
                    '—'
                  )}
                </td>
              )}
              <td>
                <AlertStatusBadge status={alert.status} />
              </td>
              <td className="text-muted">
                <Time iso={alert.detectedAt} relative />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
