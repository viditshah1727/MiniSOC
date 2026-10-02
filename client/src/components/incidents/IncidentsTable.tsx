import { Link, useNavigate } from 'react-router';
import type { IncidentListItem } from '../../types/api';
import { incidentRef } from '../../utils/format';
import { IncidentStatusBadge, SeverityBadge } from '../ui/Badges';
import { Time } from '../ui/Primitives';

export function IncidentsTable({ incidents, compact = false }: { incidents: IncidentListItem[]; compact?: boolean }) {
  const navigate = useNavigate();

  return (
    <div className="overflow-x-auto">
      <table className="data-table">
        <thead>
          <tr>
            <th>Incident</th>
            <th>Severity</th>
            <th>Status</th>
            <th>Assignee</th>
            {!compact && <th>Alerts</th>}
            <th>Opened</th>
            {!compact && <th>Resolved</th>}
          </tr>
        </thead>
        <tbody>
          {incidents.map((incident) => (
            <tr key={incident.id} className="row-link" onClick={() => navigate(`/incidents/${incident.id}`)}>
              <td className="max-w-md min-w-56">
                <Link to={`/incidents/${incident.id}`} onClick={(e) => e.stopPropagation()} className="font-medium text-fg hover:text-accent">
                  {incident.title}
                </Link>
                <div className="mt-0.5 font-mono text-xs text-faint">{incidentRef(incident.id)}</div>
              </td>
              <td>
                <SeverityBadge severity={incident.severity} />
              </td>
              <td>
                <IncidentStatusBadge status={incident.status} />
              </td>
              <td className="whitespace-nowrap text-muted">{incident.assignee?.name ?? <span className="text-faint">Unassigned</span>}</td>
              {!compact && <td className="tabular text-muted">{incident.alertCount}</td>}
              <td className="text-muted">
                <Time iso={incident.createdAt} relative />
              </td>
              {!compact && (
                <td className="text-muted">{incident.resolvedAt ? <Time iso={incident.resolvedAt} relative /> : '—'}</td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
