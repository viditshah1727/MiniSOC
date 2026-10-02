import {
  Briefcase,
  Crosshair,
  LayoutDashboard,
  type LucideIcon,
  Radar,
  ScrollText,
  Settings,
  Siren,
} from 'lucide-react';
import { NavLink } from 'react-router';
import { api } from '../../api';
import { useLiveRefresh } from '../../context/LiveUpdatesContext';
import { useApi } from '../../hooks/useApi';
import { cn } from '../../utils/cn';
import { Logo } from './Logo';

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
}

const NAVIGATION: { heading: string; items: NavItem[] }[] = [
  {
    heading: 'Monitor',
    items: [
      { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
      { to: '/alerts', label: 'Alerts', icon: Siren },
      { to: '/incidents', label: 'Incidents', icon: Briefcase },
      { to: '/events', label: 'Events', icon: ScrollText },
    ],
  },
  {
    heading: 'Intelligence',
    items: [
      { to: '/threat-intelligence', label: 'Threat Intel', icon: Radar },
      { to: '/mitre', label: 'MITRE ATT&CK', icon: Crosshair },
    ],
  },
  {
    heading: 'Configure',
    items: [{ to: '/settings', label: 'Settings', icon: Settings }],
  },
];

export function Sidebar({ open, onNavigate }: { open: boolean; onNavigate: () => void }) {
  // Live count of alerts nobody has picked up yet.
  const openAlerts = useApi((signal) => api.alerts.list({ status: 'OPEN', pageSize: 1 }, signal), []);
  useLiveRefresh(openAlerts.reload, ['alert.created', 'alert.updated']);
  const openCount = openAlerts.data?.pagination.total;

  return (
    <aside
      className={cn(
        'fixed inset-y-0 left-0 z-40 flex w-60 flex-col border-r border-line bg-surface transition-transform lg:translate-x-0',
        open ? 'translate-x-0' : '-translate-x-full',
      )}
    >
      <div className="flex items-center gap-2.5 px-4 py-4">
        <Logo className="size-8" />
        <div>
          <p className="text-[15px] leading-tight font-semibold">
            Mini<span className="text-accent">SOC</span>
          </p>
          <p className="text-[11px] leading-tight text-faint">Security Operations Center</p>
        </div>
      </div>

      <nav aria-label="Main" className="flex-1 space-y-5 overflow-y-auto px-3 py-2">
        {NAVIGATION.map((section) => (
          <div key={section.heading}>
            <p className="mb-1.5 px-2 text-[11px] font-medium tracking-wider text-faint uppercase">{section.heading}</p>
            <ul className="space-y-0.5">
              {section.items.map(({ to, label, icon: Icon }) => (
                <li key={to}>
                  <NavLink
                    to={to}
                    onClick={onNavigate}
                    className={({ isActive }) =>
                      cn(
                        'flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm transition-colors',
                        isActive ? 'bg-accent/10 font-medium text-fg' : 'text-muted hover:bg-raised hover:text-fg',
                      )
                    }
                  >
                    {({ isActive }) => (
                      <>
                        <Icon aria-hidden className={cn('size-4', isActive && 'text-accent')} />
                        <span className="flex-1">{label}</span>
                        {to === '/alerts' && openCount !== undefined && openCount > 0 && (
                          <span
                            className="tabular rounded-full bg-sev-critical/20 px-1.5 text-[11px] font-semibold text-fg ring-1 ring-sev-critical/40 ring-inset"
                            aria-label={`${openCount} open alerts`}
                          >
                            {openCount}
                          </span>
                        )}
                      </>
                    )}
                  </NavLink>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>

      <p className="border-t border-line px-4 py-3 text-[11px] text-faint">MiniSOC v2 · lightweight SOC platform</p>
    </aside>
  );
}
