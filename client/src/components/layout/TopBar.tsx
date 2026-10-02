import { LogOut, Menu } from 'lucide-react';
import { useAuth, useSession } from '../../context/AuthContext';
import { useLiveConnection } from '../../context/LiveUpdatesContext';
import { cn } from '../../utils/cn';
import { RoleBadge } from '../ui/Badges';
import { Button } from '../ui/Button';
import { SimulateMenu } from './SimulateMenu';

export function TopBar({ onOpenMenu }: { onOpenMenu: () => void }) {
  const { user, features } = useSession();
  const { logout, canEdit } = useAuth();
  const live = useLiveConnection();

  return (
    <header className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b border-line bg-canvas/85 px-4 backdrop-blur sm:px-6">
      <button
        type="button"
        onClick={onOpenMenu}
        className="rounded-md p-1.5 text-muted hover:bg-raised hover:text-fg lg:hidden"
        aria-label="Open navigation"
      >
        <Menu className="size-5" />
      </button>

      <div className="flex items-center gap-2 text-xs text-muted" title={live ? 'Receiving real-time updates' : 'Reconnecting to real-time updates...'}>
        <span className="relative flex size-2">
          {live && <span className="absolute inline-flex size-full animate-ping rounded-full bg-state-good opacity-60 motion-reduce:hidden" />}
          <span className={cn('relative inline-flex size-2 rounded-full', live ? 'bg-state-good' : 'bg-sev-medium')} />
        </span>
        {live ? 'Live' : 'Reconnecting'}
      </div>

      <div className="ml-auto flex items-center gap-3">
        {features.simulation && canEdit && <SimulateMenu />}
        <div className="hidden items-center gap-2 border-l border-line pl-3 text-right sm:flex">
          <div>
            <p className="text-sm leading-tight font-medium text-fg">{user.name}</p>
            <p className="text-[11px] leading-tight text-faint">{user.email}</p>
          </div>
          <RoleBadge role={user.role} />
        </div>
        <Button variant="ghost" size="sm" icon={LogOut} onClick={() => void logout()} aria-label="Sign out" title="Sign out" />
      </div>
    </header>
  );
}
