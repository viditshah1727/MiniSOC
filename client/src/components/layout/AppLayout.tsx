import { type ReactNode, Suspense, useState } from 'react';
import { Navigate, Outlet, useLocation } from 'react-router';
import { useAuth } from '../../context/AuthContext';
import { useLiveUpdates } from '../../context/LiveUpdatesContext';
import { useToast } from '../../context/ToastContext';
import { SEVERITY_LABEL } from '../../utils/labels';
import { LoadingState } from '../ui/States';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';

/** Pops a notification when a serious alert or a new incident arrives. */
function LiveNotifications() {
  const toast = useToast();
  useLiveUpdates((update) => {
    if (update.type === 'alert.created' && (update.severity === 'CRITICAL' || update.severity === 'HIGH')) {
      toast({
        tone: 'alert',
        title: `New ${SEVERITY_LABEL[update.severity].toLowerCase()} alert (risk ${update.riskScore})`,
        description: update.title,
        href: `/alerts/${update.id}`,
      });
    }
    if (update.type === 'incident.created') {
      toast({ tone: 'info', title: 'Incident opened', description: update.title, href: `/incidents/${update.id}` });
    }
  });
  return null;
}

export function AppLayout() {
  const [menuOpen, setMenuOpen] = useState(false);

  return (
    <div className="min-h-full">
      <Sidebar open={menuOpen} onNavigate={() => setMenuOpen(false)} />
      {menuOpen && (
        <div aria-hidden className="fixed inset-0 z-30 bg-black/60 lg:hidden" onClick={() => setMenuOpen(false)} />
      )}
      <div className="flex min-h-full min-w-0 flex-col lg:pl-60">
        <TopBar onOpenMenu={() => setMenuOpen(true)} />
        <main className="mx-auto w-full max-w-[1600px] flex-1 px-4 py-6 sm:px-6">
          <Suspense fallback={<LoadingState />}>
            <Outlet />
          </Suspense>
        </main>
      </div>
      <LiveNotifications />
    </div>
  );
}

/** Sends visitors without a session to the login page (and back afterwards). */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { session, checking } = useAuth();
  const location = useLocation();

  if (checking) return <LoadingState label="Checking your session..." className="h-full" />;
  if (!session) return <Navigate to="/login" replace state={{ from: `${location.pathname}${location.search}` }} />;
  return children;
}
