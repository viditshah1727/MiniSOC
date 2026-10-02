// DEMO ONLY: runs an attack scenario on the server (POST /api/simulate).
// Shown only when the server has ENABLE_SIMULATION=true and the user can edit.
import { ChevronDown, FlaskConical } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { ApiError } from '../../api/client';
import { api } from '../../api';
import { useToast } from '../../context/ToastContext';
import { useApi } from '../../hooks/useApi';
import { Button } from '../ui/Button';

export function SimulateMenu() {
  const [open, setOpen] = useState(false);
  const [running, setRunning] = useState<string | null>(null);
  const scenarios = useApi((signal) => api.simulation.scenarios(signal), []);
  const toast = useToast();
  const menu = useRef<HTMLDivElement>(null);

  // Close on outside click or Escape.
  useEffect(() => {
    if (!open) return;
    const onPointer = (event: PointerEvent) => {
      if (!menu.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => event.key === 'Escape' && setOpen(false);
    document.addEventListener('pointerdown', onPointer);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('pointerdown', onPointer);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  async function run(id: string) {
    setOpen(false);
    setRunning(id);
    try {
      const result = await api.simulation.run(id);
      toast({
        tone: result.alerts.length ? 'alert' : 'info',
        title: `${result.scenario.name}: ${result.eventsIngested} events sent`,
        description: result.alerts.length
          ? `${result.alerts.length} alert(s) raised: ${[...new Set(result.alerts.map((a) => a.rule.code))].join(', ')}`
          : 'No alert raised (duplicates are suppressed for an hour).',
        href: result.alerts.length ? '/alerts' : undefined,
      });
    } catch (error) {
      toast({ tone: 'error', title: 'Simulation failed', description: error instanceof ApiError ? error.message : undefined });
    } finally {
      setRunning(null);
    }
  }

  if (scenarios.error) return null;

  return (
    <div ref={menu} className="relative">
      <Button
        size="sm"
        icon={FlaskConical}
        loading={running !== null}
        onClick={() => setOpen((value) => !value)}
        aria-haspopup="menu"
        aria-expanded={open}
      >
        <span className="hidden sm:inline">Simulate attack</span>
        <ChevronDown aria-hidden className="size-3.5" />
      </Button>
      {open && (
        <div role="menu" className="absolute right-0 z-30 mt-2 w-80 rounded-lg border border-line-strong bg-overlay p-1.5 shadow-xl shadow-black/50">
          <p className="px-2.5 pt-1.5 pb-2 text-xs text-muted">Demo only: sends simulated attack traffic through the real detection pipeline.</p>
          {scenarios.data?.map((scenario) => (
            <button
              key={scenario.id}
              role="menuitem"
              type="button"
              onClick={() => void run(scenario.id)}
              className="block w-full rounded-md px-2.5 py-2 text-left hover:bg-raised focus:bg-raised"
            >
              <span className="flex items-center justify-between gap-2 text-sm font-medium text-fg">
                {scenario.name}
                <span className="font-mono text-[11px] text-faint">{scenario.expectedRules.join(' ')}</span>
              </span>
              <span className="mt-0.5 block text-xs text-muted">{scenario.description}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
