import { Briefcase, Crosshair, KeyRound, LogIn, Radar, ScrollText, Siren, Workflow } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router';
import { ApiError } from '../api/client';
import { Logo } from '../components/layout/Logo';
import { Button } from '../components/ui/Button';
import { useAuth } from '../context/AuthContext';

const CAPABILITIES = [
  { icon: ScrollText, title: 'Event monitoring', text: 'Authentication, network, process, DNS and download telemetry in one place.' },
  { icon: Workflow, title: 'Detection engineering', text: 'Deterministic correlation rules with tunable thresholds and time windows.' },
  { icon: Siren, title: 'Alert investigation', text: 'Every alert explains why it fired, how it was scored and what to check next.' },
  { icon: Briefcase, title: 'Incident response', text: 'Escalate alerts into cases with owners, notes and a full timeline.' },
  { icon: Radar, title: 'Threat intelligence', text: 'Known-bad IPs, domains and file hashes enrich every detection.' },
  { icon: Crosshair, title: 'MITRE ATT&CK', text: 'Detections mapped to techniques, with coverage gaps made visible.' },
];

export default function LoginPage() {
  const { session, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const returnTo = (location.state as { from?: string } | null)?.from ?? '/dashboard';
  if (session) return <Navigate to={returnTo} replace />;

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(email, password);
      navigate(returnTo, { replace: true });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Sign-in failed. Please try again.');
      setSubmitting(false);
    }
  }

  return (
    <div className="grid min-h-full lg:grid-cols-[1.1fr_1fr]">
      <section className="hidden flex-col justify-between border-r border-line bg-surface p-10 lg:flex">
        <div className="flex items-center gap-3">
          <Logo className="size-10" />
          <div>
            <p className="text-lg leading-tight font-semibold">
              Mini<span className="text-accent">SOC</span>
            </p>
            <p className="text-sm text-muted">Lightweight Security Operations Center Platform</p>
          </div>
        </div>

        <ul className="grid max-w-2xl grid-cols-2 gap-x-8 gap-y-7">
          {CAPABILITIES.map(({ icon: Icon, title, text }) => (
            <li key={title}>
              <Icon aria-hidden className="mb-2 size-5 text-accent" />
              <p className="text-sm font-medium text-fg">{title}</p>
              <p className="mt-1 text-sm text-muted">{text}</p>
            </li>
          ))}
        </ul>

        <p className="text-xs text-faint">Demo environment · all IP addresses and domains are reserved documentation ranges</p>
      </section>

      <section className="flex items-center justify-center px-4 py-12">
        <div className="w-full max-w-sm">
          <div className="mb-8 flex items-center gap-3 lg:hidden">
            <Logo className="size-9" />
            <p className="text-lg font-semibold">
              Mini<span className="text-accent">SOC</span>
            </p>
          </div>

          <h1 className="text-2xl font-semibold">Sign in</h1>
          <p className="mt-1 text-sm text-muted">Access the analyst console.</p>

          <form onSubmit={(event) => void handleSubmit(event)} className="mt-8 space-y-4" noValidate>
            <div>
              <label htmlFor="email" className="field-label">
                Email
              </label>
              <input
                id="email"
                type="email"
                autoComplete="username"
                required
                autoFocus
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                className="field"
                placeholder="analyst@minisoc.local"
              />
            </div>
            <div>
              <label htmlFor="password" className="field-label">
                Password
              </label>
              <input
                id="password"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                className="field"
              />
            </div>

            {error && (
              <p role="alert" className="rounded-md border border-sev-critical/40 bg-sev-critical/10 px-3 py-2 text-sm text-fg">
                {error}
              </p>
            )}

            <Button type="submit" variant="primary" icon={LogIn} loading={submitting} disabled={!email || !password} className="w-full">
              Sign in
            </Button>
          </form>

          <div className="mt-8 rounded-lg border border-line bg-surface p-4 text-xs text-muted">
            <p className="mb-2 flex items-center gap-1.5 font-medium text-fg">
              <KeyRound aria-hidden className="size-3.5 text-accent" />
              Demo accounts
            </p>
            <ul className="space-y-1 font-mono text-[12px]">
              <li>admin@minisoc.local (Admin)</li>
              <li>analyst@minisoc.local (Analyst)</li>
              <li>viewer@minisoc.local (read-only)</li>
            </ul>
            <p className="mt-2">Password: the SEED_DEMO_PASSWORD value in server/.env</p>
          </div>
        </div>
      </section>
    </div>
  );
}
