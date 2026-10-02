// OPTIONAL: asks the server's AI assistant to explain this alert. Only shown
// when the server has an API key configured. The output is advice for the
// analyst; it never changes the alert, and the core SOC works without it.
import { Sparkles } from 'lucide-react';
import { type ReactNode, useState } from 'react';
import { ApiError } from '../../api/client';
import { api } from '../../api';
import { useAuth } from '../../context/AuthContext';
import type { AiAnalysis } from '../../types/api';
import { Button } from '../ui/Button';
import { Card, CardBody, CardHeader } from '../ui/Card';
import { Mono, Time } from '../ui/Primitives';

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section>
      <h3 className="mb-1 text-xs font-medium tracking-wide text-faint uppercase">{title}</h3>
      <div className="text-sm leading-relaxed text-fg">{children}</div>
    </section>
  );
}

export function AiAnalysisPanel({ alertId }: { alertId: number }) {
  const { canEdit } = useAuth();
  const [analysis, setAnalysis] = useState<AiAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function analyze() {
    setLoading(true);
    setError(null);
    try {
      setAnalysis(await api.alerts.analyze(alertId));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The AI assistant is unavailable right now.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card>
      <CardHeader
        title="AI analyst (optional)"
        subtitle="A second opinion in plain language. Advisory only: it cannot change anything."
        actions={
          canEdit && (
            <Button size="sm" icon={Sparkles} loading={loading} onClick={() => void analyze()}>
              {analysis ? 'Analyze again' : 'Analyze with AI'}
            </Button>
          )
        }
      />
      <CardBody>
        {error && (
          <p role="alert" className="text-sm text-sev-critical">
            {error}
          </p>
        )}
        {!analysis && !error && (
          <p className="text-sm text-muted">
            {loading
              ? 'Analyzing the alert and its evidence. This usually takes 10 to 30 seconds...'
              : 'Sends this alert, its evidence and its context to Claude for a summary, likely attacker behaviour and next steps.'}
          </p>
        )}
        {analysis && (
          <div className="space-y-4">
            <Section title="Summary">{analysis.summary}</Section>
            <Section title="Why it fired">{analysis.explanation}</Section>
            <Section title="Likely attack behaviour">{analysis.likelyAttackBehavior}</Section>
            <Section title="MITRE ATT&CK">
              <Mono className="text-accent">{analysis.mitreTechnique.id}</Mono> {analysis.mitreTechnique.name}
              <p className="mt-0.5 text-muted">{analysis.mitreTechnique.rationale}</p>
            </Section>
            <Section title="Suggested next steps">
              <ol className="list-decimal space-y-1 pl-5">
                {analysis.investigationSteps.map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ol>
            </Section>
            <p className="border-t border-line pt-3 text-xs text-faint">
              Confidence: {analysis.confidence.toLowerCase()} · {analysis.model} · <Time iso={analysis.generatedAt} relative />. AI output can
              be wrong: verify it against the evidence before acting.
            </p>
          </div>
        )}
      </CardBody>
    </Card>
  );
}
