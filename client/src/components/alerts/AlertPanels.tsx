// The panels of the alert investigation page. Each one answers a question
// an analyst asks: why did this fire, how bad is it, who/what is involved,
// which ATT&CK technique is it, what does threat intel say, what do I do next?
import { ExternalLink, ListChecks, Radar } from 'lucide-react';
import type { AlertDetail } from '../../types/api';
import { formatDate, formatMinutes, formatNumber, humanizeKey } from '../../utils/format';
import { EVENT_TYPE_LABEL, INDICATOR_TYPE_LABEL, SEVERITY_LABEL } from '../../utils/labels';
import { ReputationBadge, RuleCode, SeverityBadge } from '../ui/Badges';
import { Card, CardBody, CardHeader } from '../ui/Card';
import { KeyValueList, Mono, Time } from '../ui/Primitives';
import { RiskMeter } from '../ui/RiskMeter';

function formatEvidenceValue(value: unknown): string {
  if (Array.isArray(value)) return value.join(', ');
  if (typeof value === 'number') return formatNumber(value);
  return String(value);
}

export function WhyItFiredPanel({ alert }: { alert: AlertDetail }) {
  const { rule } = alert;
  const settings = [
    rule.threshold !== null && `threshold ${rule.threshold}`,
    rule.windowMinutes !== null && `window ${formatMinutes(rule.windowMinutes)}`,
  ].filter(Boolean);

  return (
    <Card>
      <CardHeader title="Why this alert fired" subtitle="The rule's condition and the evidence that satisfied it" />
      <CardBody className="space-y-4">
        <p className="rounded-md border-l-2 border-sev-high bg-raised px-4 py-3 text-[15px] leading-relaxed text-fg">
          {alert.description}
        </p>
        <div>
          <p className="mb-1.5 flex flex-wrap items-center gap-2 text-sm">
            <RuleCode code={rule.code} />
            <span className="font-medium text-fg">{rule.name}</span>
            {settings.length > 0 && <span className="text-xs text-faint">({settings.join(', ')})</span>}
          </p>
          <p className="text-sm text-muted">{rule.description}</p>
        </div>
        <div>
          <h3 className="mb-2 text-xs font-medium tracking-wide text-faint uppercase">Evidence measured by the rule</h3>
          <KeyValueList items={Object.entries(alert.evidence).map(([key, value]) => [humanizeKey(key), formatEvidenceValue(value)])} />
        </div>
      </CardBody>
    </Card>
  );
}

export function RiskPanel({ alert }: { alert: AlertDetail }) {
  return (
    <Card>
      <CardHeader title="Risk score" subtitle="How the score was calculated" actions={<SeverityBadge severity={alert.riskLevel} label={`${SEVERITY_LABEL[alert.riskLevel]} risk`} />} />
      <CardBody className="space-y-4">
        <div className="flex items-end gap-3">
          <span className="text-4xl leading-none font-semibold text-fg">{alert.riskScore}</span>
          <span className="pb-0.5 text-sm text-faint">/ 100</span>
        </div>
        <RiskMeter score={alert.riskScore} level={alert.riskLevel} size="lg" showValue={false} />
        <ul className="divide-y divide-line text-sm">
          {alert.riskFactors.map((factor) => (
            <li key={factor.label} className="flex items-start justify-between gap-3 py-2">
              <span className="text-muted">{factor.label}</span>
              <span className="tabular font-medium text-fg">
                {factor.points > 0 ? '+' : ''}
                {factor.points}
              </span>
            </li>
          ))}
        </ul>
        <p className="text-xs text-faint">Base score by severity, +10 per risk modifier, capped at 100.</p>
      </CardBody>
    </Card>
  );
}

export function EntitiesPanel({ alert }: { alert: AlertDetail }) {
  const { event } = alert;
  return (
    <Card>
      <CardHeader title="Involved entities" />
      <CardBody>
        <KeyValueList
          items={[
            [
              'Source IP',
              alert.sourceIp && (
                <span key="ip" className="flex flex-wrap items-center gap-2">
                  <Mono>{alert.sourceIp}</Mono>
                  {alert.threatIntel?.type === 'IP' && alert.threatIntel.indicator === alert.sourceIp && (
                    <ReputationBadge reputation={alert.threatIntel.reputation} />
                  )}
                </span>
              ),
            ],
            ['Target host', alert.hostname],
            [
              'Destination',
              event.destinationIp && (
                <Mono key="dst">
                  {event.destinationIp}
                  {event.destinationPort !== null && `:${event.destinationPort}`}
                </Mono>
              ),
            ],
            ['Account', alert.username && <Mono key="user">{alert.username}</Mono>],
            ['Trigger event', `${EVENT_TYPE_LABEL[event.eventType]} (${event.source})`],
            ['Detected', <Time key="detected" iso={alert.detectedAt} />],
            ['Last update', <Time key="updated" iso={alert.updatedAt} />],
          ]}
        />
      </CardBody>
    </Card>
  );
}

export function MitrePanel({ alert }: { alert: AlertDetail }) {
  const technique = alert.mitreTechnique;
  const others = alert.rule.techniques.filter((t) => t.id !== technique?.id);

  return (
    <Card>
      <CardHeader title="MITRE ATT&CK" subtitle="What the attacker is trying to do" />
      <CardBody className="space-y-3">
        {technique ? (
          <>
            <div>
              <a
                href={`https://attack.mitre.org/techniques/${technique.id.replace('.', '/')}/`}
                target="_blank"
                rel="noreferrer noopener"
                className="group inline-flex items-center gap-1.5 font-medium text-fg hover:text-accent"
              >
                <Mono className="text-accent">{technique.id}</Mono>{' '}
                {technique.name}
                <ExternalLink aria-label="(opens attack.mitre.org)" className="size-3.5 text-faint group-hover:text-accent" />
              </a>
              <div className="mt-1.5 flex flex-wrap gap-1.5">
                {technique.tactics.map((tactic) => (
                  <span key={tactic} className="rounded bg-raised px-1.5 py-0.5 text-[11px] text-muted ring-1 ring-line ring-inset">
                    {tactic}
                  </span>
                ))}
              </div>
            </div>
            <p className="text-sm text-muted">{technique.description}</p>
          </>
        ) : (
          <p className="text-sm text-muted">No technique mapped.</p>
        )}
        {others.length > 0 && (
          <p className="text-xs text-faint">
            This rule also maps to:{' '}
            {others.map((t, i) => (
              <span key={t.id}>
                {i > 0 && ', '}
                <span className="font-mono text-muted">{t.id}</span> {t.name}
              </span>
            ))}
          </p>
        )}
      </CardBody>
    </Card>
  );
}

export function ThreatIntelPanel({ alert }: { alert: AlertDetail }) {
  const intel = alert.threatIntel;
  return (
    <Card>
      <CardHeader title="Threat intelligence" subtitle="What we already know about the indicator" />
      <CardBody>
        {intel ? (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <Mono className="break-all text-fg">{intel.indicator}</Mono>
              <ReputationBadge reputation={intel.reputation} />
            </div>
            {intel.description && <p className="text-sm text-muted">{intel.description}</p>}
            <KeyValueList
              items={[
                ['Type', INDICATOR_TYPE_LABEL[intel.type]],
                ['Confidence', `${intel.confidence}%`],
                ['Source', intel.source],
                ['First seen', formatDate(intel.firstSeen)],
                ['Last seen', formatDate(intel.lastSeen)],
              ]}
            />
          </div>
        ) : (
          <p className="flex items-start gap-2 text-sm text-muted">
            <Radar aria-hidden className="mt-0.5 size-4 shrink-0 text-faint" />
            {alert.sourceIp ? (
              <span>
                No threat-intelligence record for <Mono>{alert.sourceIp}</Mono>. Unknown is not the same as safe.
              </span>
            ) : (
              'No indicator from this alert is in the threat-intelligence database.'
            )}
          </p>
        )}
      </CardBody>
    </Card>
  );
}

export function PlaybookPanel({ steps }: { steps: string[] }) {
  return (
    <Card>
      <CardHeader title="Recommended investigation" subtitle="Playbook for this detection rule" />
      <CardBody>
        <ol className="space-y-2.5 text-sm">
          {steps.map((step, index) => (
            <li key={step} className="flex gap-3">
              <span className="tabular flex size-5 shrink-0 items-center justify-center rounded-full bg-raised text-[11px] font-semibold text-muted ring-1 ring-line-strong">
                {index + 1}
              </span>
              <span className="text-fg">{step}</span>
            </li>
          ))}
        </ol>
        <p className="mt-4 flex items-center gap-1.5 text-xs text-faint">
          <ListChecks aria-hidden className="size-3.5" />
          Record what you find with "Add note" so the timeline stays complete.
        </p>
      </CardBody>
    </Card>
  );
}
