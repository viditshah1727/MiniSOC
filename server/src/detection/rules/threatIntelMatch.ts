// R006: an internal host talks to (or downloads) a known-malicious indicator:
// an outbound connection to a bad IP, a DNS lookup of a bad domain, or a
// downloaded file whose hash is known malware.
// Inbound traffic FROM bad IPs is covered by the other rules; there, threat
// intel raises the alert's risk score instead.
import { prisma } from '../../db.js';
import type { IndicatorType } from '../../generated/prisma/enums.js';
import { normalizeIndicator } from '../../services/threatIntelService.js';
import { readMetadataString } from '../helpers.js';
import type { DetectionRuleDefinition } from '../types.js';

const DEFAULT_MIN_CONFIDENCE = 70; // "threshold": ignore low-confidence intel

interface Observable {
  type: IndicatorType;
  value: string;
  title: string; // e.g. "Lookup of malicious domain x.example"
  action: string; // completes "<host> ... <indicator>"
  mitreTechniqueId: string;
}

export const threatIntelMatch: DetectionRuleDefinition = {
  code: 'R006',
  name: 'Threat Intelligence Match',
  description: `Outbound connection, DNS lookup or file download that matches a MALICIOUS indicator with at least ${DEFAULT_MIN_CONFIDENCE}% confidence.`,
  severity: 'HIGH',
  mitreTechniqueIds: ['T1071', 'T1105'],
  defaults: { threshold: DEFAULT_MIN_CONFIDENCE, windowMinutes: null },
  thresholdLabel: 'minimum intel confidence (%)',
  eventTypes: ['NETWORK_CONNECTION', 'DNS_QUERY', 'FILE_DOWNLOAD'],
  recommendedSteps: [
    'Identify the process and user on the host that generated the traffic or download.',
    'Check how often the host contacted the indicator (one-off, or regular beaconing?).',
    'For a file hash match: locate the file, quarantine it and scan the host.',
    'Block the indicator at the firewall, DNS resolver or proxy.',
    'If malware or command-and-control is confirmed: isolate the host and escalate to an incident.',
  ],

  async evaluate(event, settings) {
    const minConfidence = settings.threshold ?? DEFAULT_MIN_CONFIDENCE;

    const observables: Observable[] = [];
    if (event.eventType === 'NETWORK_CONNECTION' && event.destinationIp) {
      const ip = event.destinationIp;
      observables.push({ type: 'IP', value: ip, title: `Outbound connection to malicious IP ${ip}`, action: 'connected to', mitreTechniqueId: 'T1071' });
    }
    const domain = readMetadataString(event, 'domain');
    if (domain) {
      const isLookup = event.eventType === 'DNS_QUERY';
      observables.push({
        type: 'DOMAIN',
        value: domain,
        title: `${isLookup ? 'Lookup of' : 'Traffic to'} malicious domain ${normalizeIndicator(domain)}`,
        action: isLookup ? 'looked up the domain' : 'exchanged traffic with the domain',
        mitreTechniqueId: 'T1071',
      });
    }
    const sha256 = readMetadataString(event, 'sha256');
    if (sha256) {
      const fileName = readMetadataString(event, 'fileName');
      observables.push({
        type: 'HASH',
        value: sha256,
        title: `Malicious file downloaded${fileName ? ` (${fileName})` : ''}`,
        action: 'downloaded a file with the known-malware hash',
        mitreTechniqueId: 'T1105',
      });
    }
    if (observables.length === 0) return null;

    const matches = await prisma.threatIntelligence.findMany({
      where: {
        reputation: 'MALICIOUS',
        confidence: { gte: minConfidence },
        OR: observables.map((o) => ({ type: o.type, indicator: normalizeIndicator(o.value) })),
      },
      orderBy: { confidence: 'desc' },
    });
    const intel = matches[0];
    if (!intel) return null;

    const observable = observables.find(
      (o) => o.type === intel.type && normalizeIndicator(o.value) === intel.indicator,
    );
    const host = event.hostname ?? event.sourceIp ?? 'unknown host';

    return {
      title: `${observable?.title ?? `Known malicious ${intel.type} ${intel.indicator}`} on ${host}`,
      description:
        `${host} ${observable?.action ?? 'matched'} ${intel.indicator}, which threat intelligence lists as ` +
        `MALICIOUS (${intel.confidence}% confidence, source: ${intel.source}).`,
      dedupKey: `ioc:${intel.indicator}|host:${host}`,
      evidenceEventIds: [],
      evidence: {
        indicator: intel.indicator,
        indicatorType: intel.type,
        confidence: intel.confidence,
        intelSource: intel.source,
        minimumConfidence: minConfidence,
        observedIn: event.eventType,
      },
      mitreTechniqueId: observable?.mitreTechniqueId,
      threatIntelId: intel.id,
    };
  },
};
