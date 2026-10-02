// The detection engine: evaluates every enabled rule against a newly stored
// event and turns each match into an alert.
//
//   event ─▶ rule.evaluate() ─▶ match? ─▶ duplicate? ─▶ threat intel ─▶ risk score ─▶ MITRE ─▶ alert
//
// Deterministic by design: the same events always produce the same alerts.
import { prisma } from '../db.js';
import type { DetectionRule, Event } from '../generated/prisma/client.js';
import { findIpIndicator } from '../services/threatIntelService.js';
import { publishLiveUpdate } from '../utils/liveUpdates.js';
import { logger } from '../utils/logger.js';
import {
  ALERT_SUPPRESSION_MINUTES,
  isPrivilegedAccount,
  minutesBefore,
  REPEATED_ACTIVITY_HOURS,
} from './constants.js';
import { distinct } from './helpers.js';
import { calculateRiskScore } from './riskScore.js';
import { getRuleDefinition } from './rules/index.js';
import type { DetectionRuleDefinition, RuleMatch } from './types.js';

export type RaisedAlert = Awaited<ReturnType<typeof raiseAlert>>;

/** Runs all enabled rules against one event; returns the alerts it raised. */
export async function runDetection(event: Event): Promise<RaisedAlert[]> {
  const enabledRules = await prisma.detectionRule.findMany({
    where: { enabled: true },
    orderBy: { code: 'asc' },
  });

  const alerts: RaisedAlert[] = [];
  for (const ruleRow of enabledRules) {
    const rule = getRuleDefinition(ruleRow.code);
    if (!rule || !rule.eventTypes.includes(event.eventType)) continue;

    try {
      const match = await rule.evaluate(event, {
        threshold: ruleRow.threshold,
        windowMinutes: ruleRow.windowMinutes,
      });
      if (!match) continue;
      if (await isDuplicate(ruleRow.id, match.dedupKey, event.timestamp)) continue;

      alerts.push(await raiseAlert(event, ruleRow, rule, match));
    } catch (error) {
      // One faulty rule must not stop the others; the event itself is already stored.
      logger.error(`Detection rule ${ruleRow.code} failed on event ${event.id}`, error);
    }
  }
  return alerts;
}

/** Alert suppression: one alert per rule and entity per hour, to avoid alert fatigue. */
async function isDuplicate(ruleId: number, dedupKey: string, at: Date): Promise<boolean> {
  const recent = await prisma.alert.findFirst({
    where: { ruleId, dedupKey, detectedAt: { gte: minutesBefore(at, ALERT_SUPPRESSION_MINUTES), lte: at } },
    select: { id: true },
  });
  return recent !== null;
}

/** "Repeated activity": did this source IP trigger any alert in the last 24 hours? */
async function hasRecentAlertFromSource(event: Event): Promise<boolean> {
  if (!event.sourceIp) return false;
  const recent = await prisma.alert.findFirst({
    where: {
      sourceIp: event.sourceIp,
      detectedAt: { gte: minutesBefore(event.timestamp, REPEATED_ACTIVITY_HOURS * 60), lte: event.timestamp },
    },
    select: { id: true },
  });
  return recent !== null;
}

async function raiseAlert(event: Event, ruleRow: DetectionRule, rule: DetectionRuleDefinition, match: RuleMatch) {
  // 1. Threat intelligence: the indicator the rule matched, otherwise the source IP's record.
  const intel =
    match.threatIntelId !== undefined
      ? await prisma.threatIntelligence.findUnique({ where: { id: match.threatIntelId } })
      : await findIpIndicator(event.sourceIp);

  // 2. Risk score, with the reasons behind it.
  const risk = calculateRiskScore({
    severity: ruleRow.severity,
    repeatedActivity: await hasRecentAlertFromSource(event),
    maliciousIndicator: intel?.reputation === 'MALICIOUS' ? intel.indicator : null,
    privilegedAccount: isPrivilegedAccount(event.username) ? event.username : null,
  });

  // 3. MITRE ATT&CK: the rule's primary technique unless the match is more specific.
  const mitreTechniqueId = match.mitreTechniqueId ?? rule.mitreTechniqueIds[0];

  // 4. Store the alert with its evidence and the first timeline entry.
  const evidenceEventIds = distinct([...match.evidenceEventIds, event.id]);
  const alert = await prisma.alert.create({
    data: {
      title: match.title,
      description: match.description,
      severity: ruleRow.severity,
      riskScore: risk.score,
      riskFactors: risk.factors,
      evidence: match.evidence,
      dedupKey: match.dedupKey,
      sourceIp: event.sourceIp,
      hostname: event.hostname,
      username: event.username,
      detectedAt: event.timestamp,
      ruleId: ruleRow.id,
      eventId: event.id,
      mitreTechniqueId,
      threatIntelId: intel?.id,
      evidenceEvents: { connect: evidenceEventIds.map((id) => ({ id })) },
      activities: {
        create: {
          type: 'CREATED',
          message: `Raised by ${ruleRow.code} ${ruleRow.name} (risk ${risk.score}/100)`,
          createdAt: event.timestamp,
        },
      },
    },
    include: { rule: { select: { code: true, name: true } } },
  });

  publishLiveUpdate({
    type: 'alert.created',
    id: alert.id,
    title: alert.title,
    severity: alert.severity,
    riskScore: alert.riskScore,
  });
  return alert;
}
