// DEMO ONLY. Generates attack traffic and pushes it through the real
// ingestion pipeline, exactly as if a log shipper had sent it.
import { type ScenarioId, getScenario, SCENARIOS } from '../simulation/scenarios.js';
import { ingestEvent } from './eventService.js';

export function listScenarios() {
  return SCENARIOS.map(({ id, name, description, expectedRules }) => ({ id, name, description, expectedRules }));
}

export async function runScenario(id: ScenarioId) {
  const scenario = getScenario(id);
  const events = scenario.build(Math.random, new Date());

  const alerts = [];
  for (const event of events) {
    const result = await ingestEvent(event); // same path as POST /api/events
    alerts.push(...result.alerts);
  }

  return {
    scenario: { id: scenario.id, name: scenario.name },
    eventsIngested: events.length,
    alerts: alerts.map((alert) => ({
      id: alert.id,
      title: alert.title,
      severity: alert.severity,
      riskScore: alert.riskScore,
      rule: alert.rule,
    })),
  };
}
