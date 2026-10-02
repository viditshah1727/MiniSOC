// The contract every detection rule implements.
import type { Event } from '../generated/prisma/client.js';
import type { EventType, Severity } from '../generated/prisma/enums.js';

/** Facts a rule measured, shown to the analyst as "why this fired". */
export type Evidence = Record<string, string | number | string[] | number[]>;

/** What a rule returns when its condition is met. */
export interface RuleMatch {
  title: string;
  /** Plain-language explanation of why the rule fired. */
  description: string;
  /** The entity the alert is about, used to suppress duplicates, e.g. "ip:203.0.113.45". */
  dedupKey: string;
  /** Events that together satisfied the condition (the trigger event is added automatically). */
  evidenceEventIds: number[];
  evidence: Evidence;
  /** Rare overrides of the rule's defaults. */
  mitreTechniqueId?: string;
  threatIntelId?: number;
}

/**
 * Tunables stored on the rule's database row, so they can be changed without a
 * deploy. `null` means the rule does not use that setting (or falls back to
 * its own default).
 */
export interface RuleSettings {
  threshold: number | null;
  windowMinutes: number | null;
}

export interface DetectionRuleDefinition {
  /** Links this code to its DetectionRule row, e.g. "R001". */
  code: string;
  name: string;
  description: string;
  severity: Severity;
  /** ATT&CK techniques this rule detects; the first is the alert's primary technique. */
  mitreTechniqueIds: string[];
  defaults: RuleSettings;
  /** What the threshold counts, for the rule settings UI (e.g. "failed logins"). */
  thresholdLabel?: string;
  /** Investigation playbook shown on the alert page. */
  recommendedSteps: string[];
  /** Only events of these types are evaluated (cheap pre-filter). */
  eventTypes: EventType[];
  evaluate(event: Event, settings: RuleSettings): Promise<RuleMatch | null>;
}
