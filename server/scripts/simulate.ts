// DEMO ONLY. Acts like a log shipper: builds a simulated attack locally and
// POSTs every event to a RUNNING MiniSOC API (POST /api/events), printing any
// alert the detection engine raises. Open the dashboard to watch it live.
//
//   npm run simulate                      list scenarios
//   npm run simulate -- ssh-brute-force   run one
//
// Logs in as the demo analyst (password: SEED_DEMO_PASSWORD from server/.env).
import { SCENARIO_IDS, SCENARIOS, type ScenarioId } from '../src/simulation/scenarios.js';

try {
  process.loadEnvFile();
} catch {
  // no .env file
}

const API = process.env.MINISOC_API_URL ?? `http://localhost:${process.env.PORT ?? 4000}`;
const EMAIL = process.env.SIMULATE_EMAIL ?? 'analyst@minisoc.local';
const PASSWORD = process.env.SEED_DEMO_PASSWORD ?? '';

async function login(): Promise<string> {
  const res = await fetch(`${API}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  });
  if (!res.ok) throw new Error(`Login failed (${res.status}). Is the API running and the database seeded?`);
  const cookie = res.headers.getSetCookie().find((c) => c.startsWith('minisoc_session='));
  if (!cookie) throw new Error('Login did not return a session cookie');
  return cookie.split(';')[0]!;
}

async function main() {
  const scenarioId = process.argv[2] as ScenarioId | undefined;
  if (!scenarioId || !SCENARIO_IDS.includes(scenarioId)) {
    console.log('Usage: npm run simulate -- <scenario>\n');
    for (const scenario of SCENARIOS) {
      console.log(`  ${scenario.id.padEnd(24)} ${scenario.description} [${scenario.expectedRules.join(', ')}]`);
    }
    process.exitCode = scenarioId ? 1 : 0;
    return;
  }

  const cookie = await login();
  const scenario = SCENARIOS.find((s) => s.id === scenarioId)!;
  const events = scenario.build(Math.random, new Date());
  console.log(`Sending ${events.length} events for "${scenario.name}" to ${API} ...\n`);

  let alertCount = 0;
  for (const event of events) {
    const res = await fetch(`${API}/api/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookie },
      body: JSON.stringify(event),
    });
    const body = (await res.json()) as {
      success: boolean;
      message?: string;
      data?: { alerts: { severity: string; riskScore: number; title: string; rule: { code: string } }[] };
    };
    if (!res.ok || !body.data) throw new Error(`Event rejected (${res.status}): ${body.message}`);

    console.log(`  ${event.eventType.padEnd(18)} ${String(event.sourceIp ?? '-').padEnd(15)} ${event.message.slice(0, 70)}`);
    for (const alert of body.data.alerts) {
      alertCount++;
      console.log(`  >> ALERT ${alert.rule.code} ${alert.severity} (risk ${alert.riskScore}): ${alert.title}`);
    }
  }
  console.log(`\nDone: ${events.length} events, ${alertCount} alert(s).`);
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
