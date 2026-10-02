// Replays a week of analyst work on the seeded alerts, using the same service
// functions the API uses: triage, false positives, incidents, notes.
// Each step is stamped with the (historical) time it "happened".
import { prisma } from '../../src/db.js';
import { updateAlert } from '../../src/services/alertService.js';
import { addIncidentNote, createIncident, updateIncident } from '../../src/services/incidentService.js';
import { KNOWN_ATTACKERS, UNKNOWN_ATTACKERS, VULN_SCANNER } from '../../src/simulation/environment.js';
import type { AuthUser } from '../../src/types/express.js';

export interface Team {
  alex: AuthUser; // admin
  jordan: AuthUser; // analyst
  sam: AuthUser; // analyst
}

const MINUTE = 60_000;

/** Runs an action, then back-dates every timeline entry it wrote to `when`. */
async function at<T>(when: Date, action: () => Promise<T>): Promise<T> {
  const { _max } = await prisma.activity.aggregate({ _max: { id: true } });
  const result = await action();
  await prisma.activity.updateMany({ where: { id: { gt: _max.id ?? 0 } }, data: { createdAt: when } });
  return result;
}

const after = (date: Date, minutes: number) => new Date(date.getTime() + minutes * MINUTE);

function findAlert(ruleCode: string, where: { sourceIp?: string; username?: string; hostname?: string }, newest = false) {
  return prisma.alert.findFirstOrThrow({
    where: { rule: { code: ruleCode }, ...where },
    orderBy: { detectedAt: newest ? 'desc' : 'asc' },
  });
}

export async function replayAnalystWork(team: Team, now: Date): Promise<void> {
  // 6 days ago: internet-wide scanner. Triaged and closed.
  const massScan = await findAlert('R002', { sourceIp: KNOWN_ATTACKERS.massScanner });
  await at(after(massScan.detectedAt, 35), () =>
    updateAlert(massScan.id, { status: 'RESOLVED', note: 'Internet-wide scanner. Only 22 and 443 are exposed; source blocked at the edge firewall.' }, team.jordan),
  );

  // 5 days ago: credential stuffing. Incident, contained, closed.
  const stuffing = await findAlert('R001', { sourceIp: KNOWN_ATTACKERS.credentialStuffer });
  const stuffingIncident = await at(after(stuffing.detectedAt, 20), () =>
    createIncident({ alertIds: [stuffing.id], title: 'Credential stuffing against bastion-01' }, team.jordan),
  );
  await at(after(stuffing.detectedAt, 55), () =>
    addIncidentNote(stuffingIncident.id, 'No successful logins from the source. Password logins disabled on bastion-01; SSH keys now required.', team.jordan),
  );
  await at(after(stuffing.detectedAt, 5 * 60), () => updateIncident(stuffingIncident.id, { status: 'RESOLVED' }, team.jordan));
  await at(after(stuffing.detectedAt, 26 * 60), () => updateIncident(stuffingIncident.id, { status: 'CLOSED' }, team.alex));

  // 4 days ago: the authorised vulnerability scanner. A false positive.
  const vulnScan = await findAlert('R002', { sourceIp: VULN_SCANNER.ip });
  await at(after(vulnScan.detectedAt, 15), () =>
    updateAlert(vulnScan.id, { status: 'FALSE_POSITIVE', note: 'Weekly authorised vulnerability scan (change CHG-2291). Scanner is listed as BENIGN in threat intel.' }, team.sam),
  );

  // 3 days ago: slow brute force from an unknown IP. Investigated, resolved.
  const slowBruteForce = await findAlert('R001', { sourceIp: UNKNOWN_ATTACKERS[0]! });
  await at(after(slowBruteForce.detectedAt, 25), () => updateAlert(slowBruteForce.id, { status: 'INVESTIGATING' }, team.sam));
  await at(after(slowBruteForce.detectedAt, 50), () =>
    updateAlert(slowBruteForce.id, { status: 'RESOLVED', note: 'No successful authentication from this source. Added to the fail2ban blocklist.' }, team.sam),
  );

  // 3 days ago: mgarcia's VPN login from a residential proxy. Still being checked.
  const mgarciaLogin = await findAlert('R003', { username: 'mgarcia' });
  await at(after(mgarciaLogin.detectedAt, 40), () =>
    updateAlert(mgarciaLogin.id, { status: 'INVESTIGATING', note: 'User is travelling. Confirming the device with IT before closing.' }, team.jordan),
  );

  // 2 days ago: the web-01 intrusion. Major incident, resolved the next day.
  const intrusionStart = new Date(now.getTime() - 3 * 24 * 60 * MINUTE);
  const intrusionEnd = new Date(now.getTime() - 24 * 60 * MINUTE);
  const intrusionAlerts = await prisma.alert.findMany({
    where: {
      detectedAt: { gte: intrusionStart, lte: intrusionEnd },
      OR: [{ sourceIp: KNOWN_ATTACKERS.bruteForceBotnet }, { hostname: 'web-01', rule: { code: { in: ['R004', 'R006'] } } }],
    },
    orderBy: { detectedAt: 'asc' },
  });
  const firstIntrusionAlert = intrusionAlerts[0]!.detectedAt;
  const intrusion = await at(after(firstIntrusionAlert, 30), () =>
    createIncident({ alertIds: intrusionAlerts.map((alert) => alert.id), title: 'Compromise of the deploy account on web-01' }, team.jordan),
  );
  await at(after(firstIntrusionAlert, 45), () => updateIncident(intrusion.id, { status: 'INVESTIGATING' }, team.jordan));
  await at(after(firstIntrusionAlert, 70), () =>
    addIncidentNote(intrusion.id, 'Attacker guessed the deploy password, escalated to root and installed a dropper that beacons to update-check.example.', team.jordan),
  );
  await at(after(firstIntrusionAlert, 95), () =>
    addIncidentNote(intrusion.id, 'Containment: web-01 isolated, deploy account disabled, C2 domain and IP blocked at DNS and firewall.', team.sam),
  );
  await at(after(firstIntrusionAlert, 18 * 60), () =>
    addIncidentNote(intrusion.id, 'Eradication: web-01 rebuilt from a clean image. deploy now authenticates with an SSH key from the CI vault only.', team.jordan),
  );
  await at(after(firstIntrusionAlert, 20 * 60), () => updateIncident(intrusion.id, { status: 'RESOLVED' }, team.jordan));

  // Yesterday: tnguyen joined the sudo group. Incident under investigation.
  const groupChange = await findAlert('R004', { username: 'tnguyen' });
  const groupIncident = await at(after(groupChange.detectedAt, 25), () =>
    createIncident({ alertIds: [groupChange.id], title: 'Unauthorised admin-group change on app-01', assigneeId: team.sam.id }, team.alex),
  );
  await at(after(groupChange.detectedAt, 40), () => updateIncident(groupIncident.id, { status: 'INVESTIGATING' }, team.sam));
  await at(after(groupChange.detectedAt, 65), () =>
    addIncidentNote(groupIncident.id, 'User says a colleague asked them to fix a deployment. Checking with the team lead; sudo membership removed meanwhile.', team.sam),
  );

  // Yesterday: EICAR test file. A false positive.
  const eicar = await findAlert('R006', { username: 'okim' });
  await at(after(eicar.detectedAt, 30), () =>
    updateAlert(eicar.id, { status: 'FALSE_POSITIVE', note: 'EICAR antivirus test file, downloaded during endpoint-protection validation (CHG-2304).' }, team.sam),
  );

  // Today: the credential stuffer is back. Being looked at.
  const stuffingAgain = await findAlert('R001', { sourceIp: KNOWN_ATTACKERS.credentialStuffer }, true);
  await at(after(stuffingAgain.detectedAt, 20), () =>
    updateAlert(stuffingAgain.id, { status: 'INVESTIGATING', note: 'Same source as last week (see incident "Credential stuffing against bastion-01"). Checking for successful logins.' }, team.jordan),
  );
  // Today: a workstation resolved a phishing domain. Incident opened, not solved yet.
  const phishing = await findAlert('R006', { hostname: 'ws-019' });
  const phishingIncident = await at(after(phishing.detectedAt, 18), () =>
    createIncident({ alertIds: [phishing.id], title: 'Phishing site visited from ws-019' }, team.jordan),
  );
  await at(after(phishing.detectedAt, 32), () =>
    addIncidentNote(phishingIncident.id, 'User reported a fake password-expiry email. Checking proxy logs for any form submission to the site.', team.jordan),
  );

  // Everything else from today stays OPEN: that is the analyst's queue
  // (including the jsmith compromise, left untouched for a live demo).
}

/** Makes row timestamps match the replayed history instead of the moment the seed ran. */
export async function alignTimestamps(): Promise<void> {
  await prisma.$executeRaw`UPDATE events SET created_at = "timestamp"`;
  await prisma.$executeRaw`UPDATE alerts SET created_at = detected_at`;
  await prisma.$executeRaw`
    UPDATE alerts a
    SET updated_at = COALESCE((SELECT max(created_at) FROM activities WHERE alert_id = a.id), a.detected_at)`;
  await prisma.$executeRaw`
    UPDATE incidents i
    SET created_at = t.first_at,
        updated_at = t.last_at,
        resolved_at = CASE WHEN i.status IN ('RESOLVED', 'CLOSED') THEN t.resolved_at ELSE NULL END
    FROM (
      SELECT incident_id,
             min(created_at) AS first_at,
             max(created_at) AS last_at,
             min(created_at) FILTER (
               WHERE type = 'STATUS_CHANGE' AND (message LIKE '% to RESOLVED' OR message LIKE '% to CLOSED')
             ) AS resolved_at
      FROM activities
      WHERE incident_id IS NOT NULL
      GROUP BY incident_id
    ) t
    WHERE i.id = t.incident_id`;
}
