import { beforeEach, describe, expect, it } from 'vitest';
import { ingestEvent } from '../src/services/eventService.js';
import { csvCell, toCsv } from '../src/utils/csv.js';
import { buildApp, loginAs, minutesAgo, resetDatabase, sshFailure, sshSuccess } from './helpers.js';

const app = buildApp();

describe('csv utility', () => {
  it('quotes commas, quotes and newlines (RFC 4180)', () => {
    expect(csvCell('plain')).toBe('plain');
    expect(csvCell('a,b')).toBe('"a,b"');
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
    expect(csvCell('line1\nline2')).toBe('"line1\nline2"');
    expect(csvCell(null)).toBe('');
    expect(csvCell(new Date('2026-01-02T03:04:05Z'))).toBe('2026-01-02T03:04:05.000Z');
  });

  it('neutralises spreadsheet formulas in text (CSV injection)', () => {
    expect(csvCell('=HYPERLINK("http://evil.example")')).toBe(`"'=HYPERLINK(""http://evil.example"")"`);
    expect(csvCell('+cmd')).toBe("'+cmd");
    expect(csvCell('@SUM(A1)')).toBe("'@SUM(A1)");
    expect(csvCell(-5)).toBe('-5'); // real numbers are left alone
  });

  it('builds a document with a header row and CRLF line endings', () => {
    expect(toCsv(['a', 'b'], [[1, 'x']])).toBe('a,b\r\n1,x\r\n');
  });
});

describe('CSV report endpoints', () => {
  beforeEach(async () => {
    await resetDatabase();
    for (let i = 0; i < 5; i++) {
      // An attacker-controlled username that is also an Excel formula.
      await ingestEvent(sshFailure('203.0.113.45', '=cmd|/c calc', minutesAgo(10 - i)));
    }
    await ingestEvent(sshSuccess('203.0.113.45', 'deploy', minutesAgo(4)));
  });

  it('exports alerts as a downloadable CSV that honours the list filters', async () => {
    const agent = await loginAs(app, 'VIEWER');
    const res = await agent.get('/api/reports/alerts.csv?severity=CRITICAL').expect(200);

    expect(res.headers['content-type']).toContain('text/csv');
    expect(res.headers['content-disposition']).toMatch(/attachment; filename="minisoc-alerts-\d{4}-\d{2}-\d{2}\.csv"/);
    const lines = res.text.trim().split('\r\n');
    expect(lines[0]).toBe('id,detected_at,severity,risk_score,risk_level,status,rule,title,source_ip,hostname,username,mitre_technique,incident_id');
    expect(lines).toHaveLength(2); // header + the single CRITICAL alert (R005)
    expect(lines[1]).toContain('R005 Brute Force Followed by Successful Login');
  });

  it('exports events with formula-injection protection', async () => {
    const agent = await loginAs(app, 'VIEWER');
    const res = await agent.get('/api/reports/events.csv?eventType=AUTH_FAILURE').expect(200);
    const lines = res.text.trim().split('\r\n');

    expect(lines).toHaveLength(6);
    expect(res.text).toContain("'=cmd|/c calc");
    expect(res.text).not.toMatch(/,=cmd/);
  });

  it('exports an incident summary with time to resolve', async () => {
    const agent = await loginAs(app, 'ANALYST');
    const alerts = (await agent.get('/api/alerts').expect(200)).body.data;
    const created = await agent.post('/api/incidents').send({ alertIds: [alerts[0].id] }).expect(201);
    await agent.patch(`/api/incidents/${created.body.data.id}`).send({ status: 'RESOLVED' }).expect(200);

    const res = await agent.get('/api/reports/incidents.csv').expect(200);
    const [header, row] = res.text.trim().split('\r\n');
    expect(header).toBe('id,title,severity,status,assignee,alert_count,created_at,resolved_at,hours_to_resolve');
    expect(row).toMatch(/,RESOLVED,Test Analyst,1,.*,0\.0$/);
  });
});
