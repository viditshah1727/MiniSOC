// Minimal CSV writer (RFC 4180 quoting) with protection against CSV formula
// injection (CWE-1236): a cell such as `=HYPERLINK(...)` would be executed by
// Excel/Sheets when an analyst opens the export. Many exported fields
// (usernames, commands, log messages) come straight from attacker-controlled
// logs, so text starting with = + - @ (or a tab/CR) is prefixed with `'`.
const FORMULA_TRIGGER = /^[=+\-@\t\r]/;

export function csvCell(value: unknown): string {
  if (value === null || value === undefined) return '';
  let text = value instanceof Date ? value.toISOString() : String(value);
  if (typeof value === 'string' && FORMULA_TRIGGER.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export function toCsv(headers: string[], rows: unknown[][]): string {
  return [headers, ...rows].map((row) => row.map(csvCell).join(',')).join('\r\n') + '\r\n';
}
