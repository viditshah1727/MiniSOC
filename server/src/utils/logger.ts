// Minimal structured logger: timestamp + level + message (+ details).
// Kept dependency-free on purpose; swap for pino/winston if logs must be shipped.
type Level = 'debug' | 'info' | 'warn' | 'error';

const quietInTests = process.env.NODE_ENV === 'test';

function write(level: Level, message: string, details?: unknown): void {
  if (quietInTests && level !== 'error') return;
  const line = `${new Date().toISOString()} ${level.toUpperCase().padEnd(5)} ${message}`;
  const output = level === 'error' ? console.error : level === 'warn' ? console.warn : console.log;
  if (details === undefined) output(line);
  else output(line, details);
}

export const logger = {
  debug: (message: string, details?: unknown) => write('debug', message, details),
  info: (message: string, details?: unknown) => write('info', message, details),
  warn: (message: string, details?: unknown) => write('warn', message, details),
  error: (message: string, details?: unknown) => write('error', message, details),
};
