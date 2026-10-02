// Tests run against a separate PostgreSQL database: <your database>_test.
// Override with TEST_DATABASE_URL if you need something different.
try {
  process.loadEnvFile();
} catch {
  // no .env file
}

export function getTestDatabaseUrl(): string {
  if (process.env.TEST_DATABASE_URL) return process.env.TEST_DATABASE_URL;

  const url = new URL(process.env.DATABASE_URL ?? 'postgresql://minisoc:minisoc@localhost:5432/minisoc');
  url.pathname = `${url.pathname.replace(/^\//, '')}_test`;
  return url.toString();
}

/** Safety net: the suite truncates tables, so never point it at a real database. */
export function assertIsTestDatabase(databaseUrl: string): void {
  if (!new URL(databaseUrl).pathname.endsWith('_test')) {
    throw new Error(`Refusing to run tests: database name must end with "_test" (got ${databaseUrl})`);
  }
}
