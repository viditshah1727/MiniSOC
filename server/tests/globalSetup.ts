// Runs once before the whole suite: bring the test database schema up to date.
// `prisma migrate deploy` creates the database if needed and only applies
// pending migrations (it never drops data).
import { execSync } from 'node:child_process';
import { assertIsTestDatabase, getTestDatabaseUrl } from './testDatabase.js';

export default function setup() {
  const databaseUrl = getTestDatabaseUrl();
  assertIsTestDatabase(databaseUrl);

  execSync('npx prisma migrate deploy', {
    env: { ...process.env, DATABASE_URL: databaseUrl },
    stdio: 'pipe',
  });
}
