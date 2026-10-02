import { defineConfig } from 'vitest/config';
import { getTestDatabaseUrl } from './tests/testDatabase.js';

export default defineConfig({
  test: {
    environment: 'node',
    globalSetup: ['./tests/globalSetup.ts'],
    // All test files share one database, so run them one at a time.
    fileParallelism: false,
    testTimeout: 20_000,
    hookTimeout: 60_000,
    // Let Node load Prisma's runtime directly. Otherwise Vitest re-transforms
    // its 4.5 MB query-compiler bundle for every test file (minutes of waiting).
    server: { deps: { external: [/@prisma[\\/]/] } },
    env: {
      NODE_ENV: 'test',
      DATABASE_URL: getTestDatabaseUrl(),
      JWT_SECRET: 'test-only-secret-that-is-at-least-32-characters-long',
      SESSION_HOURS: '8',
      BCRYPT_ROUNDS: '4', // minimum cost: fast tests (production default is 12)
      CORS_ORIGIN: 'http://localhost:5173',
      ENABLE_SIMULATION: 'true',
      ANTHROPIC_API_KEY: '',
    },
  },
});
