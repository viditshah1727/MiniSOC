// Prisma CLI configuration (used by `prisma migrate`, `prisma generate`, ...).
// Prisma 7 no longer reads .env files by itself, so load it with Node's
// built-in loader. Variables already set in the environment take precedence.
import { defineConfig } from 'prisma/config';

try {
  process.loadEnvFile();
} catch {
  // No .env file: rely on variables from the real environment (CI, Docker, ...).
}

export default defineConfig({
  schema: 'prisma/schema.prisma',
  migrations: {
    path: 'prisma/migrations',
    seed: 'tsx prisma/seed/index.ts',
  },
  datasource: {
    url: process.env.DATABASE_URL,
  },
});
