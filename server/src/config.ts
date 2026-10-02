// Loads and validates environment variables once, at startup.
// If anything required is missing or malformed, the server refuses to start
// with a clear message instead of failing later in a confusing way.
import { z } from 'zod';

try {
  process.loadEnvFile(); // reads server/.env; real environment variables win
} catch {
  // No .env file: rely on the real environment (CI, containers, ...).
}

export const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(4000),
  DATABASE_URL: z.string().min(1, 'is required'),
  JWT_SECRET: z.string().min(32, 'must be at least 32 characters'),
  SESSION_HOURS: z.coerce.number().positive().max(24).default(8),
  BCRYPT_ROUNDS: z.coerce.number().int().min(4).max(15).default(12), // tests use 4 for speed
  CORS_ORIGIN: z.string().default('http://localhost:5173'),
  ENABLE_SIMULATION: z
    .enum(['true', 'false'])
    .default('false')
    .transform((value) => value === 'true'),
  ANTHROPIC_API_KEY: z.string().optional(),
});

const parsed = envSchema.safeParse(process.env);
if (!parsed.success) {
  const problems = parsed.error.issues.map((i) => `  - ${i.path.join('.')}: ${i.message}`);
  throw new Error(`Invalid environment configuration (see server/.env.example):\n${problems.join('\n')}`);
}
const env = parsed.data;

if (env.NODE_ENV === 'production' && env.JWT_SECRET.startsWith('replace-me')) {
  throw new Error('JWT_SECRET still has the placeholder value from .env.example');
}

export const config = {
  env: env.NODE_ENV,
  isProduction: env.NODE_ENV === 'production',
  port: env.PORT,
  databaseUrl: env.DATABASE_URL,
  jwtSecret: env.JWT_SECRET,
  sessionHours: env.SESSION_HOURS,
  bcryptRounds: env.BCRYPT_ROUNDS,
  corsOrigins: env.CORS_ORIGIN.split(',')
    .map((origin) => origin.trim())
    .filter(Boolean),
  enableSimulation: env.ENABLE_SIMULATION,
  anthropicApiKey: env.ANTHROPIC_API_KEY || undefined,
};
