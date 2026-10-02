// The single Prisma client shared by the whole server.
// Prisma 7 talks to PostgreSQL through a driver adapter (node-postgres here).
// Every query Prisma builds is parameterised, so user input never becomes SQL.
import { PrismaPg } from '@prisma/adapter-pg';
import { config } from './config.js';
import { PrismaClient } from './generated/prisma/client.js';

const adapter = new PrismaPg({ connectionString: config.databaseUrl });

export const prisma = new PrismaClient({ adapter });
