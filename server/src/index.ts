// Server entry point: prepare the database, start listening, shut down cleanly.
import { createApp } from './app.js';
import { config } from './config.js';
import { prisma } from './db.js';
import { syncDetectionContent } from './detection/sync.js';
import { logger } from './utils/logger.js';

async function start() {
  try {
    // Make sure the detection rules and MITRE techniques defined in code exist in the database.
    await syncDetectionContent();
  } catch (error) {
    logger.error(
      'Could not prepare the database. Is PostgreSQL running (docker compose up -d) and migrated (npm run db:migrate)?',
      error instanceof Error ? error.message : error,
    );
    process.exit(1);
  }

  const server = createApp().listen(config.port, () => {
    logger.info(`MiniSOC API listening on http://localhost:${config.port} (${config.env})`);
    if (config.enableSimulation) logger.warn('Attack simulator is ENABLED (demo mode): POST /api/simulate');
  });

  const shutdown = async (signal: string) => {
    logger.info(`${signal} received, shutting down`);
    server.close();
    await prisma.$disconnect();
    process.exit(0);
  };
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
}

void start();
