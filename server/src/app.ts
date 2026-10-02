// Builds the Express application. Kept separate from index.ts (which starts
// listening) so tests can exercise the real app with supertest.
import cookieParser from 'cookie-parser';
import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { config } from './config.js';
import { errorHandler, notFoundHandler } from './middleware/errorHandler.js';
import { createApiRouter } from './routes/index.js';

// Built React app (client/dist). When present, the API also serves the UI,
// so production is a single origin: no CORS needed, cookies just work.
const clientDist = fileURLToPath(new URL('../../client/dist', import.meta.url));

export function createApp() {
  const app = express();

  app.use(helmet()); // secure HTTP headers (CSP, no-sniff, frame-ancestors, ...)
  app.use(cors({ origin: config.corsOrigins, credentials: true }));
  app.use(express.json({ limit: '100kb' })); // JSON bodies only, size-capped
  app.use(cookieParser());

  app.use('/api', createApiRouter());
  app.use('/api', notFoundHandler);

  if (existsSync(clientDist)) {
    app.use(express.static(clientDist));
    // Client-side routing: unknown GET paths return the SPA shell.
    app.use((req, res, next) => {
      if (req.method !== 'GET') return next();
      res.sendFile('index.html', { root: clientDist });
    });
  }

  app.use(errorHandler);
  return app;
}
