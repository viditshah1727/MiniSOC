// Mounts every feature router under /api. Built by a function so each app
// instance (and each test) gets fresh middleware state such as rate limits.
import { Router } from 'express';
import { config } from '../config.js';
import { getHealth } from '../controllers/healthController.js';
import { streamLiveUpdates } from '../controllers/streamController.js';
import { requireAuth } from '../middleware/auth.js';
import { alertRoutes } from './alertRoutes.js';
import { authRoutes } from './authRoutes.js';
import { dashboardRoutes } from './dashboardRoutes.js';
import { eventRoutes } from './eventRoutes.js';
import { incidentRoutes } from './incidentRoutes.js';
import { mitreRoutes } from './mitreRoutes.js';
import { reportRoutes } from './reportRoutes.js';
import { ruleRoutes } from './ruleRoutes.js';
import { simulationRoutes } from './simulationRoutes.js';
import { threatIntelRoutes } from './threatIntelRoutes.js';
import { userRoutes } from './userRoutes.js';

export function createApiRouter() {
  const api = Router();

  // Public
  api.get('/health', getHealth);
  api.use('/auth', authRoutes());

  // Everything below requires a logged-in user
  api.use('/dashboard', requireAuth, dashboardRoutes());
  api.use('/events', requireAuth, eventRoutes());
  api.use('/alerts', requireAuth, alertRoutes());
  api.use('/incidents', requireAuth, incidentRoutes());
  api.use('/threat-intelligence', requireAuth, threatIntelRoutes());
  api.use('/mitre', requireAuth, mitreRoutes());
  api.use('/rules', requireAuth, ruleRoutes());
  api.use('/reports', requireAuth, reportRoutes());
  api.use('/users', requireAuth, userRoutes());
  api.get('/stream', requireAuth, streamLiveUpdates);

  // Demo-only attack simulator, kept out of production builds by configuration
  if (config.enableSimulation) {
    api.use('/simulate', requireAuth, simulationRoutes());
  }

  return api;
}
