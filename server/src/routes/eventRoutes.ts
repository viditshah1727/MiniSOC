import { Router } from 'express';
import { createEvent, getEvent, listEvents } from '../controllers/eventsController.js';
import { requireRole } from '../middleware/auth.js';
import { createIngestRateLimiter } from '../middleware/rateLimit.js';

// Mounted behind requireAuth: every route needs a logged-in user.
export function eventRoutes() {
  const router = Router();
  router.get('/', listEvents);
  router.get('/:id', getEvent);
  router.post('/', requireRole('ADMIN', 'ANALYST'), createIngestRateLimiter(), createEvent);
  return router;
}
