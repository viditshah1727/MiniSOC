import { Router } from 'express';
import { listRules, updateRule } from '../controllers/rulesController.js';
import { requireRole } from '../middleware/auth.js';

// Mounted behind requireAuth. Everyone can see the rules; only admins change them.
export function ruleRoutes() {
  const router = Router();
  router.get('/', listRules);
  router.patch('/:id', requireRole('ADMIN'), updateRule);
  return router;
}
