import { Router } from 'express';
import { login, logout, me } from '../controllers/authController.js';
import { requireAuth } from '../middleware/auth.js';
import { createLoginRateLimiter } from '../middleware/rateLimit.js';

export function authRoutes() {
  const router = Router();
  router.post('/login', createLoginRateLimiter(), login);
  router.post('/logout', logout);
  router.get('/me', requireAuth, me);
  return router;
}
