import { Router } from 'express';
import { listUsers } from '../controllers/usersController.js';

// Mounted behind requireAuth.
export function userRoutes() {
  const router = Router();
  router.get('/', listUsers);
  return router;
}
