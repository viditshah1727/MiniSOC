// Adds `req.user` (set by the requireAuth middleware) to Express's Request type.
import type { Role } from '../generated/prisma/enums.js';

export interface AuthUser {
  id: number;
  email: string;
  name: string;
  role: Role;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}
