// Authentication: password hashing, credential checks and session tokens.
//
// - Passwords are hashed with bcrypt (salted, deliberately slow).
// - A session is a signed JWT carrying only the user id; it lives in an
//   httpOnly cookie, so JavaScript in the page can never read it.
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'node:crypto';
import { config } from '../config.js';
import { prisma } from '../db.js';
import type { AuthUser } from '../types/express.js';
import { unauthorized } from '../utils/AppError.js';

const JWT_ALGORITHM = 'HS256';

export function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, config.bcryptRounds); // cost 12 by default
}

// Compared against when the email does not exist, so a failed login takes the
// same time either way and response timing cannot reveal which emails exist.
let dummyHash: string | undefined;
async function getDummyHash(): Promise<string> {
  dummyHash ??= await bcrypt.hash(randomUUID(), config.bcryptRounds);
  return dummyHash;
}

/** Returns the user when the credentials are valid, otherwise throws 401. */
export async function verifyCredentials(email: string, password: string): Promise<AuthUser> {
  const user = await prisma.user.findUnique({ where: { email } });
  const passwordMatches = await bcrypt.compare(password, user?.passwordHash ?? (await getDummyHash()));

  if (!user || !passwordMatches) {
    // Same message for "unknown email" and "wrong password".
    throw unauthorized('Invalid email or password');
  }
  return { id: user.id, email: user.email, name: user.name, role: user.role };
}

export function createSessionToken(userId: number): string {
  return jwt.sign({}, config.jwtSecret, {
    subject: String(userId),
    algorithm: JWT_ALGORITHM,
    expiresIn: config.sessionHours * 60 * 60,
  });
}

/** Returns the user id from a valid token, or null if it is invalid/expired. */
export function readSessionToken(token: string): number | null {
  try {
    // Pinning the algorithm blocks "alg: none" / algorithm-confusion attacks.
    const payload = jwt.verify(token, config.jwtSecret, { algorithms: [JWT_ALGORITHM] });
    const userId = typeof payload === 'object' ? Number(payload.sub) : NaN;
    return Number.isInteger(userId) && userId > 0 ? userId : null;
  } catch {
    return null;
  }
}

/** Loads the user fresh from the database so role changes apply immediately. */
export async function findSessionUser(userId: number): Promise<AuthUser | null> {
  return prisma.user.findUnique({
    where: { id: userId },
    select: { id: true, email: true, name: true, role: true },
  });
}
