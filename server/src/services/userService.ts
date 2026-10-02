import { prisma } from '../db.js';

/** The SOC team, without password hashes. */
export function listUsers() {
  return prisma.user.findMany({
    select: { id: true, name: true, email: true, role: true },
    orderBy: { name: 'asc' },
  });
}
