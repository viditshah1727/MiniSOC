// Small zod building blocks shared by the request schemas.
import { z } from 'zod';

/** Route parameter like /alerts/:id: must be a positive integer. */
export const idParamSchema = z.object({
  id: z.coerce.number().int().positive(),
});

/** ?page=&pageSize= with sane bounds, so nobody can request a million rows. */
export const paginationSchema = z.object({
  page: z.coerce.number().int().min(1).max(10_000).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
});

/** An IPv4 or IPv6 address. */
export const ipSchema = z.union([z.ipv4(), z.ipv6()], { error: 'must be a valid IPv4 or IPv6 address' });

/** Optional free-text search term from a query string. */
export const searchSchema = z.string().trim().max(100).optional();
