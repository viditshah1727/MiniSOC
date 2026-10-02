// Every successful API response has the same shape:
//   { success: true, data }                     single resource / object
//   { success: true, data: [...], pagination }  lists
import type { Response } from 'express';

export interface Pagination {
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

export function sendData<T>(res: Response, data: T, status = 200): void {
  res.status(status).json({ success: true, data });
}

export function sendPage<T>(res: Response, items: T[], pagination: Pagination): void {
  res.json({ success: true, data: items, pagination });
}

export function buildPagination(page: number, pageSize: number, total: number): Pagination {
  return { page, pageSize, total, totalPages: Math.max(1, Math.ceil(total / pageSize)) };
}
