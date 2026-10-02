// The one place the browser talks to the API. Every response has the shape
// { success, data, pagination? } or { success: false, message, errors? };
// this wrapper unwraps it and turns failures into a typed ApiError.
// Authentication rides on the httpOnly session cookie, which the browser
// attaches automatically (same origin), so no token is ever handled in JS.
import type { Pagination } from '../types/api';

export interface FieldError {
  field: string;
  message: string;
}

export class ApiError extends Error {
  readonly status: number;
  readonly fieldErrors: FieldError[];

  constructor(status: number, message: string, fieldErrors: FieldError[] = []) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.fieldErrors = fieldErrors;
  }
}

type QueryValue = string | number | boolean | null | undefined;
export type QueryParams = Record<string, QueryValue>;

/** Builds "?a=1&b=2", skipping empty values so filters stay optional. */
export function toQueryString(params: QueryParams = {}): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') search.set(key, String(value));
  }
  const query = search.toString();
  return query ? `?${query}` : '';
}

// Lets the auth layer react when the session expires mid-use.
let onUnauthorized: (() => void) | undefined;
export function setUnauthorizedHandler(handler: () => void): void {
  onUnauthorized = handler;
}

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PATCH';
  body?: unknown;
  params?: QueryParams;
  signal?: AbortSignal;
}

interface Envelope<T> {
  success: boolean;
  data?: T;
  pagination?: Pagination;
  message?: string;
  errors?: FieldError[];
}

async function send<T>(path: string, options: RequestOptions): Promise<Envelope<T>> {
  let response: Response;
  try {
    response = await fetch(`/api${path}${toQueryString(options.params)}`, {
      method: options.method ?? 'GET',
      headers: options.body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      credentials: 'same-origin',
      signal: options.signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error;
    throw new ApiError(0, 'Cannot reach the MiniSOC API. Is the server running?');
  }

  const envelope = (await response.json().catch(() => ({}))) as Envelope<T>;
  if (!response.ok || !envelope.success) {
    if (response.status === 401 && !path.startsWith('/auth/')) onUnauthorized?.();
    throw new ApiError(response.status, envelope.message ?? `Request failed (${response.status})`, envelope.errors);
  }
  return envelope;
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const envelope = await send<T>(path, options);
  return envelope.data as T;
}

/** For list endpoints: returns the items plus pagination info. */
export async function requestPage<T>(path: string, options: RequestOptions = {}) {
  const envelope = await send<T[]>(path, options);
  return { items: envelope.data ?? [], pagination: envelope.pagination! };
}
