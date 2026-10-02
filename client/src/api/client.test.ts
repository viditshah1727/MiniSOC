import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, request, requestPage, setUnauthorizedHandler, toQueryString } from './client';

function mockFetch(status: number, body: unknown) {
  const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(body), { status }));
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('toQueryString', () => {
  it('skips empty filters so they stay optional', () => {
    expect(toQueryString({ severity: 'HIGH', q: '', page: 2, sourceIp: undefined })).toBe('?severity=HIGH&page=2');
    expect(toQueryString({})).toBe('');
  });
});

describe('request', () => {
  it('unwraps { success, data } and sends JSON to /api', async () => {
    const fetchMock = mockFetch(200, { success: true, data: { id: 7 } });
    await expect(request('/alerts/7', { method: 'PATCH', body: { status: 'RESOLVED' } })).resolves.toEqual({ id: 7 });

    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe('/api/alerts/7');
    expect(init).toMatchObject({ method: 'PATCH', body: '{"status":"RESOLVED"}', credentials: 'same-origin' });
  });

  it('returns items and pagination for list endpoints', async () => {
    const pagination = { page: 1, pageSize: 25, total: 1, totalPages: 1 };
    mockFetch(200, { success: true, data: [{ id: 1 }], pagination });
    await expect(requestPage('/events')).resolves.toEqual({ items: [{ id: 1 }], pagination });
  });

  it('turns API failures into an ApiError with field-level details', async () => {
    mockFetch(400, {
      success: false,
      message: 'Validation failed',
      errors: [{ field: 'sourceIp', message: 'must be a valid IPv4 or IPv6 address' }],
    });
    const error = await request('/events').catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 400, message: 'Validation failed' });
    expect((error as ApiError).fieldErrors[0]!.field).toBe('sourceIp');
  });

  it('signals an expired session so the app can return to the login page', async () => {
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);
    mockFetch(401, { success: false, message: 'Authentication required' });

    await expect(request('/alerts')).rejects.toThrow('Authentication required');
    expect(onUnauthorized).toHaveBeenCalledOnce();
  });

  it('reports a friendly error when the API is unreachable', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')));
    await expect(request('/alerts')).rejects.toMatchObject({ status: 0, message: expect.stringContaining('Cannot reach') });
  });
});
