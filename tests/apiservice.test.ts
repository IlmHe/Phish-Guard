import { checkUrlInSupabase, SupabaseService } from '../src/services/apiservice';
import { createClient } from '@supabase/supabase-js';

jest.mock('@supabase/supabase-js', () => ({
  createClient: jest.fn(),
}));

describe('checkUrlInSupabase', () => {
  const mockEq = jest.fn();

  beforeEach(() => {
    process.env.SUPABASE_URL = 'https://test.supabase';
    process.env.SUPABASE_KEY = 'test_key';
    (createClient as jest.Mock).mockReturnValue({
      from: () => ({
        select: () => ({ eq: mockEq }),
      }),
    });
    mockEq.mockReset();
    // Clear cache between tests
    SupabaseService.getInstance().clearCache();
  });

  it('returns true when data is found', async () => {
    mockEq.mockResolvedValue({ data: ['url'], error: null });
    const result = await checkUrlInSupabase('http://example.com');
    expect(createClient).toHaveBeenCalledWith(
      'https://test.supabase',
      'test_key'
    );
    expect(mockEq).toHaveBeenCalledWith('url', 'http://example.com');
    expect(result).toBe(true);
  });

  it('returns false when no data found', async () => {
    mockEq.mockResolvedValue({ data: [], error: null });
    await expect(
      checkUrlInSupabase('http://example.com')
    ).resolves.toBe(false);
  });

  it('throws an error when supabase returns error', async () => {
    mockEq.mockResolvedValue({ data: [], error: { message: 'Database error' } });
    await expect(
      checkUrlInSupabase('http://example.com')
    ).rejects.toThrow('Database query failed');
  });

  it('throws an error for invalid URL type', async () => {
    await expect(checkUrlInSupabase('')).rejects.toThrow('Invalid URL provided');
  });

  it('throws an error for invalid URL format', async () => {
    await expect(checkUrlInSupabase('not-a-url')).rejects.toThrow('Invalid URL format');
  });

  it('returns cached result on second call', async () => {
    mockEq.mockResolvedValue({ data: ['url'], error: null });
    const result1 = await checkUrlInSupabase('http://cached.com');
    const result2 = await checkUrlInSupabase('http://cached.com');
    expect(result1).toBe(result2);
    expect(mockEq).toHaveBeenCalledTimes(1); // Only one DB call due to cache
  });

  it('throws when missing Supabase configuration', async () => {
    const savedUrl = process.env.SUPABASE_URL;
    const savedKey = process.env.SUPABASE_KEY;
    delete process.env.SUPABASE_URL;
    delete process.env.SUPABASE_KEY;
    const service = SupabaseService.getInstance();
    service['client'] = null; // Reset client to force re-initialization
    try {
      await expect(checkUrlInSupabase('http://example.com')).rejects.toThrow('Missing Supabase');
    } finally {
      process.env.SUPABASE_URL = savedUrl;
      process.env.SUPABASE_KEY = savedKey;
    }
  });

  it('throws when Supabase URL does not start with https://', async () => {
    const savedUrl = process.env.SUPABASE_URL;
    process.env.SUPABASE_URL = 'http://insecure.supabase';
    const service = SupabaseService.getInstance();
    service['client'] = null; // Force re-initialization
    try {
      await expect(checkUrlInSupabase('http://example.com')).rejects.toThrow('Invalid Supabase URL');
    } finally {
      process.env.SUPABASE_URL = savedUrl;
      service['client'] = null;
    }
  });
});
