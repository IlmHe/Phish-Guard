import { checkUrlInSupabase } from '../src/apiservice';
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
    mockEq.mockResolvedValue({ data: [], error: new Error('fail') });
    await expect(
      checkUrlInSupabase('http://example.com')
    ).rejects.toThrow('Failed to query Supabase');
  });
});
