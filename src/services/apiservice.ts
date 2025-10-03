import { createClient, SupabaseClient } from '@supabase/supabase-js';
import logger from '../utils/logger';

interface CacheEntry {
  result: boolean;
  timestamp: number;
}

class SupabaseService {
  private static instance: SupabaseService;
  private client: SupabaseClient | null = null;
  private cache = new Map<string, CacheEntry>();
  private readonly CACHE_TTL = 5 * 60 * 1000; // 5 minutes

  private constructor() {}

  public static getInstance(): SupabaseService {
    if (!SupabaseService.instance) {
      SupabaseService.instance = new SupabaseService();
    }
    return SupabaseService.instance;
  }

  private getClient(): SupabaseClient {
    if (!this.client) {
      const supabaseUrl = process.env.SUPABASE_URL;
      const supabaseKey = process.env.SUPABASE_KEY;

      if (!supabaseUrl || !supabaseKey) {
        throw new Error('Missing Supabase configuration. Please check SUPABASE_URL and SUPABASE_KEY environment variables.');
      }

      if (!supabaseUrl.startsWith('https://')) {
        throw new Error('Invalid Supabase URL format. URL must start with https://');
      }

      this.client = createClient(supabaseUrl, supabaseKey);
    }
    return this.client;
  }

  private isValidUrl(url: string): boolean {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }

  private getCacheKey(url: string): string {
    return url.toLowerCase().trim();
  }

  private isCacheValid(entry: CacheEntry): boolean {
    return Date.now() - entry.timestamp < this.CACHE_TTL;
  }

  public async checkUrlInDatabase(url: string): Promise<boolean> {
    if (!url || typeof url !== 'string') {
      throw new Error('Invalid URL provided');
    }

    if (!this.isValidUrl(url)) {
      throw new Error('Invalid URL format');
    }

    const cacheKey = this.getCacheKey(url);
    const cachedEntry = this.cache.get(cacheKey);

    if (cachedEntry && this.isCacheValid(cachedEntry)) {
      return cachedEntry.result;
    }

    try {
      const client = this.getClient();
      const { data, error } = await client
        .from('phish-co-za_urls')
        .select('url')
        .eq('url', url);

      if (error) {
        logger.error('Supabase query error:', error);
        throw new Error(`Database query failed: ${error.message}`);
      }

      const result = data && data.length > 0;

      // Cache the result
      this.cache.set(cacheKey, {
        result,
        timestamp: Date.now()
      });

      // Clean up old cache entries periodically
      this.cleanupCache();

      return result;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error('Unknown error occurred while checking database');
    }
  }

  private cleanupCache(): void {
    const now = Date.now();
    for (const [key, entry] of this.cache.entries()) {
      if (!this.isCacheValid(entry)) {
        this.cache.delete(key);
      }
    }
  }

  public clearCache(): void {
    this.cache.clear();
  }
}

// Export the main function for backward compatibility
export async function checkUrlInSupabase(url: string): Promise<boolean> {
  const service = SupabaseService.getInstance();
  return service.checkUrlInDatabase(url);
}

// Export the service for advanced usage
export { SupabaseService };
