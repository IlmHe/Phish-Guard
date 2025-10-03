// src/sitemapService.ts - Advanced sitemap detection service
export interface SitemapResult {
  found: boolean;
  urls: string[];
  method: 'direct' | 'robots' | 'search' | 'none';
  attempts: string[];
  robotsContent?: string;
}

export interface SitemapProgress {
  stage: 'direct' | 'robots' | 'search' | 'complete';
  message: string;
  progress: number; // 0-100
}

export class SitemapService {

  /**
   * Multi-strategy sitemap detection with progress callbacks
   */
  static async findSitemapsWithProgress(
    domain: string,
    onProgress?: (progress: SitemapProgress) => void
  ): Promise<SitemapResult> {
    const result: SitemapResult = {
      found: false,
      urls: [],
      method: 'none',
      attempts: []
    };

    // Strategy 1: Try direct common sitemap URLs
    onProgress?.({ stage: 'direct', message: 'Checking common sitemap locations...', progress: 10 });
    const directUrls = await this.tryDirectUrls(domain);
    if (directUrls.length > 0) {
      result.found = true;
      result.urls = directUrls;
      result.method = 'direct';
      result.attempts.push(`Found ${directUrls.length} sitemap(s) via direct URL access`);
      onProgress?.({ stage: 'complete', message: `Found ${directUrls.length} sitemap(s) directly`, progress: 100 });
      return result;
    }

    // Strategy 2: Parse robots.txt for sitemap declarations
    onProgress?.({ stage: 'robots', message: 'Checking robots.txt for sitemaps...', progress: 50 });
    const robotsUrls = await this.parseRobotsTxt(domain);
    if (robotsUrls.urls.length > 0) {
      result.found = true;
      result.urls = robotsUrls.urls;
      result.method = 'robots';
      result.robotsContent = robotsUrls.robotsContent;
      result.attempts.push(`Found ${robotsUrls.urls.length} sitemap(s) in robots.txt`);
      onProgress?.({ stage: 'complete', message: `Found ${robotsUrls.urls.length} sitemap(s) in robots.txt`, progress: 100 });
      return result;
    }

    // Strategy 3: Fall back to search queries
    onProgress?.({ stage: 'search', message: 'Generating search fallback...', progress: 90 });
    const searchUrl = this.generateSearchUrl(domain);
    result.urls = [searchUrl];
    result.method = 'search';
    result.attempts.push('Using Google search as fallback');
    onProgress?.({ stage: 'complete', message: 'Using search fallback', progress: 100 });

    return result;
  }

  /**
   * Multi-strategy sitemap detection with cascade approach
   */
  static async findSitemaps(domain: string): Promise<SitemapResult> {
    const result: SitemapResult = {
      found: false,
      urls: [],
      method: 'none',
      attempts: []
    };

    // Strategy 1: Try direct common sitemap URLs
    const directUrls = await this.tryDirectUrls(domain);
    if (directUrls.length > 0) {
      result.found = true;
      result.urls = directUrls;
      result.method = 'direct';
      result.attempts.push(`Found ${directUrls.length} sitemap(s) via direct URL access`);
      return result;
    }

    // Strategy 2: Parse robots.txt for sitemap declarations
    const robotsUrls = await this.parseRobotsTxt(domain);
    if (robotsUrls.urls.length > 0) {
      result.found = true;
      result.urls = robotsUrls.urls;
      result.method = 'robots';
      result.robotsContent = robotsUrls.robotsContent;
      result.attempts.push(`Found ${robotsUrls.urls.length} sitemap(s) in robots.txt`);
      return result;
    }

    // Strategy 3: Fall back to search queries
    const searchUrl = this.generateSearchUrl(domain);
    result.urls = [searchUrl];
    result.method = 'search';
    result.attempts.push('Using Google search as fallback');

    return result;
  }

  /**
   * Strategy 1: Try common direct sitemap URLs
   */
  private static async tryDirectUrls(domain: string): Promise<string[]> {
    const commonSitemapPaths = [
      '/sitemap.xml',
      '/sitemap_index.xml',
      '/sitemaps.xml',
      '/sitemap/sitemap.xml',
      '/sitemap/index.xml',
      '/wp-sitemap.xml', // WordPress
      '/sitemap1.xml',
      '/sitemap/sitemap-index.xml'
    ];

    const foundUrls: string[] = [];
    const protocol = 'https://'; // Start with HTTPS

    for (const path of commonSitemapPaths) {
      const url = `${protocol}${domain}${path}`;

      try {
        // Use HEAD request to check if sitemap exists without downloading content
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 2000); // 2 second timeout

        const response = await fetch(url, {
          method: 'HEAD',
          headers: {
            'User-Agent': 'Phish-Guard/1.0 (Sitemap Detection)'
          },
          signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (response.ok && this.isValidSitemapResponse(response)) {
          foundUrls.push(url);
        }
      } catch (error) {
        // Try HTTP if HTTPS failed for first URL
        if (path === commonSitemapPaths[0] && protocol === 'https://') {
          const httpUrl = `http://${domain}${path}`;
          try {
            const httpController = new AbortController();
            const httpTimeoutId = setTimeout(() => httpController.abort(), 2000);

            const httpResponse = await fetch(httpUrl, {
              method: 'HEAD',
              headers: {
                'User-Agent': 'Phish-Guard/1.0 (Sitemap Detection)'
              },
              signal: httpController.signal
            });

            clearTimeout(httpTimeoutId);

            if (httpResponse.ok && this.isValidSitemapResponse(httpResponse)) {
              foundUrls.push(httpUrl);
            }
          } catch (httpError) {
            // HTTP fallback also failed
          }
        } else {
          // Failed to access URL
        }
      }
    }

    return foundUrls;
  }

  /**
   * Strategy 2: Parse robots.txt for sitemap declarations
   */
  private static async parseRobotsTxt(domain: string): Promise<{urls: string[], robotsContent?: string}> {
    const robotsUrls = [`https://${domain}/robots.txt`, `http://${domain}/robots.txt`];

    for (const robotsUrl of robotsUrls) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 2000); // 2 second timeout

        const response = await fetch(robotsUrl, {
          headers: {
            'User-Agent': 'Phish-Guard/1.0 (Sitemap Detection)'
          },
          signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (response.ok) {
          const robotsContent = await response.text();
          const sitemapUrls = this.extractSitemapsFromRobots(robotsContent);

          if (sitemapUrls.length > 0) {
            return { urls: sitemapUrls, robotsContent };
          }
        }
      } catch (error) {
        // Failed to fetch robots.txt
      }
    }

    return { urls: [] };
  }

  /**
   * Extract sitemap URLs from robots.txt content
   */
  private static extractSitemapsFromRobots(robotsContent: string): string[] {
    const sitemapUrls: string[] = [];
    const lines = robotsContent.split('\n');

    for (const line of lines) {
      const trimmed = line.trim();
      const sitemapMatch = trimmed.match(/^sitemap:\s*(.+)$/i);

      if (sitemapMatch) {
        const sitemapUrl = sitemapMatch[1].trim();
        if (this.isValidUrl(sitemapUrl)) {
          sitemapUrls.push(sitemapUrl);
        }
      }
    }

    return sitemapUrls;
  }

  /**
   * Strategy 3: Generate search URL as fallback
   */
  private static generateSearchUrl(domain: string): string {
    const query = `site:${domain} inurl:sitemap filetype:xml`;
    return `https://www.google.com/search?q=${encodeURIComponent(query)}`;
  }

  /**
   * Check if response is likely a valid sitemap
   */
  private static isValidSitemapResponse(response: Response): boolean {
    const contentType = response.headers.get('content-type') || '';

    // Check for XML content type
    return contentType.includes('xml') ||
           contentType.includes('text/xml') ||
           contentType.includes('application/xml');
  }

  /**
   * Validate URL format
   */
  private static isValidUrl(url: string): boolean {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Generate user-friendly summary of sitemap discovery
   */
  static generateSummary(result: SitemapResult): string {
    if (!result.found) {
      return 'No sitemaps found via direct access or robots.txt. Using search fallback.';
    }

    switch (result.method) {
      case 'direct':
        return `Found ${result.urls.length} sitemap(s) directly accessible on the domain.`;
      case 'robots':
        return `Found ${result.urls.length} sitemap(s) declared in robots.txt.`;
      case 'search':
        return 'Using Google search to find sitemaps.';
      default:
        return 'Sitemap discovery completed.';
    }
  }
}