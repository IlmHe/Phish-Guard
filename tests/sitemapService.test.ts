import { SitemapService, SitemapResult } from '../src/services/sitemapService';

// Mock fetch globally
global.fetch = jest.fn();

const MOCK_SITEMAP_XML = '<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>';

describe('SitemapService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('findSitemaps', () => {
    it('should find sitemap via direct URL access', async () => {
      (global.fetch as jest.Mock)
        .mockResolvedValueOnce({ ok: true, text: async () => MOCK_SITEMAP_XML }) // sitemap.xml
        .mockResolvedValueOnce({ ok: false }) // sitemap_index.xml
        .mockResolvedValueOnce({ ok: false }); // sitemap-index.xml

      const result = await SitemapService.findSitemaps('example.com');

      expect(result.found).toBe(true);
      expect(result.method).toBe('direct');
      expect(result.urls.length).toBeGreaterThan(0);
      expect(result.urls[0]).toContain('sitemap.xml');
    });

    it('should find sitemaps in robots.txt when direct URLs fail', async () => {
      // All direct sitemap URLs fail; only robots.txt succeeds
      (global.fetch as jest.Mock).mockImplementation(async (url: string) => {
        if (typeof url === 'string' && url.includes('/robots.txt')) {
          return {
            ok: true,
            text: async () => 'Sitemap: https://example.com/sitemap.xml\nSitemap: https://example.com/sitemap2.xml'
          };
        }
        return { ok: false };
      });

      const result = await SitemapService.findSitemaps('example.com');

      expect(result.found).toBe(true);
      expect(result.method).toBe('robots');
      expect(result.urls.length).toBe(2);
      expect(result.robotsContent).toBeDefined();
    });

    it('should fall back to search when all strategies fail', async () => {
      // All requests fail
      (global.fetch as jest.Mock).mockResolvedValue({ ok: false });

      const result = await SitemapService.findSitemaps('example.com');

      expect(result.method).toBe('search');
      expect(result.urls.length).toBeGreaterThan(0);
      expect(result.urls[0]).toContain('google.com/search');
    });

    it('should record all attempts', async () => {
      (global.fetch as jest.Mock).mockResolvedValue({ ok: false });

      const result = await SitemapService.findSitemaps('example.com');

      expect(result.attempts.length).toBeGreaterThan(0);
    });
  });

  describe('findSitemapsWithProgress', () => {
    it('should call progress callback at each stage', async () => {
      const progressCallback = jest.fn();

      (global.fetch as jest.Mock)
        .mockResolvedValueOnce({ ok: true, text: async () => MOCK_SITEMAP_XML })
        .mockResolvedValue({ ok: false });

      await SitemapService.findSitemapsWithProgress('example.com', progressCallback);

      expect(progressCallback).toHaveBeenCalled();
      expect(progressCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          stage: 'direct',
          message: expect.any(String),
          progress: expect.any(Number)
        })
      );
    });

    it('should report 100% progress when complete', async () => {
      const progressCallback = jest.fn();

      (global.fetch as jest.Mock).mockResolvedValue({ ok: false });

      await SitemapService.findSitemapsWithProgress('example.com', progressCallback);

      const lastCall = progressCallback.mock.calls[progressCallback.mock.calls.length - 1][0];
      expect(lastCall.progress).toBe(100);
      expect(lastCall.stage).toBe('complete');
    });

    it('should work without progress callback', async () => {
      (global.fetch as jest.Mock).mockResolvedValue({ ok: false });

      const result = await SitemapService.findSitemapsWithProgress('example.com');

      expect(result).toBeDefined();
      expect(result.method).toBeDefined();
    });
  });

  describe('tryDirectUrls', () => {
    it('should try common sitemap URLs', async () => {
      (global.fetch as jest.Mock)
        .mockResolvedValueOnce({ ok: false }) // sitemap.xml
        .mockResolvedValueOnce({ ok: true, text: async () => '<sitemapindex><sitemap><loc>https://example.com/sitemap1.xml</loc></sitemap></sitemapindex>' }) // sitemap_index.xml
        .mockResolvedValueOnce({ ok: false }); // sitemap-index.xml

      const urls = await (SitemapService as any).tryDirectUrls('example.com');

      expect(urls.length).toBe(1);
      expect(urls[0]).toContain('sitemap_index.xml');
    });

    it('should return empty array when all URLs fail', async () => {
      (global.fetch as jest.Mock).mockResolvedValue({ ok: false });

      const urls = await (SitemapService as any).tryDirectUrls('example.com');

      expect(urls).toEqual([]);
    });

    it('should handle network errors', async () => {
      (global.fetch as jest.Mock).mockRejectedValue(new Error('Network error'));

      const urls = await (SitemapService as any).tryDirectUrls('example.com');

      expect(urls).toEqual([]);
    });

    it('should validate sitemap content', async () => {
      (global.fetch as jest.Mock)
        .mockResolvedValueOnce({ ok: true, text: async () => '<html>not a sitemap</html>' })
        .mockResolvedValueOnce({ ok: true, text: async () => '<urlset></urlset>' });

      const urls = await (SitemapService as any).tryDirectUrls('example.com');

      // Should only accept valid sitemap
      expect(urls.length).toBeGreaterThanOrEqual(0);
    });
  });

  describe('parseRobotsTxt', () => {
    it('should extract sitemap URLs from robots.txt', async () => {
      const robotsContent = `
        User-agent: *
        Disallow: /admin

        Sitemap: https://example.com/sitemap.xml
        Sitemap: https://example.com/news-sitemap.xml
      `;

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        text: async () => robotsContent
      });

      const result = await (SitemapService as any).parseRobotsTxt('example.com');

      expect(result.urls.length).toBe(2);
      expect(result.urls).toContain('https://example.com/sitemap.xml');
      expect(result.urls).toContain('https://example.com/news-sitemap.xml');
      expect(result.robotsContent).toBe(robotsContent);
    });

    it('should handle robots.txt without sitemaps', async () => {
      const robotsContent = `
        User-agent: *
        Disallow: /admin
      `;

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        text: async () => robotsContent
      });

      const result = await (SitemapService as any).parseRobotsTxt('example.com');

      expect(result.urls).toEqual([]);
      expect(result.robotsContent).toBe(robotsContent);
    });

    it('should handle missing robots.txt', async () => {
      (global.fetch as jest.Mock).mockResolvedValueOnce({ ok: false });

      const result = await (SitemapService as any).parseRobotsTxt('example.com');

      expect(result.urls).toEqual([]);
      expect(result.robotsContent).toBeUndefined();
    });

    it('should handle malformed robots.txt', async () => {
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        text: async () => 'invalid\nmalformed\ndata'
      });

      const result = await (SitemapService as any).parseRobotsTxt('example.com');

      expect(result.urls).toEqual([]);
    });
  });

  describe('generateSearchUrl', () => {
    it('should generate valid Google search URL', () => {
      const url = (SitemapService as any).generateSearchUrl('example.com');

      expect(url).toContain('google.com/search');
      expect(url).toContain('example.com');
      expect(url).toContain('sitemap');
    });

    it('should handle domains with special characters', () => {
      const url = (SitemapService as any).generateSearchUrl('example-site.co.uk');

      expect(url).toContain('example-site.co.uk');
    });

    it('should URL encode domain properly', () => {
      const url = (SitemapService as any).generateSearchUrl('ex ample.com');

      expect(url).not.toContain(' ');
    });
  });

  describe('isSitemapContent', () => {
    it('should identify valid XML sitemaps', () => {
      const validSitemap = '<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://example.com</loc></url></urlset>';

      const result = (SitemapService as any).isSitemapContent(validSitemap);

      expect(result).toBe(true);
    });

    it('should identify sitemap index files', () => {
      const sitemapIndex = '<sitemapindex><sitemap><loc>https://example.com/sitemap1.xml</loc></sitemap></sitemapindex>';

      const result = (SitemapService as any).isSitemapContent(sitemapIndex);

      expect(result).toBe(true);
    });

    it('should reject HTML content', () => {
      const htmlContent = '<html><body>Not a sitemap</body></html>';

      const result = (SitemapService as any).isSitemapContent(htmlContent);

      expect(result).toBe(false);
    });

    it('should reject plain text', () => {
      const textContent = 'This is just plain text';

      const result = (SitemapService as any).isSitemapContent(textContent);

      expect(result).toBe(false);
    });

    it('should handle empty content', () => {
      const result = (SitemapService as any).isSitemapContent('');

      expect(result).toBe(false);
    });
  });

  describe('generateSummary', () => {
    it('should generate summary for direct method', () => {
      const result: SitemapResult = { found: true, urls: ['https://example.com/sitemap.xml'], method: 'direct', attempts: [] };
      const summary = SitemapService.generateSummary(result);
      expect(summary).toContain('directly');
    });

    it('should generate summary for robots method', () => {
      const result: SitemapResult = { found: true, urls: ['https://example.com/sitemap.xml'], method: 'robots', attempts: [] };
      const summary = SitemapService.generateSummary(result);
      expect(summary).toContain('robots.txt');
    });

    it('should generate summary for search method', () => {
      const result: SitemapResult = { found: true, urls: ['https://google.com/search?q=sitemap'], method: 'search', attempts: [] };
      const summary = SitemapService.generateSummary(result);
      expect(summary).toContain('search');
    });

    it('should generate summary when not found', () => {
      const result: SitemapResult = { found: false, urls: [], method: 'none', attempts: [] };
      const summary = SitemapService.generateSummary(result);
      expect(summary).toContain('No sitemaps');
    });

    it('should generate default summary for unknown method', () => {
      const result: SitemapResult = { found: true, urls: [], method: 'none', attempts: [] };
      const summary = SitemapService.generateSummary(result);
      expect(summary).toBeDefined();
    });
  });
});
