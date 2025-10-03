import {
  extractActualUrl,
  extractDomain,
  extractDomainRaw,
  isValidUrl,
  sanitizeUrl
} from '../src/utils/utils';

describe('Utility functions', () => {
  describe('extractActualUrl', () => {
    it('should decode url parameter if present', () => {
      const url = 'https://google.com/search?q=test&url=https%3A%2F%2Fexample.com%2Fpath';
      expect(extractActualUrl(url)).toBe('https://example.com/path');
    });

    it('should return original url if no parameter', () => {
      const url = 'https://example.com/path';
      expect(extractActualUrl(url)).toBe(url);
    });

    it('should handle multiple url parameters', () => {
      const url = 'https://redirect.com?url=https%3A%2F%2Fexample.com&another=value';
      expect(extractActualUrl(url)).toBe('https://example.com');
    });

    it('should handle invalid URLs gracefully', () => {
      const url = 'not-a-url';
      expect(extractActualUrl(url)).toBe(url);
    });
  });

  describe('extractDomain', () => {
    it('should extract domain without protocol or www', () => {
      expect(extractDomain('https://www.example.com/path')).toBe('example.com');
    });

    it('should handle domains without protocol', () => {
      expect(extractDomain('example.com')).toBe('example.com');
    });

    it('should handle domains with subdomains', () => {
      expect(extractDomain('https://subdomain.example.com/path')).toBe('subdomain.example.com');
    });

    it('should remove www prefix', () => {
      expect(extractDomain('www.example.com')).toBe('example.com');
    });

    it('should handle domains with ports', () => {
      expect(extractDomain('https://example.com:8080/path')).toBe('example.com');
    });

    it('should handle invalid URLs with fallback', () => {
      const result = extractDomain('not://a/valid/url');
      expect(result).toBeTruthy();
    });
  });

  describe('extractDomainRaw', () => {
    it('should preserve Unicode characters', () => {
      const unicodeUrl = 'https://gооgle.com'; // Contains Cyrillic 'о'
      const result = extractDomainRaw(unicodeUrl);
      expect(result).toContain('ооgle');
    });

    it('should extract domain without www', () => {
      expect(extractDomainRaw('www.example.com')).toBe('example.com');
    });

    it('should handle URLs with paths', () => {
      expect(extractDomainRaw('https://example.com/path/to/page')).toBe('example.com');
    });

    it('should handle domains with ports', () => {
      expect(extractDomainRaw('https://example.com:8080')).toBe('example.com:8080');
    });

    it('should return input for invalid URLs', () => {
      expect(extractDomainRaw('not-a-url')).toBe('not-a-url');
    });
  });

  describe('isValidUrl', () => {
    it('should validate correct URLs', () => {
      expect(isValidUrl('https://example.com')).toBe(true);
      expect(isValidUrl('http://example.com/path')).toBe(true);
      expect(isValidUrl('https://sub.example.com:8080/path?query=1')).toBe(true);
    });

    it('should reject invalid URLs', () => {
      expect(isValidUrl('not-a-url')).toBe(false);
      expect(isValidUrl('javascript:alert(1)')).toBe(false);
      expect(isValidUrl('')).toBe(false);
      expect(isValidUrl('ftp://example.com')).toBe(false);
    });
  });

  describe('sanitizeUrl', () => {
    it('should remove dangerous protocols', () => {
      expect(sanitizeUrl('javascript:alert(1)')).toBe('');
      expect(sanitizeUrl('data:text/html,<script>alert(1)</script>')).toBe('');
    });

    it('should preserve safe URLs', () => {
      const safeUrl = 'https://example.com/path';
      expect(sanitizeUrl(safeUrl)).toContain('example.com');
    });

    it('should return empty string for invalid input', () => {
      expect(sanitizeUrl('')).toBe('');
      expect(sanitizeUrl('not-a-url')).toBe('');
    });

    it('should allow http and https protocols', () => {
      expect(sanitizeUrl('http://example.com')).toContain('example.com');
      expect(sanitizeUrl('https://example.com')).toContain('example.com');
    });
  });
});
