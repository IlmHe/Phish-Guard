import { extractActualUrl, extractDomain } from '../src/utils';

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
  });

  describe('extractDomain', () => {
    it('should extract domain without protocol or www', () => {
      expect(extractDomain('https://www.example.com/path')).toBe('example.com');
    });

    it('should return input if no protocol present', () => {
      expect(extractDomain('example.com')).toBe('example.com');
    });
  });
});
