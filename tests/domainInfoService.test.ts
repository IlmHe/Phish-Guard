import { DomainInfoService } from '../src/services/domainInfoService';

// Mock fetch globally
global.fetch = jest.fn();

describe('DomainInfoService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Clear the in-memory cache so tests don't interfere with each other
    (DomainInfoService as any).cache.clear();
  });

  describe('getDomainInfo', () => {
    it('should fetch and parse WHOIS data successfully', async () => {
      const mockWhoisData = {
        domain: 'example.com',
        registrar: 'Example Registrar Inc.',
        created: '2000-01-01',
        expires: '2030-01-01',
        updated: '2020-01-01',
        status: ['ok'],
        nameservers: ['ns1.example.com', 'ns2.example.com']
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockWhoisData
      });

      const result = await DomainInfoService.getDomainInfo('example.com');

      expect(result).toBeDefined();
      expect(result?.registrar).toBe('Example Registrar Inc.');
      expect(result?.registrationDate).toBe('2000-01-01');
    });

    it('should handle API errors gracefully', async () => {
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 500
      });

      const result = await DomainInfoService.getDomainInfo('example.com');

      expect(result).toBeNull();
    });

    it('should handle network errors', async () => {
      (global.fetch as jest.Mock).mockRejectedValueOnce(new Error('Network error'));

      const result = await DomainInfoService.getDomainInfo('example.com');

      expect(result).toBeNull();
    });

    it('should handle malformed WHOIS responses', async () => {
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ invalid: 'data' })
      });

      const result = await DomainInfoService.getDomainInfo('example.com');

      // Should handle gracefully even with malformed data
      expect(result).toBeDefined();
    });

    it('should calculate domain age correctly', async () => {
      const now = Date.now();
      const oneYearAgo = new Date(now - 365 * 24 * 60 * 60 * 1000).toISOString();

      const mockWhoisData = {
        domain: 'example.com',
        created: oneYearAgo,
        registrar: 'Test Registrar'
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockWhoisData
      });

      const result = await DomainInfoService.getDomainInfo('example.com');

      expect(result?.domainAge).toBeDefined();
      expect(result?.domainAge).toBeGreaterThanOrEqual(364);
      expect(result?.domainAge).toBeLessThanOrEqual(366);
    });

    it('should handle domains without creation date', async () => {
      const mockWhoisData = {
        domain: 'example.com',
        registrar: 'Test Registrar'
        // No created date
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockWhoisData
      });

      const result = await DomainInfoService.getDomainInfo('example.com');

      expect(result).toBeDefined();
      expect(result?.domainAge).toBeUndefined();
    });
  });

  describe('calculateDomainAge', () => {
    it('should calculate age in days correctly', () => {
      const now = Date.now();
      const thirtyDaysAgo = new Date(now - 30 * 24 * 60 * 60 * 1000).toISOString();

      const age = (DomainInfoService as any).calculateDomainAge(thirtyDaysAgo);

      expect(age).toBeGreaterThanOrEqual(29);
      expect(age).toBeLessThanOrEqual(31);
    });

    it('should handle invalid date strings', () => {
      const age = (DomainInfoService as any).calculateDomainAge('invalid-date');

      expect(age).toBeUndefined();
    });

    it('should handle null or undefined dates', () => {
      const age1 = (DomainInfoService as any).calculateDomainAge(null);
      const age2 = (DomainInfoService as any).calculateDomainAge(undefined);

      expect(age1).toBeUndefined();
      expect(age2).toBeUndefined();
    });

    it('should handle future dates', () => {
      const tomorrow = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

      const age = (DomainInfoService as any).calculateDomainAge(tomorrow);

      // Should handle gracefully, likely return 0 or negative
      expect(typeof age).toBe('number');
    });
  });

  describe('parseWhoisData', () => {
    it('should parse valid WHOIS data', () => {
      const rawData = {
        domain: 'example.com',
        registrar: 'Test Registrar',
        created: '2000-01-01T00:00:00Z',
        expires: '2030-01-01T00:00:00Z',
        updated: '2020-01-01T00:00:00Z'
      };

      const result = (DomainInfoService as any).parseWhoisData(rawData);

      expect(result.registrar).toBe('Test Registrar');
      expect(result.creationDate).toBe('2000-01-01T00:00:00Z');
      expect(result.expirationDate).toBe('2030-01-01T00:00:00Z');
    });

    it('should handle missing fields', () => {
      const rawData = {
        domain: 'example.com'
      };

      const result = (DomainInfoService as any).parseWhoisData(rawData);

      expect(result).toBeDefined();
      expect(result.registrar).toBeUndefined();
    });

    it('should handle various date formats', () => {
      const rawData = {
        domain: 'example.com',
        created: '2000-01-01',
        createdDate: '2000-01-02',
        creation_date: '2000-01-03'
      };

      const result = (DomainInfoService as any).parseWhoisData(rawData);

      expect(result.creationDate).toBeDefined();
    });
  });

  describe('calculateRiskScore', () => {
    it('should return zero score for undefined inputs', () => {
      const result = DomainInfoService.calculateRiskScore(undefined, undefined);
      expect(result.score).toBe(0);
      expect(result.factors).toHaveLength(0);
    });

    it('should add score for recently registered domain', () => {
      const result = DomainInfoService.calculateRiskScore({
        domainAge: 10,
        isRecentlyRegistered: true,
        whoisUrl: 'https://who.is/whois/example.com'
      });
      expect(result.score).toBe(40);
      expect(result.factors.some(f => f.includes('recently'))).toBe(true);
    });

    it('should add score for domain less than 90 days old', () => {
      const result = DomainInfoService.calculateRiskScore({
        domainAge: 60,
        isRecentlyRegistered: false,
        whoisUrl: 'https://who.is/whois/example.com'
      });
      expect(result.score).toBe(20);
      expect(result.factors.some(f => f.includes('new'))).toBe(true);
    });

    it('should not add score for old domains', () => {
      const result = DomainInfoService.calculateRiskScore({
        domainAge: 365,
        isRecentlyRegistered: false,
        whoisUrl: 'https://who.is/whois/example.com'
      });
      expect(result.score).toBe(0);
    });

    it('should add score for self-signed certificate', () => {
      const result = DomainInfoService.calculateRiskScore(undefined, { isSelfSigned: true });
      expect(result.score).toBe(25);
      expect(result.factors).toContain('Self-signed SSL certificate');
    });

    it('should add score for recently issued certificate', () => {
      const result = DomainInfoService.calculateRiskScore(undefined, { issuedRecently: true });
      expect(result.score).toBe(15);
    });

    it('should add score for soon-expiring certificate', () => {
      const result = DomainInfoService.calculateRiskScore(undefined, { daysUntilExpiry: 3 });
      expect(result.score).toBe(10);
    });
  });

  describe('getCertificateInfo', () => {
    it('should return certificate info for valid HTTPS URL', async () => {
      const result = await DomainInfoService.getCertificateInfo('https://example.com');
      expect(result).toBeDefined();
    });

    it('should return null for invalid URL', async () => {
      const result = await DomainInfoService.getCertificateInfo('not-a-url');
      expect(result).toBeNull();
    });
  });

  describe('rate limiting', () => {
    it('should enforce rate limiting between requests', async () => {
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: async () => ({ domain: 'example.com' })
      });

      const start = Date.now();

      // Make two rapid requests
      await DomainInfoService.getDomainInfo('example1.com');
      await DomainInfoService.getDomainInfo('example2.com');

      const elapsed = Date.now() - start;

      // Should take at least 1 second due to rate limiting
      expect(elapsed).toBeGreaterThanOrEqual(1000);
    });
  });

  describe('cache behavior', () => {
    it('should cache successful responses', async () => {
      const mockData = {
        domain: 'example.com',
        registrar: 'Test'
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockData
      });

      // First request
      const result1 = await DomainInfoService.getDomainInfo('example.com');

      // Second request - should use cache
      const result2 = await DomainInfoService.getDomainInfo('example.com');

      // Fetch should only be called once
      expect(global.fetch).toHaveBeenCalledTimes(1);
      expect(result1).toEqual(result2);
    });
  });
});
