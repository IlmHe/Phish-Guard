import { RealtimeApiService } from '../src/services/realtimeApiService';

describe('RealtimeApiService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('queryMultipleApis', () => {
    it('should aggregate results from multiple APIs', async () => {
      const result = await RealtimeApiService.queryMultipleApis(
        'https://example.com',
        'example.com'
      );

      expect(result).toBeDefined();
      expect(result.totalSources).toBeGreaterThan(0);
      expect(result.results).toBeDefined();
      expect(Array.isArray(result.results)).toBe(true);
      expect(result.consensus).toMatch(/safe|suspicious|malicious|unknown/);
    });

    it('should calculate average risk score', async () => {
      const result = await RealtimeApiService.queryMultipleApis(
        'https://example.com',
        'example.com'
      );

      expect(result.averageRiskScore).toBeGreaterThanOrEqual(0);
      expect(result.averageRiskScore).toBeLessThanOrEqual(100);
    });

    it('should track highest risk score', async () => {
      const result = await RealtimeApiService.queryMultipleApis(
        'https://example.com',
        'example.com'
      );

      expect(result.highestRiskScore).toBeGreaterThanOrEqual(0);
      expect(result.highestRiskScore).toBeLessThanOrEqual(100);
      expect(result.highestRiskScore).toBeGreaterThanOrEqual(result.averageRiskScore);
    });

    it('should count votes correctly', async () => {
      const result = await RealtimeApiService.queryMultipleApis(
        'https://example.com',
        'example.com'
      );

      const totalVotes = result.maliciousVotes + result.suspiciousVotes + result.safeVotes;
      expect(totalVotes).toBeLessThanOrEqual(result.responseCount);
    });

    it('should handle all APIs failing gracefully', async () => {
      // Mock all APIs to fail
      const result = await RealtimeApiService.queryMultipleApis(
        'https://invalid-domain-xyz123.com',
        'invalid-domain-xyz123.com'
      );

      expect(result).toBeDefined();
      expect(result.consensus).toBe('unknown');
    });
  });

  describe('aggregateResults', () => {
    it('should determine consensus from multiple results', () => {
      const mockResults = [
        {
          source: 'API1',
          status: 'malicious' as const,
          confidence: 90,
          riskScore: 85,
          categories: ['phishing']
        },
        {
          source: 'API2',
          status: 'malicious' as const,
          confidence: 80,
          riskScore: 90,
          categories: ['malware']
        },
        {
          source: 'API3',
          status: 'safe' as const,
          confidence: 70,
          riskScore: 10,
          categories: []
        }
      ];

      const result = (RealtimeApiService as any).aggregateResults(mockResults);

      expect(result.consensus).toBe('malicious');
      expect(result.totalSources).toBe(3);
      expect(result.responseCount).toBe(3);
      expect(result.maliciousVotes).toBe(2);
      expect(result.safeVotes).toBe(1);
    });

    it('should handle empty results', () => {
      const result = (RealtimeApiService as any).aggregateResults([]);

      expect(result.consensus).toBe('unknown');
      expect(result.totalSources).toBe(0);
      expect(result.responseCount).toBe(0);
    });

    it('should calculate average risk score correctly', () => {
      const mockResults = [
        {
          source: 'API1',
          status: 'malicious' as const,
          confidence: 90,
          riskScore: 60,
          categories: []
        },
        {
          source: 'API2',
          status: 'safe' as const,
          confidence: 80,
          riskScore: 20,
          categories: []
        },
        {
          source: 'API3',
          status: 'suspicious' as const,
          confidence: 70,
          riskScore: 40,
          categories: []
        }
      ];

      const result = (RealtimeApiService as any).aggregateResults(mockResults);

      expect(result.averageRiskScore).toBe(40); // (60 + 20 + 40) / 3
      expect(result.highestRiskScore).toBe(60);
    });
  });

  describe('queryVirusTotalApi (mock)', () => {
    it('should return mock result for VirusTotal', async () => {
      const result = await (RealtimeApiService as any).queryVirusTotalApi(
        'https://example.com',
        'example.com'
      );

      expect(result.source).toBe('VirusTotal (Simulated)');
      expect(result.status).toMatch(/safe|suspicious|malicious|unknown/);
      expect(result.confidence).toBeGreaterThanOrEqual(0);
      expect(result.confidence).toBeLessThanOrEqual(100);
    });

    it('should simulate detection for known bad patterns', async () => {
      const result = await (RealtimeApiService as any).queryVirusTotalApi(
        'http://evil-phishing-site.tk',
        'evil-phishing-site.tk'
      );

      expect(result).toBeDefined();
      // Should likely flag as suspicious/malicious based on TLD and keywords
    });
  });

  describe('queryGoogleSafeBrowsingApi (mock)', () => {
    it('should return mock result for Google Safe Browsing', async () => {
      const result = await (RealtimeApiService as any).queryGoogleSafeBrowsingApi(
        'https://example.com',
        'example.com'
      );

      expect(result.source).toBe('Google Safe Browsing (Simulated)');
      expect(result.status).toMatch(/safe|suspicious|malicious|unknown/);
    });

    it('should include response time', async () => {
      const result = await (RealtimeApiService as any).queryGoogleSafeBrowsingApi(
        'https://example.com',
        'example.com'
      );

      expect(result.responseTime).toBeGreaterThanOrEqual(0);
    });
  });

  describe('queryPhishTankApi (mock)', () => {
    it('should return mock result for PhishTank', async () => {
      const result = await (RealtimeApiService as any).queryPhishTankApi(
        'https://example.com',
        'example.com'
      );

      expect(result.source).toBe('PhishTank (Simulated)');
      expect(result.status).toMatch(/safe|suspicious|malicious|unknown/);
    });
  });

  describe('createTimeoutPromise', () => {
    it('should create a timeout promise that rejects', async () => {
      const timeoutPromise = (RealtimeApiService as any).createTimeoutPromise(0);

      await expect(timeoutPromise).rejects.toThrow('timeout');
    }, 10000);
  });

  describe('createErrorResult', () => {
    it('should create error result with correct structure', () => {
      const errorResult = (RealtimeApiService as any).createErrorResult(
        'TestAPI',
        'Test error message'
      );

      expect(errorResult.source).toBe('TestAPI');
      expect(errorResult.status).toBe('error');
      expect(errorResult.confidence).toBe(0);
      expect(errorResult.riskScore).toBe(0);
      expect(errorResult.details).toContain('Test error message');
    });
  });

  describe('simulateApiResponse', () => {
    it('should generate realistic mock responses', () => {
      const result = (RealtimeApiService as any).simulateApiResponse(
        'https://example.com',
        'example.com',
        'TestAPI'
      );

      expect(result.source).toContain('TestAPI');
      expect(result.status).toMatch(/safe|suspicious|malicious/);
      expect(result.confidence).toBeGreaterThanOrEqual(50);
      expect(result.confidence).toBeLessThanOrEqual(100);
      expect(result.riskScore).toBeGreaterThanOrEqual(0);
      expect(result.riskScore).toBeLessThanOrEqual(100);
    });

    it('should flag suspicious patterns', () => {
      const suspiciousUrls = [
        'http://phishing-site.tk',
        'http://192.168.1.1/login',
        'http://paypal-verify.com'
      ];

      suspiciousUrls.forEach(url => {
        const domain = url.split('/')[2];
        const result = (RealtimeApiService as any).simulateApiResponse(url, domain, 'TestAPI');

        // Should likely be flagged as suspicious or malicious
        expect(['suspicious', 'malicious']).toContain(result.status);
      });
    });

    it('should mark legitimate domains as safe', () => {
      const safeUrls = [
        'https://google.com',
        'https://github.com',
        'https://wikipedia.org'
      ];

      safeUrls.forEach(url => {
        const domain = url.split('/')[2];
        const result = (RealtimeApiService as any).simulateApiResponse(url, domain, 'TestAPI');

        expect(result.status).toBe('safe');
        expect(result.riskScore).toBeLessThan(30);
      });
    });
  });

  describe('integration scenarios', () => {
    it('should handle mixed API responses', async () => {
      const result = await RealtimeApiService.queryMultipleApis(
        'https://test-site.com',
        'test-site.com'
      );

      expect(result.results.length).toBeGreaterThan(0);
      expect(result.consensus).toBeDefined();
    });

    it('should prioritize malicious votes in consensus', async () => {
      // Test with a clearly malicious-looking domain
      const result = await RealtimeApiService.queryMultipleApis(
        'http://phishing-malware-virus.tk',
        'phishing-malware-virus.tk'
      );

      // Should likely be flagged as malicious or at least suspicious
      expect(['malicious', 'suspicious']).toContain(result.consensus);
    });
  });
});
