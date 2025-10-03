import { ReputationService } from '../src/services/reputationService';
import { HomographDetector, SuspiciousDomainAnalysis } from '../src/services/homographDetector';
import { CertificateAnalysisService, CertificateAnalysis } from '../src/services/certificateAnalysisService';

// Mock dependencies
jest.mock('../src/services/realtimeApiService');

describe('ReputationService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('calculateReputation', () => {
    it('should calculate low risk for safe domain', async () => {
      const homographAnalysis: SuspiciousDomainAnalysis = {
        hasSuspiciousChars: false,
        hasMixedScripts: false,
        hasPunycode: false,
        hasExcessiveSubdomains: false,
        hasNumberLetterMix: false,
        hasLookalikeChars: false,
        suspiciousPatterns: [],
        riskScore: 0,
        recommendation: 'safe'
      };

      const result = await ReputationService.calculateReputation(
        'https://google.com',
        'google.com',
        undefined,
        undefined,
        homographAnalysis,
        'not_found',
        false
      );

      expect(result.overall).toBeLessThan(30);
      expect(result.riskLevel).toBe('low');
    });

    it('should assign critical risk when found in phishing database', async () => {
      const result = await ReputationService.calculateReputation(
        'https://evil.com',
        'evil.com',
        undefined,
        undefined,
        undefined,
        'found',
        false
      );

      expect(result.overall).toBeGreaterThanOrEqual(80);
      expect(result.riskLevel).toBe('critical');
      expect(result.factors).toContainEqual(
        expect.objectContaining({
          category: 'Known Threats',
          impact: 80
        })
      );
    });

    it('should integrate homograph analysis risk', async () => {
      const homographAnalysis: SuspiciousDomainAnalysis = {
        hasSuspiciousChars: true,
        hasMixedScripts: true,
        hasPunycode: false,
        hasExcessiveSubdomains: false,
        hasNumberLetterMix: false,
        hasLookalikeChars: true,
        suspiciousPatterns: ['mixed_scripts', 'lookalike_characters'],
        riskScore: 75,
        recommendation: 'dangerous'
      };

      const result = await ReputationService.calculateReputation(
        'https://gооgle.com',
        'gооgle.com',
        undefined,
        undefined,
        homographAnalysis,
        'not_found',
        false
      );

      expect(result.overall).toBeGreaterThan(30);
      expect(result.factors.length).toBeGreaterThan(0);
    });

    it('should integrate certificate analysis results', async () => {
      // Certificate analysis is done internally, test by checking result
      const result = await ReputationService.calculateReputation(
        'https://suspicious.com',
        'suspicious.com',
        undefined,
        undefined,
        undefined,
        'not_found',
        true // Enable API checks to run cert analysis
      );

      // Should complete without error
      expect(result.overall).toBeGreaterThanOrEqual(0);
      expect(result.riskLevel).toBeDefined();
    });

    it('should detect suspicious domain patterns', async () => {
      const result = await ReputationService.calculateReputation(
        'http://paypal-verify-security.tk',
        'paypal-verify-security.tk',
        undefined,
        undefined,
        undefined,
        'not_found',
        false
      );

      expect(result.overall).toBeGreaterThan(30);
      expect(result.factors.length).toBeGreaterThan(0);
    });

    it('should cap risk score at 100', async () => {
      const homographAnalysis: SuspiciousDomainAnalysis = {
        hasSuspiciousChars: true,
        hasMixedScripts: true,
        hasPunycode: true,
        hasExcessiveSubdomains: true,
        hasNumberLetterMix: true,
        hasLookalikeChars: true,
        suspiciousPatterns: ['all', 'the', 'patterns'],
        riskScore: 100,
        recommendation: 'dangerous'
      };

      const result = await ReputationService.calculateReputation(
        'http://192.168.1.1',
        '192.168.1.1',
        undefined,
        undefined,
        homographAnalysis,
        'found',
        false
      );

      expect(result.overall).toBeLessThanOrEqual(100);
    });

    it('should assign correct risk levels based on score', async () => {
      // Test low risk
      const lowResult = await ReputationService.calculateReputation(
        'https://google.com',
        'google.com',
        undefined,
        undefined,
        undefined,
        'not_found',
        false
      );
      expect(lowResult.riskLevel).toBe('low');

      // Test critical risk
      const criticalResult = await ReputationService.calculateReputation(
        'https://evil.com',
        'evil.com',
        undefined,
        undefined,
        undefined,
        'found',
        false
      );
      expect(criticalResult.riskLevel).toBe('critical');
    });

    it('should handle domain age analysis', async () => {
      const domainInfo = {
        age: 30,
        registrar: 'Test Registrar',
        creationDate: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
        expirationDate: new Date(Date.now() + 335 * 24 * 60 * 60 * 1000).toISOString(),
        lastUpdated: new Date().toISOString()
      };

      const result = await ReputationService.calculateReputation(
        'https://newsite.com',
        'newsite.com',
        domainInfo,
        undefined,
        undefined,
        'not_found',
        false
      );

      expect(result.factors.some(f => f.category === 'Domain Age')).toBe(true);
    });

    it('should detect non-HTTPS URLs', async () => {
      const result = await ReputationService.calculateReputation(
        'http://example.com',
        'example.com',
        undefined,
        undefined,
        undefined,
        'not_found',
        false
      );

      expect(result.factors.some(f => f.description.includes('HTTPS'))).toBe(true);
    });
  });
});
