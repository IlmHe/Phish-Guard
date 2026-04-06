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
        domainAge: 30,
        isRecentlyRegistered: true,
        registrar: 'Test Registrar',
        registrationDate: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
        expirationDate: new Date(Date.now() + 335 * 24 * 60 * 60 * 1000).toISOString(),
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

    it('should detect suspicious TLD domains', async () => {
      const result = await ReputationService.calculateReputation(
        'http://evil.tk',
        'evil.tk',
        undefined, undefined, undefined, 'not_found', false
      );
      expect(result.overall).toBeGreaterThan(0);
      expect(result.factors.some(f => f.category === 'Domain Structure')).toBe(true);
    });

    it('should detect long URLs', async () => {
      const longUrl = 'https://example.com/' + 'a'.repeat(200);
      const result = await ReputationService.calculateReputation(
        longUrl, 'example.com',
        undefined, undefined, undefined, 'not_found', false
      );
      expect(result.factors.some(f => f.description.includes('long URL'))).toBe(true);
    });

    it('should detect URL shorteners', async () => {
      const result = await ReputationService.calculateReputation(
        'https://bit.ly/abc123', 'bit.ly',
        undefined, undefined, undefined, 'not_found', false
      );
      expect(result.factors.some(f => f.description.includes('shortener'))).toBe(true);
    });

    it('should detect suspicious registrar', async () => {
      const domainInfo = {
        domainAge: 365,
        isRecentlyRegistered: false,
        registrar: 'Freenom',
        registrationDate: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString(),
      };
      const result = await ReputationService.calculateReputation(
        'https://example.com', 'example.com',
        domainInfo, undefined, undefined, 'not_found', false
      );
      expect(result.factors.some(f => f.category === 'Registrar')).toBe(true);
    });

    it('should detect self-signed certificate', async () => {
      const certInfo = { isSelfSigned: true };
      const result = await ReputationService.calculateReputation(
        'https://example.com', 'example.com',
        undefined, certInfo, undefined, 'not_found', false
      );
      expect(result.factors.some(f => f.description.includes('Self-signed'))).toBe(true);
    });

    it('should detect recently issued certificate', async () => {
      const certInfo = { issuedRecently: true };
      const result = await ReputationService.calculateReputation(
        'https://example.com', 'example.com',
        undefined, certInfo, undefined, 'not_found', false
      );
      expect(result.factors.some(f => f.description.includes('issued'))).toBe(true);
    });

    it('should detect direct IP address URL', async () => {
      const result = await ReputationService.calculateReputation(
        'http://192.168.1.1/page', '192.168.1.1',
        undefined, undefined, undefined, 'not_found', false
      );
      expect(result.factors.some(f => f.category === 'Network')).toBe(true);
    });

    it('should detect excessive subdomains', async () => {
      const result = await ReputationService.calculateReputation(
        'https://a.b.c.d.evil.com', 'a.b.c.d.evil.com',
        undefined, undefined, undefined, 'not_found', false
      );
      expect(result.factors.some(f => f.description.includes('subdomains'))).toBe(true);
    });
  });

  describe('getRiskDescription', () => {
    it('should return description for low risk with score 0', () => {
      expect(ReputationService.getRiskDescription('low', 0)).toContain('No threat');
    });

    it('should return description for low risk with non-zero score', () => {
      expect(ReputationService.getRiskDescription('low', 10)).toContain('safe');
    });

    it('should return description for medium risk', () => {
      expect(ReputationService.getRiskDescription('medium')).toContain('caution');
    });

    it('should return description for high risk', () => {
      expect(ReputationService.getRiskDescription('high')).toContain('risk factor');
    });

    it('should return description for critical risk', () => {
      expect(ReputationService.getRiskDescription('critical')).toContain('malicious');
    });
  });

  describe('getRiskClass', () => {
    it('should return success class for low risk', () => {
      expect(ReputationService.getRiskClass('low')).toBe('is-success');
    });

    it('should return warning class for medium risk', () => {
      expect(ReputationService.getRiskClass('medium')).toBe('is-warning');
    });

    it('should return danger class for high risk', () => {
      expect(ReputationService.getRiskClass('high')).toBe('is-danger');
    });

    it('should return danger class for critical risk', () => {
      expect(ReputationService.getRiskClass('critical')).toBe('is-danger');
    });
  });
});
