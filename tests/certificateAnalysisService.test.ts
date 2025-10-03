import { CertificateAnalysisService } from '../src/services/certificateAnalysisService';

// Mock fetch globally
global.fetch = jest.fn();

describe('CertificateAnalysisService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('analyzeCertificate', () => {
    it('should return error when no certificates found', async () => {
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => []
      });

      const result = await CertificateAnalysisService.analyzeCertificate('example.com');

      expect(result.error).toBe('No certificates found in CT logs');
      expect(result.riskPoints).toBe(0);
      expect(result.certAgeDays).toBeNull();
    });

    it('should detect very new certificates (<24 hours)', async () => {
      const now = Date.now();
      const twelveHoursAgo = new Date(now - 12 * 60 * 60 * 1000).toISOString();

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => [{
          issuer_name: "C=US, O=Let's Encrypt, CN=R3",
          not_before: twelveHoursAgo,
          not_after: new Date(now + 90 * 24 * 60 * 60 * 1000).toISOString(),
          name_value: 'example.com',
          min_cert_id: 123,
          min_entry_timestamp: twelveHoursAgo
        }]
      });

      const result = await CertificateAnalysisService.analyzeCertificate('example.com');

      expect(result.isVeryNewCert).toBe(true);
      expect(result.isNewCert).toBe(true);
      expect(result.riskPoints).toBeGreaterThanOrEqual(25);
      expect(result.riskFactors.length).toBeGreaterThan(0);
    });

    it('should detect new certificates (<7 days)', async () => {
      const now = Date.now();
      const threeDaysAgo = new Date(now - 3 * 24 * 60 * 60 * 1000).toISOString();

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => [{
          issuer_name: "C=US, O=DigiCert Inc, CN=DigiCert",
          not_before: threeDaysAgo,
          not_after: new Date(now + 90 * 24 * 60 * 60 * 1000).toISOString(),
          name_value: 'example.com',
          min_cert_id: 123,
          min_entry_timestamp: threeDaysAgo
        }]
      });

      const result = await CertificateAnalysisService.analyzeCertificate('example.com');

      expect(result.isNewCert).toBe(true);
      expect(result.isVeryNewCert).toBe(false);
      expect(result.riskPoints).toBeGreaterThanOrEqual(15);
    });

    it('should detect free CA certificates', async () => {
      const now = Date.now();
      const twoDaysAgo = new Date(now - 2 * 24 * 60 * 60 * 1000).toISOString();

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => [{
          issuer_name: "C=US, O=Let's Encrypt, CN=R3",
          not_before: twoDaysAgo,
          not_after: new Date(now + 90 * 24 * 60 * 60 * 1000).toISOString(),
          name_value: 'example.com',
          min_cert_id: 123,
          min_entry_timestamp: twoDaysAgo
        }]
      });

      const result = await CertificateAnalysisService.analyzeCertificate('example.com');

      expect(result.isFreeCA).toBe(true);
      expect(result.riskFactors).toContain(expect.stringContaining('Free automated certificate'));
    });

    it('should handle API errors', async () => {
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 500
      });

      const result = await CertificateAnalysisService.analyzeCertificate('example.com');

      expect(result.error).toBe('API returned 500');
      expect(result.riskPoints).toBe(0);
    });

    it('should find the newest certificate when multiple exist', async () => {
      const now = Date.now();
      const oneDayAgo = new Date(now - 1 * 24 * 60 * 60 * 1000).toISOString();
      const tenDaysAgo = new Date(now - 10 * 24 * 60 * 60 * 1000).toISOString();

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => [
          {
            issuer_name: "C=US, O=Let's Encrypt",
            not_before: tenDaysAgo,
            not_after: new Date(now + 80 * 24 * 60 * 60 * 1000).toISOString(),
            name_value: 'example.com',
            min_cert_id: 100,
            min_entry_timestamp: tenDaysAgo
          },
          {
            issuer_name: "C=US, O=Let's Encrypt",
            not_before: oneDayAgo,
            not_after: new Date(now + 89 * 24 * 60 * 60 * 1000).toISOString(),
            name_value: 'example.com',
            min_cert_id: 123,
            min_entry_timestamp: oneDayAgo
          }
        ]
      });

      const result = await CertificateAnalysisService.analyzeCertificate('example.com');

      expect(result.certAgeDays).toBeLessThanOrEqual(2);
      expect(result.isNewCert).toBe(true);
    });
  });

  describe('generateSummary', () => {
    it('should return unavailable message when no certificate data', () => {
      const analysis = {
        certAgeDays: null,
        certAgeHours: null,
        isNewCert: false,
        isVeryNewCert: false,
        isFreeCA: false,
        issuer: null,
        notBefore: null,
        riskPoints: 0,
        riskFactors: [],
        error: 'No data'
      };

      const summary = CertificateAnalysisService.generateSummary(analysis);
      expect(summary).toBe('Certificate information unavailable');
    });

    it('should show warning for very new certificates', () => {
      const analysis = {
        certAgeDays: 0.5,
        certAgeHours: 12,
        isNewCert: true,
        isVeryNewCert: true,
        isFreeCA: true,
        issuer: "C=US, O=Let's Encrypt, CN=R3",
        notBefore: new Date().toISOString(),
        riskPoints: 35,
        riskFactors: []
      };

      const summary = CertificateAnalysisService.generateSummary(analysis);
      expect(summary).toContain('⚠️');
      expect(summary).toContain('12h ago');
    });
  });

  describe('isHighRiskPattern', () => {
    it('should detect high risk: very new cert + very new domain + free CA', () => {
      const certAnalysis = {
        certAgeDays: 1,
        certAgeHours: 24,
        isNewCert: true,
        isVeryNewCert: true,
        isFreeCA: true,
        issuer: "Let's Encrypt",
        notBefore: new Date().toISOString(),
        riskPoints: 35,
        riskFactors: []
      };

      const isHighRisk = CertificateAnalysisService.isHighRiskPattern(certAnalysis, 5);
      expect(isHighRisk).toBe(true);
    });

    it('should detect moderate risk: new cert + new domain', () => {
      const certAnalysis = {
        certAgeDays: 5,
        certAgeHours: 120,
        isNewCert: true,
        isVeryNewCert: false,
        isFreeCA: false,
        issuer: "DigiCert",
        notBefore: new Date().toISOString(),
        riskPoints: 15,
        riskFactors: []
      };

      const isHighRisk = CertificateAnalysisService.isHighRiskPattern(certAnalysis, 25);
      expect(isHighRisk).toBe(true);
    });

    it('should not flag old certificates as high risk', () => {
      const certAnalysis = {
        certAgeDays: 365,
        certAgeHours: 8760,
        isNewCert: false,
        isVeryNewCert: false,
        isFreeCA: true,
        issuer: "Let's Encrypt",
        notBefore: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString(),
        riskPoints: 0,
        riskFactors: []
      };

      const isHighRisk = CertificateAnalysisService.isHighRiskPattern(certAnalysis, 400);
      expect(isHighRisk).toBe(false);
    });
  });
});
