import { HomographDetector } from '../src/services/homographDetector';

describe('HomographDetector', () => {
  describe('detectSuspiciousDomain', () => {
    it('should detect safe domains correctly', () => {
      const result = HomographDetector.detectSuspiciousDomain('google.com');
      expect(result.recommendation).toBe('safe');
      expect(result.riskScore).toBe(0);
      expect(result.suspiciousPatterns).toHaveLength(0);
    });

    it('should detect punycode domains', () => {
      const result = HomographDetector.detectSuspiciousDomain('xn--googl-fsa.com');
      expect(result.hasPunycode).toBe(true);
      expect(result.suspiciousPatterns).toContain('punycode_encoding');
      expect(result.riskScore).toBeGreaterThan(0);
    });

    it('should detect mixed scripts', () => {
      const result = HomographDetector.detectSuspiciousDomain('gооgle.com'); // Contains Cyrillic о
      expect(result.hasMixedScripts).toBe(true);
      expect(result.suspiciousPatterns).toContain('mixed_scripts');
    });

    it('should detect lookalike characters', () => {
      const result = HomographDetector.detectSuspiciousDomain('g0ogle.com'); // 0 instead of o
      expect(result.hasLookalikeChars).toBe(true);
      expect(result.suspiciousPatterns).toContain('lookalike_characters');
    });

    it('should detect number-letter mixing', () => {
      const result = HomographDetector.detectSuspiciousDomain('g00gle.com');
      expect(result.hasNumberLetterMix).toBe(true);
      expect(result.suspiciousPatterns).toContain('number_letter_substitution');
    });

    it('should detect excessive subdomains', () => {
      const result = HomographDetector.detectSuspiciousDomain('a.b.c.d.e.google.com');
      expect(result.hasExcessiveSubdomains).toBe(true);
      expect(result.suspiciousPatterns).toContain('excessive_subdomains');
    });

    it('should detect typosquatting of popular domains', () => {
      const result = HomographDetector.detectSuspiciousDomain('g00gle.com');
      expect(result.suspiciousPatterns.length).toBeGreaterThan(0);
      expect(result.riskScore).toBeGreaterThan(20);
    });

    it('should assign appropriate risk levels', () => {
      const dangerousResult = HomographDetector.detectSuspiciousDomain('xn--g00gl3-evil.com');
      expect(dangerousResult.recommendation).toBe('dangerous');
      expect(dangerousResult.riskScore).toBeGreaterThanOrEqual(60);

      const safeResult = HomographDetector.detectSuspiciousDomain('legitimate-site.com');
      expect(safeResult.recommendation).toBe('safe');
      expect(safeResult.riskScore).toBeLessThan(30);
    });

    it('should handle invalid input gracefully', () => {
      expect(() => {
        HomographDetector.detectSuspiciousDomain('');
      }).toThrow('Invalid domain provided');

      expect(() => {
        HomographDetector.detectSuspiciousDomain(null as any);
      }).toThrow('Invalid domain provided');
    });

    it('should provide useful detection summary', () => {
      const analysis = HomographDetector.detectSuspiciousDomain('g00gle.com');
      const summary = HomographDetector.getDetectionSummary(analysis);

      expect(summary).toContain('Risk Level:');
      expect(summary).toContain('Score:');

      if (analysis.suspiciousPatterns.length > 0) {
        expect(summary).toContain('Suspicious patterns:');
      }
    });
  });
});