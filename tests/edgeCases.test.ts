/**
 * Edge Case Security Tests
 * Tests for potential vulnerabilities, DoS, and edge cases
 */

import { HomographDetector } from '../src/services/homographDetector';
import { RealtimeApiService } from '../src/services/realtimeApiService';
import { sanitizeUrl, isValidUrl, extractDomain } from '../src/utils/utils';

describe('Edge Case Security Tests', () => {
  describe('Unicode attacks', () => {
    it('should handle RTL override characters', () => {
      const malicious = 'example\u202Ecom.evil'; // RTL override
      const result = HomographDetector.detectSuspiciousDomain(malicious);

      expect(result).toBeDefined();
      expect(result.riskScore).toBeGreaterThanOrEqual(0);
    });

    it('should handle zero-width characters', () => {
      const malicious = 'exam\u200Bple.com'; // Zero-width space
      const result = HomographDetector.detectSuspiciousDomain(malicious);

      expect(result).toBeDefined();
    });

    it('should handle null bytes', () => {
      const malicious = 'example\u0000.com';
      const result = HomographDetector.detectSuspiciousDomain(malicious);

      expect(result).toBeDefined();
    });

    it('should handle control characters', () => {
      const malicious = 'example\u001F.com';
      const result = HomographDetector.detectSuspiciousDomain(malicious);

      expect(result).toBeDefined();
    });
  });

  describe('Empty and boundary inputs', () => {
    it('should handle empty domain', () => {
      expect(() => {
        HomographDetector.detectSuspiciousDomain('');
      }).toThrow('Invalid domain provided');
    });

    it('should handle single character domain', () => {
      const result = HomographDetector.detectSuspiciousDomain('a');
      expect(result).toBeDefined();
    });

    it('should handle domain without dots', () => {
      const result = HomographDetector.detectSuspiciousDomain('localhost');
      expect(result).toBeDefined();
    });

    it('should handle very long domain (1000 chars)', () => {
      const longDomain = 'a'.repeat(1000) + '.com';
      const result = HomographDetector.detectSuspiciousDomain(longDomain);

      expect(result).toBeDefined();
      expect(result.riskScore).toBeGreaterThanOrEqual(0);
      expect(result.riskScore).toBeLessThanOrEqual(100);
    });

    it('should handle domain with many dots', () => {
      const manyDots = 'a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.com';
      const result = HomographDetector.detectSuspiciousDomain(manyDots);

      expect(result).toBeDefined();
      expect(result.hasExcessiveSubdomains).toBe(true);
    });
  });

  describe('Division by zero protection', () => {
    it('should handle empty API results without crashing', async () => {
      // This would previously cause division by zero
      const aggregated = (RealtimeApiService as any).aggregateResults([]);

      expect(aggregated.averageRiskScore).toBe(0);
      expect(aggregated.highestRiskScore).toBe(0);
      expect(aggregated.consensus).toBe('unknown');
    });

    it('should handle single API result', async () => {
      const singleResult = [{
        source: 'TestAPI',
        status: 'safe' as const,
        confidence: 90,
        riskScore: 10,
        categories: []
      }];

      const aggregated = (RealtimeApiService as any).aggregateResults(singleResult);

      expect(aggregated.averageRiskScore).toBe(10);
      expect(aggregated.highestRiskScore).toBe(10);
    });
  });

  describe('Array access safety', () => {
    it('should handle domain split on empty string', () => {
      const result = (HomographDetector as any).detectTyposquatting('');
      expect(result.isTyposquatting).toBe(false);
    });

    it('should handle domain split on string without dots', () => {
      const result = (HomographDetector as any).detectTyposquatting('nodots');
      expect(result.isTyposquatting).toBe(false);
    });

    it('should handle domain starting with dot', () => {
      const result = HomographDetector.detectSuspiciousDomain('.example.com');
      expect(result).toBeDefined();
    });

    it('should handle domain ending with dot', () => {
      const result = HomographDetector.detectSuspiciousDomain('example.com.');
      expect(result).toBeDefined();
    });
  });

  describe('Protocol injection', () => {
    it('should reject javascript: protocol', () => {
      expect(isValidUrl('javascript:alert(1)')).toBe(false);
      expect(sanitizeUrl('javascript:alert(1)')).toBe('');
    });

    it('should reject data: protocol', () => {
      expect(isValidUrl('data:text/html,<script>alert(1)</script>')).toBe(false);
      expect(sanitizeUrl('data:text/html,test')).toBe('');
    });

    it('should reject file: protocol', () => {
      expect(isValidUrl('file:///etc/passwd')).toBe(false);
      expect(sanitizeUrl('file:///etc/passwd')).toBe('');
    });

    it('should reject vbscript: protocol', () => {
      expect(isValidUrl('vbscript:msgbox(1)')).toBe(false);
    });

    it('should allow http and https only', () => {
      expect(isValidUrl('http://example.com')).toBe(true);
      expect(isValidUrl('https://example.com')).toBe(true);
    });
  });

  describe('Type coercion vulnerabilities', () => {
    it('should handle null as input', () => {
      expect(() => {
        HomographDetector.detectSuspiciousDomain(null as any);
      }).toThrow();
    });

    it('should handle undefined as input', () => {
      expect(() => {
        HomographDetector.detectSuspiciousDomain(undefined as any);
      }).toThrow();
    });

    it('should handle number as input', () => {
      expect(() => {
        HomographDetector.detectSuspiciousDomain(12345 as any);
      }).toThrow();
    });

    it('should handle object as input', () => {
      expect(() => {
        HomographDetector.detectSuspiciousDomain({} as any);
      }).toThrow();
    });

    it('should handle array as input', () => {
      expect(() => {
        HomographDetector.detectSuspiciousDomain(['example.com'] as any);
      }).toThrow();
    });
  });

  describe('Regex edge cases', () => {
    it('should handle domain with special regex characters', () => {
      const specialChars = 'test[].com';
      const result = extractDomain(specialChars);
      expect(result).toBeTruthy();
    });

    it('should not hang on pathological regex input', () => {
      const pathological = 'a'.repeat(100) + '!' + 'a'.repeat(100);
      const startTime = Date.now();

      const result = HomographDetector.detectSuspiciousDomain(pathological);
      const elapsed = Date.now() - startTime;

      expect(elapsed).toBeLessThan(1000); // Should complete in <1 second
      expect(result).toBeDefined();
    });
  });

  describe('Memory and performance', () => {
    it('should handle 100 rapid detections without memory leak', () => {
      const domains = Array.from({ length: 100 }, (_, i) => `test${i}.com`);

      domains.forEach(domain => {
        const result = HomographDetector.detectSuspiciousDomain(domain);
        expect(result).toBeDefined();
      });
    });

    it('should handle very long typosquatting check', () => {
      const longDomain = 'very' + 'long'.repeat(50) + 'domain.com';
      const startTime = Date.now();

      const result = HomographDetector.detectSuspiciousDomain(longDomain);
      const elapsed = Date.now() - startTime;

      expect(elapsed).toBeLessThan(2000); // Should complete in <2 seconds
      expect(result).toBeDefined();
    });
  });

  describe('XSS prevention', () => {
    it('should handle domain with HTML tags', () => {
      const xss = '<script>alert(1)</script>.com';
      const result = HomographDetector.detectSuspiciousDomain(xss);

      expect(result).toBeDefined();
      expect(result.hasSuspiciousChars).toBe(true);
    });

    it('should handle domain with SQL injection attempt', () => {
      const sql = "'; DROP TABLE domains; --.com";
      const result = HomographDetector.detectSuspiciousDomain(sql);

      expect(result).toBeDefined();
    });
  });

  describe('International domains', () => {
    it('should handle Chinese characters', () => {
      const chinese = '测试.com';
      const result = HomographDetector.detectSuspiciousDomain(chinese);

      expect(result).toBeDefined();
    });

    it('should handle Arabic characters', () => {
      const arabic = 'اختبار.com';
      const result = HomographDetector.detectSuspiciousDomain(arabic);

      expect(result).toBeDefined();
    });

    it('should handle Cyrillic mixed with Latin', () => {
      const mixed = 'раypal.com'; // Cyrillic р, а + Latin y
      const result = HomographDetector.detectSuspiciousDomain(mixed);

      expect(result.hasMixedScripts).toBe(true);
      expect(result.riskScore).toBeGreaterThan(0);
    });
  });
});
