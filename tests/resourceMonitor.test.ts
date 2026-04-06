import { ResourceMonitor } from '../src/services/resourceMonitor';

describe('ResourceMonitor', () => {
  beforeEach(() => {
    // Setup DOM environment
    document.body.innerHTML = '';
  });

  describe('scanPageResources', () => {
    it('should scan all resource types on page', () => {
      document.body.innerHTML = `
        <iframe src="https://example.com/frame"></iframe>
        <script src="https://cdn.example.com/script.js"></script>
        <img src="https://images.example.com/photo.jpg" />
        <link href="https://fonts.example.com/style.css" rel="stylesheet" />
      `;

      Object.defineProperty(window, 'location', {
        value: { hostname: 'mysite.com', protocol: 'https:' },
        writable: true
      });

      const result = ResourceMonitor.scanPageResources();

      expect(result.totalResources).toBe(4);
      expect(result.externalDomains.length).toBeGreaterThan(0);
    });

    it('should detect suspicious iframes with IP addresses', () => {
      document.body.innerHTML = '<iframe src="http://192.168.1.1/frame"></iframe>';

      Object.defineProperty(window, 'location', {
        value: { hostname: 'mysite.com', protocol: 'https:' },
        writable: true
      });

      const result = ResourceMonitor.scanPageResources();

      expect(result.suspiciousResources.length).toBeGreaterThan(0);
      expect(result.suspiciousResources[0].riskLevel).toBe('critical');
      expect(result.suspiciousResources[0].reasons).toContainEqual(
        expect.stringContaining('IP address')
      );
    });

    it('should detect mixed content warnings', () => {
      document.body.innerHTML = '<script src="http://example.com/script.js"></script>';

      Object.defineProperty(window, 'location', {
        value: { hostname: 'mysite.com', protocol: 'https:' },
        writable: true
      });

      const result = ResourceMonitor.scanPageResources();

      expect(result.mixedContentWarnings.length).toBeGreaterThan(0);
      expect(result.mixedContentWarnings[0].type).toBe('mixed_content');
      expect(result.mixedContentWarnings[0].insecureUrl).toContain('http://');
    });

    it('should skip known safe CDN domains', () => {
      document.body.innerHTML = `
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0/dist/js/bootstrap.min.js"></script>
      `;

      Object.defineProperty(window, 'location', {
        value: { hostname: 'mysite.com', protocol: 'https:' },
        writable: true
      });

      const result = ResourceMonitor.scanPageResources();

      expect(result.suspiciousResources.length).toBe(0);
      expect(result.riskScore).toBe(0);
    });

    it('should detect free TLD domains', () => {
      document.body.innerHTML = '<script src="https://evil-site.tk/malware.js"></script>';

      Object.defineProperty(window, 'location', {
        value: { hostname: 'mysite.com', protocol: 'https:' },
        writable: true
      });

      const result = ResourceMonitor.scanPageResources();

      expect(result.suspiciousResources.length).toBeGreaterThan(0);
      expect(result.riskScore).toBeGreaterThan(0);
    });

    it('should detect excessive subdomains', () => {
      document.body.innerHTML = '<iframe src="https://a.b.c.d.e.evil.com/frame"></iframe>';

      Object.defineProperty(window, 'location', {
        value: { hostname: 'mysite.com', protocol: 'https:' },
        writable: true
      });

      const result = ResourceMonitor.scanPageResources();

      expect(result.suspiciousResources.length).toBeGreaterThan(0);
      expect(result.suspiciousResources[0].reasons).toContainEqual(
        expect.stringContaining('subdomains')
      );
    });

    it('should deduplicate suspicious resources by URL', () => {
      document.body.innerHTML = `
        <script src="https://evil.tk/script.js"></script>
        <script src="https://evil.tk/script.js"></script>
        <script src="https://evil.tk/script.js"></script>
      `;

      Object.defineProperty(window, 'location', {
        value: { hostname: 'mysite.com', protocol: 'https:' },
        writable: true
      });

      const result = ResourceMonitor.scanPageResources();

      expect(result.suspiciousResources.length).toBe(1);
    });

    it('should calculate risk score correctly', () => {
      document.body.innerHTML = `
        <iframe src="http://192.168.1.1/frame"></iframe>
        <script src="http://evil.tk/malware.js"></script>
      `;

      Object.defineProperty(window, 'location', {
        value: { hostname: 'mysite.com', protocol: 'https:' },
        writable: true
      });

      const result = ResourceMonitor.scanPageResources();

      expect(result.riskScore).toBeGreaterThan(50);
      expect(result.riskScore).toBeLessThanOrEqual(100);
    });

    it('should skip same-domain resources', () => {
      document.body.innerHTML = `
        <script src="https://mysite.com/script.js"></script>
        <img src="https://mysite.com/image.jpg" />
      `;

      Object.defineProperty(window, 'location', {
        value: { hostname: 'mysite.com', protocol: 'https:' },
        writable: true
      });

      const result = ResourceMonitor.scanPageResources();

      expect(result.externalDomains.length).toBe(0);
      expect(result.suspiciousResources.length).toBe(0);
    });

    it('should handle invalid URLs gracefully', () => {
      document.body.innerHTML = '<script src="javascript:alert(1)"></script>';

      Object.defineProperty(window, 'location', {
        value: { hostname: 'mysite.com', protocol: 'https:' },
        writable: true
      });

      const result = ResourceMonitor.scanPageResources();

      // Should not crash
      expect(result.totalResources).toBe(1);
    });

    it('should generate appropriate summary for safe page', () => {
      document.body.innerHTML = '<script src="https://cdnjs.cloudflare.com/lib.js"></script>';

      Object.defineProperty(window, 'location', {
        value: { hostname: 'mysite.com', protocol: 'https:' },
        writable: true
      });

      const result = ResourceMonitor.scanPageResources();

      expect(result.summary).toContain('safe');
    });

    it('should generate appropriate summary for suspicious page', () => {
      document.body.innerHTML = '<iframe src="http://evil.tk/frame"></iframe>';

      Object.defineProperty(window, 'location', {
        value: { hostname: 'mysite.com', protocol: 'https:' },
        writable: true
      });

      const result = ResourceMonitor.scanPageResources();

      expect(result.summary).toContain('suspicious');
    });
  });

  describe('isResourceElement', () => {
    it('should correctly identify iframe elements', () => {
      const iframe = document.createElement('iframe');
      iframe.src = 'https://example.com';

      // Access private method via any type assertion
      const isResource = (ResourceMonitor as any).isResourceElement(iframe);
      expect(isResource).toBe(true);
    });

    it('should correctly identify script elements with src', () => {
      const script = document.createElement('script');
      script.src = 'https://example.com/script.js';

      const isResource = (ResourceMonitor as any).isResourceElement(script);
      expect(isResource).toBe(true);
    });

    it('should not identify script elements without src', () => {
      const script = document.createElement('script');
      script.textContent = 'console.log("test")';

      const isResource = (ResourceMonitor as any).isResourceElement(script);
      expect(isResource).toBe(false);
    });

    it('should not identify non-resource elements', () => {
      const div = document.createElement('div');

      const isResource = (ResourceMonitor as any).isResourceElement(div);
      expect(isResource).toBe(false);
    });
  });
});
