// src/resourceMonitor.ts - Monitor suspicious iframes and external resources
import { ReputationService } from './reputationService';

export interface ResourceScanResult {
  totalResources: number;
  externalDomains: string[];
  suspiciousResources: SuspiciousResource[];
  mixedContentWarnings: MixedContentWarning[];
  riskScore: number;
  summary: string;
}

export interface SuspiciousResource {
  type: 'iframe' | 'script' | 'image' | 'media' | 'link';
  url: string;
  domain: string;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  reasons: string[];
}

export interface MixedContentWarning {
  type: 'mixed_content';
  description: string;
  insecureUrl: string;
  secureContext: boolean;
}

export class ResourceMonitor {
  // Suspicious patterns in resource URLs
  private static readonly SUSPICIOUS_PATTERNS = [
    /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/, // Direct IP addresses
    /\.tk($|\/|\?|#)/, // Free .tk domains
    /\.ml($|\/|\?|#)/, // Free .ml domains
    /\.ga($|\/|\?|#)/, // Free .ga domains
    /\.cf($|\/|\?|#)/, // Free .cf domains
    /\.gq($|\/|\?|#)/, // Free .gq domains
    /(phishing|malware|virus|trojan|bitcoin|crypto|wallet)/i, // Suspicious keywords
    // Removed: /[a-z0-9]{20,}\./ - too aggressive, triggers on legitimate long domains
    /-(verification|security|update|alert)\./i, // Suspicious subdomain keywords
  ];

  // Known CDN domains that are generally safe
  private static readonly SAFE_DOMAINS = new Set([
    'cdnjs.cloudflare.com',
    'cdn.jsdelivr.net',
    'unpkg.com',
    'code.jquery.com',
    'maxcdn.bootstrapcdn.com',
    'stackpath.bootstrapcdn.com',
    'fonts.googleapis.com',
    'fonts.gstatic.com',
    'ajax.googleapis.com',
    'use.fontawesome.com',
    'cdn.datatables.net',
    'cdn.plot.ly',
    'cdn.rawgit.com'
  ]);

  /**
   * Scan all resources on the current page for security issues
   */
  public static scanPageResources(): ResourceScanResult {
    const currentDomain = window.location.hostname;
    const isHTTPS = window.location.protocol === 'https:';

    const suspiciousResources: SuspiciousResource[] = [];
    const mixedContentWarnings: MixedContentWarning[] = [];
    const externalDomains = new Set<string>();
    let totalResources = 0;

    console.debug('🔍 Resource Monitor: Scanning page resources for', currentDomain);

    // Scan iframes
    const iframes = document.querySelectorAll('iframe');
    totalResources += iframes.length;

    iframes.forEach(iframe => {
      const src = iframe.src;
      if (src && src.startsWith('http')) {
        const analysis = this.analyzeResource('iframe', src, currentDomain, isHTTPS);
        if (analysis.domain !== currentDomain) {
          externalDomains.add(analysis.domain);
        }
        if (analysis.suspicious) {
          suspiciousResources.push(analysis.suspicious);
        }
        if (analysis.mixedContent) {
          mixedContentWarnings.push(analysis.mixedContent);
        }
      }
    });

    // Scan script tags
    const scripts = document.querySelectorAll('script[src]');
    totalResources += scripts.length;

    scripts.forEach(script => {
      const src = (script as HTMLScriptElement).src;
      if (src && src.startsWith('http')) {
        const analysis = this.analyzeResource('script', src, currentDomain, isHTTPS);
        if (analysis.domain !== currentDomain) {
          externalDomains.add(analysis.domain);
        }
        if (analysis.suspicious) {
          suspiciousResources.push(analysis.suspicious);
        }
        if (analysis.mixedContent) {
          mixedContentWarnings.push(analysis.mixedContent);
        }
      }
    });

    // Scan images
    const images = document.querySelectorAll('img[src]');
    totalResources += images.length;

    images.forEach(img => {
      const src = (img as HTMLImageElement).src;
      if (src && src.startsWith('http')) {
        const analysis = this.analyzeResource('image', src, currentDomain, isHTTPS);
        if (analysis.domain !== currentDomain) {
          externalDomains.add(analysis.domain);
        }
        if (analysis.suspicious) {
          suspiciousResources.push(analysis.suspicious);
        }
        if (analysis.mixedContent) {
          mixedContentWarnings.push(analysis.mixedContent);
        }
      }
    });

    // Scan stylesheets and other resources
    const links = document.querySelectorAll('link[href]');
    totalResources += links.length;

    links.forEach(link => {
      const href = (link as HTMLLinkElement).href;
      if (href && href.startsWith('http')) {
        const analysis = this.analyzeResource('link', href, currentDomain, isHTTPS);
        if (analysis.domain !== currentDomain) {
          externalDomains.add(analysis.domain);
        }
        if (analysis.suspicious) {
          suspiciousResources.push(analysis.suspicious);
        }
        if (analysis.mixedContent) {
          mixedContentWarnings.push(analysis.mixedContent);
        }
      }
    });

    // Deduplicate suspicious resources by URL
    const uniqueResourceUrls = new Set<string>();
    const deduplicatedSuspiciousResources: SuspiciousResource[] = [];

    for (const resource of suspiciousResources) {
      if (!uniqueResourceUrls.has(resource.url)) {
        uniqueResourceUrls.add(resource.url);
        deduplicatedSuspiciousResources.push(resource);
      }
    }

    // Calculate overall risk score (use deduplicated resources)
    let riskScore = 0;
    deduplicatedSuspiciousResources.forEach(resource => {
      switch (resource.riskLevel) {
        case 'critical': riskScore += 40; break;
        case 'high': riskScore += 25; break;
        case 'medium': riskScore += 15; break;
        case 'low': riskScore += 5; break;
      }
    });

    // Add points for mixed content
    riskScore += mixedContentWarnings.length * 10;

    // Cap at 100
    riskScore = Math.min(riskScore, 100);

    // Generate summary (use deduplicated count)
    const summary = this.generateSummary(
      deduplicatedSuspiciousResources.length,
      mixedContentWarnings.length,
      externalDomains.size,
      totalResources
    );

    return {
      totalResources,
      externalDomains: Array.from(externalDomains),
      suspiciousResources: deduplicatedSuspiciousResources,
      mixedContentWarnings,
      riskScore,
      summary
    };
  }

  /**
   * Analyze a single resource for security issues
   */
  private static analyzeResource(
    type: 'iframe' | 'script' | 'image' | 'media' | 'link',
    url: string,
    currentDomain: string,
    isHTTPS: boolean
  ): {
    domain: string;
    suspicious?: SuspiciousResource;
    mixedContent?: MixedContentWarning;
  } {
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname;
      const isResourceHTTPS = urlObj.protocol === 'https:';

      const result: {
        domain: string;
        suspicious?: SuspiciousResource;
        mixedContent?: MixedContentWarning;
      } = { domain };

      // Check for mixed content (HTTPS page loading HTTP resources)
      if (isHTTPS && !isResourceHTTPS) {
        result.mixedContent = {
          type: 'mixed_content',
          description: `Insecure ${type} loaded on secure page`,
          insecureUrl: url,
          secureContext: isHTTPS
        };
      }

      // Skip analysis for same domain and known safe domains
      if (domain === currentDomain || this.SAFE_DOMAINS.has(domain)) {
        return result;
      }

      // Analyze for suspicious patterns
      const reasons: string[] = [];
      let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';

      // Check against suspicious patterns
      for (const pattern of this.SUSPICIOUS_PATTERNS) {
        if (pattern.test(url)) {
          reasons.push(`Matches suspicious pattern: ${pattern.source}`);
          riskLevel = 'high';
          break;
        }
      }

      // Check for direct IP addresses
      if (/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/.test(domain)) {
        reasons.push('Uses direct IP address instead of domain name');
        riskLevel = 'critical';
      }

      // Check for excessive subdomains
      const subdomainCount = (domain.match(/\./g) || []).length;
      if (subdomainCount > 3) {
        reasons.push(`Excessive subdomains (${subdomainCount} levels)`);
        riskLevel = riskLevel === 'low' ? 'medium' : riskLevel;
      }

      // Check for very long domain names (potential obfuscation)
      if (domain.length > 30) {
        reasons.push('Unusually long domain name');
        riskLevel = riskLevel === 'low' ? 'medium' : riskLevel;
      }

      // Check for mixed case in domain (suspicious)
      if (domain !== domain.toLowerCase() && domain !== domain.toUpperCase()) {
        reasons.push('Mixed case domain name');
        riskLevel = riskLevel === 'low' ? 'medium' : riskLevel;
      }

      // If we found reasons to be suspicious, add to results
      if (reasons.length > 0) {
        result.suspicious = {
          type,
          url,
          domain,
          riskLevel,
          reasons
        };
      }

      return result;
    } catch (error) {
      // Invalid URL
      return {
        domain: 'invalid',
        suspicious: {
          type,
          url,
          domain: 'invalid',
          riskLevel: 'high',
          reasons: ['Invalid or malformed URL']
        }
      };
    }
  }

  /**
   * Generate human-readable summary
   */
  private static generateSummary(
    suspiciousCount: number,
    mixedContentCount: number,
    externalDomainCount: number,
    totalResources: number
  ): string {
    if (suspiciousCount === 0 && mixedContentCount === 0) {
      return `All ${totalResources} resources appear safe. ${externalDomainCount} external domains detected.`;
    }

    const issues: string[] = [];
    if (suspiciousCount > 0) {
      issues.push(`${suspiciousCount} suspicious resource(s)`);
    }
    if (mixedContentCount > 0) {
      issues.push(`${mixedContentCount} mixed content warning(s)`);
    }

    return `Found ${issues.join(' and ')} among ${totalResources} total resources from ${externalDomainCount} external domains.`;
  }

  /**
   * Set up monitoring for dynamically added resources
   */
  public static setupDynamicMonitoring(callback: (newFindings: ResourceScanResult) => void): void {
    // Use MutationObserver to watch for new resources being added
    const observer = new MutationObserver((mutations) => {
      let hasNewResources = false;

      mutations.forEach((mutation) => {
        if (mutation.type === 'childList') {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              const element = node as Element;

              // Check if it's a resource element or contains resource elements
              if (this.isResourceElement(element) || element.querySelector('iframe, script[src], img[src], link[href]')) {
                hasNewResources = true;
              }
            }
          });
        }
      });

      // If new resources were detected, rescan and notify
      if (hasNewResources) {
        setTimeout(() => {
          const newScanResult = this.scanPageResources();
          callback(newScanResult);
        }, 100); // Small delay to allow DOM to settle
      }
    });

    // Start observing - wait for body to be available
    const startObserving = () => {
      if (document.body) {
        observer.observe(document.body, {
          childList: true,
          subtree: true
        });
        console.debug('🔍 Resource Monitor: Dynamic monitoring started');
      } else {
        // Body not ready, try again
        setTimeout(startObserving, 100);
      }
    };

    startObserving();
  }

  /**
   * Check if an element is a resource element we care about
   */
  private static isResourceElement(element: Element): boolean {
    const tagName = element.tagName.toLowerCase();
    switch (tagName) {
      case 'iframe':
        return true;
      case 'script':
        return element.hasAttribute('src');
      case 'img':
        return element.hasAttribute('src');
      case 'link':
        return element.hasAttribute('href');
      default:
        return false;
    }
  }
}