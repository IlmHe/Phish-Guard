// src/reputationService.ts - Advanced URL reputation scoring system
import { DomainInfo, CertificateInfo } from '../types';
import { HomographDetector, SuspiciousDomainAnalysis } from './homographDetector';
import { RealtimeApiService, AggregatedApiResult } from './realtimeApiService';
import { CertificateAnalysisService, CertificateAnalysis } from './certificateAnalysisService';

export interface ReputationScore {
  overall: number; // 0-100, higher = more dangerous
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  threatTypes: ThreatType[];
  factors: ReputationFactor[];
  confidence: number; // 0-100, higher = more confident in assessment
  apiResults?: AggregatedApiResult; // Real-time threat intelligence
  certAnalysis?: CertificateAnalysis; // Certificate age analysis
}

export interface ThreatType {
  type: 'phishing' | 'malware' | 'unwanted_software' | 'billing_scam' | 'suspicious_redirect' | 'data_harvesting';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
}

export interface ReputationFactor {
  category: string;
  impact: number; // Points added to risk score
  description: string;
  evidence: string;
}

export class ReputationService {
  // Suspicious TLDs that are commonly used for malicious purposes
  private static readonly SUSPICIOUS_TLDS = new Set([
    '.tk', '.ml', '.ga', '.cf', '.gq', // Free TLDs often used by scammers
    '.bit', '.onion', // Special domains
    '.info', '.biz', // Often used for spam
    '.click', '.download', '.loan', '.work' // Suspicious generic TLDs
  ]);

  // IP address ranges commonly used for malicious hosting
  private static readonly SUSPICIOUS_IP_PATTERNS = [
    /^10\./, // Private networks in public use
    /^169\.254\./, // Link-local addresses
    /^127\./, // Loopback (if used publicly)
    /^0\./, // Invalid networks
  ];

  // Known bad URL patterns
  private static readonly MALICIOUS_PATTERNS = [
    /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/, // Raw IP addresses
    // Removed: /[a-z0-9]{20,}\./ - too aggressive, triggers on legitimate long domains
    /-(verification|security|update|alert)\./, // Suspicious keywords in subdomain
    /\.(exe|scr|bat|cmd|pif|vbs|js)($|\?|#)/, // Dangerous file extensions in URL
    /(phishing|malware|virus|trojan|bitcoin|crypto|wallet)/i, // Suspicious keywords
  ];

  /**
   * Calculate comprehensive reputation score for a URL
   */
  public static async calculateReputation(
    url: string,
    domain: string,
    domainInfo?: DomainInfo,
    certificateInfo?: CertificateInfo,
    homographAnalysis?: SuspiciousDomainAnalysis,
    supabaseStatus?: 'found' | 'not_found' | 'error' | 'not_checked',
    enableApiChecks: boolean = true
  ): Promise<ReputationScore> {
    const factors: ReputationFactor[] = [];
    const threatTypes: ThreatType[] = [];
    let riskScore = 0;
    let confidence = 50; // Base confidence

    // 1. Supabase database check (highest priority)
    if (supabaseStatus === 'found') {
      riskScore += 80;
      confidence += 30;
      factors.push({
        category: 'Known Threats',
        impact: 80,
        description: 'Found in phishing database',
        evidence: 'Domain matches known phishing sites in Supabase database'
      });
      threatTypes.push({
        type: 'phishing',
        severity: 'critical',
        description: 'This domain is in our phishing database'
      });
    }

    // 2. Homograph analysis
    if (homographAnalysis) {
      if (homographAnalysis.riskScore > 0) {
        const homographImpact = Math.floor(homographAnalysis.riskScore * 0.6); // Scale down slightly
        riskScore += homographImpact;
        confidence += 20;

        factors.push({
          category: 'Homograph Attack',
          impact: homographImpact,
          description: `Suspicious character patterns detected`,
          evidence: `Patterns: ${homographAnalysis.suspiciousPatterns.join(', ')}`
        });

        if (homographAnalysis.recommendation === 'dangerous') {
          threatTypes.push({
            type: 'phishing',
            severity: 'high',
            description: 'Domain uses suspicious character substitution'
          });
        }
      }
    }

    // 3. Domain age analysis
    if (domainInfo) {
      if (domainInfo.isRecentlyRegistered) {
        riskScore += 25;
        confidence += 15;
        factors.push({
          category: 'Domain Age',
          impact: 25,
          description: 'Recently registered domain',
          evidence: `Domain is only ${domainInfo.domainAge} days old`
        });
        threatTypes.push({
          type: 'suspicious_redirect',
          severity: 'medium',
          description: 'Newly registered domains are often used for temporary scams'
        });
      }

      // Check for suspicious registrar patterns
      if (domainInfo.registrar && this.isSuspiciousRegistrar(domainInfo.registrar)) {
        riskScore += 15;
        factors.push({
          category: 'Registrar',
          impact: 15,
          description: 'Suspicious domain registrar',
          evidence: `Registrar: ${domainInfo.registrar}`
        });
      }
    }

    // 4. SSL/Certificate analysis
    if (certificateInfo) {
      if (certificateInfo.isSelfSigned) {
        riskScore += 20;
        factors.push({
          category: 'SSL Certificate',
          impact: 20,
          description: 'Self-signed SSL certificate',
          evidence: 'Self-signed certificates are not validated by trusted authorities'
        });
      }

      if (certificateInfo.issuedRecently) {
        riskScore += 10;
        factors.push({
          category: 'SSL Certificate',
          impact: 10,
          description: 'Recently issued SSL certificate',
          evidence: 'Certificate was issued very recently'
        });
      }
    } else if (url.startsWith('http://')) {
      riskScore += 15;
      factors.push({
        category: 'SSL Certificate',
        impact: 15,
        description: 'No SSL encryption',
        evidence: 'Site does not use HTTPS encryption'
      });
      threatTypes.push({
        type: 'data_harvesting',
        severity: 'medium',
        description: 'Data transmitted without encryption'
      });
    }

    // 5. URL structure analysis
    const urlAnalysis = this.analyzeUrlStructure(url, domain);
    riskScore += urlAnalysis.riskPoints;
    confidence += urlAnalysis.confidenceBoost;
    factors.push(...urlAnalysis.factors);
    threatTypes.push(...urlAnalysis.threats);

    // 6. Domain structure analysis
    const domainAnalysis = this.analyzeDomainStructure(domain);
    riskScore += domainAnalysis.riskPoints;
    factors.push(...domainAnalysis.factors);
    threatTypes.push(...domainAnalysis.threats);

    // 7. Network analysis
    const networkAnalysis = await this.analyzeNetworkIndicators(domain);
    riskScore += networkAnalysis.riskPoints;
    factors.push(...networkAnalysis.factors);
    threatTypes.push(...networkAnalysis.threats);

    // 8. Certificate age analysis - MOVED TO ASYNC LOADING IN POPUP
    // This prevents slow crt.sh API from blocking initial scan results
    // Certificate analysis will be loaded separately and update the UI when ready
    let certAnalysis: CertificateAnalysis | undefined;

    // 9. Real-time API threat intelligence (DISABLED - contains mock implementations)
    // TODO: Implement real API integrations with VirusTotal, Google Safe Browsing, PhishTank
    let apiResults: AggregatedApiResult | undefined;
    // DISABLED FOR PRODUCTION - Mock APIs only
    /*
    if (enableApiChecks) {
      try {
        apiResults = await RealtimeApiService.queryMultipleApis(url, domain);

        if (apiResults.responseCount > 0) {
          const apiImpact = RealtimeApiService.getReputationImpact(apiResults);
          riskScore += apiImpact.riskPoints;
          confidence += apiImpact.confidence;

          // Only add to factors if it has actual impact
          if (apiImpact.riskPoints > 0) {
            factors.push({
              category: 'Local Security Analysis',
              impact: apiImpact.riskPoints,
              description: apiImpact.description,
              evidence: `${apiResults.responseCount}/${apiResults.totalSources} analysis checks performed`
            });
          }

          // Add API-specific threat types
          if (apiResults.consensus === 'malicious') {
            threatTypes.push({
              type: 'phishing',
              severity: 'critical',
              description: 'Flagged as malicious by local pattern analysis'
            });
          } else if (apiResults.consensus === 'suspicious') {
            threatTypes.push({
              type: 'suspicious_redirect',
              severity: 'medium',
              description: 'Reported as suspicious by local pattern analysis'
            });
          }
        }
      } catch (error) {
        logger.warn('Local security analysis failed:', error);
        // Don't fail the entire reputation calculation if APIs fail
      }
    }
    */

    // Cap the risk score at 100
    riskScore = Math.min(riskScore, 100);
    confidence = Math.min(confidence, 100);

    // Determine risk level
    let riskLevel: 'low' | 'medium' | 'high' | 'critical';
    if (riskScore === 0) {
      // Score of 0 means no threat indicators found, but also no positive reputation data
      riskLevel = 'low';
    } else if (riskScore >= 80) {
      riskLevel = 'critical';
    } else if (riskScore >= 60) {
      riskLevel = 'high';
    } else if (riskScore >= 30) {
      riskLevel = 'medium';
    } else {
      riskLevel = 'low';
    }

    return {
      overall: riskScore,
      riskLevel,
      threatTypes: this.deduplicateThreats(threatTypes),
      factors,
      confidence,
      apiResults,
      certAnalysis
    };
  }

  /**
   * Analyze URL structure for suspicious patterns
   */
  private static analyzeUrlStructure(url: string, domain: string): {
    riskPoints: number;
    confidenceBoost: number;
    factors: ReputationFactor[];
    threats: ThreatType[];
  } {
    const factors: ReputationFactor[] = [];
    const threats: ThreatType[] = [];
    let riskPoints = 0;
    let confidenceBoost = 0;

    // Check for malicious patterns
    for (const pattern of this.MALICIOUS_PATTERNS) {
      if (pattern.test(url)) {
        riskPoints += 30;
        confidenceBoost += 10;
        factors.push({
          category: 'URL Structure',
          impact: 30,
          description: 'Suspicious URL pattern detected',
          evidence: `URL matches pattern: ${pattern.source}`
        });
        threats.push({
          type: 'malware',
          severity: 'high',
          description: 'URL contains patterns commonly used in malicious attacks'
        });
        break; // Only count once
      }
    }

    // Check for excessive length (potential obfuscation)
    if (url.length > 200) {
      riskPoints += 15;
      factors.push({
        category: 'URL Structure',
        impact: 15,
        description: 'Unusually long URL',
        evidence: `URL length: ${url.length} characters`
      });
    }

    // Check for suspicious query parameters
    const suspiciousParams = ['phish', 'malware', 'download', 'install', 'update', 'security'];
    const urlLower = url.toLowerCase();
    for (const param of suspiciousParams) {
      if (urlLower.includes(param)) {
        riskPoints += 10;
        factors.push({
          category: 'URL Structure',
          impact: 10,
          description: 'Suspicious parameter detected',
          evidence: `Contains: ${param}`
        });
        break;
      }
    }

    // Check for URL shorteners (potential redirect hiding)
    const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link'];
    if (shorteners.some(shortener => domain.includes(shortener))) {
      riskPoints += 20;
      factors.push({
        category: 'URL Structure',
        impact: 20,
        description: 'URL shortener detected',
        evidence: 'URL shorteners can hide malicious destinations'
      });
      threats.push({
        type: 'suspicious_redirect',
        severity: 'medium',
        description: 'Shortened URLs may redirect to malicious sites'
      });
    }

    return { riskPoints, confidenceBoost, factors, threats };
  }

  /**
   * Analyze domain structure for suspicious patterns
   */
  private static analyzeDomainStructure(domain: string): {
    riskPoints: number;
    factors: ReputationFactor[];
    threats: ThreatType[];
  } {
    const factors: ReputationFactor[] = [];
    const threats: ThreatType[] = [];
    let riskPoints = 0;

    // Check for suspicious TLDs
    for (const tld of this.SUSPICIOUS_TLDS) {
      if (domain.endsWith(tld)) {
        riskPoints += 25;
        factors.push({
          category: 'Domain Structure',
          impact: 25,
          description: 'Suspicious top-level domain',
          evidence: `Uses TLD: ${tld}`
        });
        threats.push({
          type: 'phishing',
          severity: 'medium',
          description: 'Domain uses TLD commonly associated with malicious sites'
        });
        break;
      }
    }

    // Check for excessive subdomains
    const subdomainCount = (domain.match(/\./g) || []).length;
    if (subdomainCount > 3) {
      riskPoints += 20;
      factors.push({
        category: 'Domain Structure',
        impact: 20,
        description: 'Excessive subdomains',
        evidence: `${subdomainCount} levels of subdomains`
      });
    }

    // Check for suspicious domain length
    const domainParts = domain.split('.');
    const mainDomain = domainParts[domainParts.length - 2] || '';
    if (mainDomain.length > 20) {
      riskPoints += 15;
      factors.push({
        category: 'Domain Structure',
        impact: 15,
        description: 'Unusually long domain name',
        evidence: `Main domain: ${mainDomain.length} characters`
      });
    }

    // Check for numbers mixed with letters (typosquatting indicator)
    if (/[0-9].*[a-zA-Z]|[a-zA-Z].*[0-9]/.test(mainDomain)) {
      riskPoints += 10;
      factors.push({
        category: 'Domain Structure',
        impact: 10,
        description: 'Numbers mixed with letters',
        evidence: 'Pattern often used in typosquatting attacks'
      });
    }

    return { riskPoints, factors, threats };
  }

  /**
   * Analyze network-level indicators
   */
  private static async analyzeNetworkIndicators(domain: string): Promise<{
    riskPoints: number;
    factors: ReputationFactor[];
    threats: ThreatType[];
  }> {
    const factors: ReputationFactor[] = [];
    const threats: ThreatType[] = [];
    let riskPoints = 0;

    // Check if domain is an IP address
    if (/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/.test(domain)) {
      riskPoints += 40;
      factors.push({
        category: 'Network',
        impact: 40,
        description: 'Direct IP address instead of domain',
        evidence: 'Legitimate sites rarely use IP addresses directly'
      });
      threats.push({
        type: 'phishing',
        severity: 'high',
        description: 'Direct IP access often indicates malicious hosting'
      });

      // Check if it's a suspicious IP range
      for (const pattern of this.SUSPICIOUS_IP_PATTERNS) {
        if (pattern.test(domain)) {
          riskPoints += 20;
          factors.push({
            category: 'Network',
            impact: 20,
            description: 'Suspicious IP address range',
            evidence: `IP in range: ${pattern.source}`
          });
          break;
        }
      }
    }

    return { riskPoints, factors, threats };
  }

  /**
   * Check if registrar is commonly used by malicious domains
   */
  private static isSuspiciousRegistrar(registrar: string): boolean {
    const suspiciousRegistrars = [
      'freenom', 'namecheap', 'domains4bitcoins', 'regru'
    ];
    const registrarLower = registrar.toLowerCase();
    return suspiciousRegistrars.some(suspicious => registrarLower.includes(suspicious));
  }

  /**
   * Remove duplicate threat types
   */
  private static deduplicateThreats(threats: ThreatType[]): ThreatType[] {
    const seen = new Set<string>();
    return threats.filter(threat => {
      const key = `${threat.type}-${threat.severity}`;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
  }

  /**
   * Get user-friendly description of risk level
   */
  public static getRiskDescription(riskLevel: 'low' | 'medium' | 'high' | 'critical', score?: number): string {
    switch (riskLevel) {
      case 'low':
        if (score === 0) {
          return 'No threat indicators detected, but limited reputation data available.';
        }
        return 'This site appears to be safe based on our analysis.';
      case 'medium':
        return 'This site shows some suspicious indicators. Exercise caution.';
      case 'high':
        return 'This site has multiple risk factors. Avoid entering personal information.';
      case 'critical':
        return 'This site is likely malicious. Do not proceed or enter any information.';
      default:
        return 'Risk assessment unavailable.';
    }
  }

  /**
   * Get CSS class for risk level styling
   */
  public static getRiskClass(riskLevel: 'low' | 'medium' | 'high' | 'critical'): string {
    switch (riskLevel) {
      case 'low':
        return 'is-success';
      case 'medium':
        return 'is-warning';
      case 'high':
        return 'is-danger';
      case 'critical':
        return 'is-danger';
      default:
        return 'is-info';
    }
  }
}