// Certificate Analysis Service - Detects phishing via certificate age and issuer patterns
// Uses Certificate Transparency logs via crt.sh API

import logger from '../utils/logger';

export interface CertificateAnalysis {
  certAgeDays: number | null;
  certAgeHours: number | null;
  isNewCert: boolean; // < 7 days old
  isVeryNewCert: boolean; // < 24 hours old
  isFreeCA: boolean; // Let's Encrypt, ZeroSSL, etc.
  issuer: string | null;
  notBefore: string | null;
  riskPoints: number;
  riskFactors: string[];
  error?: string;
}

interface CrtShResponse {
  issuer_name: string;
  not_before: string;
  not_after: string;
  name_value: string;
  min_cert_id: number;
  min_entry_timestamp: string;
}

export class CertificateAnalysisService {
  private static readonly API_URL = 'https://crt.sh/';
  private static readonly TIMEOUT_MS = 15000; // 15 second timeout (crt.sh can be slow)
  private static lastRequestTime = 0;
  private static readonly MIN_REQUEST_INTERVAL_MS = 1000; // 1 second between requests to prevent API abuse

  // Free Certificate Authorities commonly used by phishers
  private static readonly FREE_CA_PATTERNS = [
    "Let's Encrypt",
    "ZeroSSL",
    "Buypass",
    "SSL.com Free"
  ];

  /**
   * Analyze certificate age and issuer patterns to detect phishing
   * NEW certificates on NEW domains with FREE CAs = HIGH RISK
   */
  public static async analyzeCertificate(domain: string): Promise<CertificateAnalysis> {
    const defaultResponse: CertificateAnalysis = {
      certAgeDays: null,
      certAgeHours: null,
      isNewCert: false,
      isVeryNewCert: false,
      isFreeCA: false,
      issuer: null,
      notBefore: null,
      riskPoints: 0,
      riskFactors: [],
      error: 'No certificate data available'
    };

    try {
      // Rate limiting: ensure minimum interval between requests
      const now = Date.now();
      const timeSinceLastRequest = now - this.lastRequestTime;
      if (timeSinceLastRequest < this.MIN_REQUEST_INTERVAL_MS) {
        const waitTime = this.MIN_REQUEST_INTERVAL_MS - timeSinceLastRequest;
        logger.log(`⏳ Rate limiting: waiting ${waitTime}ms before crt.sh request`);
        await new Promise(resolve => setTimeout(resolve, waitTime));
      }
      this.lastRequestTime = Date.now();

      logger.log(`🔍 Checking certificate age for ${domain} via crt.sh...`);

      // Query crt.sh Certificate Transparency logs
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.TIMEOUT_MS);

      const response = await fetch(`${this.API_URL}?q=${encodeURIComponent(domain)}&output=json`, {
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        logger.warn(`⚠️ crt.sh API returned ${response.status} for ${domain}`);
        return { ...defaultResponse, error: `API returned ${response.status}` };
      }

      const certificates: CrtShResponse[] = await response.json();

      if (!certificates || certificates.length === 0) {
        logger.log(`ℹ️ No certificates found in CT logs for ${domain}`);
        return { ...defaultResponse, error: 'No certificates found in CT logs' };
      }

      logger.log(`✅ Found ${certificates.length} certificate(s) for ${domain}`);

      // Find the newest certificate (most recent not_before date)
      const newestCert = certificates.reduce((newest, cert) => {
        const certDate = new Date(cert.not_before);
        const newestDate = new Date(newest.not_before);
        return certDate > newestDate ? cert : newest;
      });

      // Calculate certificate age
      const certIssuedDate = new Date(newestCert.not_before);
      const currentTime = Date.now();
      const certAgeMs = currentTime - certIssuedDate.getTime();
      const certAgeDays = certAgeMs / (1000 * 60 * 60 * 24);
      const certAgeHours = certAgeMs / (1000 * 60 * 60);

      const isNewCert = certAgeDays < 7;
      const isVeryNewCert = certAgeHours < 24;

      // Check if issuer is a free CA
      const isFreeCA = this.FREE_CA_PATTERNS.some(pattern =>
        newestCert.issuer_name.includes(pattern)
      );

      // Calculate risk points and factors
      let riskPoints = 0;
      const riskFactors: string[] = [];

      if (isVeryNewCert) {
        riskPoints += 25;
        riskFactors.push(`Certificate issued only ${Math.round(certAgeHours)} hours ago`);
      } else if (isNewCert) {
        riskPoints += 15;
        riskFactors.push(`Certificate issued ${Math.round(certAgeDays)} days ago (very recent)`);
      }

      if (isFreeCA && isNewCert) {
        riskPoints += 10;
        riskFactors.push(`Free automated certificate on newly issued cert (common phishing pattern)`);
      }

      logger.log(`📜 Certificate for ${domain}: Age ${Math.round(certAgeDays)} days, Issuer: ${newestCert.issuer_name.split(',')[0]}, Risk: +${riskPoints} points`);

      return {
        certAgeDays: Math.round(certAgeDays * 10) / 10, // Round to 1 decimal
        certAgeHours: Math.round(certAgeHours),
        isNewCert,
        isVeryNewCert,
        isFreeCA,
        issuer: newestCert.issuer_name,
        notBefore: newestCert.not_before,
        riskPoints,
        riskFactors
      };

    } catch (error: any) {
      // Timeout or network error - don't fail the entire scan
      if (error.name === 'AbortError') {
        logger.warn(`⏱️ Certificate lookup timed out for ${domain} (crt.sh took >8s)`);
        return { ...defaultResponse, error: 'Certificate lookup timed out' };
      }
      logger.error(`❌ Certificate lookup failed for ${domain}:`, error.message);
      return { ...defaultResponse, error: error.message || 'Unknown error' };
    }
  }

  /**
   * Generate user-friendly summary of certificate analysis
   */
  public static generateSummary(analysis: CertificateAnalysis): string {
    if (analysis.error || !analysis.issuer) {
      return 'Certificate information unavailable';
    }

    const ageParts: string[] = [];

    if (analysis.isVeryNewCert) {
      ageParts.push(`⚠️ Certificate issued ${analysis.certAgeHours}h ago`);
    } else if (analysis.isNewCert) {
      ageParts.push(`Certificate issued ${analysis.certAgeDays} days ago`);
    } else {
      ageParts.push(`Certificate issued ${analysis.certAgeDays} days ago`);
    }

    if (analysis.isFreeCA) {
      ageParts.push(`Free CA: ${analysis.issuer.split(',')[0]}`);
    } else {
      ageParts.push(`CA: ${analysis.issuer.split(',')[0]}`);
    }

    return ageParts.join(' • ');
  }

  /**
   * Determine if certificate pattern indicates phishing risk
   */
  public static isHighRiskPattern(
    certAnalysis: CertificateAnalysis,
    domainAgeDays?: number
  ): boolean {
    // Very new cert + very new domain + free CA = STRONG phishing indicator
    if (certAnalysis.isVeryNewCert &&
        domainAgeDays !== undefined &&
        domainAgeDays < 7 &&
        certAnalysis.isFreeCA) {
      return true;
    }

    // New cert + new domain = moderate risk
    if (certAnalysis.isNewCert &&
        domainAgeDays !== undefined &&
        domainAgeDays < 30) {
      return true;
    }

    return false;
  }
}