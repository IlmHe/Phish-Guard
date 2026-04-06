// src/realtimeApiService.ts - Real-time threat intelligence API integration
// ⚠️ WARNING: This file contains MOCK/SIMULATED API implementations for development
// ⚠️ These are NOT real API calls and should NOT be used in production
// ⚠️ To use in production, replace with real API integrations (requires API keys)
// ⚠️ Currently DISABLED in reputationService.ts

import logger from '../utils/logger';

export interface ApiReputationResult {
  source: string;
  status: 'safe' | 'suspicious' | 'malicious' | 'unknown' | 'error';
  confidence: number; // 0-100
  riskScore: number; // 0-100
  categories: string[];
  lastSeen?: string;
  details?: string;
  responseTime?: number;
}

export interface AggregatedApiResult {
  consensus: 'safe' | 'suspicious' | 'malicious' | 'unknown';
  totalSources: number;
  responseCount: number;
  results: ApiReputationResult[];
  averageRiskScore: number;
  highestRiskScore: number;
  maliciousVotes: number;
  suspiciousVotes: number;
  safeVotes: number;
}

export class RealtimeApiService {
  private static readonly TIMEOUT_MS = 5000; // 5 second timeout for API calls
  private static readonly MAX_CONCURRENT_APIS = 3; // Limit concurrent API calls

  /**
   * Query multiple real-time threat intelligence APIs
   */
  public static async queryMultipleApis(url: string, domain: string): Promise<AggregatedApiResult> {
    const startTime = Date.now();

    // List of API functions to call
    const apiCalls = [
      () => this.queryVirusTotalApi(url, domain),
      () => this.queryGoogleSafeBrowsingApi(url, domain),
      () => this.queryPhishTankApi(url, domain),
      // Add more APIs as needed
    ];

    // Execute API calls with timeout and error handling
    const apiPromises = apiCalls.map(async (apiCall, index) => {
      try {
        const result = await Promise.race([
          apiCall(),
          this.createTimeoutPromise(index)
        ]);
        return result;
      } catch (error) {
        logger.warn(`API ${index} failed:`, error);
        return this.createErrorResult(`API_${index}`, error instanceof Error ? error.message : 'Unknown error');
      }
    });

    // Wait for all API calls to complete (or timeout)
    const results = await Promise.allSettled(apiPromises);
    const validResults: ApiReputationResult[] = [];

    // Process results
    results.forEach((result, index) => {
      if (result.status === 'fulfilled' && result.value) {
        validResults.push(result.value);
      } else {
        logger.warn(`API ${index} rejected:`, result.status === 'rejected' ? result.reason : 'Unknown');
        validResults.push(this.createErrorResult(`API_${index}`, 'Request failed or timed out'));
      }
    });

    const aggregated = this.aggregateResults(validResults);

    return aggregated;
  }

  /**
   * Simulate an API reputation response based on URL and domain patterns.
   * Returns 'unknown' for domains with no recognisable risk signals or safe signals.
   */
  public static simulateApiResponse(url: string, domain: string, source: string): ApiReputationResult {
    let riskScore = 0;
    let status: 'safe' | 'suspicious' | 'malicious' | 'unknown' = 'unknown';
    const categories: string[] = [];

    const domainLower = domain.toLowerCase();

    // Clearly malicious patterns
    if (domainLower.includes('phish') || domainLower.includes('malware') ||
        domainLower.includes('scam') || domainLower.includes('virus') ||
        domainLower.includes('trojan')) {
      riskScore = 85;
      status = 'malicious';
      categories.push('phishing', 'malware');
    } else if (/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/.test(domain)) {
      // Direct IP address
      riskScore = 70;
      status = 'malicious';
      categories.push('ip_address', 'phishing');
    } else if (domain.match(/\.(tk|ml|ga|cf|gq)$/)) {
      // Free suspicious TLDs
      riskScore = 60;
      status = 'suspicious';
      categories.push('suspicious_domain');
    } else if (domainLower.includes('suspicious') || domainLower.includes('temp') ||
               /[0-9]{8,}/.test(domain)) {
      riskScore = 45;
      status = 'suspicious';
      categories.push('suspicious');
    } else {
      // Check for suspicious keywords in domain (brand impersonation patterns)
      const suspiciousKeywords = ['verify', 'secure', 'login', 'signin', 'update', 'account', 'confirm'];
      const hasSuspiciousKeyword = suspiciousKeywords.some(kw => domainLower.includes(kw));
      if (hasSuspiciousKeyword) {
        riskScore = 50;
        status = 'suspicious';
        categories.push('suspicious_keywords');
      } else {
        // Known safe domains
        const knownSafe = ['google', 'github', 'wikipedia', 'microsoft', 'apple',
                           'amazon', 'facebook', 'youtube', 'twitter', 'instagram',
                           'example'];
        const isSafe = knownSafe.some(safe => domainLower.includes(safe));
        if (isSafe) {
          riskScore = 5;
          status = 'safe';
        } else {
          // Not enough information to make a determination
          riskScore = 0;
          status = 'unknown';
        }
      }
    }

    return {
      source: `${source} (Simulated)`,
      status,
      confidence: status === 'unknown' ? 0 : 75,
      riskScore,
      categories,
      responseTime: 0,
      details: `Simulated analysis for ${domain}`
    };
  }

  /**
   * Query VirusTotal API (simulated - no real API key required)
   */
  private static async queryVirusTotalApi(url: string, domain: string): Promise<ApiReputationResult> {
    const startTime = Date.now();
    try {
      const result = this.simulateApiResponse(url, domain, 'VirusTotal');
      return { ...result, responseTime: Date.now() - startTime };
    } catch (error) {
      return this.createErrorResult('VirusTotal (Simulated)', error instanceof Error ? error.message : 'API call failed');
    }
  }

  /**
   * Query Google Safe Browsing API (simulated - no real API key required)
   */
  private static async queryGoogleSafeBrowsingApi(url: string, domain: string): Promise<ApiReputationResult> {
    const startTime = Date.now();
    try {
      const result = this.simulateApiResponse(url, domain, 'Google Safe Browsing');
      return { ...result, responseTime: Date.now() - startTime };
    } catch (error) {
      return this.createErrorResult('Google Safe Browsing (Simulated)', error instanceof Error ? error.message : 'API call failed');
    }
  }

  /**
   * Query PhishTank API (simulated - no real API key required)
   */
  private static async queryPhishTankApi(url: string, domain: string): Promise<ApiReputationResult> {
    const startTime = Date.now();
    try {
      const result = this.simulateApiResponse(url, domain, 'PhishTank');
      return { ...result, responseTime: Date.now() - startTime };
    } catch (error) {
      return this.createErrorResult('PhishTank (Simulated)', error instanceof Error ? error.message : 'API call failed');
    }
  }

  /**
   * Create a timeout promise for API calls
   */
  private static createTimeoutPromise(apiIndex: number): Promise<never> {
    return new Promise((_, reject) => {
      setTimeout(() => {
        reject(new Error(`API ${apiIndex} timeout after ${this.TIMEOUT_MS}ms`));
      }, this.TIMEOUT_MS);
    });
  }

  /**
   * Create an error result for failed API calls
   */
  private static createErrorResult(source: string, error: string): ApiReputationResult {
    return {
      source,
      status: 'error',
      confidence: 0,
      riskScore: 0,
      categories: ['error'],
      details: `Error: ${error}`
    };
  }

  /**
   * Aggregate results from multiple APIs into consensus
   */
  private static aggregateResults(results: ApiReputationResult[]): AggregatedApiResult {
    const validResults = results.filter(result => result.status !== 'error');
    const totalSources = results.length;
    const responseCount = validResults.length;

    if (responseCount === 0) {
      return {
        consensus: 'unknown',
        totalSources,
        responseCount,
        results,
        averageRiskScore: 0,
        highestRiskScore: 0,
        maliciousVotes: 0,
        suspiciousVotes: 0,
        safeVotes: 0
      };
    }

    // Count votes
    const maliciousVotes = validResults.filter(r => r.status === 'malicious').length;
    const suspiciousVotes = validResults.filter(r => r.status === 'suspicious').length;
    const safeVotes = validResults.filter(r => r.status === 'safe').length;

    // Calculate scores
    const riskScores = validResults.map(r => r.riskScore);
    const averageRiskScore = riskScores.length > 0
      ? riskScores.reduce((sum, score) => sum + score, 0) / riskScores.length
      : 0;
    const highestRiskScore = riskScores.length > 0 ? Math.max(...riskScores) : 0;

    // Determine consensus
    let consensus: 'safe' | 'suspicious' | 'malicious' | 'unknown';

    if (maliciousVotes > 0) {
      consensus = 'malicious';
    } else if (suspiciousVotes > safeVotes) {
      consensus = 'suspicious';
    } else if (safeVotes > 0) {
      consensus = 'safe';
    } else {
      consensus = 'unknown';
    }

    // Override consensus if average risk score is very high
    if (averageRiskScore >= 70) {
      consensus = 'malicious';
    } else if (averageRiskScore >= 40 && consensus === 'safe') {
      consensus = 'suspicious';
    }

    return {
      consensus,
      totalSources,
      responseCount,
      results,
      averageRiskScore: Math.round(averageRiskScore),
      highestRiskScore,
      maliciousVotes,
      suspiciousVotes,
      safeVotes
    };
  }

  /**
   * Get user-friendly summary of API results
   */
  public static getApiSummary(apiResult: AggregatedApiResult): string {
    if (apiResult.responseCount === 0) {
      return 'No threat intelligence data available';
    }

    const { responseCount, totalSources, consensus, maliciousVotes, suspiciousVotes } = apiResult;

    if (consensus === 'malicious') {
      return `🚨 ${maliciousVotes}/${responseCount} analysis checks flag this as malicious`;
    } else if (consensus === 'suspicious') {
      return `⚠️ ${suspiciousVotes}/${responseCount} analysis checks report suspicious patterns`;
    } else if (consensus === 'safe') {
      return `✅ ${responseCount}/${totalSources} analysis checks report no issues`;
    } else {
      return `❓ ${responseCount}/${totalSources} analysis checks provided inconclusive results`;
    }
  }

  /**
   * Get detailed breakdown of API responses
   */
  public static getApiBreakdown(apiResult: AggregatedApiResult): string[] {
    return apiResult.results.map(result => {
      const statusIcon = {
        'safe': '✅',
        'suspicious': '⚠️',
        'malicious': '🚨',
        'unknown': '❓',
        'error': '❌'
      }[result.status];

      const responseTime = result.responseTime ? ` (${result.responseTime}ms)` : '';
      const categories = result.categories.length > 0 ? ` - ${result.categories.join(', ')}` : '';

      return `${statusIcon} ${result.source}: ${result.status}${categories}${responseTime}`;
    });
  }

  /**
   * Convert API consensus to reputation score impact
   */
  public static getReputationImpact(apiResult: AggregatedApiResult): {
    riskPoints: number;
    confidence: number;
    description: string;
  } {
    if (apiResult.responseCount === 0) {
      return {
        riskPoints: 0,
        confidence: 0,
        description: 'No threat intelligence available'
      };
    }

    const { consensus, averageRiskScore, maliciousVotes, responseCount } = apiResult;

    switch (consensus) {
      case 'malicious':
        return {
          riskPoints: Math.min(60, averageRiskScore),
          confidence: 40,
          description: `${maliciousVotes}/${responseCount} analysis checks flag as malicious`
        };

      case 'suspicious':
        return {
          riskPoints: Math.min(30, averageRiskScore * 0.5),
          confidence: 25,
          description: `Local analysis indicates suspicious patterns`
        };

      case 'safe':
        return {
          riskPoints: 0,
          confidence: 20,
          description: `Local analysis found no security issues`
        };

      default:
        return {
          riskPoints: 5,
          confidence: 10,
          description: `Inconclusive local analysis results`
        };
    }
  }
}