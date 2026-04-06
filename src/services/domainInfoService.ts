// src/domainInfoService.ts - Service for fetching domain and certificate information
import { DomainInfo, CertificateInfo } from '../types';
import logger from '../utils/logger';

export class DomainInfoService {
    private static readonly RECENTLY_REGISTERED_DAYS = 30;
    private static lastRequestTime = 0;
    private static readonly MIN_REQUEST_INTERVAL_MS = 1000; // 1 second between WHOIS requests

    // In-memory cache: domain → { info, timestamp }
    private static readonly cache = new Map<string, { info: DomainInfo | null; timestamp: number }>();
    private static readonly CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

    /**
     * Get domain information including age, registrar, etc.
     */
    public static async getDomainInfo(domain: string): Promise<DomainInfo | null> {
        // Check cache first
        const cached = this.cache.get(domain);
        if (cached && Date.now() - cached.timestamp < this.CACHE_TTL_MS) {
            return cached.info;
        }

        try {
            const domainInfo = await this.fetchDomainInfoFromAPI(domain);
            this.cache.set(domain, { info: domainInfo, timestamp: Date.now() });
            return domainInfo;
        } catch (error) {
            return null;
        }
    }

    /**
     * Get certificate information for a URL
     */
    public static async getCertificateInfo(url: string): Promise<CertificateInfo | null> {
        try {
            // For browser extensions, we can't directly access certificate info
            // But we can provide lookup URLs for manual verification
            const domain = new URL(url).hostname;
            return this.createCertificateLookupInfo(domain);
        } catch (error) {
            return null;
        }
    }

    /**
     * Try to fetch domain info from a free WHOIS API with timeout and fallback
     */
    private static async fetchDomainInfoFromAPI(domain: string): Promise<DomainInfo | null> {
        // Skip API calls for IP addresses or invalid domains
        if (/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/.test(domain)) {
            return this.createFallbackDomainInfo(domain);
        }

        // Try multiple free APIs in sequence with timeout
        const apis = [
            // WhoisJS (free tier) - may not be available
            `https://whois.freecodecamp.com/api/v1/${domain}`,
            // JSONWhois (if available) - may not be available
            `https://jsonwhois.com/api/v1/whois?domain=${domain}`,
        ];

        for (const apiUrl of apis) {
            try {
                // Rate limiting: ensure minimum interval between requests
                const now = Date.now();
                const timeSinceLastRequest = now - this.lastRequestTime;
                if (timeSinceLastRequest < this.MIN_REQUEST_INTERVAL_MS) {
                    const waitTime = this.MIN_REQUEST_INTERVAL_MS - timeSinceLastRequest;
                    logger.log(`⏳ Rate limiting: waiting ${waitTime}ms before WHOIS request`);
                    await new Promise(resolve => setTimeout(resolve, waitTime));
                }
                this.lastRequestTime = Date.now();

                // Create abort controller for timeout
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 3000); // 3 second timeout

                const response = await fetch(apiUrl, {
                    method: 'GET',
                    headers: {
                        'Accept': 'application/json',
                        'User-Agent': 'Phish-Guard/1.0'
                    },
                    signal: controller.signal
                });

                clearTimeout(timeoutId);

                if (response.ok) {
                    const data = await response.json();
                    return this.parseAPIResponse(data, domain);
                }
                // If response is not ok, try the next API
            } catch (error) {
                // Network error or abort - try the next API
                continue;
            }
        }

        // All APIs failed - return null (no data available)
        return null;
    }

    /**
     * Create fallback domain info when APIs fail
     */
    private static createFallbackDomainInfo(domain: string): DomainInfo {
        return {
            whoisUrl: `https://who.is/whois/${domain}`,
            // We can't determine age without API, so don't set those fields
        };
    }

    /**
     * Parse raw WHOIS API response into a normalized structure
     */
    private static parseWhoisData(data: any): { registrar?: string; creationDate?: string; expirationDate?: string } {
        const result: { registrar?: string; creationDate?: string; expirationDate?: string } = {};

        // Extract registrar from various field names
        if (data.registrar || data.registrar_name) {
            result.registrar = data.registrar || data.registrar_name;
        }

        // Extract creation date from various field names
        const creationDate = data.creation_date || data.created_date || data.createdDate || data.created;
        if (creationDate) {
            result.creationDate = creationDate;
        }

        // Extract expiration date from various field names
        const expirationDate = data.expiration_date || data.expires_date || data.expirationDate || data.expires;
        if (expirationDate) {
            result.expirationDate = expirationDate;
        }

        return result;
    }

    /**
     * Calculate domain age in days from a date string.
     * Returns undefined for invalid or missing dates.
     */
    private static calculateDomainAge(dateString: string | null | undefined): number | undefined {
        if (!dateString) {
            return undefined;
        }
        const date = new Date(dateString);
        if (isNaN(date.getTime())) {
            return undefined;
        }
        const ageMs = Date.now() - date.getTime();
        return Math.floor(ageMs / (1000 * 60 * 60 * 24));
    }

    /**
     * Parse API response and extract domain info
     */
    private static parseAPIResponse(data: any, domain: string): DomainInfo {
        const parsed = this.parseWhoisData(data);

        const domainAge = this.calculateDomainAge(parsed.creationDate);
        const isRecentlyRegistered = domainAge !== undefined && domainAge <= this.RECENTLY_REGISTERED_DAYS;

        return {
            registrationDate: parsed.creationDate,
            expirationDate: parsed.expirationDate,
            registrar: parsed.registrar,
            domainAge,
            isRecentlyRegistered,
            whoisUrl: `https://who.is/whois/${domain}`,
        };
    }

    /**
     * Create certificate lookup info (external services)
     */
    private static createCertificateLookupInfo(domain: string): CertificateInfo {
        return {
            // We can't directly access cert info, but we can provide lookup URLs
            // The UI can display these as external links for manual verification
        };
    }

    /**
     * Calculate overall risk score based on domain and certificate info
     */
    static calculateRiskScore(domainInfo?: DomainInfo, certificateInfo?: CertificateInfo): {
        score: number;
        factors: string[];
    } {
        let score = 0;
        const factors: string[] = [];

        // Domain age factors
        if (domainInfo?.isRecentlyRegistered) {
            score += 40;
            factors.push(`Domain registered recently (${domainInfo.domainAge} days ago)`);
        } else if (domainInfo?.domainAge !== undefined) {
            if (domainInfo.domainAge < 90) {
                score += 20;
                factors.push(`Domain is relatively new (${domainInfo.domainAge} days old)`);
            }
        }

        // Certificate factors
        if (certificateInfo?.issuedRecently) {
            score += 15;
            factors.push('SSL certificate issued recently');
        }

        if (certificateInfo?.isSelfSigned) {
            score += 25;
            factors.push('Self-signed SSL certificate');
        }

        if (certificateInfo?.daysUntilExpiry !== undefined && certificateInfo.daysUntilExpiry < 7) {
            score += 10;
            factors.push('SSL certificate expires soon');
        }

        return { score, factors };
    }
}
