// src/domainInfoService.ts - Service for fetching domain and certificate information
import { DomainInfo, CertificateInfo } from '../types';
import logger from '../utils/logger';

export class DomainInfoService {
    private static readonly RECENTLY_REGISTERED_DAYS = 30;
    private static lastRequestTime = 0;
    private static readonly MIN_REQUEST_INTERVAL_MS = 1000; // 1 second between WHOIS requests

    /**
     * Get domain information including age, registrar, etc.
     */
    public static async getDomainInfo(domain: string): Promise<DomainInfo | null> {
        try {
            // Try to fetch from API first, then fallback to manual lookup
            const domainInfo = await this.fetchDomainInfoFromAPI(domain);
            return domainInfo;
        } catch (error) {
            // Return fallback info with manual lookup URLs
            return this.createFallbackDomainInfo(domain);
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
    private static async fetchDomainInfoFromAPI(domain: string): Promise<DomainInfo> {
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
            } catch (error) {
                continue;
            }
        }

        return this.createFallbackDomainInfo(domain);
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
     * Parse API response and extract domain info
     */
    private static parseAPIResponse(data: any, domain: string): DomainInfo {
        let registrationDate: string | undefined;
        let expirationDate: string | undefined;
        let registrar: string | undefined;

        // Try to extract common fields from different API formats
        if (data.creation_date || data.created_date || data.createdDate) {
            registrationDate = data.creation_date || data.created_date || data.createdDate;
        }

        if (data.expiration_date || data.expires_date || data.expirationDate) {
            expirationDate = data.expiration_date || data.expires_date || data.expirationDate;
        }

        if (data.registrar || data.registrar_name) {
            registrar = data.registrar || data.registrar_name;
        }

        // Calculate domain age
        let domainAge: number | undefined;
        let isRecentlyRegistered = false;

        if (registrationDate) {
            const regDate = new Date(registrationDate);
            const now = new Date();
            domainAge = Math.floor((now.getTime() - regDate.getTime()) / (1000 * 60 * 60 * 24));
            isRecentlyRegistered = domainAge <= this.RECENTLY_REGISTERED_DAYS;
        }

        return {
            registrationDate,
            expirationDate,
            registrar,
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