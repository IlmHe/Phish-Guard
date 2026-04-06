import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import browser from 'webextension-polyfill';
import logger from './utils/logger';
import { checkUrlInSupabase } from './services/apiservice';
import { extractActualUrl, extractDomain, extractDomainRaw, sanitizeUrl, isValidUrl } from './utils/utils';
import { HomographDetector, SuspiciousDomainAnalysis } from './services/homographDetector';
import { DomainInfoService } from './services/domainInfoService';
import { SitemapService, SitemapResult, SitemapProgress } from './services/sitemapService';
import { ReputationService } from './services/reputationService';
import { RealtimeApiService } from './services/realtimeApiService';
import { CertificateAnalysisService } from './services/certificateAnalysisService';
import { PhishGuardSettings, StorageData, defaultSettings, ScanResult, DomainInfo, CertificateInfo } from './types';
import { ResourceScanResult } from './services/resourceMonitor';
import { SafetyStatusCard, SimpleModeView, AdvancedModeView, ErrorBoundary } from './components';

// Sitemap detection function using the working Google dork
const generateSitemapSearchUrl = (domain: string): string => {
    // Use the proven working query format
    const query = `site:${domain} inurl:sitemap filetype:xml`;
    return `https://www.google.com/search?q=${encodeURIComponent(query)}`;
};

export const Popup = (): React.ReactElement => {
    const [url, setUrl] = useState<string>('');
    const [domain, setDomain] = useState<string>('');
    const [scanResult, setScanResult] = useState<ScanResult | null>(null);
    const [isScanning, setIsScanning] = useState<boolean>(false);
    const [settings, setSettings] = useState<PhishGuardSettings>(defaultSettings);
    const [error, setError] = useState<string | null>(null);
    const [homographAnalysis, setHomographAnalysis] = useState<SuspiciousDomainAnalysis | null>(null);
    const [resourceScan, setResourceScan] = useState<ResourceScanResult | null>(null);
    const [sitemapLoading, setSitemapLoading] = useState<boolean>(false);
    const [sitemapProgress, setSitemapProgress] = useState<SitemapProgress | null>(null);
    const [certLoading, setCertLoading] = useState<boolean>(false);

    useEffect(() => {
        // Get the URL from the query parameters
        const params = new URLSearchParams(window.location.search);
        const urlParam = params.get('url');

        if (urlParam) {
            const actualUrl = extractActualUrl(urlParam);

            // IMPORTANT: Extract domain preserving Unicode/homograph characters
            // Use extractDomainRaw() which doesn't use URL() constructor
            // This prevents browser from converting Cyrillic/homograph chars to punycode
            const originalDomain = extractDomainRaw(actualUrl);

            const sanitizedUrl = sanitizeUrl(actualUrl);

            if (!sanitizedUrl) {
                setError('Invalid or unsafe URL format');
                return;
            }

            const domainUrl = extractDomain(sanitizedUrl);
            setUrl(sanitizedUrl);
            setDomain(domainUrl);

            // Perform homograph analysis on ORIGINAL domain (preserves suspicious chars)
            try {
                const analysis = HomographDetector.detectSuspiciousDomain(originalDomain);
                setHomographAnalysis(analysis);
            } catch (error) {
                logger.error('Homograph analysis failed:', error);
            }

            handleConfirm(sanitizedUrl);
        }
    }, []);

    const extractedUrl = url;

    const handleConfirm = async (overrideUrl?: string) => {
        const urlToUse = overrideUrl || extractedUrl;
        if (!urlToUse) {
            setError('Could not extract a valid URL.');
            return;
        }

        if (!isValidUrl(urlToUse)) {
            setError('Invalid URL format. Please check the URL and try again.');
            return;
        }

        setIsScanning(true);
        setScanResult(null);
        setError(null);

        try {
            // 1. Reload settings from storage FIRST
            const settingsData: StorageData = await browser.storage.sync.get('phishGuardSettings');
            const currentSettings = { ...defaultSettings, ...settingsData.phishGuardSettings };
            setSettings(currentSettings); // Update settings state

            // 2. Extract domain from the URL being scanned
            const scanDomain = extractDomain(urlToUse);

            // 3. Prepare initial ScanResult structure
            //    (Explicitly type satisfies ScanResult but allows building)
            let resultObject: {
                url: string;
                robotsUrl?: string;
                sitemapUrl?: string;
                sitemapResult?: SitemapResult;
                virusTotalUrl?: string;
                supabaseStatus: 'found' | 'not_found' | 'error' | 'not_checked';
                domainInfo?: DomainInfo;
                certificateInfo?: CertificateInfo;
                reputationScore?: any; // Will be calculated later
                error?: string;
            } = {
                url: urlToUse, // Include the required url
                robotsUrl: `http://${scanDomain}/robots.txt`,
                sitemapUrl: generateSitemapSearchUrl(scanDomain),
                virusTotalUrl: `https://www.virustotal.com/gui/domain/${encodeURIComponent(scanDomain)}`,
                supabaseStatus: 'not_checked', // Start as not checked
                error: undefined // Start with no error
            };

            // 4. Perform fast security checks first (excluding slow sitemap)
            const fastChecks = await Promise.allSettled([
                // Supabase check
                checkUrlInSupabase(urlToUse),
                // Domain info check
                DomainInfoService.getDomainInfo(scanDomain),
                // Certificate info check (for HTTPS)
                DomainInfoService.getCertificateInfo(urlToUse),
                // Security monitoring (from content script)
                browser.tabs.query({ active: true, currentWindow: true }).then(tabs => {
                    if (tabs[0]?.id) {
                        return browser.tabs.sendMessage(tabs[0].id, { type: 'GET_ALL_SCANS' });
                    }
                    return Promise.reject(new Error('No active tab found'));
                }).catch(() => null) // Fail silently if content script not ready
            ]);

            // Process fast results
            const [supabaseResult, domainInfoResult, certificateInfoResult, securityScanResult] = fastChecks;

            if (supabaseResult.status === 'fulfilled') {
                resultObject.supabaseStatus = supabaseResult.value ? 'found' : 'not_found';
            } else {
                logger.error('Supabase check failed:', supabaseResult.reason);
                resultObject.supabaseStatus = 'error';
                resultObject.error = 'Error checking Supabase: ' + (supabaseResult.reason instanceof Error ? supabaseResult.reason.message : 'Unknown error');
            }

            // Process domain info result
            if (domainInfoResult.status === 'fulfilled') {
                resultObject.domainInfo = domainInfoResult.value || undefined;
            } else {
                logger.error('Domain info check failed:', domainInfoResult.reason);
            }

            // Process certificate info result
            if (certificateInfoResult.status === 'fulfilled') {
                resultObject.certificateInfo = certificateInfoResult.value || undefined;
            } else {
                logger.error('Certificate info check failed:', certificateInfoResult.reason);
            }

            // Set fallback sitemap URL initially
            resultObject.sitemapUrl = generateSitemapSearchUrl(scanDomain);

            // Check if this URL has automatic scan results stored
            try {
                const automaticScan: any = await browser.runtime.sendMessage({
                    type: 'GET_AUTOMATIC_SCAN',
                    url: urlToUse
                });

                if (automaticScan && automaticScan.scan) {
                    logger.log('📊 Using automatic scan results:', automaticScan);
                    setResourceScan(automaticScan.scan);
                }
            } catch (error) {
                logger.log('No automatic scan results available');
            }

            // Process security scan results (resource + download monitoring)
            if (securityScanResult.status === 'fulfilled' && securityScanResult.value && typeof securityScanResult.value === 'object') {
                const scanData = securityScanResult.value as any;

                if (scanData.resourceScan) {
                    setResourceScan(scanData.resourceScan);
                }

            }

            // 5. Calculate comprehensive reputation score
            try {
                const reputationScore = await ReputationService.calculateReputation(
                    urlToUse,
                    scanDomain,
                    resultObject.domainInfo,
                    resultObject.certificateInfo || undefined,
                    homographAnalysis || undefined,
                    resultObject.supabaseStatus
                );
                resultObject.reputationScore = reputationScore;
            } catch (error) {
                logger.error('Failed to calculate reputation score:', error);
                // Don't fail the entire scan if reputation calculation fails
            }

            // 6. Simulate delay (optional)
            await new Promise(resolve => setTimeout(resolve, 500));

            // 7. Set the final state ONCE with the fully constructed object (fast results)
            setScanResult(resultObject);

            // 8. Start background sitemap discovery (slow operation)
            setSitemapLoading(true);
            SitemapService.findSitemaps(scanDomain).then(sitemapResult => {
                // Update scan result with sitemap info
                setScanResult(prev => {
                    if (!prev) return prev;
                    return {
                        ...prev,
                        sitemapResult: sitemapResult,
                        sitemapUrl: sitemapResult.found ? undefined : generateSitemapSearchUrl(scanDomain)
                    };
                });
            }).catch(error => {
                logger.error('Sitemap discovery failed:', error);
            }).finally(() => {
                setSitemapLoading(false);
            });

            // 9. Start background certificate analysis (slow operation - can take 8+ seconds)
            if (urlToUse.startsWith('https://')) {
                setCertLoading(true);
                CertificateAnalysisService.analyzeCertificate(scanDomain).then(certAnalysis => {
                    // Update scan result with certificate analysis
                    setScanResult(prev => {
                        if (!prev || !prev.reputationScore) return prev;

                        // Calculate additional risk from certificate
                        let additionalRisk = 0;
                        const newFactors = [...(prev.reputationScore.factors || [])];
                        const newThreats = [...(prev.reputationScore.threatTypes || [])];

                        if (certAnalysis && !certAnalysis.error && certAnalysis.riskPoints > 0) {
                            additionalRisk = certAnalysis.riskPoints;

                            // Add certificate risk factors
                            certAnalysis.riskFactors.forEach(factor => {
                                newFactors.push({
                                    category: 'Certificate Analysis',
                                    impact: certAnalysis.riskPoints,
                                    description: 'Recently issued certificate',
                                    evidence: factor
                                });
                            });

                            // Check for high-risk pattern (new cert + new domain + free CA)
                            if (CertificateAnalysisService.isHighRiskPattern(certAnalysis, prev.domainInfo?.domainAge)) {
                                newThreats.push({
                                    type: 'phishing',
                                    severity: 'high',
                                    description: 'New domain with newly issued free certificate (common phishing setup)'
                                });
                            }
                        }

                        // Recalculate risk score and level
                        const newRiskScore = Math.min(prev.reputationScore.overall + additionalRisk, 100);
                        let newRiskLevel: 'low' | 'medium' | 'high' | 'critical';
                        if (newRiskScore >= 80) {
                            newRiskLevel = 'critical';
                        } else if (newRiskScore >= 60) {
                            newRiskLevel = 'high';
                        } else if (newRiskScore >= 30) {
                            newRiskLevel = 'medium';
                        } else {
                            newRiskLevel = 'low';
                        }

                        return {
                            ...prev,
                            reputationScore: {
                                ...prev.reputationScore,
                                overall: newRiskScore,
                                riskLevel: newRiskLevel,
                                factors: newFactors,
                                threatTypes: newThreats,
                                certAnalysis
                            }
                        };
                    });
                }).catch(error => {
                    logger.error('Certificate analysis failed:', error);
                }).finally(() => {
                    setCertLoading(false);
                });
            }

        } catch (err: any) {
            logger.error('Scan failed:', err);
            setError(err.message || 'Failed to scan URL');
            setScanResult(null); // Ensure result is null on general failure
        } finally {
            setIsScanning(false);
        }
    };

    const handleCancel = () => {
        window.close();
    };

    const toggleAdvancedMode = async () => {
        const newAdvancedMode = !settings.advancedMode;
        const newSettings = { ...settings, advancedMode: newAdvancedMode };
        setSettings(newSettings);

        // Save to storage
        await browser.storage.sync.set({ phishGuardSettings: newSettings });
    };

    const toggleAutomaticMonitoring = async () => {
        const newAutomaticMonitoring = !settings.automaticMonitoring;
        const newSettings = { ...settings, automaticMonitoring: newAutomaticMonitoring };
        setSettings(newSettings);

        // Save to storage
        await browser.storage.sync.set({ phishGuardSettings: newSettings });
    };

    const toggleNotifications = async () => {
        const newShowNotifications = !settings.showNotifications;
        const newSettings = { ...settings, showNotifications: newShowNotifications };
        setSettings(newSettings);

        // Save to storage
        await browser.storage.sync.set({ phishGuardSettings: newSettings });
    };

    // Helper function to determine overall safety status
    const getOverallSafetyStatus = () => {
        if (!scanResult) return { status: 'unknown', color: 'grey', icon: '❓', message: 'Analyzing...' };

        // Critical threats
        if (scanResult.supabaseStatus === 'found') {
            return { status: 'dangerous', color: 'danger', icon: '🚨', message: 'DANGEROUS - Known phishing site!' };
        }

        if (homographAnalysis?.recommendation === 'dangerous') {
            return { status: 'dangerous', color: 'danger', icon: '⚠️', message: 'DANGEROUS - Suspicious domain!' };
        }

        // High risk factors
        const highRiskFactors = [];

        if (scanResult.reputationScore?.riskLevel === 'critical') {
            highRiskFactors.push('Critical reputation risk');
        }

        if ((resourceScan?.riskScore || 0) >= 70) {
            highRiskFactors.push('Dangerous resources detected');
        }


        if (highRiskFactors.length > 0) {
            return { status: 'high-risk', color: 'danger', icon: '🔴', message: `HIGH RISK - ${highRiskFactors[0]}` };
        }

        // Medium risk factors
        const mediumRiskFactors = [];

        if (scanResult.reputationScore?.riskLevel === 'high' || scanResult.reputationScore?.riskLevel === 'medium') {
            mediumRiskFactors.push('Elevated security risk');
        }

        if (homographAnalysis?.recommendation === 'caution') {
            mediumRiskFactors.push('Domain requires caution');
        }

        if ((resourceScan?.riskScore || 0) >= 30) {
            mediumRiskFactors.push('Suspicious resources found');
        }


        if (scanResult.domainInfo?.isRecentlyRegistered) {
            mediumRiskFactors.push('Recently registered domain');
        }

        if (mediumRiskFactors.length > 0) {
            return { status: 'medium-risk', color: 'warning', icon: '🟡', message: `CAUTION - ${mediumRiskFactors[0]}` };
        }

        // Default to safe if no major issues
        return { status: 'safe', color: 'success', icon: '✅', message: 'SAFE - No major threats detected' };
    };

    const safetyStatus = getOverallSafetyStatus();

    return (
        <div className="popup-container">
            <div className="content-card">
                {/* Header with controls */}
                <div style={{ marginBottom: '15px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                        <h1 className="phish-guard-title">🛡️ Phish Guard</h1>
                        <button
                            className={`button is-small ${settings.advancedMode ? 'is-info' : 'is-light'}`}
                            onClick={toggleAdvancedMode}
                            style={{ fontSize: '0.75rem' }}
                        >
                            {settings.advancedMode ? '🔧 Advanced' : '👤 Simple'}
                        </button>
                    </div>

                    {/* Privacy Controls */}
                    <div style={{ display: 'flex', gap: '10px', fontSize: '0.75rem', flexWrap: 'wrap' }}>
                        <button
                            className={`button is-small ${settings.automaticMonitoring ? 'is-success' : 'is-light'}`}
                            onClick={toggleAutomaticMonitoring}
                            title="Enable automatic monitoring of page resources for security threats"
                        >
                            🤖 Auto Monitor: {settings.automaticMonitoring ? 'ON' : 'OFF'}
                        </button>

                        {settings.automaticMonitoring && (
                            <button
                                className={`button is-small ${settings.showNotifications ? 'is-info' : 'is-light'}`}
                                onClick={toggleNotifications}
                                title="Show browser notifications for automatic security alerts"
                            >
                                🔔 Alerts: {settings.showNotifications ? 'ON' : 'OFF'}
                            </button>
                        )}
                    </div>
                </div>

                {/* URL display - simplified in simple mode */}
                {url && (
                    <div className="url-display" style={{ marginBottom: '15px' }}>
                        {settings.advancedMode ? (
                            <>
                                <strong>Scanning:</strong> {url}
                                <br />
                                <strong>Domain:</strong> {domain}
                            </>
                        ) : (
                            <div style={{ fontSize: '0.9rem', color: '#666' }}>
                                <div><strong>Link:</strong> <a href={url} style={{ wordBreak: 'break-all' }}>{url}</a></div>
                                <div><strong>Domain:</strong> {domain}</div>
                            </div>
                        )}
                    </div>
                )}

                {/* Error display */}
                {error && (
                    <div className="notification is-danger">
                        <strong>Error:</strong> {error}
                        <button className="button is-light" onClick={handleCancel} style={{ marginTop: '15px', display: 'block' }}>Close</button>
                    </div>
                )}

                {/* Loader - shown during scan */}
                {isScanning && (
                    <div style={{ textAlign: 'center', padding: '40px' }}>
                        <div className="spinner"></div>
                    </div>
                )}
                {/* Results section - simplified with components */}
                {scanResult && (
                    <>
                        <SafetyStatusCard
                            safetyStatus={safetyStatus}
                            isAdvancedMode={settings.advancedMode}
                        />

                        {!settings.advancedMode ? (
                            <SimpleModeView
                                scanResult={scanResult}
                                resourceScan={resourceScan}
                                url={url}
                                certLoading={certLoading}
                                onToggleAdvanced={toggleAdvancedMode}
                                onCancel={handleCancel}
                            />
                        ) : (
                            <AdvancedModeView
                                scanResult={scanResult}
                                resourceScan={resourceScan}
                                homographAnalysis={homographAnalysis}
                                url={url}
                                domain={domain}
                                sitemapLoading={sitemapLoading}
                                certLoading={certLoading}
                                onCancel={handleCancel}
                            />
                        )}
                    </>
                )}
            </div>
        </div>
    );
};

const container = document.getElementById('root');
if (container) {
  const root = createRoot(container);
  root.render(
    <ErrorBoundary>
      <Popup />
    </ErrorBoundary>
  );
}

export default Popup;