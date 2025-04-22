import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import browser from 'webextension-polyfill'; // Add this import
import { checkUrlInSupabase } from './apiservice';
import { PhishGuardSettings, StorageData, defaultSettings, ScanResult } from './types';

export function extractActualUrl(googleUrl: string): string {
    const urlMatch = googleUrl.match(/[?&]url=([^&]+)/);
    return urlMatch ? decodeURIComponent(urlMatch[1]) : googleUrl;
}

export function extractDomain(url: string): string {
    const domainMatch = url.match(/^(?:https?:\/\/)?(?:www\.)?([^\/]+)/i);
    return domainMatch ? domainMatch[1] : url;
}

export const Popup = (): React.ReactElement => {
    const [url, setUrl] = useState<string>('');
    const [domain, setDomain] = useState<string>('');
    const [scanResult, setScanResult] = useState<ScanResult | null>(null);
    const [isScanning, setIsScanning] = useState<boolean>(false);
    const [settings, setSettings] = useState<PhishGuardSettings>(defaultSettings);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        console.log('Popup component loaded');

        // Get the URL from the query parameters
        const params = new URLSearchParams(window.location.search);
        const urlParam = params.get('url');

        if (urlParam) {
            const actualUrl = extractActualUrl(urlParam);
            const domainUrl = extractDomain(actualUrl);
            console.log(`URL to display: ${actualUrl}`);
            console.log(`Domain to display: ${domainUrl}`);
            setUrl(actualUrl);
            setDomain(domainUrl);
            handleConfirm(actualUrl);
        }
    }, []);

    const extractedUrl = url;

    const handleConfirm = async (overrideUrl?: string) => {
        const urlToUse = overrideUrl || extractedUrl;
        if (!urlToUse) {
            setError('Could not extract a valid URL.');
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

            // 2. Prepare initial ScanResult structure 
            //    (Explicitly type satisfies ScanResult but allows building)
            let resultObject: { 
                url: string;
                robotsUrl?: string;
                sitemapUrl?: string;
                virusTotalUrl?: string;
                supabaseStatus: 'found' | 'not_found' | 'error' | 'not_checked';
                error?: string;
            } = {
                url: urlToUse, // Include the required url
                robotsUrl: `http://${new URL(urlToUse).hostname}/robots.txt`,
                sitemapUrl: `https://www.google.com/search?q=${encodeURIComponent(`site:${domain} (filetype:xml OR filetype:txt) inurl:sitemap`)}`, // Use Google Dork
                virusTotalUrl: `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}`,
                supabaseStatus: 'not_checked', // Start as not checked
                error: undefined // Start with no error
            };

            // 3. Perform Supabase check and update the resultObject
            try {
                const isUrlInSupabase = await checkUrlInSupabase(urlToUse); 
                resultObject.supabaseStatus = isUrlInSupabase ? 'found' : 'not_found';
            } catch (supabaseError) {
                console.error('Supabase check failed:', supabaseError);
                resultObject.supabaseStatus = 'error';
                resultObject.error = 'Error checking Supabase: ' + (supabaseError instanceof Error ? supabaseError.message : 'Unknown error');
                // Optionally clear other links if Supabase fails 
                // resultObject.virusTotalUrl = undefined; 
            }

            // 4. Simulate delay (optional)
            await new Promise(resolve => setTimeout(resolve, 500));

            // 5. Set the final state ONCE with the fully constructed object
            setScanResult(resultObject);

        } catch (err: any) {
            console.error('Scan failed:', err);
            setError(err.message || 'Failed to scan URL');
            setScanResult(null); // Ensure result is null on general failure
        } finally {
            setIsScanning(false);
        }
    };

    const handleCancel = () => {
        window.close();
    };

    return (
        <div className="container" style={{ padding: '20px' }}>
            {/* Initial prompt disabled */}
            {false && !isScanning && !scanResult && (
                <>
                    <div className="field">
                        <div className="control">
                            <textarea
                                className="textarea"
                                id="url"
                                value={url}
                                onChange={(e) => setUrl(e.target.value)}
                                style={{ height: '100px', wordBreak: 'break-all' }}
                            />
                        </div>
                    </div>
                    <div className="field">
                        <div className="control">
                            <input
                                className="input"
                                id="domain"
                                value={domain}
                                readOnly
                                style={{ wordBreak: 'break-all' }}
                            />
                        </div>
                    </div>
                    <div className="buttons">
                        <button className="button is-primary" onClick={() => { void handleConfirm(); }}>Scan</button>
                        <button className="button is-light" onClick={handleCancel}>Cancel</button>
                    </div>
                </>
            )}
            {/* Loader - shown during scan */}
            {isScanning && <div className="loader">Scanning...</div>}
            {/* Results section - shown after scan */}
            {scanResult && (
                <div className={`notification ${scanResult.supabaseStatus === 'error' ? 'is-danger' : scanResult.supabaseStatus === 'found' ? 'is-warning' : 'is-info'}`}>
                    {/* Supabase Status */}
                    {settings.showSupabase && (
                        <>
                            {scanResult.supabaseStatus === 'found' && <p className="has-text-danger"><strong>Status:</strong> Found in Phishing DB (Supabase)</p>}
                            {scanResult.supabaseStatus === 'not_found' && <p className="has-text-success"><strong>Status:</strong> Not found in our own phishing databases.</p>}
                            {scanResult.supabaseStatus === 'error' && <p className="has-text-warning"><strong>Status:</strong> Error checking Phishing DB: {scanResult.error}</p>}
                            {scanResult.supabaseStatus === 'not_checked' && <p><strong>Status:</strong> Checking Supabase...</p>}
                        </>
                    )}
                    {/* Display scanned link and domain */}
                    <p><strong>Link:</strong> <a href={scanResult.url} target="_blank" rel="noopener noreferrer">{scanResult.url}</a></p>
                    <p><strong>Domain:</strong> {domain}</p>
                    <div className="buttons mt-3"> {/* Add margin-top */} 
                         {settings.showRobotsTxt && scanResult.robotsUrl && (
                             <a href={scanResult.robotsUrl} target="_blank" rel="noopener noreferrer" className="button is-link is-light">
                                 View robots.txt
                             </a>
                         )}
                         {settings.showSitemap && scanResult.sitemapUrl && (
                             <a href={scanResult.sitemapUrl} target="_blank" rel="noopener noreferrer" className="button is-link is-light">
                                 Search Sitemap
                             </a>
                         )}
                         {settings.showVirusTotal && scanResult.virusTotalUrl && (
                             <a href={scanResult.virusTotalUrl} target="_blank" rel="noopener noreferrer" className="button is-link is-light">
                                VirusTotal Domain Lookup
                             </a>
                         )}
                    </div>

                    <button className="button is-light" onClick={handleCancel} style={{ marginTop: '15px' }}>Close</button>
                </div>
            )}
        </div>
    );
};

const container = document.getElementById('root');
if (container) {
  const root = createRoot(container);
  root.render(<Popup />);
}

export default Popup;