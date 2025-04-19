import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { checkUrlInSupabase } from './apiservice';

function extractActualUrl(googleUrl: string): string {
    const urlMatch = googleUrl.match(/[?&]url=([^&]+)/);
    return urlMatch ? decodeURIComponent(urlMatch[1]) : googleUrl;
}

function extractDomain(url: string): string {
    const domainMatch = url.match(/^(?:https?:\/\/)?(?:www\.)?([^\/]+)/i);
    return domainMatch ? domainMatch[1] : url;
}

// Define a more descriptive type for scan results
type ScanResult =
    | {
          supabaseStatus: 'found' | 'not_found';
          virusTotalLink: string;
          error?: undefined; // No error during Supabase check
      }
    | {
          supabaseStatus: 'error';
          virusTotalLink: null; // Supabase check failed
          error: string;
      }
    | null;

const Popup = (): React.ReactElement => {
    const [url, setUrl] = useState<string>('');
    const [domain, setDomain] = useState<string>('');
    const [scanResult, setScanResult] = useState<ScanResult>(null);
    const [isScanning, setIsScanning] = useState<boolean>(false);

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
        }
    }, []);

    const handleConfirm = async () => {
        setIsScanning(true);
        setScanResult(null); // Reset previous result
        const virusTotalLink = `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}`; // Prepare VT link regardless
        try {
            const isUrlInSupabase = await checkUrlInSupabase(url);
            // Set state including VT link and Supabase status
            setScanResult({
                supabaseStatus: isUrlInSupabase ? 'found' : 'not_found',
                virusTotalLink: virusTotalLink,
            });
        } catch (error) {
            // Set state for Supabase check error
            setScanResult({
                supabaseStatus: 'error',
                virusTotalLink: null, // Indicate Supabase check failed
                error: 'Error checking Supabase: ' + (error instanceof Error ? error.message : 'Unknown error'),
            });
        } finally {
            setIsScanning(false);
        }
    };

    const handleCancel = () => {
        window.close();
    };

    return (
        <div className="container" style={{ padding: '20px' }}>
            <h1 className="title">Confirm URL</h1>
            {!isScanning && !scanResult && (
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
                        <button className="button is-primary" onClick={handleConfirm}>Scan</button>
                        <button className="button is-light" onClick={handleCancel}>Cancel</button>
                    </div>
                </>
            )}
            {/* Loader - shown during scan */}
            {isScanning && <div className="loader">Scanning...</div>}
            {/* Results section - shown after scan */}
            {scanResult && (
                <div className={`notification ${scanResult.supabaseStatus === 'error' ? 'is-danger' : scanResult.supabaseStatus === 'found' ? 'is-warning' : 'is-info'}`}>
                    <h2>Scan Results</h2>
                    {/* Supabase Status */}
                    {scanResult.supabaseStatus === 'found' && <p><strong>Status:</strong> URL found in known phishing sites database.</p>}
                    {scanResult.supabaseStatus === 'not_found' && <p><strong>Status:</strong> URL not found in known phishing sites database.</p>}
                    {scanResult.supabaseStatus === 'error' && <p><strong>Status:</strong> Error checking database: {scanResult.error}</p>}

                    {/* VirusTotal Link (show unless Supabase check failed) */}
                    {scanResult.virusTotalLink && (
                        <p style={{ marginTop: '10px' }}>Check domain on VirusTotal: <a href={scanResult.virusTotalLink} target="_blank" rel="noopener noreferrer">{scanResult.virusTotalLink}</a></p>
                    )}

                    {/* robots.txt and sitemap.xml buttons (show unless Supabase check failed) */}
                    {scanResult.virusTotalLink && (
                        <div className="buttons" style={{ marginTop: '15px' }}>
                             {/* Updated button style */}
                             <a href={`https://${domain}/robots.txt`} target="_blank" rel="noopener noreferrer" className="button is-link">View robots.txt</a>
                             {/* Updated button style */}
                             <a href={`https://www.google.com/search?q=${encodeURIComponent(`site:${domain} (filetype:xml OR filetype:txt) inurl:sitemap`)}`} target="_blank" rel="noopener noreferrer" className="button is-link">Search for Sitemap</a>
                        </div>
                    )}

                    <button className="button is-light" onClick={handleCancel} style={{ marginTop: '15px' }}>Close</button>
                </div>
            )}
        </div>
    );
};

const container = document.getElementById('root') as HTMLElement;
const root = createRoot(container);
root.render(<Popup />);