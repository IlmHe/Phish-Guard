import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { checkUrlInSupabase } from './apiservice';

const Popup: React.FC = () => {
    const [url, setUrl] = useState<string>('');
    const [domain, setDomain] = useState<string>('');
    const [scanResult, setScanResult] = useState<{ domainLink: string } | null>(null);
    const [isScanning, setIsScanning] = useState<boolean>(false);

    useEffect(() => {
        console.log('Popup component loaded');

        function extractActualUrl(googleUrl: string): string {
            const urlMatch = googleUrl.match(/[?&]url=([^&]+)/);
            return urlMatch ? decodeURIComponent(urlMatch[1]) : googleUrl;
        }

        function extractDomain(url: string): string {
            const domainMatch = url.match(/^(?:https?:\/\/)?(?:www\.)?([^\/]+)/i);
            return domainMatch ? domainMatch[1] : url;
        }

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
        try {
            const isUrlInSupabase = await checkUrlInSupabase(url);
            const result = isUrlInSupabase
                ? { domainLink: `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}` }
                : { urlLink: 'URL not found in Supabase', domainLink: '' };
            setScanResult(result);
        } catch (error) {
            setScanResult({ domainLink: 'Error: ' + (error instanceof Error ? error.message : 'Unknown error'), });
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
            {isScanning && <div className="loader">Scanning...</div>}
            {scanResult && (
                <div className="notification is-info">
                    <h2>Scan Results</h2>
                    <p>Domain Scan: <a href={scanResult.domainLink} target="_blank" rel="noopener noreferrer">{scanResult.domainLink}</a></p>
                    <button className="button is-light" onClick={handleCancel}>Close</button>
                </div>
            )}
        </div>
    );
};

const container = document.getElementById('root') as HTMLElement;
const root = createRoot(container);
root.render(<Popup />);