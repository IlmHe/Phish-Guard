import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import browser from 'webextension-polyfill';

const Popup: React.FC = () => {
    const [url, setUrl] = useState<string>('');

    useEffect(() => {
        console.log('Popup component loaded');

        function extractActualUrl(googleUrl: string): string {
            const urlMatch = googleUrl.match(/[?&]url=([^&]+)/);
            return urlMatch ? decodeURIComponent(urlMatch[1]) : googleUrl;
        }

        // Get the URL from the query parameters
        const params = new URLSearchParams(window.location.search);
        const urlParam = params.get('url');

        if (urlParam) {
            const actualUrl = extractActualUrl(urlParam);
            console.log(`URL to display: ${actualUrl}`);
            setUrl(actualUrl);
        }
    }, []);

    const handleConfirm = () => {
        // Send a message to the background script to scan the URL
        browser.runtime.sendMessage({ action: 'scanUrl', url });
        window.close();
    };

    const handleCancel = () => {
        window.close();
    };

    return (
        <div className="container" style={{ padding: '20px' }}>
            <h1 className="title">Confirm URL</h1>
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
            <div className="buttons">
                <button className="button is-primary" onClick={handleConfirm}>Scan</button>
                <button className="button is-light" onClick={handleCancel}>Cancel</button>
            </div>
        </div>
    );
};

const container = document.getElementById('root') as HTMLElement;
const root = createRoot(container);
root.render(<Popup />);