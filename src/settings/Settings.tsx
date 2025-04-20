// src/settings/Settings.tsx
import React, { useState, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import browser from 'webextension-polyfill';
import { PhishGuardSettings, StorageData, defaultSettings } from '../types';

const Settings: React.FC = () => {
    const [settings, setSettings] = useState<PhishGuardSettings>(defaultSettings);
    const [isLoading, setIsLoading] = useState(true);
    const [status, setStatus] = useState(''); // To show 'Saved' status

    // Load settings on mount
    useEffect(() => {
        browser.storage.sync.get({ phishGuardSettings: defaultSettings })
            .then((data: StorageData) => {
                // Use optional chaining and nullish coalescing for safety
                setSettings(data.phishGuardSettings ?? defaultSettings);
                setIsLoading(false);
            })
            .catch((error: Error) => {
                console.error("Error loading settings:", error);
                setIsLoading(false); // Still finish loading even if error
            });
    }, []);

    // Handle checkbox change
    const handleCheckboxChange = (event: React.ChangeEvent<HTMLInputElement>) => {
        const { name, checked } = event.target;
        const updatedSettings = { ...settings, [name]: checked };
        setSettings(updatedSettings);

        // Save updated settings
        browser.storage.sync.set({ phishGuardSettings: updatedSettings })
            .then(() => {
                setStatus('Settings saved!');
                setTimeout(() => setStatus(''), 1500); // Clear status after 1.5s
            })
            .catch((error: Error) => {
                console.error("Error saving settings:", error); // Log the specific error object
                setStatus(`Error saving: ${error.message}`); // Show the error message in status
            });
    };

    if (isLoading) {
        return <div className="section"><div className="loader">Loading...</div></div>; // Add loader styling
    }

    return (
        <section className="section" style={{ width: '350px', padding: '20px' }}> {/* Use section, adjust width */}
            <h2 className="title is-4">Scan Page Layout Settings</h2> {/* Add title class */}

            <div className="field"> {/* Wrap in field */}
                <div className="control"> {/* Wrap in control */}
                    <label className="checkbox"> {/* Use checkbox class for label */} 
                        <input
                            type="checkbox"
                            name="showRobotsTxt"
                            checked={settings.showRobotsTxt}
                            onChange={handleCheckboxChange}
                            style={{ marginRight: '5px' }} // Add some spacing
                        />
                        Show Robots.txt Button
                    </label>
                </div>
            </div>

            <div className="field">
                <div className="control">
                    <label className="checkbox">
                        <input
                            type="checkbox"
                            name="showSitemap"
                            checked={settings.showSitemap}
                            onChange={handleCheckboxChange}
                             style={{ marginRight: '5px' }}
                        />
                        Show Sitemap Search Button
                    </label>
                </div>
            </div>

            <div className="field">
                <div className="control">
                    <label className="checkbox">
                        <input
                            type="checkbox"
                            name="showVirusTotal"
                            checked={settings.showVirusTotal}
                            onChange={handleCheckboxChange}
                             style={{ marginRight: '5px' }}
                        />
                        Show VirusTotal Button
                    </label>
                </div>
            </div>

            <div className="field">
                <div className="control">
                    <label className="checkbox">
                        <input
                            type="checkbox"
                            name="showSupabase"
                            checked={settings.showSupabase}
                            onChange={handleCheckboxChange}
                             style={{ marginRight: '5px' }}
                        />
                        Show Supabase DB Button
                    </label>
                </div>
            </div>

             {/* Style status message */}
             {status && (
                <div className={`notification ${status.startsWith('Error') ? 'is-danger' : 'is-success'} is-light is-small mt-3`}>
                    {status}
                </div>
            )}
        </section>
    );
};

// Find the root element in your settings HTML page (which needs to be generated by your build process)
const container = document.getElementById('settings-root');
if (container) {
    const root = createRoot(container);
    root.render(
        <React.StrictMode>
            <Settings />
        </React.StrictMode>
    );
} else {
    console.error("Could not find root element '#settings-root' for settings page.");
    // Attempt to create and append if not found (useful for testing/fallback)
    const fallbackContainer = document.createElement('div');
    fallbackContainer.id = 'settings-root';
    document.body.appendChild(fallbackContainer);
    const root = createRoot(fallbackContainer);
    root.render(
        <React.StrictMode>
            <Settings />
        </React.StrictMode>
    );
}
