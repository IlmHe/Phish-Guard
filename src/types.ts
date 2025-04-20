// src/types.ts

// Settings for Phish Guard extension
export interface PhishGuardSettings {
    showRobotsTxt: boolean;
    showSitemap: boolean;
    showVirusTotal: boolean;
    showSupabase: boolean;
}

// Structure for storing/retrieving settings from browser.storage.sync
export interface StorageData {
    phishGuardSettings?: PhishGuardSettings;
}

// Default settings values
export const defaultSettings: PhishGuardSettings = {
    showRobotsTxt: true,
    showSitemap: true,
    showVirusTotal: true,
    showSupabase: true
};

// Defines the structure for the scan results displayed in the popup
export type ScanResult = {
    url: string;
    robotsUrl?: string;      // Optional: URL for robots.txt
    sitemapUrl?: string;     // Optional: URL for sitemap
    virusTotalUrl?: string;  // Optional: URL for VirusTotal scan
    supabaseStatus: 'found' | 'not_found' | 'error' | 'not_checked'; // Status from Supabase check
    error?: string;          // Optional: Error message if something went wrong
} | null; // Can be null initially or if no scan is performed
