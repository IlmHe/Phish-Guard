// src/types.ts

// Import reputation types
import { ReputationScore } from './services/reputationService';

// Settings for Phish Guard extension
export interface PhishGuardSettings {
  advancedMode: boolean; // Simple vs Advanced interface mode
  automaticMonitoring: boolean; // Enable/disable automatic resource monitoring
  showNotifications: boolean; // Show browser notifications for automatic alerts
}

// Structure for storing/retrieving settings from browser.storage.sync
export interface StorageData {
  phishGuardSettings?: PhishGuardSettings;
}

// Default settings values
export const defaultSettings: PhishGuardSettings = {
  advancedMode: false, // Default to simple mode for regular users
  automaticMonitoring: false, // Default to OFF for privacy (opt-in)
  showNotifications: true, // Show notifications when automatic monitoring is enabled
};

// Domain information structure
export interface DomainInfo {
  registrationDate?: string;
  expirationDate?: string;
  registrar?: string;
  domainAge?: number; // in days
  isRecentlyRegistered?: boolean; // registered in last 30 days
  whoisUrl?: string;
}

// SSL Certificate information structure
export interface CertificateInfo {
  issuer?: string;
  validFrom?: string;
  validTo?: string;
  issuedRecently?: boolean; // issued in last 30 days
  isSelfSigned?: boolean;
  daysUntilExpiry?: number;
}

// Defines the structure for the scan results displayed in the popup
export type ScanResult = {
  url: string;
  robotsUrl?: string; // Optional: URL for robots.txt
  sitemapUrl?: string; // Optional: URL for sitemap (fallback)
  sitemapResult?: any; // Advanced sitemap discovery results
  virusTotalUrl?: string; // Optional: URL for VirusTotal scan
  supabaseStatus: 'found' | 'not_found' | 'error' | 'not_checked'; // Status from Supabase check
  homographRisk?: 'safe' | 'caution' | 'dangerous'; // Homograph detection result
  domainInfo?: DomainInfo; // Domain age and registration info
  certificateInfo?: CertificateInfo; // SSL certificate info
  reputationScore?: ReputationScore; // Comprehensive reputation analysis
  error?: string; // Optional: Error message if something went wrong
} | null; // Can be null initially or if no scan is performed

// Settings for enabling/disabling homograph detection
export interface ExtendedPhishGuardSettings extends PhishGuardSettings {
  showHomographAnalysis: boolean;
}

// Extended default settings
export const extendedDefaultSettings: ExtendedPhishGuardSettings = {
  ...defaultSettings,
  showHomographAnalysis: true,
};
