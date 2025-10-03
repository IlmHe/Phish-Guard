# Privacy Policy - Phish Guard Browser Extension

**Last Updated:** September 30, 2025
**Version:** 1.0.1

## Overview

Phish Guard is a browser extension that helps protect users from phishing websites by analyzing URLs and providing security assessments. This privacy policy explains what data we collect, how we use it, and your rights regarding your information.

## Data Collection and Usage

### Automatic Monitoring (Optional - User Opt-In Required)

**IMPORTANT**: Automatic monitoring is **DISABLED BY DEFAULT**. You must explicitly enable it through the extension settings.

**When Automatic Monitoring is ENABLED, We Collect:**
- External resources loaded by ALL websites you visit (scripts, images, iframes, stylesheets)
- Resource URLs and domains from external content
- Domain names of websites you visit
- Mouse cursor position and movement (for popup positioning)
- Window dimensions and scroll position
- Security risk scores for suspicious external resources
- Timestamps of when suspicious resources are detected

**When Automatic Monitoring is DISABLED (Default), We Collect:**
- Only mouse cursor position (for popup positioning when you manually scan)
- NO automatic resource monitoring
- NO automatic website domain collection
- NO automatic security scanning

**How We Use Automatic Monitoring Data (When Enabled):**
- Monitor external resources for suspicious patterns (IP addresses, free domains, malicious keywords)
- Detect mixed content warnings (HTTP resources on HTTPS pages)
- Calculate risk scores for external resources loaded by pages
- Generate security alerts for high-risk external resources (risk score > 30)
- Display automatic security popups when threats are detected

### Manual Scan Data Collection

**What We Collect When You Scan:**
- URLs you choose to scan using our extension
- Domain names extracted from those URLs

**How We Use Manual Scan Data:**
- Check URLs against our phishing database (hosted on Supabase)
- Retrieve domain registration information via WHOIS APIs
- Perform comprehensive security analysis and risk assessment

**Data Retention:**
- Automatic monitoring data: Stored temporarily in browser memory for up to 5 minutes, then automatically deleted by our cleanup service (runs every 60 seconds)
- Manual scan results: Cached locally in your browser for up to 5 minutes, then automatically deleted
- Alert cooldown data: Stored for 60 seconds per domain to prevent notification spam, then automatically deleted
- No browsing history is stored permanently anywhere
- Supabase database queries are logged by Supabase (see their privacy policy)
- All data is stored locally in your browser - nothing is sent to our servers
- Data cleanup service runs automatically every minute to ensure old data is removed

### External Services We Use (Manual Scans Only)

**Supabase Database:**
- Purpose: Check if URLs exist in our known phishing database
- Data Sent: Only the specific URL you choose to scan manually
- Data Retention: Queries are logged by Supabase per their privacy policy
- Frequency: Only when you actively request a URL scan

**WHOIS APIs (Optional):**
- Purpose: Retrieve domain registration information for security analysis
- Data Sent: Domain names only (e.g., "example.com")
- Services Used: whois.freecodecamp.com and jsonwhois.com
- User-Agent: Requests identify as "Phish-Guard/1.0"
- Frequency: Only when you manually scan URLs and domain info is available

**Target Website Requests (Optional):**
- Purpose: Check for sitemaps and security configuration files on scanned sites
- Data Sent: Standard HTTP requests to robots.txt and sitemap paths
- User-Agent: Requests identify as "Phish-Guard/1.0 (Sitemap Detection)"
- Frequency: Only when you manually scan URLs that support sitemap discovery

**CDN Services:**
- Purpose: Load Bulma CSS framework for extension UI
- Service: cdn.jsdelivr.net
- Data Sent: Standard HTTP requests for CSS files
- Frequency: Only when extension popup is opened

### Mock Services (No External Data Transmission)

**Threat Intelligence APIs:**
These services are simulated locally and do NOT send data externally:
- VirusTotal API simulation (local pattern analysis only)
- Google Safe Browsing API simulation (local pattern analysis only)
- PhishTank API simulation (local pattern analysis only)

The extension displays "3/3 APIs responded" but this refers to local analysis modules, not external API calls.

## Data We DO NOT Collect

- We do not collect personal information (name, email, addresses, phone numbers)
- We do not permanently store your browsing history anywhere
- We do not use cookies or tracking pixels for advertising
- We do not share data with advertisers or marketing companies
- We do not record keystrokes or form inputs
- We do not access your bookmarks, passwords, or saved data
- We do not track you when automatic monitoring is disabled

## Important Clarifications

**By Default (Automatic Monitoring OFF), We Only Collect:**
- Mouse position when you manually scan a URL
- The specific URL you choose to scan manually
- Manual scan results (stored locally for 5 minutes)

**When You Enable Automatic Monitoring, We Additionally Collect:**
- URLs and resource information from ALL websites you visit
- Domain names of websites you visit
- Security scan results and risk assessments for all pages

**All data collection is:**
- Stored locally in your browser only
- Used solely for security analysis and phishing protection
- Never sold or shared with third parties
- Cleared when you disable monitoring or uninstall the extension

## Local Processing

Most security analysis happens locally in your browser:
- Homograph and typosquatting detection
- URL structure analysis
- Risk scoring and reputation calculation
- Certificate validation checks

## Browser Permissions Explained

**Active Tab Permission:**
- Used to scan the current webpage when requested
- Only activates when you use the context menu

**Storage Permission:**
- Used to save your simple/advanced mode preference
- Used to cache scan results temporarily (5 minutes)

**Context Menus Permission:**
- Adds "Scan with Phish-Guard" option to right-click menus

**Host Permissions (*://*/*):**
- Required to analyze any website you choose to scan
- Only used when you actively request a scan via context menu
- Necessary for sitemap detection and security analysis
- Does not grant access to websites you don't scan

## Your Rights and Choices

**Control Over Automatic Monitoring:**
- Automatic monitoring is **DISABLED BY DEFAULT**
- You must explicitly enable it by clicking "Auto Monitor: OFF" button in the extension popup
- You can disable it at any time by clicking "Auto Monitor: ON" to turn it off
- When disabled, the extension only collects data during manual scans

**Control Over Manual Scanning:**
- All manual scans are initiated by you via right-click context menu
- You can choose which URLs to scan
- Manual scanning works independently of automatic monitoring

**Data Deletion:**
- Automatic monitoring data is cleared when you close the tab or disable monitoring
- Manual scan results are automatically deleted after 5 minutes
- You can clear all cached data by restarting your browser or disabling the extension
- Uninstalling the extension removes all local data immediately

**Settings:**
- Toggle between Simple and Advanced modes for scan results
- Enable/disable automatic resource monitoring (OFF by default)
- Enable/disable security notifications (ON by default when monitoring is enabled)

## Security Measures

- All external API communications use HTTPS encryption
- Local data is stored using browser's secure storage APIs
- No sensitive data is logged or transmitted unnecessarily
- Regular security audits of our codebase

## Third-Party Privacy Policies

Please review the privacy policies of external services we use:
- [Supabase Privacy Policy](https://supabase.com/privacy)
- [FreCodeCamp API Terms](https://www.freecodecamp.org/news/privacy-policy/)

## Changes to This Policy

We will notify users of any material changes to this privacy policy through:
- Extension store update descriptions
- Updates to this document with revised "Last Updated" date

## Contact Information

For questions about this privacy policy or data practices:
- GitHub Issues: [https://github.com/IlmHe/Phish-Guard/issues](https://github.com/IlmHe/Phish-Guard/issues)
- Repository: [https://github.com/IlmHe/Phish-Guard](https://github.com/IlmHe/Phish-Guard)

## Compliance

This privacy policy is designed to comply with:
- Chrome Web Store Developer Program Policies
- General Data Protection Regulation (GDPR) principles
- California Consumer Privacy Act (CCPA) where applicable

---

*This policy covers only the Phish Guard browser extension. Links to external websites (VirusTotal, SSL Labs, etc.) are provided for your convenience and are governed by their respective privacy policies.*