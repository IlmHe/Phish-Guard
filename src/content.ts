// src/content.ts - Content script to capture mouse position and monitor resources
import browser from 'webextension-polyfill';
import { ResourceMonitor } from './services/resourceMonitor';
import { PhishGuardSettings, defaultSettings } from './types';
import logger from './utils/logger';

// Store last mouse position
let lastMousePosition = { x: 0, y: 0 };

// Store latest scan results
let latestResourceScan: any = null;

// Store current settings
let currentSettings: PhishGuardSettings = defaultSettings;

// Track mouse movement
document.addEventListener('mousemove', (event) => {
  lastMousePosition = {
    x: event.clientX,
    y: event.clientY
  };
});

// Listen for context menu events and send mouse position
document.addEventListener('contextmenu', (event) => {
  const mousePosition = {
    x: event.clientX,
    y: event.clientY,
    screenX: event.screenX,
    screenY: event.screenY,
    pageX: event.pageX,
    pageY: event.pageY,
    windowWidth: window.innerWidth,
    windowHeight: window.innerHeight,
    windowScrollX: window.scrollX,
    windowScrollY: window.scrollY
  };

  // Send mouse position to background script
  browser.runtime.sendMessage({
    type: 'MOUSE_POSITION',
    position: mousePosition
  }).catch(error => {
    logger.error('Failed to send mouse position:', error);
  });
});

// Load settings and perform initial scans when page loads
async function performSecurityScans() {
  try {
    // Load settings first
    const settingsData = await browser.storage.sync.get('phishGuardSettings');
    currentSettings = { ...defaultSettings, ...(settingsData.phishGuardSettings || {}) };

    // Check if automatic monitoring is enabled
    if (!currentSettings.automaticMonitoring) {
      logger.log('🛡️ Phish Guard: Automatic monitoring disabled by user settings');
      logger.log('🛡️ Phish Guard: To enable, right-click any page and select "Scan with Phish-Guard", then click "Auto Monitor: OFF" button');
      return;
    }

    logger.log('🛡️ Phish Guard: Starting automatic resource monitoring for', window.location.hostname);

    // Resource monitoring
    latestResourceScan = ResourceMonitor.scanPageResources();

    logger.log('🛡️ Phish Guard: Scan completed -', {
      domain: window.location.hostname,
      totalResources: latestResourceScan.totalResources,
      externalDomains: latestResourceScan.externalDomains.length,
      suspiciousResources: latestResourceScan.suspiciousResources.length,
      riskScore: latestResourceScan.riskScore,
      summary: latestResourceScan.summary
    });

    // Send alerts for security concerns
    if (latestResourceScan.riskScore > 30) {
      logger.warn('🚨 Phish Guard: HIGH RISK PAGE DETECTED!', {
        riskScore: latestResourceScan.riskScore,
        suspiciousResources: latestResourceScan.suspiciousResources
      });

      browser.runtime.sendMessage({
        type: 'RESOURCE_SECURITY_ALERT',
        scan: latestResourceScan,
        url: window.location.href
      }).catch(error => {
        logger.error('Failed to send resource security alert:', error);
      });
    }

  } catch (error) {
    logger.error('🛡️ Phish Guard: Security scans failed:', error);
  }
}

// Run initial scans when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', performSecurityScans);
} else {
  performSecurityScans();
}

// Set up dynamic monitoring for new resources only if enabled
async function setupDynamicMonitoringIfEnabled() {
  // Load current settings
  const settingsData = await browser.storage.sync.get('phishGuardSettings');
  currentSettings = { ...defaultSettings, ...(settingsData.phishGuardSettings || {}) };

  if (!currentSettings.automaticMonitoring) {
    logger.log('🛡️ Phish Guard: Dynamic monitoring disabled by user settings');
    return;
  }

  ResourceMonitor.setupDynamicMonitoring((newFindings) => {
    logger.log('🛡️ Phish Guard: Dynamic resource change detected', {
      newRiskScore: newFindings.riskScore,
      suspiciousResources: newFindings.suspiciousResources.length
    });

    latestResourceScan = newFindings;

    // Alert if new suspicious resources are detected
    if (newFindings.riskScore > 30) {
      logger.warn('🚨 Phish Guard: NEW HIGH RISK RESOURCES DETECTED!', {
        riskScore: newFindings.riskScore,
        suspiciousResources: newFindings.suspiciousResources
      });

      browser.runtime.sendMessage({
        type: 'RESOURCE_SECURITY_ALERT',
        scan: newFindings,
        url: window.location.href
      }).catch(error => {
        logger.error('Failed to send dynamic security alert:', error);
      });
    }
  });
}

// Initialize dynamic monitoring
setupDynamicMonitoringIfEnabled();


// Also listen for message requests for current mouse position and security scans
browser.runtime.onMessage.addListener((message: any, sender, sendResponse) => {
  if (message.type === 'GET_MOUSE_POSITION') {
    sendResponse({
      position: {
        ...lastMousePosition,
        screenX: lastMousePosition.x + window.screenX,
        screenY: lastMousePosition.y + window.screenY,
        windowWidth: window.innerWidth,
        windowHeight: window.innerHeight,
        windowScrollX: window.scrollX,
        windowScrollY: window.scrollY
      }
    });
  } else if (message.type === 'GET_RESOURCE_SCAN') {
    // Perform fresh resource scan if requested
    const currentScan = ResourceMonitor.scanPageResources();
    sendResponse({
      scan: currentScan
    });
  } else if (message.type === 'GET_ALL_SCANS') {
    // Return all current scan results
    sendResponse({
      resourceScan: latestResourceScan || ResourceMonitor.scanPageResources()
    });
  }
  return true; // Always return true to keep message channel open
});