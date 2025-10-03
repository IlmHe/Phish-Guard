import browser from 'webextension-polyfill';
import { HomographDetector } from './services/homographDetector';
import logger from './utils/logger';

// Store mouse position from content script
let lastMousePosition: {
  x: number;
  y: number;
  screenX: number;
  screenY: number;
  windowWidth: number;
  windowHeight: number;
} | null = null;

// Rate limiting for context menu actions
const rateLimiter = new Map<string, number>();
const RATE_LIMIT_MS = 2000; // 2 seconds between scans

// Store notification details for click handling
const notificationDetails = new Map<string, any>();

// Store automatic scan results for popup retrieval
const automaticScanResults = new Map<string, any>();

// Track recently shown alerts to prevent spam (domain -> timestamp)
const recentAlerts = new Map<string, number>();
const ALERT_COOLDOWN_MS = 60000; // 60 seconds cooldown per domain

// Cleanup intervals
const SCAN_RESULTS_MAX_AGE_MS = 5 * 60 * 1000; // 5 minutes
const CLEANUP_INTERVAL_MS = 60 * 1000; // Run cleanup every minute

// Periodic cleanup of old data
function cleanupOldData() {
  const now = Date.now();

  // Cleanup old scan results (keep for 5 minutes max as stated in privacy policy)
  for (const [url, data] of automaticScanResults.entries()) {
    if (now - data.timestamp > SCAN_RESULTS_MAX_AGE_MS) {
      automaticScanResults.delete(url);
      logger.log(`🗑️ Cleaned up old scan result for ${url}`);
    }
  }

  // Cleanup expired alert cooldowns
  for (const [domain, timestamp] of recentAlerts.entries()) {
    if (now - timestamp > ALERT_COOLDOWN_MS) {
      recentAlerts.delete(domain);
    }
  }

  // Cleanup expired rate limiters
  for (const [tabId, timestamp] of rateLimiter.entries()) {
    if (now - timestamp > RATE_LIMIT_MS) {
      rateLimiter.delete(tabId);
    }
  }
}

// Run cleanup every minute
setInterval(cleanupOldData, CLEANUP_INTERVAL_MS);
logger.log('🧹 Data cleanup service started - runs every 60 seconds');

function isRateLimited(tabId: number): boolean {
  const now = Date.now();
  const lastAction = rateLimiter.get(tabId.toString());

  if (lastAction && now - lastAction < RATE_LIMIT_MS) {
    return true;
  }

  rateLimiter.set(tabId.toString(), now);
  return false;
}

// Listen for messages from content script
browser.runtime.onMessage.addListener((message: any, sender, sendResponse) => {
  if (message.type === 'MOUSE_POSITION') {
    lastMousePosition = message.position;
  } else if (message.type === 'RESOURCE_SECURITY_ALERT') {
    handleResourceSecurityAlert(message, sender).catch(error => {
      logger.error('Failed to handle resource security alert:', error);
    });
  } else if (message.type === 'GET_AUTOMATIC_SCAN') {
    // Retrieve stored automatic scan results
    const storedScan = automaticScanResults.get(message.url);
    if (storedScan) {
      sendResponse(storedScan);
    } else {
      sendResponse(null);
    }
  }
  return true; // Keep message channel open
});

// Handle automatic security alerts
async function handleResourceSecurityAlert(message: any, sender: any) {
  try {
    // Load user settings to check if notifications are enabled
    const settingsData = await browser.storage.sync.get('phishGuardSettings');
    const settings = {
      automaticMonitoring: false,
      showNotifications: true,
      advancedMode: false,
      ...(settingsData.phishGuardSettings || {})
    };

    if (!settings.showNotifications) {
      logger.log('📵 Phish Guard: Notifications disabled by user');
      return;
    }

    const { scan, url } = message;
    const domain = new URL(url).hostname;

    // Check if we recently showed an alert for this domain (prevent spam)
    const now = Date.now();
    const lastAlertTime = recentAlerts.get(domain);

    if (lastAlertTime && now - lastAlertTime < ALERT_COOLDOWN_MS) {
      logger.log(`⏱️ Phish Guard: Alert cooldown active for ${domain} (${Math.round((ALERT_COOLDOWN_MS - (now - lastAlertTime)) / 1000)}s remaining)`);
      return; // Skip alert - too soon
    }

    // Update last alert time for this domain
    recentAlerts.set(domain, now);

    // Create notification with detailed information
    const notificationId = `phishguard_${Date.now()}`;

    await browser.notifications.create(notificationId, {
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: '🚨 Phish Guard Security Alert',
      message: `High-risk resources detected on ${domain}\n\nRisk Score: ${scan.riskScore}/100\nSuspicious Resources: ${scan.suspiciousResources.length}\n\nClick to view details`,
      priority: 2
    });

    // Store notification details for click handling
    notificationDetails.set(notificationId, { scan, url, domain });

    logger.log('🔔 Security notification sent for', domain);

    // Store scan results for later retrieval
    automaticScanResults.set(url, { scan, timestamp: Date.now() });

    // Automatically show alert popup window for high-risk detections
    logger.log('🚨 Phish Guard: Auto-opening alert for high-risk detection');
    showAlertWindow(scan, url);

  } catch (error) {
    logger.error('Failed to send security notification:', error);
  }
}

browser.runtime.onInstalled.addListener(() => {
  try {
    // Create context-specific menu items for better user clarity
    browser.contextMenus.create({
      id: 'scanLink',
      title: '🛡️ Scan this link with Phish-Guard',
      contexts: ['link'],
    });

    browser.contextMenus.create({
      id: 'scanSelection',
      title: '🛡️ Scan selected URL with Phish-Guard',
      contexts: ['selection'],
    });

    browser.contextMenus.create({
      id: 'scanPage',
      title: '🛡️ Scan current page with Phish-Guard',
      contexts: ['page'],
    });

    logger.log('🛡️ Phish Guard: Context menus created successfully');
  } catch (error) {
    logger.error('🛡️ Phish Guard: Failed to create context menus:', error);
  }
});

// Handle notification clicks - open scan popup
browser.notifications.onClicked.addListener(async (notificationId) => {
  const details = notificationDetails.get(notificationId);
  if (details) {
    // Open scan popup for the URL that triggered the alert
    showPopupWindow(details.url);

    // Clear the notification
    browser.notifications.clear(notificationId);
    notificationDetails.delete(notificationId);
  }
});

// Handle notification close/timeout
browser.notifications.onClosed.addListener((notificationId) => {
  // Clean up stored details
  notificationDetails.delete(notificationId);
});

// Handle extension icon click (Brave/Manifest V2 compatibility)
const actionAPI = browser.action || browser.browserAction;
if (actionAPI && actionAPI.onClicked) {
  actionAPI.onClicked.addListener(async (tab) => {
    if (tab?.id && tab.url) {
      logger.log('Extension icon clicked, scanning current page:', tab.url);
      showPopupWindow(tab.url);
    }
  });
} else {
  logger.warn('No action API available (action or browserAction)');
}

browser.contextMenus.onClicked.addListener(async (info, tab) => {
  logger.log('🛡️ Phish Guard: Context menu clicked:', info.menuItemId, 'Tab ID:', tab?.id);

  if ((info.menuItemId === 'scanLink' || info.menuItemId === 'scanSelection' || info.menuItemId === 'scanPage') && tab?.id) {
    logger.log('🛡️ Phish Guard: Valid context menu item selected, proceeding with scan...');

    // Rate limiting check
    if (isRateLimited(tab.id)) {
      logger.log('🛡️ Phish Guard: Request rate limited, ignoring...');
      return;
    }

    // Try to get fresh mouse position from content script
    try {
      const response: any = await browser.tabs.sendMessage(tab.id, { type: 'GET_MOUSE_POSITION' });
      if (response && response.position) {
        lastMousePosition = response.position;
      }
    } catch (error) {
      // Failed to get fresh mouse position
    }

    let urlToScan = '';

    // Handle different menu items with specific logic
    if (info.menuItemId === 'scanLink' && info.linkUrl) {
      urlToScan = info.linkUrl;
    } else if (info.menuItemId === 'scanSelection' && info.selectionText) {
      // Try to extract URL from selected text with improved patterns
      // IMPORTANT: Preserve Unicode/homograph characters (Cyrillic, Greek) for detection
      const selectionText = info.selectionText.trim();

      // First try to find URLs with protocol (preserves all Unicode characters)
      const urlWithProtocolPattern = /(https?:\/\/[^\s\)\]\}\'"<>]+)/gi;
      let matches = selectionText.match(urlWithProtocolPattern);

      if (matches) {
        urlToScan = matches[0];
      } else {
        // Try to find URLs without protocol
        // Include Unicode ranges for Cyrillic (\u0400-\u04FF) and Greek (\u0370-\u03FF) for homograph detection
        const urlWithoutProtocolPattern = /([a-zA-Z0-9\u0400-\u04FF\u0370-\u03FF][a-zA-Z0-9\u0400-\u04FF\u0370-\u03FF-]{0,61}[a-zA-Z0-9\u0400-\u04FF\u0370-\u03FF]?\.)+[a-zA-Z]{2,}(\/[^\s\)\]\}\'"<>]*)?/gi;
        matches = selectionText.match(urlWithoutProtocolPattern);

        if (matches) {
          // Add protocol if missing
          let potentialUrl = matches[0];
          if (!potentialUrl.startsWith('http')) {
            potentialUrl = 'https://' + potentialUrl;
          }
          urlToScan = potentialUrl;
        } else {
          // If no URL pattern found, check if the entire selection looks like a domain
          // Include Unicode ranges for homograph characters
          const domainPattern = /^[a-zA-Z0-9\u0400-\u04FF\u0370-\u03FF][a-zA-Z0-9\u0400-\u04FF\u0370-\u03FF-]{0,61}[a-zA-Z0-9\u0400-\u04FF\u0370-\u03FF]?\.[a-zA-Z]{2,}$/;
          if (domainPattern.test(selectionText)) {
            urlToScan = 'https://' + selectionText;
          } else {
            return; // Exit early if no valid URL found
          }
        }
      }
    } else if (info.menuItemId === 'scanPage' && tab.url) {
      urlToScan = tab.url;
    }

    if (urlToScan) {
      // Validate URL before proceeding
      try {
        new URL(urlToScan);
      } catch {
        logger.error('Invalid URL format:', urlToScan);
        return;
      }

      // Show popup window for all scans
      showPopupWindow(urlToScan);
    }
  }
});

// Helper function to show alert popup for automatic detections
function showAlertWindow(scan: any, url: string) {
  const popupWidth = 400;
  const popupHeight = 500;

  // Get top suspicious resources (deduplicate and limit to 5)
  const uniqueUrls = new Set<string>();
  const deduplicatedResources: string[] = [];

  for (const r of scan.suspiciousResources) {
    const url = r.url || r;
    if (!uniqueUrls.has(url) && deduplicatedResources.length < 5) {
      uniqueUrls.add(url);
      deduplicatedResources.push(url);
    }
  }

  const resourcesParam = encodeURIComponent(JSON.stringify(deduplicatedResources));

  let left: number;
  let top: number;

  if (lastMousePosition) {
    left = lastMousePosition.screenX + 20;
    top = lastMousePosition.screenY - 50;

    const screenWidth = 1920;
    const screenHeight = 1080;

    if (left + popupWidth > screenWidth) {
      left = lastMousePosition.screenX - popupWidth - 20;
    }
    if (top + popupHeight > screenHeight) {
      top = screenHeight - popupHeight - 50;
    }
    if (left < 0) left = 20;
    if (top < 0) top = 50;
  } else {
    left = Math.round((1920 - popupWidth) / 2);
    top = Math.round((1080 - popupHeight) / 3);
  }

  logger.log('🛡️ Phish Guard: Creating alert window for URL:', url);

  browser.windows.create({
    url: `alert.html?url=${encodeURIComponent(url)}&risk=${scan.riskScore}&count=${deduplicatedResources.length}&resources=${resourcesParam}`,
    type: 'popup',
    width: popupWidth,
    height: popupHeight,
    focused: true,
    left: left,
    top: top,
  }).then(window => {
    logger.log('🛡️ Phish Guard: Alert window created successfully:', window?.id);
  }).catch(error => {
    logger.error('🛡️ Phish Guard: Failed to create alert window:', error);
  });
}

// Helper function to show popup window positioned near mouse cursor
function showPopupWindow(urlToScan: string) {
  // Calculate optimal popup size based on content
  const popupWidth = 850; // Wider for better button visibility
  const popupHeight = 700; // Taller for all content without scrolling

  let left: number;
  let top: number;

  if (lastMousePosition) {
    // Position popup near mouse cursor, but offset so it doesn't cover the cursor
    left = lastMousePosition.screenX + 20; // 20px to the right of cursor
    top = lastMousePosition.screenY - 50; // 50px above cursor

    // Get screen dimensions (fallback to common values since screen API not available in background)
    const screenWidth = 1920; // Default screen width
    const screenHeight = 1080; // Default screen height

    // Ensure popup stays within screen bounds
    if (left + popupWidth > screenWidth) {
      left = lastMousePosition.screenX - popupWidth - 20; // Position to the left instead
    }
    if (top + popupHeight > screenHeight) {
      top = screenHeight - popupHeight - 50; // Move up if needed
    }
    if (left < 0) left = 20; // Minimum left margin
    if (top < 0) top = 50; // Minimum top margin

  } else {
    // Fallback to center-ish position if no mouse position available
    left = Math.round((1920 - popupWidth) / 2);
    top = Math.round((1080 - popupHeight) / 3);
  }

  logger.log('🛡️ Phish Guard: Creating popup window for URL:', urlToScan);
  logger.log('🛡️ Phish Guard: Popup parameters:', { width: popupWidth, height: popupHeight, left, top });

  browser.windows.create({
    url: `popup.html?url=${encodeURIComponent(urlToScan)}`,
    type: 'popup',
    width: popupWidth,
    height: popupHeight,
    focused: true,
    left: left,
    top: top,
  }).then(window => {
    logger.log('🛡️ Phish Guard: Popup window created successfully:', window?.id);
  }).catch(error => {
    logger.error('🛡️ Phish Guard: Failed to create popup window with positioning:', error);
    logger.log('🛡️ Phish Guard: Attempting fallback without positioning...');
    // Fallback: try without positioning
    return browser.windows.create({
      url: `popup.html?url=${encodeURIComponent(urlToScan)}`,
      type: 'popup',
      width: popupWidth,
      height: popupHeight,
      focused: true,
    });
  }).then(fallbackWindow => {
    if (fallbackWindow) {
      logger.log('🛡️ Phish Guard: Fallback popup created successfully:', fallbackWindow.id);
    }
  }).catch(fallbackError => {
    logger.error('🛡️ Phish Guard: Fallback popup creation also failed:', fallbackError);
    logger.error('🛡️ Phish Guard: Error details:', fallbackError.message || fallbackError);
  });
}

