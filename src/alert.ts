// alert.ts - Security alert popup for automatic detections
import browser from 'webextension-polyfill';
import logger from './utils/logger';

// Flag to prevent double initialization
let isInitialized = false;

// Get URL parameters
const urlParams = new URLSearchParams(window.location.search);
const pageUrl = urlParams.get('url') || '';
const riskScore = parseInt(urlParams.get('risk') || '0');
const suspiciousCount = parseInt(urlParams.get('count') || '0');

// Parse suspicious resources from URL
let suspiciousResources: string[] = [];
try {
    const resourcesParam = urlParams.get('resources');
    if (resourcesParam) {
        suspiciousResources = JSON.parse(decodeURIComponent(resourcesParam));
    }
} catch (e) {
    logger.error('Failed to parse suspicious resources:', e);
}

// Initialize alert popup (runs once)
function initializeAlert() {
    if (isInitialized) {
        logger.warn('⚠️ Alert already initialized, skipping duplicate initialization');
        return;
    }
    isInitialized = true;
    logger.log('🚨 Initializing alert popup for:', pageUrl);
    try {
        const domain = new URL(pageUrl).hostname;
        document.getElementById('domain')!.textContent = domain;
    } catch (e) {
        document.getElementById('domain')!.textContent = pageUrl;
    }

    const riskScoreElement = document.getElementById('riskScore')!;
    riskScoreElement.textContent = `${riskScore}/100`;
    riskScoreElement.className = `info-value risk-score ${riskScore >= 50 ? 'risk-high' : 'risk-medium'}`;

    document.getElementById('suspiciousCount')!.textContent = suspiciousCount.toString();

    // Display suspicious resources
    const resourceList = document.getElementById('resourceList')!;
    resourceList.innerHTML = ''; // Clear any existing items first
    if (suspiciousResources.length > 0) {
        suspiciousResources.forEach(resource => {
            const item = document.createElement('div');
            item.className = 'resource-item';
            item.textContent = resource;
            resourceList.appendChild(item);
        });
    }

    // Handle dismiss button
    const dismissBtn = document.getElementById('dismissBtn')!;
    dismissBtn.addEventListener('click', () => {
        logger.log('🚫 Dismissing alert window');
        window.close();
    }, { once: true });

    // Handle details button - open full scan popup
    const detailsBtn = document.getElementById('detailsBtn') as HTMLButtonElement;
    detailsBtn.addEventListener('click', async (event) => {
        event.preventDefault(); // Prevent any default behavior
        event.stopPropagation(); // Stop event from bubbling

        // Disable button immediately to prevent double clicks
        detailsBtn.disabled = true;
        detailsBtn.textContent = 'Opening...';

        logger.log('🔍 Opening full scan popup for:', pageUrl);

        try {
            const newWindow = await browser.windows.create({
                url: `popup.html?url=${encodeURIComponent(pageUrl)}`,
                type: 'popup',
                width: 850,
                height: 700,
                focused: true
            });
            logger.log('✅ Popup opened successfully, window ID:', newWindow?.id);

            // Close alert window after a brief delay to ensure popup is visible
            setTimeout(() => {
                logger.log('🚪 Closing alert window');
                window.close();
            }, 100);
        } catch (error) {
            logger.error('❌ Failed to open popup window:', error);
            // Re-enable button on error
            detailsBtn.disabled = false;
            detailsBtn.textContent = 'View Full Scan';
        }
    }, { once: true }); // Only fire once to prevent double-clicks
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeAlert, { once: true });
} else {
    // DOM already loaded, initialize immediately
    initializeAlert();
}