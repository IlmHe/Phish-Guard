import browser from 'webextension-polyfill';

console.log('Background script loaded');

browser.runtime.onInstalled.addListener(() => {
  browser.contextMenus.create({
    id: "scanWithPhishGuard",
    title: "Scan using Phish-Guard",
    contexts: ["selection", "link", "page", "frame", "editable", "image", "video", "audio", "browser_action", "page_action"]
  }, () => {
    if (browser.runtime.lastError) {
      console.error(`Error creating context menu: ${browser.runtime.lastError}`);
    } else {
      console.log('Context menu item created');
    }
  });
});

browser.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "scanWithPhishGuard") {
    const selectedText = info.selectionText || info.linkUrl || tab?.url;
    if (selectedText) {
      console.log(`Preparing to scan: ${selectedText}`);
      // Open the popup to confirm the URL
      browser.windows.create({
        url: `popup.html?url=${encodeURIComponent(selectedText)}`,
        type: 'popup',
        width: 400,
        height: 300
      });
    } else {
      console.log('No text or link selected');
    }
  }
});

// browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
//   if (typeof message === 'object' && message !== null && 'action' in message && 'url' in message && 'domain' in message && (message as any).action === 'scanUrl' && (message as any).url && (message as any).domain) {
//     console.log(`Generating VirusTotal domain link for: ${message.domain}`);
//     const virusTotalDomainLink = `https://www.virustotal.com/gui/domain/${encodeURIComponent(message.domain as string)}`;
//     sendResponse({ virusTotalDomainLink });
//     return true;
//   }
//   return undefined;
// });