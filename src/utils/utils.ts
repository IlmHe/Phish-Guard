/**
 * Extract domain from URL preserving Unicode/homograph characters
 * IMPORTANT: Does NOT use new URL() to avoid punycode conversion
 * Use this for homograph detection to preserve suspicious characters
 */
export function extractDomainRaw(url: string): string {
  if (!url || typeof url !== 'string') {
    return url;
  }

  // Use regex to extract domain WITHOUT URL constructor (preserves Unicode)
  // Match: optional http(s)://, optional www., capture domain until / or end
  const domainMatch = url.match(/^(?:https?:\/\/)?(?:www\.)?([^\/\s:?#]+)/i);
  const domain = domainMatch ? domainMatch[1] : url;

  // Remove www prefix if present
  return domain.replace(/^www\./, '');
}

export function extractActualUrl(googleUrl: string): string {
  if (!googleUrl || typeof googleUrl !== 'string') {
    return googleUrl;
  }

  try {
    // Handle Google redirect URLs
    const urlMatch = googleUrl.match(/[?&]url=([^&]+)/);
    if (urlMatch) {
      const decodedUrl = decodeURIComponent(urlMatch[1]);
      // Validate the extracted URL
      new URL(decodedUrl);
      return decodedUrl;
    }

    // Validate the original URL
    new URL(googleUrl);
    return googleUrl;
  } catch {
    // If URL validation fails, return original string
    return googleUrl;
  }
}

export function extractDomain(url: string): string {
  if (!url || typeof url !== 'string') {
    return url;
  }

  try {
    const urlObj = new URL(url.startsWith('http') ? url : `https://${url}`);

    // Use hostname which preserves Unicode characters better than href
    let hostname = urlObj.hostname;

    // Remove www prefix but preserve Unicode characters
    hostname = hostname.replace(/^www\./, '');

    return hostname;
  } catch {
    // Fallback to regex if URL constructor fails - preserve Unicode
    const domainMatch = url.match(/^(?:https?:\/\/)?(?:www\.)?([^\/\s]+)/i);
    const domain = domainMatch ? domainMatch[1] : url;
    return domain;
  }
}

export function sanitizeUrl(url: string): string {
  if (!url || typeof url !== 'string') {
    return '';
  }

  try {
    const urlObj = new URL(url);
    // Only allow http and https protocols
    if (!['http:', 'https:'].includes(urlObj.protocol)) {
      throw new Error('Invalid protocol');
    }

    return urlObj.toString();
  } catch (error) {
    return '';
  }
}

export function isValidUrl(url: string): boolean {
  try {
    const urlObj = new URL(url);
    return ['http:', 'https:'].includes(urlObj.protocol);
  } catch {
    return false;
  }
}
