export function extractActualUrl(googleUrl: string): string {
  const urlMatch = googleUrl.match(/[?&]url=([^&]+)/);
  return urlMatch ? decodeURIComponent(urlMatch[1]) : googleUrl;
}

export function extractDomain(url: string): string {
  const domainMatch = url.match(/^(?:https?:\/\/)?(?:www\.)?([^\/]+)/i);
  return domainMatch ? domainMatch[1] : url;
}
