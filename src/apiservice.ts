export async function sendToApi(url: string): Promise<any> {
  const response = await fetch('https://your-backend-endpoint.com/scan', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ url }),
  });

  if (!response.ok) {
    throw new Error('Failed to send link to backend');
  }

  return response.json();
}

/*
https://openphish.com/phishing_database.html
https://github.com/openphish/pyopdb/wiki/1.-Installation
https://check.spamhaus.org/
https://developers.google.com/safe-browsing/v4
https://www.phishtank.com/developer_info.php
https://docs.virustotal.com/reference/public-vs-premium-api
*/
