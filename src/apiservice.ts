export async function sendToApi(url: string): Promise<any> {
  console.log('Sending URL to backend:', url);
  // const response = await fetch('https://your-backend-endpoint.com/scan', {
  //   method: 'POST',
  //   headers: {
  //     'Content-Type': 'application/json',
  //   },
  //   body: JSON.stringify({ url }),
  // });

  // if (!response.ok) {
  //   throw new Error('Failed to send link to backend');
  // }

  // return response.json();
}

/*
https://www.phishtank.com/developer_info.php
https://docs.virustotal.com/reference/public-vs-premium-api
*/
