chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'fetchURLInfo') {
    fetchURLInfo(message.url)
      .then((data) => sendResponse({ success: true, data }))
      .catch((error) => sendResponse({ success: false, error: error.message }));
    return true; // Return true to indicate that sendResponse will be called asynchronously
  }
});

async function fetchURLInfo(url) {
  const apiKey = '77d7872ee5d7deffe29d3d5f9a2860c82f621222c6531cff92636e8cbc1f9567'; // Replace with your VirusTotal API key
  const apiUrl = `https://www.virustotal.com/api/v3/urls/${encodeURIComponent(url)}`;
  
  const response = await fetch(apiUrl, {
    headers: {
      'x-apikey': apiKey
    }
  });

  if (!response.ok) {
    throw new Error('Failed to fetch URL information');
  }

  return response.json();
}
