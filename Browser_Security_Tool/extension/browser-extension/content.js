chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'getURL') {
    const url = window.location.href;
    chrome.runtime.sendMessage({ action: 'fetchURLID', url });
  }
});
