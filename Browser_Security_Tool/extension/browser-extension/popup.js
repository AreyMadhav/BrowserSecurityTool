document.addEventListener('DOMContentLoaded', function() {
  document.getElementById('checkButton').addEventListener('click', function() {
    const url = document.getElementById('urlInput').value;
    chrome.runtime.sendMessage({ action: 'fetchURLInfo', url }, function(response) {
      if (response.success) {
        displayURLInfo(response.data);
      } else {
        displayErrorMessage(response.error);
      }
    });
  });
});

function displayURLInfo(data) {
  const resultElement = document.getElementById('result');
  resultElement.innerHTML = `<strong>URL:</strong> ${data.data.id}<br>`;
  resultElement.innerHTML += `<strong>Harmless:</strong> ${data.data.attributes.last_analysis_stats.harmless}<br>`;
  resultElement.innerHTML += `<strong>Malicious:</strong> ${data.data.attributes.last_analysis_stats.malicious}<br>`;
  resultElement.innerHTML += `<strong>Suspicious:</strong> ${data.data.attributes.last_analysis_stats.suspicious}<br>`;
  resultElement.innerHTML += `<strong>Undetected:</strong> ${data.data.attributes.last_analysis_stats.undetected}<br>`;
}

function displayErrorMessage(error) {
  const resultElement = document.getElementById('result');
  resultElement.innerHTML = `<span style="color: red;">Error: ${error}</span>`;
}
