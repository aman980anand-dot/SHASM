// js/consent.js

document.addEventListener('DOMContentLoaded', () => {
  const consentText = document.getElementById('consentText');
  const continueBtn = document.getElementById('continueBtn');
  const requiredPhrase = "I have permission"; // The exact phrase to enable the button

  if (!consentText || !continueBtn) {
    console.error('Consent elements not found. Check index.html IDs.');
    return;
  }

  // --- Input Event Listener ---
  consentText.addEventListener('input', () => {
    // Trim whitespace and check if the input matches the required phrase
    if (consentText.value.trim() === requiredPhrase) {
      continueBtn.disabled = false; // Enable the button
    } else {
      continueBtn.disabled = true;  // Keep/Disable the button
    }
  });

  // --- Button Click Event Listener ---
  continueBtn.addEventListener('click', () => {
    if (!continueBtn.disabled) { // Only proceed if the button is enabled
      console.log("Consent confirmed. Navigating to scan page.");
      // Navigate to the scan page
      window.location.href = 'scan.html';
    }
  });

  // Optional: Add a check for URL parameters if coming back from another page
  // This could be useful if you want to remember consent, but for this project,
  // we'll keep it simple and require consent each time.
});