/**
 * CryptoLab - Main Application Bootstrap & Navigation
 */

document.addEventListener('DOMContentLoaded', () => {
  // Navigation Tabs Switching
  const navTabs = document.querySelectorAll('.nav-tab-btn');
  const sections = document.querySelectorAll('.content-section');

  function switchTab(targetTabId) {
    navTabs.forEach((tab) => {
      const isTarget = tab.getAttribute('data-target') === targetTabId;
      if (isTarget) {
        tab.classList.add('bg-cyan-950/80', 'text-cyan-400', 'border-cyan-500');
        tab.classList.remove('text-gray-400', 'border-transparent');
      } else {
        tab.classList.remove('bg-cyan-950/80', 'text-cyan-400', 'border-cyan-500');
        tab.classList.add('text-gray-400', 'border-transparent');
      }
    });

    sections.forEach((sec) => {
      if (sec.id === targetTabId) {
        sec.classList.remove('hidden');
      } else {
        sec.classList.add('hidden');
      }
    });
  }

  navTabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      const target = tab.getAttribute('data-target');
      switchTab(target);
    });
  });

  // Check Web Crypto API support
  const isWebCryptoSupported = !!(window.crypto && window.crypto.subtle);
  const cryptoStatusBadge = document.getElementById('webcrypto-status-badge');
  if (cryptoStatusBadge) {
    if (isWebCryptoSupported) {
      cryptoStatusBadge.innerHTML = '<span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span> Web Crypto API Active';
      cryptoStatusBadge.className = 'flex items-center gap-2 px-2.5 py-1 rounded-full text-xs font-mono bg-emerald-950 text-emerald-400 border border-emerald-700';
    } else {
      cryptoStatusBadge.innerHTML = '⚠️ Web Crypto API Restricted (Fallback Mode)';
      cryptoStatusBadge.className = 'flex items-center gap-2 px-2.5 py-1 rounded-full text-xs font-mono bg-yellow-950 text-yellow-400 border border-yellow-700';
    }
  }

  // Initialize Modules
  if (typeof HashInspectorModule !== 'undefined') HashInspectorModule.init();
  if (typeof EncryptionPlaygroundModule !== 'undefined') EncryptionPlaygroundModule.init();
  if (typeof CrackingSimulatorModule !== 'undefined') CrackingSimulatorModule.init();
  if (typeof SlowHashBenchmarkModule !== 'undefined') SlowHashBenchmarkModule.init();
  if (typeof TestSuiteModule !== 'undefined') TestSuiteModule.init();

  console.log('⚡ CryptoLab Initialized Successfully.');
});
