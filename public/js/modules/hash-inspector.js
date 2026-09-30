/**
 * CryptoLab - Module A: Hash Inspector & Salt Visualizer
 * Handles real-time multi-hash calculation, salt alteration visualization, and rainbow table lookups.
 */

const HashInspectorModule = (function () {
  let isSaltEnabled = false;
  let currentSalt = '';
  let saltPosition = 'prefix';
  let rainbowCache = null;

  function init() {
    const plaintextInput = document.getElementById('hash-plaintext-input');
    const saltToggle = document.getElementById('toggle-salt-btn');
    const regenSaltBtn = document.getElementById('regen-salt-btn');
    const saltInput = document.getElementById('salt-hex-input');
    const saltPosSelect = document.getElementById('salt-position-select');
    const rainbowCheckBtn = document.getElementById('rainbow-lookup-btn');
    const sampleButtons = document.querySelectorAll('.hash-sample-btn');

    if (!plaintextInput) return;

    // Live update on typing
    plaintextInput.addEventListener('input', updateHashes);

    // Salt toggle
    if (saltToggle) {
      saltToggle.addEventListener('click', () => {
        isSaltEnabled = !isSaltEnabled;
        const saltContainer = document.getElementById('salt-controls-panel');
        if (isSaltEnabled) {
          saltToggle.classList.add('bg-emerald-500', 'text-black');
          saltToggle.classList.remove('bg-gray-800', 'text-emerald-400');
          saltToggle.innerText = '✓ Salt Enabled (16-Byte Hex)';
          if (!currentSalt) {
            currentSalt = CryptoEngine.generateSalt(16);
            if (saltInput) saltInput.value = currentSalt;
          }
          if (saltContainer) saltContainer.classList.remove('hidden');
        } else {
          saltToggle.classList.remove('bg-emerald-500', 'text-black');
          saltToggle.classList.add('bg-gray-800', 'text-emerald-400');
          saltToggle.innerText = '+ Enable Salt';
          if (saltContainer) saltContainer.classList.add('hidden');
        }
        updateHashes();
      });
    }

    // Regenerate salt
    if (regenSaltBtn) {
      regenSaltBtn.addEventListener('click', () => {
        currentSalt = CryptoEngine.generateSalt(16);
        if (saltInput) saltInput.value = currentSalt;
        updateHashes();
      });
    }

    // Edit salt manually
    if (saltInput) {
      saltInput.addEventListener('input', (e) => {
        currentSalt = e.target.value.trim();
        updateHashes();
      });
    }

    // Salt position change
    if (saltPosSelect) {
      saltPosSelect.addEventListener('change', (e) => {
        saltPosition = e.target.value;
        updateHashes();
      });
    }

    // Sample click handlers
    sampleButtons.forEach((btn) => {
      btn.addEventListener('click', () => {
        const text = btn.getAttribute('data-text') || '';
        plaintextInput.value = text;
        updateHashes();
      });
    });

    // Rainbow Table Lookup button
    if (rainbowCheckBtn) {
      rainbowCheckBtn.addEventListener('click', performRainbowTableLookup);
    }

    // Copy digest buttons
    document.addEventListener('click', (e) => {
      const copyBtn = e.target.closest('.copy-hash-btn');
      if (copyBtn) {
        const targetId = copyBtn.getAttribute('data-target');
        const textElement = document.getElementById(targetId);
        if (textElement) {
          navigator.clipboard.writeText(textElement.innerText);
          const origText = copyBtn.innerText;
          copyBtn.innerText = 'Copied!';
          copyBtn.classList.add('text-emerald-400');
          setTimeout(() => {
            copyBtn.innerText = origText;
            copyBtn.classList.remove('text-emerald-400');
          }, 1500);
        }
      }
    });

    // Initial calculation
    updateHashes();
  }

  async function updateHashes() {
    const plaintextInput = document.getElementById('hash-plaintext-input');
    const rawText = plaintextInput ? plaintextInput.value : 'admin';
    const saltToUse = isSaltEnabled ? currentSalt : '';

    const digestResult = await CryptoEngine.digestAll(rawText, saltToUse, saltPosition);
    renderDigests(digestResult);
    renderByteStream(rawText, saltToUse, saltPosition);
  }

  function renderDigests(data) {
    const { results } = data;

    // MD5
    setDigestCard('md5', results.md5);
    // SHA-1
    setDigestCard('sha1', results.sha1);
    // SHA-256
    setDigestCard('sha256', results.sha256);
    // SHA-512
    setDigestCard('sha512', results.sha512);
  }

  function setDigestCard(idPrefix, algoData) {
    const digestEl = document.getElementById(`${idPrefix}-digest`);
    const timeEl = document.getElementById(`${idPrefix}-time`);
    const lenEl = document.getElementById(`${idPrefix}-length`);

    if (digestEl) digestEl.innerText = algoData.digest;
    if (timeEl) timeEl.innerText = `${algoData.durationMs.toFixed(3)} ms`;
    if (lenEl) lenEl.innerText = `${algoData.bitLength} bits (${algoData.hexLength} hex chars)`;
  }

  function renderByteStream(rawText, salt, position) {
    const visualizer = document.getElementById('salt-visualizer-stream');
    if (!visualizer) return;

    if (!salt) {
      visualizer.innerHTML = `
        <div class="flex items-center gap-2 p-3 bg-gray-900 border border-gray-800 rounded-lg text-xs font-mono">
          <span class="px-2 py-0.5 rounded bg-cyan-900/60 text-cyan-300 border border-cyan-700">Plaintext (${rawText.length} bytes): "${escapeHtml(rawText)}"</span>
          <span class="text-gray-500">→ Single deterministic output. Vulnerable to precomputation tables.</span>
        </div>
      `;
      return;
    }

    let html = '<div class="flex flex-wrap items-center gap-2 p-3 bg-gray-900 border border-purple-800/40 rounded-lg text-xs font-mono">';

    if (position === 'prefix') {
      html += `<span class="px-2 py-0.5 rounded bg-purple-900/80 text-purple-300 border border-purple-600">Salt [16B]: ${salt.substring(0, 16)}...</span>`;
      html += `<span class="text-gray-400">+</span>`;
      html += `<span class="px-2 py-0.5 rounded bg-cyan-900/80 text-cyan-300 border border-cyan-600">Plaintext: "${escapeHtml(rawText)}"</span>`;
    } else if (position === 'suffix') {
      html += `<span class="px-2 py-0.5 rounded bg-cyan-900/80 text-cyan-300 border border-cyan-600">Plaintext: "${escapeHtml(rawText)}"</span>`;
      html += `<span class="text-gray-400">+</span>`;
      html += `<span class="px-2 py-0.5 rounded bg-purple-900/80 text-purple-300 border border-purple-600">Salt [16B]: ${salt.substring(0, 16)}...</span>`;
    }

    html += `<span class="text-emerald-400 ml-auto font-semibold">⚡ Salt Defense Active (Unique per credential)</span></div>`;
    visualizer.innerHTML = html;
  }

  async function performRainbowTableLookup() {
    const resultBox = document.getElementById('rainbow-result-box');
    const queryInput = document.getElementById('rainbow-query-input');
    const queryHash = (queryInput?.value || document.getElementById('sha256-digest')?.innerText || '').trim();

    if (!queryHash) {
      if (resultBox) {
        resultBox.innerHTML = '<div class="p-3 text-sm text-yellow-400 bg-yellow-950/40 border border-yellow-800 rounded">Please enter a hash to lookup or compute one above.</div>';
      }
      return;
    }

    if (resultBox) {
      resultBox.innerHTML = '<div class="p-3 text-sm text-cyan-400 bg-cyan-950/40 border border-cyan-800 rounded animate-pulse">Querying 5,000 pre-indexed Rainbow Table hashes...</div>';
    }

    try {
      const response = await fetch('/api/rainbow-table/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hash: queryHash })
      });
      const data = await response.json();

      if (data.found) {
        resultBox.innerHTML = `
          <div class="p-4 bg-red-950/50 border border-red-500/80 rounded-xl space-y-2">
            <div class="flex items-center justify-between">
              <span class="text-red-400 font-bold flex items-center gap-2">
                <span class="w-2.5 h-2.5 rounded-full bg-red-500 animate-ping"></span>
                ⚡ COLLISION FOUND! (Precomputed Table Hit)
              </span>
              <span class="text-xs font-mono text-gray-400">Lookup Time: ${data.lookupTimeMicros} µs (O(1) Memory Access)</span>
            </div>
            <div class="text-sm text-gray-200">
              Recovered Plaintext: <strong class="text-emerald-400 font-mono text-base px-2 py-0.5 bg-black/60 rounded border border-emerald-500/40">"${escapeHtml(data.plaintext)}"</strong>
            </div>
            <p class="text-xs text-red-200/80">
              ${data.explanation} Unsalted hashes allow attackers to trade storage memory for instant O(1) cracking without performing active computations.
            </p>
          </div>
        `;
      } else {
        resultBox.innerHTML = `
          <div class="p-4 bg-emerald-950/50 border border-emerald-500/80 rounded-xl space-y-2">
            <div class="flex items-center justify-between">
              <span class="text-emerald-400 font-bold flex items-center gap-2">
                <span class="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
                ✓ CACHE MISS (Rainbow Table Defeated)
              </span>
              <span class="text-xs font-mono text-gray-400">Lookup Time: ${data.lookupTimeMicros} µs</span>
            </div>
            <div class="text-sm text-gray-300">
              No matching precomputed digest found across ${data.tableSize} indexed entries.
            </div>
            <p class="text-xs text-emerald-200/80">
              ${data.explanation} When unique 16-byte salts are applied, precomputed rainbow tables become completely useless because the attacker would have to compute a new 2^128 table for every individual user salt!
            </p>
          </div>
        `;
      }
    } catch (err) {
      if (resultBox) {
        resultBox.innerHTML = `<div class="p-3 text-sm text-red-400 bg-red-950/40 border border-red-800 rounded">Lookup failed: ${err.message}</div>`;
      }
    }
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  return { init, updateHashes, performRainbowTableLookup };
})();
