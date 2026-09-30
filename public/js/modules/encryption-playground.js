/**
 * CryptoLab - Module B: Symmetric vs Asymmetric Encryption Playground
 * Implements AES-256-GCM with bit-tampering AEAD authentication test, and RSA-OAEP 2048-bit keypair workflow.
 */

const EncryptionPlaygroundModule = (function () {
  // AES State
  let aesKeyObject = null;
  let aesIvBytes = null;
  let originalCiphertextBytes = null;
  let currentCiphertextBytes = null;
  let originalTagBytes = null;
  let currentTagBytes = null;
  let isAesTampered = false;
  let tamperedTarget = null; // 'ciphertext' | 'tag'

  // RSA State
  let rsaKeyPair = null;
  let rsaCiphertextBuffer = null;

  function init() {
    initAesControls();
    initRsaControls();
  }

  // ==========================================
  // AES-256-GCM Controls
  // ==========================================
  function initAesControls() {
    const genAesKeyBtn = document.getElementById('aes-gen-key-btn');
    const encryptAesBtn = document.getElementById('aes-encrypt-btn');
    const decryptAesBtn = document.getElementById('aes-decrypt-btn');
    const tamperCipherBtn = document.getElementById('aes-tamper-cipher-btn');
    const tamperTagBtn = document.getElementById('aes-tamper-tag-btn');
    const resetTamperBtn = document.getElementById('aes-reset-tamper-btn');

    if (genAesKeyBtn) genAesKeyBtn.addEventListener('click', generateNewAesKey);
    if (encryptAesBtn) encryptAesBtn.addEventListener('click', handleAesEncrypt);
    if (decryptAesBtn) decryptAesBtn.addEventListener('click', handleAesDecrypt);
    if (tamperCipherBtn) tamperCipherBtn.addEventListener('click', () => applyAesTamper('ciphertext'));
    if (tamperTagBtn) tamperTagBtn.addEventListener('click', () => applyAesTamper('tag'));
    if (resetTamperBtn) resetTamperBtn.addEventListener('click', resetAesTamper);

    // Initial default key & IV generation
    generateNewAesKey();
  }

  async function generateNewAesKey() {
    try {
      const keyData = await CryptoEngine.generateAesGcmKey();
      const ivData = CryptoEngine.generateIv(12);

      aesKeyObject = keyData.key;
      aesIvBytes = ivData.ivArray;

      const keyDisplay = document.getElementById('aes-key-hex');
      const ivDisplay = document.getElementById('aes-iv-hex');
      if (keyDisplay) keyDisplay.innerText = keyData.rawHex;
      if (ivDisplay) ivDisplay.innerText = ivData.ivHex;

      // Auto encrypt sample text
      handleAesEncrypt();
    } catch (err) {
      console.error('AES key generation error:', err);
    }
  }

  async function handleAesEncrypt() {
    if (!aesKeyObject || !aesIvBytes) await generateNewAesKey();

    const plaintextInput = document.getElementById('aes-plaintext-input');
    const text = plaintextInput ? plaintextInput.value : 'Top Secret Message: Transfer $1,000,000 to Account #9482';

    try {
      const encrypted = await CryptoEngine.encryptAesGcm(aesKeyObject, aesIvBytes, text);
      originalCiphertextBytes = new Uint8Array(encrypted.ciphertextBytes);
      currentCiphertextBytes = new Uint8Array(encrypted.ciphertextBytes);

      originalTagBytes = new Uint8Array(encrypted.tagBytes);
      currentTagBytes = new Uint8Array(encrypted.tagBytes);

      isAesTampered = false;
      tamperedTarget = null;

      renderAesOutputs(encrypted);
      updateTamperStatusUI();

      // Clear previous decrypt results
      const decryptOutput = document.getElementById('aes-decrypt-output');
      if (decryptOutput) {
        decryptOutput.innerHTML = `
          <div class="p-3 bg-gray-900/60 border border-gray-800 rounded-lg text-xs text-gray-400 font-mono">
            Ready to decrypt. Click "Decrypt Ciphertext" to verify AEAD integrity.
          </div>
        `;
      }
    } catch (err) {
      console.error('AES Encryption error:', err);
    }
  }

  function renderAesOutputs(encrypted) {
    const cipherHexEl = document.getElementById('aes-ciphertext-hex');
    const cipherB64El = document.getElementById('aes-ciphertext-b64');
    const tagHexEl = document.getElementById('aes-tag-hex');

    if (cipherHexEl) cipherHexEl.innerText = CryptoEngine.bufferToHex(currentCiphertextBytes.buffer);
    if (cipherB64El) cipherB64El.innerText = CryptoEngine.bufferToBase64(currentCiphertextBytes.buffer);
    if (tagHexEl) tagHexEl.innerText = CryptoEngine.bufferToHex(currentTagBytes.buffer);
  }

  function applyAesTamper(target) {
    if (!currentCiphertextBytes || !currentTagBytes) return;

    if (target === 'ciphertext') {
      // Flip the 0th bit of the first byte
      currentCiphertextBytes[0] ^= 0x01;
      isAesTampered = true;
      tamperedTarget = 'ciphertext (Byte 0 bit flipped)';
    } else if (target === 'tag') {
      // Flip a bit in the 16-byte authentication tag
      currentTagBytes[0] ^= 0x80;
      isAesTampered = true;
      tamperedTarget = 'Authentication Tag (Bit 7 altered)';
    }

    renderAesOutputs();
    updateTamperStatusUI();

    // Auto trigger decrypt to showcase immediate AEAD rejection
    handleAesDecrypt();
  }

  function resetAesTamper() {
    if (!originalCiphertextBytes || !originalTagBytes) return;
    currentCiphertextBytes = new Uint8Array(originalCiphertextBytes);
    currentTagBytes = new Uint8Array(originalTagBytes);
    isAesTampered = false;
    tamperedTarget = null;

    renderAesOutputs();
    updateTamperStatusUI();
    handleAesDecrypt();
  }

  function updateTamperStatusUI() {
    const badge = document.getElementById('aes-tamper-badge');
    if (!badge) return;

    if (isAesTampered) {
      badge.className = 'px-3 py-1 text-xs font-bold font-mono rounded-full bg-red-950 text-red-400 border border-red-600 animate-pulse';
      badge.innerText = `⚠️ TAMPERED: ${tamperedTarget}`;
    } else {
      badge.className = 'px-3 py-1 text-xs font-mono rounded-full bg-emerald-950 text-emerald-400 border border-emerald-600';
      badge.innerText = '✓ Clean / Untampered (Original Payload)';
    }
  }

  async function handleAesDecrypt() {
    const decryptOutput = document.getElementById('aes-decrypt-output');
    if (!decryptOutput || !aesKeyObject || !aesIvBytes || !currentCiphertextBytes || !currentTagBytes) return;

    const result = await CryptoEngine.decryptAesGcm(aesKeyObject, aesIvBytes, currentCiphertextBytes, currentTagBytes);

    if (result.success) {
      decryptOutput.innerHTML = `
        <div class="p-4 bg-emerald-950/60 border border-emerald-500 rounded-xl space-y-2">
          <div class="flex items-center justify-between">
            <span class="text-emerald-400 font-bold flex items-center gap-2">
              <span class="w-3 h-3 rounded-full bg-emerald-500"></span>
              ✓ AEAD AUTHENTICATION & DECRYPTION SUCCESSFUL
            </span>
            <span class="text-xs px-2 py-0.5 rounded bg-emerald-900/60 text-emerald-300 font-mono">128-bit Tag Match</span>
          </div>
          <div class="text-sm font-mono text-gray-100 bg-black/50 p-3 rounded border border-emerald-800/60">
            "${escapeHtml(result.plaintext)}"
          </div>
          <p class="text-xs text-emerald-300/80">
            ${result.message} AES-GCM ensures both <strong>Confidentiality</strong> (encryption) and <strong>Integrity/Authenticity</strong> (GMAC tag).
          </p>
        </div>
      `;
    } else {
      decryptOutput.innerHTML = `
        <div class="p-4 bg-red-950/60 border border-red-500 rounded-xl space-y-2">
          <div class="flex items-center justify-between">
            <span class="text-red-400 font-bold flex items-center gap-2">
              <span class="w-3 h-3 rounded-full bg-red-500 animate-ping"></span>
              ⛔ INTEGRITY REJECTION (OperationError)
            </span>
            <span class="text-xs px-2 py-0.5 rounded bg-red-900/60 text-red-300 font-mono">Tag Mismatch</span>
          </div>
          <div class="text-xs font-mono text-red-200 bg-black/60 p-3 rounded border border-red-800">
            ${result.errorMessage}
          </div>
          <p class="text-xs text-red-300/90">
            <strong>Why did this happen?</strong> AES-GCM computes a Galois Message Authentication Code (GMAC) over the ciphertext. If even a single bit is modified in transit, the calculated tag will not match the provided tag, and the Web Crypto API aborts immediately before releasing any unauthenticated decrypted bytes to the application.
          </p>
        </div>
      `;
    }
  }

  // ==========================================
  // RSA-OAEP (2048-bit) Controls
  // ==========================================
  function initRsaControls() {
    const genRsaBtn = document.getElementById('rsa-gen-keys-btn');
    const encryptRsaBtn = document.getElementById('rsa-encrypt-btn');
    const decryptRsaBtn = document.getElementById('rsa-decrypt-btn');

    if (genRsaBtn) genRsaBtn.addEventListener('click', generateRsaKeys);
    if (encryptRsaBtn) encryptRsaBtn.addEventListener('click', handleRsaEncrypt);
    if (decryptRsaBtn) decryptRsaBtn.addEventListener('click', handleRsaDecrypt);

    // Default generation
    generateRsaKeys();
  }

  async function generateRsaKeys() {
    const pubPemEl = document.getElementById('rsa-public-pem');
    const privPemEl = document.getElementById('rsa-private-pem');
    const genBtn = document.getElementById('rsa-gen-keys-btn');

    if (genBtn) {
      genBtn.disabled = true;
      genBtn.innerHTML = '<span class="animate-spin inline-block mr-2">⚙</span> Generating 2048-bit Primes...';
    }

    try {
      const keys = await CryptoEngine.generateRsaKeyPair(2048);
      rsaKeyPair = keys.keyPair;

      if (pubPemEl) pubPemEl.value = keys.publicKeyPem;
      if (privPemEl) privPemEl.value = keys.privateKeyPem;

      // Automatically run sample encrypt
      handleRsaEncrypt();
    } catch (err) {
      console.error('RSA Key generation error:', err);
    } finally {
      if (genBtn) {
        genBtn.disabled = false;
        genBtn.innerText = '⚡ Generate New RSA-2048 Keypair';
      }
    }
  }

  async function handleRsaEncrypt() {
    if (!rsaKeyPair) await generateRsaKeys();

    const plaintextInput = document.getElementById('rsa-plaintext-input');
    const text = plaintextInput ? plaintextInput.value : 'Shared AES Session Key: 9f8a3c4b2e1d0f5a7b8c';
    const cipherDisplay = document.getElementById('rsa-ciphertext-output');

    try {
      const encrypted = await CryptoEngine.encryptRsaOaep(rsaKeyPair.publicKey, text);
      rsaCiphertextBuffer = encrypted.ciphertextBuffer;

      if (cipherDisplay) {
        cipherDisplay.innerHTML = `
          <div class="space-y-2">
            <div class="flex items-center justify-between text-xs text-cyan-400">
              <span>RSA-OAEP-SHA256 Encrypted (${encrypted.byteLength} bytes / 2048 bits)</span>
              <span class="text-gray-400">Public Key Encrypted</span>
            </div>
            <textarea readonly rows="4" class="w-full bg-black/60 border border-cyan-800 rounded p-2.5 font-mono text-xs text-cyan-300 select-all">${encrypted.ciphertextBase64}</textarea>
          </div>
        `;
      }

      // Clear previous decrypt output
      const decryptOutput = document.getElementById('rsa-decrypt-output');
      if (decryptOutput) {
        decryptOutput.innerHTML = `
          <div class="p-3 bg-gray-900/60 border border-gray-800 rounded-lg text-xs text-gray-400 font-mono">
            Encrypted with Public Key. Click "Decrypt with Private Key" to test recovery.
          </div>
        `;
      }
    } catch (err) {
      if (cipherDisplay) {
        cipherDisplay.innerHTML = `<div class="p-3 bg-red-950/60 border border-red-800 text-xs text-red-300 rounded">${err.message}</div>`;
      }
    }
  }

  async function handleRsaDecrypt() {
    const decryptOutput = document.getElementById('rsa-decrypt-output');
    if (!decryptOutput || !rsaKeyPair || !rsaCiphertextBuffer) return;

    const result = await CryptoEngine.decryptRsaOaep(rsaKeyPair.privateKey, rsaCiphertextBuffer);

    if (result.success) {
      decryptOutput.innerHTML = `
        <div class="p-4 bg-emerald-950/60 border border-emerald-500 rounded-xl space-y-2">
          <div class="flex items-center justify-between">
            <span class="text-emerald-400 font-bold flex items-center gap-2">
              <span class="w-3 h-3 rounded-full bg-emerald-500"></span>
              ✓ ASYMMETRIC DECRYPTION SUCCESSFUL
            </span>
            <span class="text-xs px-2 py-0.5 rounded bg-emerald-900/60 text-emerald-300 font-mono">OAEP-SHA256 Padding Verified</span>
          </div>
          <div class="text-sm font-mono text-gray-100 bg-black/50 p-3 rounded border border-emerald-800/60">
            "${escapeHtml(result.plaintext)}"
          </div>
          <p class="text-xs text-emerald-300/80">
            Only the corresponding Private Key mathematically factorizes and decrypts this ciphertext. OAEP (Optimal Asymmetric Encryption Padding) prevents chosen-ciphertext attacks and padding oracle exploits.
          </p>
        </div>
      `;
    } else {
      decryptOutput.innerHTML = `
        <div class="p-4 bg-red-950/60 border border-red-500 rounded-xl text-xs text-red-300">
          ${result.error}
        </div>
      `;
    }
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  return { init, generateNewAesKey, generateRsaKeys };
})();
