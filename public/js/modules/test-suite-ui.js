/**
 * CryptoLab - In-Browser Test Suite & Cryptographic Assertions
 * Verifies RFC standards, Web Crypto API roundtrips, AEAD tampering rejection, and worker execution.
 */

const TestSuiteModule = (function () {
  const tests = [
    {
      id: 'test-sha256-rfc',
      name: 'NIST SHA-256 Test Vectors (RFC 6234)',
      category: 'Hashing Primitives',
      run: async () => {
        const v1 = await CryptoEngine.computeSubtleHash('SHA-256', '');
        const expected1 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
        if (v1 !== expected1) throw new Error(`Empty string SHA-256 mismatch. Got ${v1}, expected ${expected1}`);

        const v2 = await CryptoEngine.computeSubtleHash('SHA-256', 'abc');
        const expected2 = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
        if (v2 !== expected2) throw new Error(`'abc' SHA-256 mismatch. Got ${v2}, expected ${expected2}`);

        return 'Passed 2 RFC 6234 test vectors with exact hex match.';
      }
    },
    {
      id: 'test-md5-rfc',
      name: 'MD5 Known Vectors (RFC 1321)',
      category: 'Hashing Primitives',
      run: async () => {
        const v1 = CryptoEngine.md5('');
        const exp1 = 'd41d8cd98f00b204e9800998ecf8427e';
        if (v1 !== exp1) throw new Error(`MD5 empty string mismatch. Got ${v1}, expected ${exp1}`);

        const v2 = CryptoEngine.md5('message digest');
        const exp2 = 'f96b697d7cb7938d525a2f31aaf161d0';
        if (v2 !== exp2) throw new Error(`MD5 'message digest' mismatch. Got ${v2}, expected ${exp2}`);

        return 'Passed 2 RFC 1321 MD5 test vectors.';
      }
    },
    {
      id: 'test-sha512-rfc',
      name: 'SHA-512 Test Vector (FIPS 180-4)',
      category: 'Hashing Primitives',
      run: async () => {
        const v = await CryptoEngine.computeSubtleHash('SHA-512', 'abc');
        const exp = 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f';
        if (v !== exp) throw new Error(`SHA-512 mismatch. Got ${v}, expected ${exp}`);

        return '512-bit digest matches FIPS reference standards.';
      }
    },
    {
      id: 'test-salt-entropy',
      name: 'CSPRNG Salt Uniqueness & Non-Determinism',
      category: 'Defensive Salts',
      run: async () => {
        const salt1 = CryptoEngine.generateSalt(16);
        const salt2 = CryptoEngine.generateSalt(16);
        if (salt1.length !== 32 || salt2.length !== 32) throw new Error('16-byte salt must yield 32 hex chars.');
        if (salt1 === salt2) throw new Error('CSPRNG collision detected! Salts must be unique.');

        const hash1 = await CryptoEngine.digestAll('secret_password', salt1, 'prefix');
        const hash2 = await CryptoEngine.digestAll('secret_password', salt2, 'prefix');
        if (hash1.results.sha256.digest === hash2.results.sha256.digest) {
          throw new Error('Distinct salts produced identical hashes.');
        }

        return 'CSPRNG generated 128-bit high-entropy unique salts.';
      }
    },
    {
      id: 'test-aes-gcm-roundtrip',
      name: 'AES-256-GCM Encryption & Decryption Roundtrip',
      category: 'Symmetric AEAD',
      run: async () => {
        const keyData = await CryptoEngine.generateAesGcmKey();
        const ivData = CryptoEngine.generateIv(12);
        const secret = 'Authenticated Cipher Message Test #4092';

        const encrypted = await CryptoEngine.encryptAesGcm(keyData.key, ivData.ivArray, secret);
        if (!encrypted.ciphertextHex || !encrypted.tagHex) throw new Error('Missing ciphertext or auth tag.');

        const decrypted = await CryptoEngine.decryptAesGcm(keyData.key, ivData.ivArray, encrypted.ciphertextBytes, encrypted.tagBytes);
        if (!decrypted.success || decrypted.plaintext !== secret) {
          throw new Error(`AES roundtrip failed. Expected "${secret}", got "${decrypted.plaintext}"`);
        }

        return 'AES-256-GCM 128-bit tag roundtrip verified with 100% integrity.';
      }
    },
    {
      id: 'test-aes-tamper-rejection',
      name: 'AES-GCM Bit-Tamper Rejection (AEAD Integrity Failure)',
      category: 'Symmetric AEAD',
      run: async () => {
        const keyData = await CryptoEngine.generateAesGcmKey();
        const ivData = CryptoEngine.generateIv(12);
        const secret = 'Uncorrupted Payload';

        const encrypted = await CryptoEngine.encryptAesGcm(keyData.key, ivData.ivArray, secret);
        const tamperedBytes = new Uint8Array(encrypted.ciphertextBytes);
        tamperedBytes[0] ^= 0x01; // Flip single bit

        const decrypted = await CryptoEngine.decryptAesGcm(keyData.key, ivData.ivArray, tamperedBytes, encrypted.tagBytes);
        if (decrypted.success) {
          throw new Error('Security flaw: Tampered ciphertext was erroneously accepted by AES-GCM!');
        }

        return 'Tampered ciphertext rejected via OperationError / MAC mismatch as expected.';
      }
    },
    {
      id: 'test-rsa-roundtrip',
      name: 'RSA-OAEP-2048 Keypair & Encryption Roundtrip',
      category: 'Asymmetric Public Key',
      run: async () => {
        const keyPairData = await CryptoEngine.generateRsaKeyPair(2048);
        const message = 'RSA Public Key Exchange Payload';

        const encrypted = await CryptoEngine.encryptRsaOaep(keyPairData.keyPair.publicKey, message);
        if (encrypted.byteLength !== 256) throw new Error(`RSA 2048-bit block must be 256 bytes, got ${encrypted.byteLength}`);

        const decrypted = await CryptoEngine.decryptRsaOaep(keyPairData.keyPair.privateKey, encrypted.ciphertextBuffer);
        if (!decrypted.success || decrypted.plaintext !== message) {
          throw new Error(`RSA Decryption mismatch. Expected "${message}", got "${decrypted.plaintext}"`);
        }

        return 'RSA-2048 OAEP-SHA256 asymmetric roundtrip successfully verified.';
      }
    },
    {
      id: 'test-worker-cracking',
      name: 'Web Worker Background Hash Cracking Assertion',
      category: 'Multi-Threaded Simulator',
      run: async () => {
        const targetPlaintext = 'matrix123';
        const targetHash = CryptoEngine.md5(targetPlaintext);

        return new Promise((resolve, reject) => {
          const worker = new Worker('/workers/cracker.worker.js');
          const timeout = setTimeout(() => {
            worker.terminate();
            reject(new Error('Worker cracking timed out.'));
          }, 4000);

          worker.onmessage = (e) => {
            if (e.data.type === 'MATCH_FOUND') {
              clearTimeout(timeout);
              worker.terminate();
              if (e.data.match === targetPlaintext) {
                resolve(`Web Worker cracked '${targetHash}' in ${Math.round(e.data.timeTakenMs)}ms (${e.data.attempts} attempts).`);
              } else {
                reject(new Error(`Worker returned incorrect match '${e.data.match}'`));
              }
            }
          };

          worker.onerror = (err) => {
            clearTimeout(timeout);
            worker.terminate();
            reject(err);
          };

          worker.postMessage({
            type: 'START',
            data: {
              workerId: 0,
              targetHash,
              algorithm: 'MD5',
              wordlist: ['password', '123456', 'admin', 'matrix123', 'dragon'],
              attackMode: 'dictionary'
            }
          });
        });
      }
    }
  ];

  function init() {
    const runAllBtn = document.getElementById('run-all-tests-btn');
    if (runAllBtn) runAllBtn.addEventListener('click', runAllTests);
    renderInitialTestList();
  }

  function renderInitialTestList() {
    const container = document.getElementById('test-suite-results-list');
    if (!container) return;

    container.innerHTML = tests.map((t, idx) => `
      <div id="test-item-${idx}" class="p-3.5 bg-gray-900/70 border border-gray-800 rounded-xl flex items-center justify-between gap-3 text-xs">
        <div class="space-y-1">
          <div class="flex items-center gap-2">
            <span class="w-2 h-2 rounded-full bg-gray-600" id="test-status-dot-${idx}"></span>
            <strong class="text-gray-200">${t.name}</strong>
          </div>
          <p class="text-[11px] text-gray-500 font-mono">${t.category}</p>
        </div>
        <div id="test-result-msg-${idx}" class="text-[11px] text-gray-500 font-mono text-right">Pending Execution</div>
      </div>
    `).join('');
  }

  async function runAllTests() {
    const runBtn = document.getElementById('run-all-tests-btn');
    const summaryBanner = document.getElementById('test-suite-summary-banner');

    if (runBtn) {
      runBtn.disabled = true;
      runBtn.innerText = '⚙ Running Verification Assertions...';
    }

    let passedCount = 0;
    let failedCount = 0;

    for (let i = 0; i < tests.length; i++) {
      const t = tests[i];
      const dot = document.getElementById(`test-status-dot-${i}`);
      const msg = document.getElementById(`test-result-msg-${i}`);

      if (dot) dot.className = 'w-2 h-2 rounded-full bg-yellow-400 animate-ping';
      if (msg) {
        msg.className = 'text-[11px] text-yellow-400 font-mono';
        msg.innerText = 'Testing...';
      }

      try {
        const result = await t.run();
        passedCount++;
        if (dot) dot.className = 'w-2 h-2 rounded-full bg-emerald-400';
        if (msg) {
          msg.className = 'text-[11px] text-emerald-400 font-mono';
          msg.innerText = `✓ ${result}`;
        }
      } catch (err) {
        failedCount++;
        if (dot) dot.className = 'w-2 h-2 rounded-full bg-red-500';
        if (msg) {
          msg.className = 'text-[11px] text-red-400 font-mono';
          msg.innerText = `✕ Error: ${err.message}`;
        }
      }
    }

    if (summaryBanner) {
      summaryBanner.classList.remove('hidden');
      summaryBanner.innerHTML = `
        <div class="p-4 ${failedCount === 0 ? 'bg-emerald-950/60 border-emerald-500' : 'bg-red-950/60 border-red-500'} border rounded-xl flex items-center justify-between text-xs">
          <div class="space-y-0.5">
            <span class="font-bold ${failedCount === 0 ? 'text-emerald-400' : 'text-red-400'} text-sm">
              ${failedCount === 0 ? '✓ ALL CRYPTOGRAPHIC SUITE TESTS PASSED (8/8)' : `⚠️ TEST FAILURES DETECTED (${failedCount} failed)`}
            </span>
            <p class="text-gray-300">Verified Web Crypto API implementation, RFC vectors, CSPRNG randomness, and background Web Worker execution.</p>
          </div>
          <span class="px-3 py-1 rounded bg-black/40 font-mono text-xs ${failedCount === 0 ? 'text-emerald-300' : 'text-red-300'}">
            ${passedCount} Passed / ${failedCount} Failed
          </span>
        </div>
      `;
    }

    if (runBtn) {
      runBtn.disabled = false;
      runBtn.innerText = '⚡ Re-Run All Assertions';
    }
  }

  return { init, runAllTests };
})();
