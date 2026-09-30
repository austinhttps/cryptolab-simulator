/**
 * CryptoLab - Automated Verification & API Test Runner
 */

const assert = require('assert');
const http = require('http');
const crypto = require('crypto');
const app = require('../server');
const CryptoEngine = require('../public/js/crypto-engine');

const PORT = 3099;
let server;

function request(path, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(`http://localhost:${PORT}${path}`, {
      method: options.method || 'GET',
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {})
      }
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          resolve({ status: res.statusCode, body: parsed, raw: data });
        } catch (e) {
          resolve({ status: res.statusCode, raw: data });
        }
      });
    });

    req.on('error', reject);
    if (options.body) {
      req.write(typeof options.body === 'string' ? options.body : JSON.stringify(options.body));
    }
    req.end();
  });
}

async function runAllTests() {
  console.log('\n======================================================');
  console.log('  🧪 CryptoLab Automated Test Runner');
  console.log('======================================================\n');

  let passed = 0;
  let failed = 0;

  async function test(name, fn) {
    try {
      await fn();
      console.log(`  ✓ PASSED: ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ✕ FAILED: ${name}`);
      console.error(`    Error: ${err.message}`);
      failed++;
    }
  }

  // 1. Crypto Engine Pure JS MD5 & SHA-256 Tests
  await test('MD5 RFC 1321 Standard Test Vectors', () => {
    assert.strictEqual(CryptoEngine.md5(''), 'd41d8cd98f00b204e9800998ecf8427e');
    assert.strictEqual(CryptoEngine.md5('a'), '0cc175b9c0f1b6a831c399e269772661');
    assert.strictEqual(CryptoEngine.md5('message digest'), 'f96b697d7cb7938d525a2f31aaf161d0');
  });

  await test('SHA-256 Sync RFC 6234 Test Vectors', () => {
    assert.strictEqual(CryptoEngine.sha256Sync(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    assert.strictEqual(CryptoEngine.sha256Sync('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  await test('CSPRNG Salt Generator produces valid 16-byte hex', () => {
    const salt1 = CryptoEngine.generateSalt(16);
    const salt2 = CryptoEngine.generateSalt(16);
    assert.strictEqual(salt1.length, 32);
    assert.notStrictEqual(salt1, salt2);
  });

  await test('Hex & Buffer Encoding Utilities', () => {
    const originalHex = '00112233445566778899aabbccddeeff';
    const buf = CryptoEngine.hexToBuffer(originalHex);
    const backHex = CryptoEngine.bufferToHex(buf);
    assert.strictEqual(backHex, originalHex);
  });

  // Start server for API tests
  await new Promise((resolve) => {
    server = app.listen(PORT, resolve);
  });

  // 2. Server API Tests
  await test('GET /api/health returns online status', async () => {
    const res = await request('/api/health');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.status, 'online');
    assert.strictEqual(res.body.appName, 'CryptoLab');
  });

  await test('GET /api/samples returns targets & RFC vectors', async () => {
    const res = await request('/api/samples');
    assert.strictEqual(res.status, 200);
    assert.ok(Array.isArray(res.body.targets));
    assert.ok(res.body.targets.length > 0);
    assert.ok(res.body.vectors.sha256);
  });

  await test('GET /api/wordlists/1000 returns 1000 words array', async () => {
    const res = await request('/api/wordlists/1000');
    assert.strictEqual(res.status, 200);
    assert.ok(Array.isArray(res.body));
    assert.strictEqual(res.body.length, 1000);
  });

  await test('POST /api/rainbow-table/lookup finds unsalted collision hit', async () => {
    const md5Password = crypto.createHash('md5').update('password').digest('hex');
    const res = await request('/api/rainbow-table/lookup', {
      method: 'POST',
      body: { hash: md5Password, algorithm: 'md5' }
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.found, true);
    assert.strictEqual(res.body.plaintext, 'password');
    assert.ok(res.body.lookupTimeMicros >= 0);
  });

  await test('POST /api/rainbow-table/lookup correctly misses non-indexed hash', async () => {
    const res = await request('/api/rainbow-table/lookup', {
      method: 'POST',
      body: { hash: 'ffffffffffffffffffffffffffffffff', algorithm: 'md5' }
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.found, false);
    assert.strictEqual(res.body.plaintext, null);
  });

  await test('POST /api/benchmark/slow-hash runs bcrypt computation', async () => {
    const res = await request('/api/benchmark/slow-hash', {
      method: 'POST',
      body: {
        algorithm: 'bcrypt',
        password: 'securePassword!',
        costFactor: 8
      }
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.algorithm, 'bcrypt');
    assert.ok(res.body.durationMs > 0);
    assert.ok(res.body.sampleOutputHash.startsWith('$2'));
    assert.ok(res.body.gpuSecurityAnalysis);
  });

  await test('POST /api/benchmark/slow-hash runs PBKDF2 computation', async () => {
    const res = await request('/api/benchmark/slow-hash', {
      method: 'POST',
      body: {
        algorithm: 'pbkdf2',
        password: 'securePassword!',
        iterations: 10000
      }
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.algorithm, 'pbkdf2');
    assert.ok(res.body.durationMs > 0);
    assert.ok(res.body.sampleOutputHash.includes('$pbkdf2-sha256$'));
  });

  // Teardown
  if (server) {
    server.close();
  }

  console.log('\n======================================================');
  console.log(`  Test Summary: ${passed} Passed, ${failed} Failed`);
  console.log('======================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runAllTests().catch((err) => {
  console.error('Test runner fatal error:', err);
  if (server) server.close();
  process.exit(1);
});
