const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Load precomputed datasets
const dataDir = path.join(__dirname, 'data');
const samplesDir = path.join(__dirname, 'samples');

let rainbowTable = { md5: {}, sha1: {}, sha256: {}, metadata: {} };
try {
  const rtPath = path.join(dataDir, 'rainbow-table-sample.json');
  if (fs.existsSync(rtPath)) {
    rainbowTable = JSON.parse(fs.readFileSync(rtPath, 'utf8'));
  }
} catch (err) {
  console.error('Error loading rainbow table data:', err.message);
}

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    appName: 'CryptoLab',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    cryptoSubtleSupport: 'Client-side Web Crypto API'
  });
});

// Sample hashes and test vectors endpoint
app.get('/api/samples', (req, res) => {
  try {
    const targetsPath = path.join(samplesDir, 'target-hashes.json');
    const vectorsPath = path.join(samplesDir, 'vectors-test.json');
    
    const targets = fs.existsSync(targetsPath) ? JSON.parse(fs.readFileSync(targetsPath, 'utf8')) : [];
    const vectors = fs.existsSync(vectorsPath) ? JSON.parse(fs.readFileSync(vectorsPath, 'utf8')) : {};

    res.json({ targets, vectors });
  } catch (err) {
    res.status(500).json({ error: 'Failed to read samples', message: err.message });
  }
});

// Wordlist endpoint
app.get('/api/wordlists/:size', (req, res) => {
  const size = req.params.size || '1000';
  const validSizes = ['1000', '5000', '10000'];
  const targetSize = validSizes.includes(size) ? size : '1000';
  const filePath = path.join(dataDir, `wordlist-${targetSize}.json`);

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: `Wordlist size ${targetSize} not found.` });
  }

  res.setHeader('Content-Type', 'application/json');
  fs.createReadStream(filePath).pipe(res);
});

// Rainbow Table Lookup endpoint
app.post('/api/rainbow-table/lookup', (req, res) => {
  const { hash, algorithm } = req.body;
  if (!hash) {
    return res.status(400).json({ error: 'Missing hash parameter' });
  }

  const normalizedHash = hash.trim().toLowerCase();
  const algo = (algorithm || 'auto').toLowerCase();
  const startTime = process.hrtime.bigint();

  let match = null;
  let detectedAlgo = null;

  if (algo === 'md5' || (algo === 'auto' && normalizedHash.length === 32)) {
    match = rainbowTable.md5[normalizedHash] || null;
    detectedAlgo = 'MD5';
  } else if (algo === 'sha1' || (algo === 'auto' && normalizedHash.length === 40)) {
    match = rainbowTable.sha1[normalizedHash] || null;
    detectedAlgo = 'SHA-1';
  } else if (algo === 'sha256' || (algo === 'auto' && normalizedHash.length === 64)) {
    match = rainbowTable.sha256[normalizedHash] || null;
    detectedAlgo = 'SHA-256';
  }

  const endTime = process.hrtime.bigint();
  const lookupTimeMicros = Number(endTime - startTime) / 1000; // microseconds

  res.json({
    queriedHash: normalizedHash,
    algorithm: detectedAlgo || algo,
    found: Boolean(match),
    plaintext: match,
    lookupTimeMicros: parseFloat(lookupTimeMicros.toFixed(3)),
    tableSize: rainbowTable.metadata?.totalEntries || 5000,
    explanation: match
      ? 'Instant O(1) Precomputed Collision Hit! Unsalted hash was found in the precomputed lookup map.'
      : 'Cache Miss! The hash does not exist in the precomputed table (Salted hashes or complex passwords thwart precomputation tables).'
  });
});

// Slow Hash Function Benchmark endpoint (bcrypt, PBKDF2, scrypt)
app.post('/api/benchmark/slow-hash', async (req, res) => {
  const {
    algorithm = 'bcrypt',
    password = 'password123',
    costFactor = 10,
    salt = null,
    iterations = 100000,
    keylen = 32
  } = req.body;

  try {
    const start = process.hrtime.bigint();
    let resultHash = '';
    let memoryUsageEst = 'Low (<1 MB)';

    if (algorithm.toLowerCase() === 'bcrypt') {
      const rounds = Math.min(Math.max(parseInt(costFactor) || 10, 4), 14); // safety cap
      const saltRounds = await bcrypt.genSalt(rounds);
      resultHash = await bcrypt.hash(password, saltRounds);
      memoryUsageEst = '4 KB per thread (Eksblowfish algorithm)';
    } else if (algorithm.toLowerCase() === 'pbkdf2') {
      const iter = Math.min(Math.max(parseInt(iterations) || 100000, 1000), 1000000);
      const usedSalt = salt || crypto.randomBytes(16).toString('hex');
      const derivedKey = crypto.pbkdf2Sync(password, usedSalt, iter, keylen, 'sha256');
      resultHash = `$pbkdf2-sha256$i=${iter}$${usedSalt}$${derivedKey.toString('hex')}`;
      memoryUsageEst = 'CPU bound, memory negligible (vulnerable to ASIC parallelization)';
    } else if (algorithm.toLowerCase() === 'scrypt' || algorithm.toLowerCase() === 'argon2_sim') {
      // Node native scrypt to demonstrate memory hardness
      const cost = Math.pow(2, Math.min(Math.max(parseInt(costFactor) || 14, 10), 16)); // N: 16384 default
      const usedSalt = salt || crypto.randomBytes(16).toString('hex');
      const derivedKey = crypto.scryptSync(password, usedSalt, 32, { N: cost, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
      resultHash = `$scrypt$ln=${Math.log2(cost)},r=8,p=1$${usedSalt}$${derivedKey.toString('hex')}`;
      memoryUsageEst = `${((cost * 8 * 128) / (1024 * 1024)).toFixed(1)} MB RAM per hash (Memory-Hard)`;
    } else {
      return res.status(400).json({ error: 'Unsupported algorithm. Choose bcrypt, pbkdf2, or scrypt.' });
    }

    const end = process.hrtime.bigint();
    const durationMs = Number(end - start) / 1000000;
    const hashesPerSec = durationMs > 0 ? (1000 / durationMs).toFixed(2) : 'N/A';

    // Calculate theoretical GPU cracking time for 8-char alphanumeric password (~2.18 * 10^14 combinations)
    const combinations = 2.18e14;
    // An 8x RTX 4090 rig does ~150 GH/s for MD5, ~60 GH/s for SHA-256, but only ~80 kH/s for bcrypt cost 10, or ~8 kH/s for bcrypt 13!
    let gpuHashrate = 80000; // 80 kH/s for bcrypt 10 on 8x 4090
    if (algorithm.toLowerCase() === 'bcrypt') {
      const rounds = parseInt(costFactor) || 10;
      gpuHashrate = 80000 / Math.pow(2, rounds - 10);
    } else if (algorithm.toLowerCase() === 'scrypt' || algorithm.toLowerCase() === 'argon2_sim') {
      gpuHashrate = 5000; // memory-bound on GPU
    } else if (algorithm.toLowerCase() === 'pbkdf2') {
      gpuHashrate = 200000;
    }

    const gpuSeconds = combinations / gpuHashrate;
    const gpuYears = (gpuSeconds / (3600 * 24 * 365)).toFixed(1);

    res.json({
      algorithm,
      costParameter: algorithm === 'bcrypt' ? `Cost factor 2^${costFactor} (${Math.pow(2, costFactor)} rounds)` : algorithm === 'pbkdf2' ? `${iterations} iterations` : `N=2^${costFactor} (Memory-Hard)`,
      durationMs: parseFloat(durationMs.toFixed(2)),
      singleThreadHashesPerSec: hashesPerSec,
      memoryUsage: memoryUsageEst,
      sampleOutputHash: resultHash,
      gpuSecurityAnalysis: {
        estimatedGpuClusterHashrate: `${(gpuHashrate / 1000).toFixed(1)} kH/s (8x RTX 4090 cluster)`,
        estimatedTimeFor8CharPassword: `${gpuYears} Years`,
        md5ComparisonTime: '0.0015 Seconds (at 150 Billion H/s)',
        verdict: 'Cryptographically Secure Work Factor: Slow, salted KDF defeats brute force attacks.'
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Benchmark execution failed', message: err.message });
  }
});

// Fallback to index.html for SPA routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server if not imported by test runner
if (require.main === module) {
  const startServer = (port) => {
    const serverInstance = app.listen(port, () => {
      console.log(`====================================================`);
      console.log(`  CryptoLab Simulator Server running on port ${port}`);
      console.log(`  URL: http://localhost:${port}`);
      console.log(`====================================================`);
    });

    serverInstance.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        console.warn(`Port ${port} in use, attempting port ${port + 1}...`);
        startServer(port + 1);
      } else {
        console.error('Server error:', err);
      }
    });
  };

  startServer(PORT);
}

module.exports = app;
