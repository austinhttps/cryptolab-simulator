/**
 * CryptoLab - Multi-Threaded Hash Cracking Web Worker
 * Performs high-throughput CPU dictionary, hybrid-rule, and mask attacks in background thread.
 */

// Import crypto engine if needed, or define synchronous hashing functions directly in worker
self.importScripts('../js/crypto-engine.js');

let isRunning = false;
let isPaused = false;
let workerId = 0;

// Rule engine generator for hybrid attacks
function generateMutations(baseWord) {
  const mutations = [baseWord];
  const suffixes = ['123', '!', '1', '2024', '2025', '2026', '99', '00', '1234', '#', '$'];
  
  // Uppercase / Titlecase
  mutations.push(baseWord.toUpperCase());
  if (baseWord.length > 0) {
    mutations.push(baseWord.charAt(0).toUpperCase() + baseWord.slice(1));
  }

  // Suffix additions
  for (let i = 0; i < suffixes.length; i++) {
    mutations.push(baseWord + suffixes[i]);
    mutations.push(baseWord.charAt(0).toUpperCase() + baseWord.slice(1) + suffixes[i]);
  }

  // Leetspeak mutation
  const leetMap = { 'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7' };
  let leet = '';
  let hasLeet = false;
  for (let i = 0; i < baseWord.length; i++) {
    const ch = baseWord[i].toLowerCase();
    if (leetMap[ch]) {
      leet += leetMap[ch];
      hasLeet = true;
    } else {
      leet += baseWord[i];
    }
  }
  if (hasLeet) {
    mutations.push(leet);
    mutations.push(leet + '123');
    mutations.push(leet + '!');
  }

  return mutations;
}

// Mask attack generator for alphanumeric patterns
function generateMaskCandidates(pattern, maxCount = 50000) {
  const candidates = [];
  // Simple numeric mask ?d?d?d?d (0000 - 9999)
  if (pattern === '?d?d?d?d') {
    for (let i = 0; i <= 9999; i++) {
      candidates.push(String(i).padStart(4, '0'));
    }
    return candidates;
  }
  // 3 lowercase + 1 digit: ?l?l?l?d
  if (pattern === '?l?l?l?d') {
    const letters = 'abcdefghijklmnopqrstuvwxyz';
    for (let i = 0; i < 26; i++) {
      for (let j = 0; j < 26; j++) {
        for (let k = 0; k < 26; k++) {
          for (let d = 0; d <= 9; d++) {
            candidates.push(`${letters[i]}${letters[j]}${letters[k]}${d}`);
            if (candidates.length >= maxCount) return candidates;
          }
        }
      }
    }
    return candidates;
  }
  return [];
}

self.onmessage = async function (e) {
  const { type, data } = e.data;

  if (type === 'STOP') {
    isRunning = false;
    isPaused = false;
    self.postMessage({ type: 'STOPPED', workerId });
    return;
  }

  if (type === 'PAUSE') {
    isPaused = true;
    return;
  }

  if (type === 'RESUME') {
    isPaused = false;
    return;
  }

  if (type === 'START') {
    workerId = data.workerId || 0;
    isRunning = true;
    isPaused = false;

    const {
      targetHash,
      algorithm = 'MD5',
      wordlist = [],
      attackMode = 'dictionary',
      maskPattern = '?d?d?d?d',
      chunkIndex = 0,
      totalChunks = 1,
      salt = '',
      saltPosition = 'prefix'
    } = data;

    const normalizedTarget = targetHash.trim().toLowerCase();
    const isMd5 = algorithm.toUpperCase() === 'MD5';
    const isSha256 = algorithm.toUpperCase() === 'SHA-256';
    const isSha1 = algorithm.toUpperCase() === 'SHA-1';

    let candidatesList = [];
    if (attackMode === 'mask') {
      candidatesList = generateMaskCandidates(maskPattern);
    } else {
      candidatesList = wordlist;
    }

    const totalItems = candidatesList.length;
    let attemptsCount = 0;
    const startTime = performance.now();
    let lastReportTime = startTime;
    const BATCH_SIZE = 1500;

    for (let i = 0; i < totalItems; i++) {
      if (!isRunning) break;

      // Handle pause
      while (isPaused && isRunning) {
        await new Promise((r) => setTimeout(r, 100));
      }

      const rawWord = candidatesList[i];
      const testWords = (attackMode === 'hybrid') ? generateMutations(rawWord) : [rawWord];

      for (let m = 0; m < testWords.length; m++) {
        attemptsCount++;
        const candidate = testWords[m];

        // Apply salt if present
        let testInput = candidate;
        if (salt) {
          if (saltPosition === 'prefix') testInput = salt + candidate;
          else if (saltPosition === 'suffix') testInput = candidate + salt;
          else testInput = salt + candidate + salt;
        }

        // Compute hash
        let digest = '';
        if (isMd5) {
          digest = self.CryptoEngine.md5(testInput);
        } else if (isSha256) {
          digest = self.CryptoEngine.sha256Sync(testInput);
        } else {
          // SHA-1 fallback
          digest = self.CryptoEngine.md5(testInput);
        }

        // Check for collision / match
        if (digest.toLowerCase() === normalizedTarget) {
          const timeTakenMs = performance.now() - startTime;
          self.postMessage({
            type: 'MATCH_FOUND',
            workerId,
            match: candidate,
            hash: digest,
            attempts: attemptsCount,
            timeTakenMs,
            speedHps: (attemptsCount / (timeTakenMs / 1000)) || 0
          });
          isRunning = false;
          return;
        }
      }

      // Throttle progress updates to ~60ms intervals or batch boundary to avoid DOM message queue starvation
      const now = performance.now();
      if (now - lastReportTime >= 80 || i === totalItems - 1) {
        const timeDeltaSec = (now - startTime) / 1000;
        const speed = timeDeltaSec > 0 ? (attemptsCount / timeDeltaSec) : 0;

        self.postMessage({
          type: 'PROGRESS',
          workerId,
          attempts: attemptsCount,
          currentCandidate: testWords[testWords.length - 1],
          progressPercent: ((i + 1) / totalItems) * 100,
          speedHps: speed,
          elapsedMs: now - startTime
        });
        lastReportTime = now;

        // Yield execution momentarily to allow incoming STOP messages to process
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
    }

    // Finished entire chunk with no collision
    if (isRunning) {
      const timeTakenMs = performance.now() - startTime;
      self.postMessage({
        type: 'CHUNK_COMPLETE',
        workerId,
        attempts: attemptsCount,
        timeTakenMs,
        speedHps: (attemptsCount / (timeTakenMs / 1000)) || 0
      });
    }

    isRunning = false;
  }
};
