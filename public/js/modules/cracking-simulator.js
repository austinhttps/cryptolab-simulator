/**
 * CryptoLab - Module C: Multi-Threaded Hash Cracking Simulator
 * Coordinates dedicated Web Workers for parallel dictionary, hybrid-rule, and mask attacks.
 */

const CrackingSimulatorModule = (function () {
  let workers = [];
  let isCracking = false;
  let isPaused = false;
  let wordlistsCache = {};
  let startTime = 0;
  let timerInterval = null;
  let totalAttempts = 0;
  let activeWorkersCount = 0;
  let completedWorkersCount = 0;
  let workerStats = {};

  function init() {
    initControls();
    initPresets();
    preloadDefaultWordlist();
  }

  function initControls() {
    const startBtn = document.getElementById('crack-start-btn');
    const stopBtn = document.getElementById('crack-stop-btn');
    const pauseBtn = document.getElementById('crack-pause-btn');
    const threadSelect = document.getElementById('crack-threads-select');
    const wordlistSelect = document.getElementById('crack-wordlist-select');
    const attackModeSelect = document.getElementById('crack-attack-mode-select');

    if (startBtn) startBtn.addEventListener('click', startAttack);
    if (stopBtn) stopBtn.addEventListener('click', stopAttack);
    if (pauseBtn) pauseBtn.addEventListener('click', togglePause);

    // Auto populate available threads from hardwareConcurrency
    if (threadSelect) {
      const logicalCores = navigator.hardwareConcurrency || 4;
      threadSelect.innerHTML = `
        <option value="1">1 Worker Thread (Single Core)</option>
        <option value="2">2 Worker Threads</option>
        <option value="4" ${logicalCores >= 4 ? 'selected' : ''}>4 Worker Threads (Parallel)</option>
        <option value="${logicalCores}" ${logicalCores > 4 ? 'selected' : ''}>${logicalCores} Worker Threads (Max Hardware)</option>
      `;
    }

    // Toggle mask pattern input if mask attack is chosen
    if (attackModeSelect) {
      attackModeSelect.addEventListener('change', (e) => {
        const maskContainer = document.getElementById('crack-mask-config');
        if (maskContainer) {
          if (e.target.value === 'mask') maskContainer.classList.remove('hidden');
          else maskContainer.classList.add('hidden');
        }
      });
    }
  }

  async function preloadDefaultWordlist() {
    try {
      const res = await fetch('/api/wordlists/5000');
      wordlistsCache['5000'] = await res.json();
    } catch (e) {
      console.warn('Wordlist preloading deferred', e);
    }
  }

  async function getWordlist(size) {
    if (wordlistsCache[size]) return wordlistsCache[size];
    const res = await fetch(`/api/wordlists/${size}`);
    const data = await res.json();
    wordlistsCache[size] = data;
    return data;
  }

  function initPresets() {
    const presetContainer = document.getElementById('crack-presets-container');
    if (!presetContainer) return;

    // Fetch sample targets from server
    fetch('/api/samples')
      .then((r) => r.json())
      .then((data) => {
        const targets = data.targets || [];
        presetContainer.innerHTML = targets.map((t) => `
          <button type="button" class="sample-preset-btn text-left p-2.5 rounded-lg bg-gray-900/80 border border-gray-800 hover:border-cyan-500 hover:bg-gray-800 transition flex flex-col gap-1 text-xs"
            data-hash="${t.hash}"
            data-algo="${t.algorithm}"
            data-mode="${t.id.includes('hybrid') || t.id.includes('medium') ? 'hybrid' : 'dictionary'}"
            data-title="${escapeHtml(t.title)}"
            data-desc="${escapeHtml(t.description)}">
            <div class="flex items-center justify-between w-full">
              <span class="font-bold text-cyan-300">${escapeHtml(t.title)}</span>
              <span class="px-1.5 py-0.5 rounded text-[10px] ${t.salted ? 'bg-purple-950 text-purple-400 border border-purple-800' : 'bg-emerald-950 text-emerald-400 border border-emerald-800'}">${t.difficulty}</span>
            </div>
            <div class="font-mono text-[11px] text-gray-400 truncate w-full">${t.hash}</div>
          </button>
        `).join('');

        // Add click handlers
        presetContainer.querySelectorAll('.sample-preset-btn').forEach((btn) => {
          btn.addEventListener('click', () => {
            const hashInput = document.getElementById('crack-target-hash');
            const algoSelect = document.getElementById('crack-algorithm-select');
            const attackMode = document.getElementById('crack-attack-mode-select');

            if (hashInput) hashInput.value = btn.getAttribute('data-hash');
            if (algoSelect) algoSelect.value = btn.getAttribute('data-algo');
            if (attackMode) attackMode.value = btn.getAttribute('data-mode') || 'dictionary';

            // Glow animation on input
            if (hashInput) {
              hashInput.classList.add('ring-2', 'ring-cyan-400');
              setTimeout(() => hashInput.classList.remove('ring-2', 'ring-cyan-400'), 1000);
            }
          });
        });
      })
      .catch((err) => console.error('Failed to load sample targets', err));
  }

  async function startAttack() {
    if (isCracking) return;

    const targetHashInput = document.getElementById('crack-target-hash');
    const targetHash = (targetHashInput?.value || '').trim();
    if (!targetHash) {
      alert('Please enter a target hash or click a preset sample button.');
      return;
    }

    const algo = document.getElementById('crack-algorithm-select')?.value || 'MD5';
    const wordlistSize = document.getElementById('crack-wordlist-select')?.value || '5000';
    const numThreads = parseInt(document.getElementById('crack-threads-select')?.value || '4', 10);
    const attackMode = document.getElementById('crack-attack-mode-select')?.value || 'dictionary';
    const maskPattern = document.getElementById('crack-mask-pattern')?.value || '?d?d?d?d';

    // Clear previous results and UI
    resetHUD();
    setRunningState(true);

    let fullWordlist = [];
    if (attackMode !== 'mask') {
      fullWordlist = await getWordlist(wordlistSize);
    }

    // Terminate existing workers
    terminateWorkers();

    startTime = performance.now();
    totalAttempts = 0;
    activeWorkersCount = numThreads;
    completedWorkersCount = 0;
    workerStats = {};

    // Start timer interval
    timerInterval = setInterval(updateTimerHUD, 60);

    // Split wordlist into chunks per worker
    const chunkSize = Math.ceil((fullWordlist.length || 10000) / numThreads);
    renderWorkerCards(numThreads);

    for (let i = 0; i < numThreads; i++) {
      const worker = new Worker('/workers/cracker.worker.js');
      const chunk = attackMode === 'mask' ? [] : fullWordlist.slice(i * chunkSize, (i + 1) * chunkSize);

      workerStats[i] = { attempts: 0, speed: 0, candidate: '' };

      worker.onmessage = (e) => handleWorkerMessage(e.data, numThreads);
      worker.onerror = (err) => console.error(`Worker #${i} error:`, err);

      worker.postMessage({
        type: 'START',
        data: {
          workerId: i,
          targetHash,
          algorithm: algo,
          wordlist: chunk,
          attackMode,
          maskPattern,
          chunkIndex: i,
          totalChunks: numThreads
        }
      });

      workers.push(worker);
    }
  }

  function handleWorkerMessage(data, numThreads) {
    if (!isCracking && data.type !== 'MATCH_FOUND') return;

    if (data.type === 'PROGRESS') {
      workerStats[data.workerId] = {
        attempts: data.attempts,
        speed: data.speedHps,
        candidate: data.currentCandidate
      };
      updateAggregatedProgress(numThreads);
      updateWorkerCardUI(data.workerId, data);
    } else if (data.type === 'MATCH_FOUND') {
      // Immediate broadcast to all other workers
      terminateWorkers();
      setRunningState(false);
      clearInterval(timerInterval);

      renderSuccessBanner(data);
    } else if (data.type === 'CHUNK_COMPLETE') {
      completedWorkersCount++;
      if (completedWorkersCount >= activeWorkersCount) {
        // All workers finished with no collision
        setRunningState(false);
        clearInterval(timerInterval);
        renderExhaustionBanner();
      }
    }
  }

  function updateAggregatedProgress(numThreads) {
    let aggAttempts = 0;
    let aggSpeed = 0;
    let latestCandidate = '';

    for (const id in workerStats) {
      aggAttempts += workerStats[id].attempts || 0;
      aggSpeed += workerStats[id].speed || 0;
      if (workerStats[id].candidate) latestCandidate = workerStats[id].candidate;
    }

    totalAttempts = aggAttempts;

    const attemptsEl = document.getElementById('hud-total-attempts');
    const speedEl = document.getElementById('hud-hashrate');
    const candidateEl = document.getElementById('hud-current-candidate');
    const progressBar = document.getElementById('hud-progress-bar');
    const progressPercent = document.getElementById('hud-progress-percent');

    if (attemptsEl) attemptsEl.innerText = totalAttempts.toLocaleString();
    if (speedEl) speedEl.innerText = formatHashrate(aggSpeed);
    if (candidateEl) candidateEl.innerText = latestCandidate ? `"${latestCandidate}"` : 'Searching...';

    const wordlistSize = parseInt(document.getElementById('crack-wordlist-select')?.value || '5000', 10);
    const approxTotal = wordlistSize * (document.getElementById('crack-attack-mode-select')?.value === 'hybrid' ? 15 : 1);
    const pct = Math.min(100, Math.max(1, ((totalAttempts / approxTotal) * 100))).toFixed(1);

    if (progressBar) progressBar.style.width = `${pct}%`;
    if (progressPercent) progressPercent.innerText = `${pct}%`;
  }

  function updateTimerHUD() {
    const elapsedEl = document.getElementById('hud-elapsed-time');
    if (!elapsedEl || !startTime) return;

    const elapsedMs = performance.now() - startTime;
    const seconds = (elapsedMs / 1000).toFixed(2);
    elapsedEl.innerText = `${seconds}s (${Math.floor(elapsedMs)} ms)`;
  }

  function formatHashrate(hps) {
    if (hps >= 1000000) return `${(hps / 1000000).toFixed(2)} MH/s`;
    if (hps >= 1000) return `${(hps / 1000).toFixed(2)} kH/s`;
    return `${Math.round(hps)} H/s`;
  }

  function stopAttack() {
    terminateWorkers();
    setRunningState(false);
    clearInterval(timerInterval);

    const banner = document.getElementById('crack-result-banner');
    if (banner) {
      banner.innerHTML = `
        <div class="p-4 bg-gray-900 border border-gray-700 rounded-xl text-xs text-gray-300 flex items-center justify-between">
          <span class="flex items-center gap-2">
            <span class="w-2.5 h-2.5 rounded-full bg-yellow-500"></span>
            Attack aborted by user. Tested ${totalAttempts.toLocaleString()} candidates.
          </span>
          <span class="font-mono text-gray-500">${new Date().toLocaleTimeString()}</span>
        </div>
      `;
    }
  }

  function togglePause() {
    const pauseBtn = document.getElementById('crack-pause-btn');
    if (!isCracking) return;

    isPaused = !isPaused;
    workers.forEach((w) => w.postMessage({ type: isPaused ? 'PAUSE' : 'RESUME' }));

    if (pauseBtn) {
      pauseBtn.innerText = isPaused ? '▶ Resume' : '⏸ Pause';
      pauseBtn.classList.toggle('bg-yellow-600', isPaused);
    }
  }

  function terminateWorkers() {
    workers.forEach((w) => {
      try {
        w.terminate();
      } catch (e) {}
    });
    workers = [];
  }

  function setRunningState(running) {
    isCracking = running;
    isPaused = false;

    const startBtn = document.getElementById('crack-start-btn');
    const stopBtn = document.getElementById('crack-stop-btn');
    const pauseBtn = document.getElementById('crack-pause-btn');

    if (startBtn) startBtn.disabled = running;
    if (stopBtn) stopBtn.disabled = !running;
    if (pauseBtn) {
      pauseBtn.disabled = !running;
      pauseBtn.innerText = '⏸ Pause';
      pauseBtn.classList.remove('bg-yellow-600');
    }
  }

  function resetHUD() {
    const banner = document.getElementById('crack-result-banner');
    if (banner) banner.innerHTML = '';

    const attemptsEl = document.getElementById('hud-total-attempts');
    const speedEl = document.getElementById('hud-hashrate');
    const candidateEl = document.getElementById('hud-current-candidate');
    const elapsedEl = document.getElementById('hud-elapsed-time');
    const progressBar = document.getElementById('hud-progress-bar');
    const progressPercent = document.getElementById('hud-progress-percent');

    if (attemptsEl) attemptsEl.innerText = '0';
    if (speedEl) speedEl.innerText = '0 H/s';
    if (candidateEl) candidateEl.innerText = 'Initializing Web Workers...';
    if (elapsedEl) elapsedEl.innerText = '0.00s (0 ms)';
    if (progressBar) progressBar.style.width = '0%';
    if (progressPercent) progressPercent.innerText = '0%';
  }

  function renderWorkerCards(numThreads) {
    const container = document.getElementById('crack-workers-grid');
    if (!container) return;

    let html = '';
    for (let i = 0; i < numThreads; i++) {
      html += `
        <div id="worker-card-${i}" class="p-3 bg-gray-900/90 border border-cyan-900/40 rounded-lg text-xs space-y-1 font-mono">
          <div class="flex items-center justify-between text-cyan-400 font-bold">
            <span class="flex items-center gap-1.5">
              <span class="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
              Thread #${i + 1}
            </span>
            <span id="worker-speed-${i}" class="text-[10px] text-gray-400">0 H/s</span>
          </div>
          <div class="text-[11px] text-gray-300 truncate">Candidate: <span id="worker-candidate-${i}" class="text-emerald-300">...</span></div>
          <div class="text-[10px] text-gray-500">Tested: <span id="worker-attempts-${i}">0</span></div>
        </div>
      `;
    }
    container.innerHTML = html;
  }

  function updateWorkerCardUI(workerId, data) {
    const speedEl = document.getElementById(`worker-speed-${workerId}`);
    const candidateEl = document.getElementById(`worker-candidate-${workerId}`);
    const attemptsEl = document.getElementById(`worker-attempts-${workerId}`);

    if (speedEl) speedEl.innerText = formatHashrate(data.speedHps);
    if (candidateEl) candidateEl.innerText = `"${data.currentCandidate}"`;
    if (attemptsEl) attemptsEl.innerText = data.attempts.toLocaleString();
  }

  function renderSuccessBanner(data) {
    const banner = document.getElementById('crack-result-banner');
    if (!banner) return;

    const durationSec = (data.timeTakenMs / 1000).toFixed(3);
    const totalSpeed = formatHashrate(totalAttempts / (data.timeTakenMs / 1000));

    banner.innerHTML = `
      <div class="p-5 bg-gradient-to-r from-emerald-950 via-gray-900 to-emerald-950 border-2 border-emerald-500 rounded-2xl shadow-2xl space-y-3">
        <div class="flex flex-wrap items-center justify-between gap-2 border-b border-emerald-800/60 pb-3">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-xl bg-emerald-500/20 border border-emerald-500 flex items-center justify-center text-emerald-400 text-xl font-bold">
              ✓
            </div>
            <div>
              <h3 class="text-base font-bold text-emerald-400">PASSWORD CRACKED SUCCESSFULLY!</h3>
              <p class="text-xs text-gray-300">Collision found via Worker Thread #${data.workerId + 1}</p>
            </div>
          </div>
          <div class="px-3 py-1 rounded bg-emerald-900/60 border border-emerald-600 text-emerald-300 font-mono text-xs">
            Elapsed: ${durationSec}s (${Math.round(data.timeTakenMs)} ms)
          </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1">
          <div class="p-3 bg-black/60 rounded-xl border border-emerald-500/40">
            <span class="text-[11px] text-gray-400 uppercase tracking-wider block">Recovered Plaintext</span>
            <span class="text-xl font-bold font-mono text-emerald-300 select-all">"${escapeHtml(data.match)}"</span>
          </div>
          <div class="p-3 bg-black/60 rounded-xl border border-gray-800">
            <span class="text-[11px] text-gray-400 uppercase tracking-wider block">Total Attempts</span>
            <span class="text-xl font-bold font-mono text-gray-100">${totalAttempts.toLocaleString()}</span>
          </div>
          <div class="p-3 bg-black/60 rounded-xl border border-gray-800">
            <span class="text-[11px] text-gray-400 uppercase tracking-wider block">Peak Throughput</span>
            <span class="text-xl font-bold font-mono text-cyan-400">${totalSpeed}</span>
          </div>
        </div>

        <div class="p-3 bg-yellow-950/40 border border-yellow-800/80 rounded-lg text-xs text-yellow-200/90 leading-relaxed">
          <strong>Security Takeaway:</strong> General-purpose hash algorithms like MD5 and SHA-256 are engineered for speed (streaming files and block validation), allowing simple CPU/GPU loops to test tens of millions to billions of candidates per second. Storing passwords with fast hashes leaves users vulnerable to automated dictionary and hybrid attacks. Use adaptive Key Derivation Functions (Argon2id, bcrypt, PBKDF2) instead!
        </div>
      </div>
    `;
  }

  function renderExhaustionBanner() {
    const banner = document.getElementById('crack-result-banner');
    if (!banner) return;

    banner.innerHTML = `
      <div class="p-5 bg-gray-900 border border-red-500/60 rounded-2xl space-y-3">
        <div class="flex items-center justify-between border-b border-gray-800 pb-3">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-xl bg-red-500/20 border border-red-500 flex items-center justify-center text-red-400 text-xl font-bold">
              ✕
            </div>
            <div>
              <h3 class="text-base font-bold text-red-400">SEARCH SPACE EXHAUSTED</h3>
              <p class="text-xs text-gray-400">No match found within selected wordlist & rules</p>
            </div>
          </div>
          <div class="text-xs font-mono text-gray-400">Total Attempts: ${totalAttempts.toLocaleString()}</div>
        </div>
        <p class="text-xs text-gray-300 leading-relaxed">
          The candidate target is either salted with a unique random nonce, contains high entropy (e.g. 16+ randomized characters), or is not present in the current dictionary chunk. This highlights the power of salt + password complexity in thwarting dictionary cracking.
        </p>
      </div>
    `;
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  return { init, startAttack, stopAttack };
})();
