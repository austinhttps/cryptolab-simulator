/**
 * CryptoLab - Slow Hash Benchmark & KDF Security Calculator
 * Benchmarks bcrypt, PBKDF2, and scrypt/Argon2 vs fast hashes to demonstrate defense in depth.
 */

const SlowHashBenchmarkModule = (function () {
  function init() {
    const runBtn = document.getElementById('benchmark-run-btn');
    const algoSelect = document.getElementById('benchmark-algo-select');
    const costSlider = document.getElementById('benchmark-cost-slider');
    const costValDisplay = document.getElementById('benchmark-cost-val');

    if (runBtn) runBtn.addEventListener('click', runBenchmark);

    if (costSlider && costValDisplay) {
      costSlider.addEventListener('input', (e) => {
        costValDisplay.innerText = e.target.value;
      });
    }

    if (algoSelect) {
      algoSelect.addEventListener('change', (e) => {
        const algo = e.target.value;
        const costLabel = document.getElementById('benchmark-cost-label');
        const costSliderEl = document.getElementById('benchmark-cost-slider');

        if (algo === 'bcrypt') {
          if (costLabel) costLabel.innerText = 'Bcrypt Salt Rounds (Cost Factor 2^N):';
          if (costSliderEl) {
            costSliderEl.min = '8';
            costSliderEl.max = '14';
            costSliderEl.value = '10';
            if (costValDisplay) costValDisplay.innerText = '10';
          }
        } else if (algo === 'pbkdf2') {
          if (costLabel) costLabel.innerText = 'PBKDF2-SHA256 Iterations (x1,000):';
          if (costSliderEl) {
            costSliderEl.min = '10';
            costSliderEl.max = '300';
            costSliderEl.value = '100';
            if (costValDisplay) costValDisplay.innerText = '100';
          }
        } else if (algo === 'scrypt' || algo === 'argon2_sim') {
          if (costLabel) costLabel.innerText = 'Memory Cost Factor (N = 2^N):';
          if (costSliderEl) {
            costSliderEl.min = '10';
            costSliderEl.max = '16';
            costSliderEl.value = '14';
            if (costValDisplay) costValDisplay.innerText = '14 (16,384 memory blocks)';
          }
        }
      });
    }

    // Run initial demo benchmark
    runBenchmark();
  }

  async function runBenchmark() {
    const btn = document.getElementById('benchmark-run-btn');
    const resultsContainer = document.getElementById('benchmark-results-container');
    const algo = document.getElementById('benchmark-algo-select')?.value || 'bcrypt';
    const costRaw = parseInt(document.getElementById('benchmark-cost-slider')?.value || '10', 10);
    const password = document.getElementById('benchmark-password-input')?.value || 'password123';

    let costFactor = costRaw;
    let iterations = 100000;
    if (algo === 'pbkdf2') {
      iterations = costRaw * 1000;
    }

    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<span class="animate-spin inline-block mr-2">⚙</span> Computing Costly Hash...';
    }

    if (resultsContainer) {
      resultsContainer.innerHTML = '<div class="p-4 bg-gray-900 border border-gray-800 rounded-xl text-xs text-cyan-400 font-mono animate-pulse">Executing intensive cryptographic loop...</div>';
    }

    try {
      const response = await fetch('/api/benchmark/slow-hash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          algorithm: algo,
          password,
          costFactor,
          iterations
        })
      });

      const data = await response.json();
      renderBenchmarkResults(data);
    } catch (err) {
      if (resultsContainer) {
        resultsContainer.innerHTML = `<div class="p-4 bg-red-950/60 border border-red-800 rounded-xl text-xs text-red-300">Benchmark error: ${err.message}</div>`;
      }
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerText = '⚡ Run Live KDF Benchmark';
      }
    }
  }

  function renderBenchmarkResults(data) {
    const resultsContainer = document.getElementById('benchmark-results-container');
    if (!resultsContainer) return;

    resultsContainer.innerHTML = `
      <div class="p-5 bg-gray-900 border border-cyan-800/60 rounded-2xl space-y-4">
        <div class="flex flex-wrap items-center justify-between gap-2 border-b border-gray-800 pb-3">
          <div>
            <h4 class="text-sm font-bold text-cyan-400 uppercase tracking-wide">Live KDF Execution Metrics (${data.algorithm.toUpperCase()})</h4>
            <p class="text-xs text-gray-400">${data.costParameter} • ${data.memoryUsage}</p>
          </div>
          <div class="px-3 py-1 rounded bg-cyan-950 border border-cyan-700 text-cyan-300 font-mono text-xs font-bold">
            ${data.durationMs} ms per single hash
          </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-3 text-center">
          <div class="p-3 bg-black/50 rounded-xl border border-gray-800">
            <span class="text-[11px] text-gray-400 block uppercase">Single Core Speed</span>
            <span class="text-xl font-mono font-bold text-yellow-400">${data.singleThreadHashesPerSec} H/s</span>
          </div>
          <div class="p-3 bg-black/50 rounded-xl border border-gray-800">
            <span class="text-[11px] text-gray-400 block uppercase">Estimated GPU Cluster Speed</span>
            <span class="text-xl font-mono font-bold text-purple-400">${data.gpuSecurityAnalysis.estimatedGpuClusterHashrate}</span>
          </div>
          <div class="p-3 bg-black/50 rounded-xl border border-gray-800">
            <span class="text-[11px] text-gray-400 block uppercase">Time to Exhaust 8-Char Space</span>
            <span class="text-xl font-mono font-bold text-emerald-400">${data.gpuSecurityAnalysis.estimatedTimeFor8CharPassword}</span>
          </div>
        </div>

        <div class="p-3 bg-black/70 rounded-lg border border-gray-800">
          <span class="text-[11px] text-gray-500 uppercase tracking-wider block mb-1">Generated Slow Hash Digest</span>
          <div class="font-mono text-xs text-gray-300 break-all select-all">${escapeHtml(data.sampleOutputHash)}</div>
        </div>

        <div class="p-3 bg-gray-950/80 rounded-xl border border-cyan-900/50 space-y-2 text-xs">
          <h5 class="font-bold text-cyan-300 flex items-center gap-1.5">
            🛡️ Why KDFs Defeat GPU Clusters (The Mathematics of Asymmetry):
          </h5>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-2 text-gray-300">
            <div class="p-2.5 bg-red-950/30 border border-red-900/50 rounded">
              <strong class="text-red-400 block">Fast Hashes (MD5 / SHA-256)</strong>
              <p class="text-[11px] text-gray-300 mt-1">
                Optimized for extreme throughput (checksums, git, TLS stream integrity). An 8x RTX 4090 rig computes <strong>150 Billion MD5 / sec</strong>, exhausting an 8-char keyspace in <strong>${data.gpuSecurityAnalysis.md5ComparisonTime}</strong>.
              </p>
            </div>
            <div class="p-2.5 bg-emerald-950/30 border border-emerald-900/50 rounded">
              <strong class="text-emerald-400 block">Slow KDFs (bcrypt / Argon2id)</strong>
              <p class="text-[11px] text-gray-300 mt-1">
                Engineered with tunable CPU/memory hardness. For legitimate users verifying a login, a 100ms delay is imperceptible, but for an adversary attempting billions of guesses, cracking becomes computationally and economically prohibitive (<strong>${data.gpuSecurityAnalysis.estimatedTimeFor8CharPassword}</strong>).
              </p>
            </div>
          </div>
        </div>
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

  return { init, runBenchmark };
})();
