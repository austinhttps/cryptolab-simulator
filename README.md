# 🛡️ CryptoLab — Interactive Cryptography & Hash Cracking Simulator

> A full-stack, browser-driven cybersecurity laboratory demonstrating client-side cryptographic primitives (Web Crypto API `window.crypto.subtle`), multi-threaded Web Worker hash-cracking attacks, authenticated symmetric encryption tampering detection (AES-256-GCM), 2048-bit asymmetric keypairs (RSA-OAEP), and Key Derivation Function (KDF) defense-in-depth benchmarks.

---

## 📸 Architecture & Workflow Diagram

```mermaid
flowchart TD
    subgraph BrowserClient["Browser Client (Main UI Thread - 60 FPS)"]
        UI["Interactive Dashboard (Tailwind CSS Dark Theme)"]
        WCA["Web Crypto API (window.crypto.subtle)"]
        Engine["Crypto Engine (AES-256-GCM, RSA-OAEP-2048, MD5, SHA-1/256/512)"]
        
        UI --> Engine
        Engine --> WCA
    end

    subgraph WebWorkerPool["Multi-Threaded Web Worker Pool"]
        W1["Cracker Worker #1 (Batch Slices)"]
        W2["Cracker Worker #2 (Batch Slices)"]
        W3["Cracker Worker #3 (Batch Slices)"]
        W4["Cracker Worker #N (Batch Slices)"]
        
        UI -- "postMessage(START, Wordlist Chunks)" --> WebWorkerPool
        WebWorkerPool -- "postMessage(PROGRESS / MATCH_FOUND)" --> UI
    end

    subgraph NodeBackend["Node.js & Express Backend"]
        Server["Express Server (Port 3000)"]
        SampleAPI["/api/samples & /api/wordlists"]
        RainbowAPI["/api/rainbow-table/lookup (O(1) Map)"]
        KDFBenchmark["/api/benchmark/slow-hash (bcrypt / scrypt / PBKDF2)"]
        
        Server --> SampleAPI
        Server --> RainbowAPI
        Server --> KDFBenchmark
    end

    UI -- "REST API (Fetch)" --> NodeBackend
```

---

## ⚡ Core Features & Modules

### 🔍 Module A: Hash Inspector & Salt Visualizer
- **Multi-Algorithm Live Stream**: Computes MD5 (RFC 1321), SHA-1 (RFC 3174), SHA-256 (RFC 6234), and SHA-512 (FIPS 180-4) synchronously and via Web Crypto API in real-time as you type.
- **CSPRNG Salting Engine**: Generates 16-byte (128-bit) cryptographically secure random salts with configurable prefix, suffix, and wrapping placement.
- **Rainbow Table Collision Demo**: Queries a precomputed map of 5,000 hashes to demonstrate instant $O(1)$ space-time preimage attacks on unsalted digests, contrasting it against the total immunity provided by unique salts.

### 🔐 Module B: Symmetric vs. Asymmetric Encryption Playground
- **AES-256-GCM (AEAD)**:
  - 256-bit key generation with 96-bit Initialization Vector (IV) and 128-bit Galois Message Authentication Code (GMAC) tag.
  - **Interactive Tamper Station**: Allows manual single-bit corruption in the ciphertext or authentication tag to demonstrate how AES-GCM rejects tampered payloads with a Web Crypto `OperationError`.
- **RSA-OAEP (2048-bit)**:
  - Generates 2048-bit RSA keypairs with standard SPKI/PKCS#8 PEM formatting (`-----BEGIN PUBLIC KEY-----` / `-----BEGIN PRIVATE KEY-----`).
  - Step-by-step Public Key encryption and Private Key decryption with OAEP-SHA256 padding oracle mitigation.

### ⚡ Module C: Multi-Threaded Hash Cracking Simulator (Web Worker Pool)
- **Zero UI Blocking**: Dedicated Web Workers execute heavy dictionary, hybrid rule mutations (years, leetspeak `@/3/1/0/$`, suffixes), and mask brute-force attacks (`?d?d?d?d`, `?l?l?l?d`) without dropping frames on the main 60 FPS thread.
- **Dynamic Parallelism**: Automatic hardware concurrency detection with configurable worker thread counts (1 to $N$ cores).
- **Live Telemetry HUD**: Real-time hashrate meter (H/s, kH/s, MH/s), candidate string stream, batch progress bar, elapsed timer with millisecond precision, and collision detection alerts.

### 🛡️ Module D: Slow Hashes & Key Derivation Functions (KDFs)
- **Live KDF Benchmarking**: Real-time server-side and client-side benchmarks of bcrypt (cost factors $2^8$ to $2^{14}$), PBKDF2-SHA256 (10k to 300k iterations), and memory-hard scrypt/Argon2.
- **GPU Cluster Defense Calculator**: Mathematical comparison showing why an 8-GPU RTX 4090 cluster computing 150 Billion MD5 hashes/sec cracks an 8-character password in **0.0015 seconds**, while bcrypt/Argon2 requires **years**, defeating offline brute-force attacks.

### 🧪 Module E: Test Suite & Standards Verification
- In-browser and command-line test suites asserting RFC 1321 (MD5), RFC 6234 (SHA-256/SHA-512), AES-GCM roundtrip, AEAD tamper rejection, RSA keypair generation, and Web Worker cracking.

---

## 📊 Comparison Tables

### 1. Symmetric vs. Asymmetric Encryption

| Feature | Symmetric (AES-256-GCM) | Asymmetric (RSA-2048-OAEP) |
| :--- | :--- | :--- |
| **Key Architecture** | 1 Shared Secret Key (Encrypt & Decrypt) | Keypair: Public (Encrypt) + Private (Decrypt) |
| **Throughput Speed** | **Extremely Fast** (GB/s with AES-NI hardware) | **Slow** (KB/s due to modular exponentiation) |
| **Key Distribution** | Difficult (Requires pre-shared secure channel) | Simple (Public key distributed over open internet) |
| **Max Payload Size** | Arbitrary streaming length (up to 64 GB per IV) | Limited by modulus: $\le 190$ bytes (2048-bit with SHA-256) |
| **Integrity Assurance** | Built-in 128-bit GMAC Authentication Tag (AEAD) | Requires Digital Signature (RSA-PSS / ECDSA) |
| **Production Use Case** | Bulk storage, database encryption, TLS record layer | TLS handshake key exchange, SSH auth, PGP email |

### 2. Fast Hashes vs. Adaptive Key Derivation Functions (KDFs)

| Metric / Dimension | Fast Hashes (MD5, SHA-256) | Password KDFs (bcrypt, Argon2id, scrypt) |
| :--- | :--- | :--- |
| **Design Objective** | Rapid file checksums, Git commits, block validation | Compute-heavy & memory-hard password verification |
| **Attacker Hashrate (8x RTX 4090)** | $\sim 150,000,000,000$ Hashes/sec (150 GH/s) | $\sim 8,000$ to $80,000$ Hashes/sec (Memory-choked) |
| **8-Char Brute Force Time** | **$\approx 0.0015$ Seconds** | **$\approx 4.2$ to $300+$ Years** |
| **Salt Handling** | Manual concatenation (risk of developer error) | Automatically structured into modular output string |
| **Password Storage Verdict** | 🚨 **Vulnerable / Dangerous** | 🛡️ **Industry Standard (NIST / OWASP recommended)** |

---

## 🚀 Quickstart Guide

### Prerequisites
- Node.js $\ge 18.0.0$
- npm $\ge 9.0.0$

### 1. Installation
```bash
git clone https://github.com/austinhttps/cryptolab-simulator.git
cd cryptolab-simulator
npm install
```

### 2. Run Automated Test Verification
```bash
npm test
```

### 3. Launch the Application
```bash
npm start
```
Open your browser and navigate to:
```
http://localhost:3000
```

---

## 💼 Resume-Ready Project Highlights

Use these bullet points for your software engineering / cybersecurity resume:

- **High-Performance Web Crypto API Engineering**: Architected client-side cryptographic laboratory implementing `window.crypto.subtle` for AES-256-GCM AEAD encryption, 2048-bit RSA-OAEP keypair generation, and SHA-256/512 digest verification with zero external runtime dependencies.
- **Multi-Threaded Web Worker Distributed Cracking**: Engineered a parallel hash-cracking simulator utilizing dedicated Web Workers with automated keyspace chunking, delivering 100k+ H/s background throughput while maintaining 60 FPS responsiveness on the main UI thread.
- **Cryptographic Integrity & Tamper Testing**: Designed an interactive AEAD verification station proving Galois Message Authentication Code (GMAC) integrity rejection via bit-level ciphertext and authentication tag corruptions.
- **Defensive Engineering & KDF Benchmarking**: Developed backend microservices and interactive calculators comparing GPU brute-force feasibility between fast general-purpose hashes (MD5/SHA-256) and adaptive memory-hard KDFs (bcrypt, PBKDF2, scrypt).

---

## 📂 Project Structure

```
.
├── package.json
├── server.js                          # Express API & static server
├── data/
│   ├── generate-data.js              # Wordlist & rainbow table generator
│   ├── wordlist-1000.json            # Curated 1,000 common passwords
│   ├── wordlist-5000.json            # Curated 5,000 common passwords
│   ├── wordlist-10000.json           # Curated 10,000 common passwords
│   └── rainbow-table-sample.json     # 5,000 pre-indexed hash lookup map
├── samples/
│   ├── target-hashes.json            # Preset sample hashes (cracked vs uncracked)
│   └── vectors-test.json             # RFC 6234 and RFC 1321 test vectors
├── tests/
│   └── run-tests.js                  # Automated verification test suite
├── public/
│   ├── index.html                    # Dark cybersecurity dashboard UI
│   ├── css/
│   │   └── styles.css                # Cyber glassmorphism styling
│   ├── js/
│   │   ├── crypto-engine.js          # WebCrypto API + pure JS MD5 & SHA-256
│   │   ├── app.js                    # Main coordinator & tab manager
│   │   └── modules/
│   │       ├── hash-inspector.js      # Module A: Live hashing & salt visualizer
│   │       ├── encryption-playground.js# Module B: AES-GCM & RSA-OAEP playground
│   │       ├── cracking-simulator.js  # Module C: Multi-threaded Web Worker HUD
│   │       ├── slow-hash-benchmark.js # Module D: KDF benchmark & GPU calculator
│   │       └── test-suite-ui.js       # Module E: In-browser test runner
│   └── workers/
│       └── cracker.worker.js         # Dedicated Web Worker cracking engine
└── README.md
```

---

## 📜 License
MIT License. Built for educational and cybersecurity training purposes.
