const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Curated list of most common realistic passwords and base terms
const baseWords = [
  'password', '123456', '12345678', '1234', 'qwerty', '12345', 'dragon', 'pussy', 'baseball', 'football',
  'letmein', 'master', 'sunshine', 'princess', 'welcome', 'shadow', 'superman', 'trustno1', 'secret', 'admin',
  'login', 'root', 'iloveyou', 'starwars', 'monkey', 'chelsea', 'charlie', 'jordan', 'michael', 'jessica',
  'hunter', 'alex', 'computer', 'system', 'default', 'pass123', 'admin123', 'root123', 'freedom', 'security',
  'cyber', 'crypto', 'hacker', 'matrix', 'access', 'network', 'oracle', 'database', 'qwerty123', 'welcome1',
  'testing', 'guest', 'november', 'december', 'summer', 'winter', 'spring', 'autumn', 'coffee', 'cookie',
  'yellow', 'purple', 'orange', 'silver', 'diamond', 'phoenix', 'galaxy', 'thunder', 'phantom', 'wizard',
  'warrior', 'knight', 'spiderman', 'batman', 'avengers', 'champion', 'blessed', 'genesis', 'infinity', 'matrix123',
  'qwertyuiop', 'asdfghjkl', 'zxcvbnm', 'ilovegod', 'jesus123', 'michelle', 'thomas', 'richard', 'william', 'daniel',
  'anthony', 'donald', 'steven', 'paul123', 'andrew', 'joshua', 'kenneth', 'kevin123', 'brian123', 'george'
];

// Expand to high-frequency password permutations
function generateExpandedWordlist(targetCount) {
  const set = new Set(baseWords);
  const years = ['1998', '1999', '2000', '2001', '2005', '2010', '2015', '2020', '2021', '2022', '2023', '2024', '2025', '2026', '99', '00', '01', '123', '1234', '!', '#', '$', '0', '1', '2', '3'];
  const prefixes = ['my', 'the', 'super', 'mega', 'ultra', 'cool', 'big', 'dark', 'cyber', 'i_love_', 'iam_'];

  // Numeric patterns
  for (let i = 0; i <= 9999; i++) {
    if (set.size >= targetCount) break;
    set.add(String(i).padStart(4, '0'));
    set.add(String(i).padStart(6, '0'));
  }

  // Base + Suffix
  for (const w of baseWords) {
    for (const y of years) {
      if (set.size >= targetCount) break;
      set.add(w + y);
      set.add(w.charAt(0).toUpperCase() + w.slice(1) + y);
      set.add(w.toUpperCase() + y);
    }
  }

  // Prefix + Base
  for (const p of prefixes) {
    for (const w of baseWords) {
      if (set.size >= targetCount) break;
      set.add(p + w);
      set.add(p + w + '123');
    }
  }

  // Leetspeak & compound variations
  const leetMap = { a: '@', e: '3', i: '1', o: '0', s: '$', t: '7' };
  for (const w of baseWords) {
    if (set.size >= targetCount) break;
    let leet = w;
    for (const [k, v] of Object.entries(leetMap)) {
      leet = leet.split(k).join(v);
    }
    set.add(leet);
    set.add(leet + '123');
    set.add(leet + '!');
  }

  // Additional word list fill
  let counter = 1;
  while (set.size < targetCount) {
    set.add(`user_pass_${counter}`);
    set.add(`secure_key_${counter}`);
    set.add(`test_node_${counter}`);
    set.add(`cryptolab_${counter}`);
    counter++;
  }

  return Array.from(set).slice(0, targetCount);
}

const list1k = generateExpandedWordlist(1000);
const list5k = generateExpandedWordlist(5000);
const list10k = generateExpandedWordlist(10000);

// Ensure data directory exists
const dataDir = path.join(__dirname, '..', 'data');
const samplesDir = path.join(__dirname, '..', 'samples');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
if (!fs.existsSync(samplesDir)) fs.mkdirSync(samplesDir, { recursive: true });

fs.writeFileSync(path.join(dataDir, 'wordlist-1000.json'), JSON.stringify(list1k, null, 2));
fs.writeFileSync(path.join(dataDir, 'wordlist-5000.json'), JSON.stringify(list5k, null, 2));
fs.writeFileSync(path.join(dataDir, 'wordlist-10000.json'), JSON.stringify(list10k, null, 2));

console.log(`Generated wordlists: 1k, 5k, 10k items.`);

// Generate Rainbow Table Sample Index (5,000 entries with MD5, SHA-1, SHA-256)
const rainbowTable = {
  metadata: {
    generatedAt: new Date().toISOString(),
    totalEntries: list5k.length,
    description: 'Pre-indexed hash lookup map simulating a rainbow table lookup attack for unsalted hashes.'
  },
  md5: {},
  sha1: {},
  sha256: {}
};

for (const word of list5k) {
  const md5Hash = crypto.createHash('md5').update(word).digest('hex');
  const sha1Hash = crypto.createHash('sha1').update(word).digest('hex');
  const sha256Hash = crypto.createHash('sha256').update(word).digest('hex');

  rainbowTable.md5[md5Hash] = word;
  rainbowTable.sha1[sha1Hash] = word;
  rainbowTable.sha256[sha256Hash] = word;
}

fs.writeFileSync(path.join(dataDir, 'rainbow-table-sample.json'), JSON.stringify(rainbowTable, null, 2));
console.log(`Generated Rainbow Table sample with ${list5k.length} indexed hashes.`);

// Generate Sample Target Hashes for the UI quick-load buttons
const sampleTargets = [
  {
    id: 'sample-md5-easy',
    title: 'Easy MD5 (Common Password)',
    plaintext: 'password',
    algorithm: 'MD5',
    hash: crypto.createHash('md5').update('password').digest('hex'),
    difficulty: 'Instant (Top 10)',
    description: 'Classic high-frequency unsalted MD5 digest found in almost all wordlists.',
    salted: false
  },
  {
    id: 'sample-md5-medium',
    title: 'Medium MD5 (Dictionary + Number)',
    plaintext: 'shadow2024',
    algorithm: 'MD5',
    hash: crypto.createHash('md5').update('shadow2024').digest('hex'),
    difficulty: 'Fast (1k-5k words / Hybrid)',
    description: 'Compound word with year suffix, cracked via hybrid dictionary attack.',
    salted: false
  },
  {
    id: 'sample-sha256-easy',
    title: 'Easy SHA-256 (System Admin)',
    plaintext: 'admin123',
    algorithm: 'SHA-256',
    hash: crypto.createHash('sha256').update('admin123').digest('hex'),
    difficulty: 'Instant (Top 50)',
    description: 'Unsalted SHA-256 hash representing a common default corporate credential.',
    salted: false
  },
  {
    id: 'sample-sha256-medium',
    title: 'Medium SHA-256 (Cyber Theme)',
    plaintext: 'cryptolab_42',
    algorithm: 'SHA-256',
    hash: crypto.createHash('sha256').update('cryptolab_42').digest('hex'),
    difficulty: 'Medium (10k wordlist)',
    description: 'Simulated custom application password in the extended 10k corpus.',
    salted: false
  },
  {
    id: 'sample-sha256-hard',
    title: 'Hard / Uncrackable (High-Entropy Salted)',
    plaintext: 'Unknown [Random 128-bit key]',
    algorithm: 'SHA-256',
    hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', // SHA256 of empty/secure token
    difficulty: 'Exhaustion (Simulated Uncrackable)',
    description: 'Demonstrates search space exhaustion when targeted digest is not in the dictionary.',
    salted: true
  },
  {
    id: 'sample-md5-leetspeak',
    title: 'Leetspeak MD5 (p@ssw0rd!)',
    plaintext: 'p@ssw0rd!',
    algorithm: 'MD5',
    hash: crypto.createHash('md5').update('p@ssw0rd!').digest('hex'),
    difficulty: 'Rule / Mask Based',
    description: 'Shows effectiveness of rule-based mutations against naive character substitutions.',
    salted: false
  }
];

fs.writeFileSync(path.join(samplesDir, 'target-hashes.json'), JSON.stringify(sampleTargets, null, 2));

// Test vectors for verification assertions (RFC standards)
const testVectors = {
  sha256: [
    {
      input: "",
      expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      description: "Empty string SHA-256 RFC 6234 vector"
    },
    {
      input: "abc",
      expected: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      description: "RFC 6234 standard test vector 'abc'"
    },
    {
      input: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      expected: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
      description: "RFC 6234 multi-block SHA-256 vector"
    }
  ],
  md5: [
    {
      input: "",
      expected: "d41d8cd98f00b204e9800998ecf8427e",
      description: "RFC 1321 empty string MD5"
    },
    {
      input: "a",
      expected: "0cc175b9c0f1b6a831c399e269772661",
      description: "RFC 1321 single char 'a'"
    },
    {
      input: "message digest",
      expected: "f96b697d7cb7938d525a2f31aaf161d0",
      description: "RFC 1321 'message digest'"
    }
  ],
  sha512: [
    {
      input: "abc",
      expected: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
      description: "RFC 6234 SHA-512 'abc'"
    }
  ]
};

fs.writeFileSync(path.join(samplesDir, 'vectors-test.json'), JSON.stringify(testVectors, null, 2));
console.log('Sample files generated successfully.');
