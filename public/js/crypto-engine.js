/**
 * CryptoLab - Core Cryptographic Engine
 * Uses browser Web Crypto API (window.crypto.subtle) & RFC-compliant JS primitives
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.CryptoEngine = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ==========================================
  // 1. Pure JS MD5 Implementation (RFC 1321)
  // ==========================================
  function md5(str) {
    function safeAdd(x, y) {
      const lsw = (x & 0xffff) + (y & 0xffff);
      const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
      return (msw << 16) | (lsw & 0xffff);
    }
    function bitRol(num, cnt) {
      return (num << cnt) | (num >>> (32 - cnt));
    }
    function md5cmn(q, a, b, x, s, t) {
      return safeAdd(bitRol(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b);
    }
    function md5ff(a, b, c, d, x, s, t) {
      return md5cmn((b & c) | (~b & d), a, b, x, s, t);
    }
    function md5gg(a, b, c, d, x, s, t) {
      return md5cmn((b & d) | (c & ~d), a, b, x, s, t);
    }
    function md5hh(a, b, c, d, x, s, t) {
      return md5cmn(b ^ c ^ d, a, b, x, s, t);
    }
    function md5ii(a, b, c, d, x, s, t) {
      return md5cmn(c ^ (b | ~d), a, b, x, s, t);
    }

    function binlMD5(x, len) {
      x[len >> 5] |= 0x80 << (len % 32);
      x[(((len + 64) >>> 9) << 4) + 14] = len;

      let a = 1732584193;
      let b = -271733879;
      let c = -1732584194;
      let d = 271733878;

      for (let i = 0; i < x.length; i += 16) {
        const olda = a;
        const oldb = b;
        const oldc = c;
        const oldd = d;

        a = md5ff(a, b, c, d, x[i], 7, -680876936);
        d = md5ff(d, a, b, c, x[i + 1], 12, -389564586);
        c = md5ff(c, d, a, b, x[i + 2], 17, 606105819);
        b = md5ff(b, c, d, a, x[i + 3], 22, -1044525330);
        a = md5ff(a, b, c, d, x[i + 4], 7, -176418897);
        d = md5ff(d, a, b, c, x[i + 5], 12, 1200080426);
        c = md5ff(c, d, a, b, x[i + 6], 17, -1473231341);
        b = md5ff(b, c, d, a, x[i + 7], 22, -45705983);
        a = md5ff(a, b, c, d, x[i + 8], 7, 1770035416);
        d = md5ff(d, a, b, c, x[i + 9], 12, -1958414417);
        c = md5ff(c, d, a, b, x[i + 10], 17, -42063);
        b = md5ff(b, c, d, a, x[i + 11], 22, -1990404162);
        a = md5ff(a, b, c, d, x[i + 12], 7, 1804603682);
        d = md5ff(d, a, b, c, x[i + 13], 12, -40341101);
        c = md5ff(c, d, a, b, x[i + 14], 17, -1502002290);
        b = md5ff(b, c, d, a, x[i + 15], 22, 1236535329);

        a = md5gg(a, b, c, d, x[i + 1], 5, -165796510);
        d = md5gg(d, a, b, c, x[i + 6], 9, -1069501632);
        c = md5gg(c, d, a, b, x[i + 11], 14, 643717713);
        b = md5gg(b, c, d, a, x[i], 20, -373897302);
        a = md5gg(a, b, c, d, x[i + 5], 5, -701558691);
        d = md5gg(d, a, b, c, x[i + 10], 9, 38016083);
        c = md5gg(c, d, a, b, x[i + 15], 14, -660478335);
        b = md5gg(b, c, d, a, x[i + 4], 20, -405537848);
        a = md5gg(a, b, c, d, x[i + 9], 5, 568446438);
        d = md5gg(d, a, b, c, x[i + 14], 9, -1019803690);
        c = md5gg(c, d, a, b, x[i + 3], 14, -187363961);
        b = md5gg(b, c, d, a, x[i + 8], 20, 1163531501);
        a = md5gg(a, b, c, d, x[i + 13], 5, -1444681467);
        d = md5gg(d, a, b, c, x[i + 2], 9, -51403784);
        c = md5gg(c, d, a, b, x[i + 7], 14, 1735328473);
        b = md5gg(b, c, d, a, x[i + 12], 20, -1926607734);

        a = md5hh(a, b, c, d, x[i + 5], 4, -378558);
        d = md5hh(d, a, b, c, x[i + 8], 11, -2022574463);
        c = md5hh(c, d, a, b, x[i + 11], 16, 1839030562);
        b = md5hh(b, c, d, a, x[i + 14], 23, -35309556);
        a = md5hh(a, b, c, d, x[i + 1], 4, -1530992060);
        d = md5hh(d, a, b, c, x[i + 4], 11, 1272893353);
        c = md5hh(c, d, a, b, x[i + 7], 16, -155497632);
        b = md5hh(b, c, d, a, x[i + 10], 23, -1094730640);
        a = md5hh(a, b, c, d, x[i + 13], 4, 681279174);
        d = md5hh(d, a, b, c, x[i], 11, -358537222);
        c = md5hh(c, d, a, b, x[i + 3], 16, -722521979);
        b = md5hh(b, c, d, a, x[i + 6], 23, 76029189);
        a = md5hh(a, b, c, d, x[i + 9], 4, -640364487);
        d = md5hh(d, a, b, c, x[i + 12], 11, -421815835);
        c = md5hh(c, d, a, b, x[i + 15], 16, 530742520);
        b = md5hh(b, c, d, a, x[i + 2], 23, -995338651);

        a = md5ii(a, b, c, d, x[i], 6, -198630844);
        d = md5ii(d, a, b, c, x[i + 7], 10, 1126891415);
        c = md5ii(c, d, a, b, x[i + 14], 15, -1416354905);
        b = md5ii(b, c, d, a, x[i + 5], 21, -57434055);
        a = md5ii(a, b, c, d, x[i + 12], 6, 1700485571);
        d = md5ii(d, a, b, c, x[i + 3], 10, -1894986606);
        c = md5ii(c, d, a, b, x[i + 10], 15, -1051523);
        b = md5ii(b, c, d, a, x[i + 1], 21, -2054922799);
        a = md5ii(a, b, c, d, x[i + 8], 6, 1873313359);
        d = md5ii(d, a, b, c, x[i + 15], 10, -30611744);
        c = md5ii(c, d, a, b, x[i + 6], 15, -1560198380);
        b = md5ii(b, c, d, a, x[i + 13], 21, 1309151649);
        a = md5ii(a, b, c, d, x[i + 4], 6, -145523070);
        d = md5ii(d, a, b, c, x[i + 11], 10, -1120210379);
        c = md5ii(c, d, a, b, x[i + 2], 15, 718787259);
        b = md5ii(b, c, d, a, x[i + 9], 21, -343485551);

        a = safeAdd(a, olda);
        b = safeAdd(b, oldb);
        c = safeAdd(c, oldc);
        d = safeAdd(d, oldd);
      }
      return [a, b, c, d];
    }

    function str2rstrUTF8(input) {
      return unescape(encodeURIComponent(input));
    }

    function rstr2binl(input) {
      const output = [];
      for (let i = 0; i < input.length * 8; i += 8) {
        output[i >> 5] |= (input.charCodeAt(i / 8) & 0xff) << (i % 32);
      }
      return output;
    }

    function binl2rstr(input) {
      let output = '';
      for (let i = 0; i < input.length * 32; i += 8) {
        output += String.fromCharCode((input[i >> 5] >>> (i % 32)) & 0xff);
      }
      return output;
    }

    function rstr2hex(input) {
      const hexTab = '0123456789abcdef';
      let output = '';
      for (let i = 0; i < input.length; i++) {
        const x = input.charCodeAt(i);
        output += hexTab.charAt((x >>> 4) & 0x0f) + hexTab.charAt(x & 0x0f);
      }
      return output;
    }

    const utf8 = str2rstrUTF8(str);
    return rstr2hex(binl2rstr(binlMD5(rstr2binl(utf8), utf8.length * 8)));
  }

  // ==========================================
  // Standard-Compliant SHA-256 (RFC 6234)
  // ==========================================
  const K256 = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  function sha256Sync(ascii) {
    function rotr(n, x) {
      return (x >>> n) | (x << (32 - n));
    }
    function sigma0(x) {
      return rotr(2, x) ^ rotr(13, x) ^ rotr(22, x);
    }
    function sigma1(x) {
      return rotr(6, x) ^ rotr(11, x) ^ rotr(25, x);
    }
    function gamma0(x) {
      return rotr(7, x) ^ rotr(18, x) ^ (x >>> 3);
    }
    function gamma1(x) {
      return rotr(17, x) ^ rotr(19, x) ^ (x >>> 10);
    }
    function ch(x, y, z) {
      return (x & y) ^ (~x & z);
    }
    function maj(x, y, z) {
      return (x & y) ^ (x & z) ^ (y & z);
    }

    const utf8 = unescape(encodeURIComponent(ascii));
    const msgLen = utf8.length;
    const words = [];

    for (let i = 0; i < msgLen; i++) {
      words[i >>> 2] |= (utf8.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
    }

    // Padding
    words[msgLen >>> 2] |= 0x80 << (24 - (msgLen % 4) * 8);
    const bitLen = msgLen * 8;
    const wordCount = (((msgLen + 8) >>> 6) + 1) << 4;
    words[wordCount - 1] = bitLen & 0xffffffff;
    words[wordCount - 2] = Math.floor(bitLen / 0x100000000);

    let H0 = 0x6a09e667;
    let H1 = 0xbb67ae85;
    let H2 = 0x3c6ef372;
    let H3 = 0xa54ff53a;
    let H4 = 0x510e527f;
    let H5 = 0x9b05688c;
    let H6 = 0x1f83d9ab;
    let H7 = 0x5be0cd19;

    const W = new Uint32Array(64);

    for (let i = 0; i < wordCount; i += 16) {
      for (let t = 0; t < 16; t++) {
        W[t] = words[i + t] || 0;
      }
      for (let t = 16; t < 64; t++) {
        W[t] = (gamma1(W[t - 2]) + W[t - 7] + gamma0(W[t - 15]) + W[t - 16]) >>> 0;
      }

      let a = H0;
      let b = H1;
      let c = H2;
      let d = H3;
      let e = H4;
      let f = H5;
      let g = H6;
      let h = H7;

      for (let t = 0; t < 64; t++) {
        const T1 = (h + sigma1(e) + ch(e, f, g) + K256[t] + W[t]) >>> 0;
        const T2 = (sigma0(a) + maj(a, b, c)) >>> 0;
        h = g;
        g = f;
        f = e;
        e = (d + T1) >>> 0;
        d = c;
        c = b;
        b = a;
        a = (T1 + T2) >>> 0;
      }

      H0 = (H0 + a) >>> 0;
      H1 = (H1 + b) >>> 0;
      H2 = (H2 + c) >>> 0;
      H3 = (H3 + d) >>> 0;
      H4 = (H4 + e) >>> 0;
      H5 = (H5 + f) >>> 0;
      H6 = (H6 + g) >>> 0;
      H7 = (H7 + h) >>> 0;
    }

    function toHex(val) {
      return val.toString(16).padStart(8, '0');
    }

    return toHex(H0) + toHex(H1) + toHex(H2) + toHex(H3) + toHex(H4) + toHex(H5) + toHex(H6) + toHex(H7);
  }

  // ==========================================
  // 2. Web Crypto API Helpers
  // ==========================================
  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  function bufferToHex(buffer) {
    const bytes = new Uint8Array(buffer);
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex;
  }

  function hexToBuffer(hexString) {
    const cleanHex = hexString.replace(/[^0-9a-fA-F]/g, '');
    const bytes = new Uint8Array(cleanHex.length / 2);
    for (let i = 0; i < cleanHex.length; i += 2) {
      bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
    }
    return bytes.buffer;
  }

  function bufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function base64ToBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  // SubtleCrypto Hash
  async function computeSubtleHash(algorithm, text) {
    const subtle = (typeof window !== 'undefined' ? window.crypto?.subtle : null) ||
                   (typeof self !== 'undefined' ? self.crypto?.subtle : null);
    
    if (subtle) {
      const data = textEncoder.encode(text);
      const digestBuffer = await subtle.digest(algorithm, data);
      return bufferToHex(digestBuffer);
    }
    
    // Fallback if subtle is unavailable
    if (algorithm === 'SHA-256') return sha256Sync(text);
    if (algorithm === 'MD5') return md5(text);
    throw new Error(`Web Crypto Subtle not available for ${algorithm}`);
  }

  // Live Multi-Digest Computation
  async function digestAll(plaintext, salt = '', saltPosition = 'prefix') {
    let combinedInput = plaintext;
    if (salt) {
      if (saltPosition === 'prefix') combinedInput = salt + plaintext;
      else if (saltPosition === 'suffix') combinedInput = plaintext + salt;
      else if (saltPosition === 'wrap') combinedInput = salt + plaintext + salt;
    }

    const t0 = performance.now();
    const md5Digest = md5(combinedInput);
    const tMd5 = performance.now() - t0;

    const t1 = performance.now();
    const sha1Digest = await computeSubtleHash('SHA-1', combinedInput);
    const tSha1 = performance.now() - t1;

    const t2 = performance.now();
    const sha256Digest = await computeSubtleHash('SHA-256', combinedInput);
    const tSha256 = performance.now() - t2;

    const t3 = performance.now();
    const sha512Digest = await computeSubtleHash('SHA-512', combinedInput);
    const tSha512 = performance.now() - t3;

    return {
      plaintext,
      salt,
      saltPosition,
      effectiveInput: combinedInput,
      results: {
        md5: { name: 'MD5', digest: md5Digest, bitLength: 128, hexLength: 32, durationMs: tMd5, rfc: 'RFC 1321 (Broken)' },
        sha1: { name: 'SHA-1', digest: sha1Digest, bitLength: 160, hexLength: 40, durationMs: tSha1, rfc: 'RFC 3174 (Deprecated)' },
        sha256: { name: 'SHA-256', digest: sha256Digest, bitLength: 256, hexLength: 64, durationMs: tSha256, rfc: 'FIPS 180-4 / RFC 6234' },
        sha512: { name: 'SHA-512', digest: sha512Digest, bitLength: 512, hexLength: 128, durationMs: tSha512, rfc: 'FIPS 180-4 / RFC 6234' }
      }
    };
  }

  // Salt Generator
  function generateSalt(byteLength = 16) {
    const cryptoObj = (typeof window !== 'undefined' ? window.crypto : null) ||
                      (typeof self !== 'undefined' ? self.crypto : null);
    const bytes = new Uint8Array(byteLength);
    if (cryptoObj?.getRandomValues) {
      cryptoObj.getRandomValues(bytes);
    } else {
      for (let i = 0; i < byteLength; i++) bytes[i] = Math.floor(Math.random() * 256);
    }
    return bufferToHex(bytes.buffer);
  }

  // ==========================================
  // 3. Symmetric Encryption: AES-256-GCM (AEAD)
  // ==========================================
  async function generateAesGcmKey() {
    const subtle = window.crypto.subtle;
    const key = await subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
    const exportedRaw = await subtle.exportKey('raw', key);
    return {
      key,
      rawHex: bufferToHex(exportedRaw),
      rawBase64: bufferToBase64(exportedRaw),
      lengthBits: 256
    };
  }

  function generateIv(byteLength = 12) {
    const iv = new Uint8Array(byteLength); // 96-bit standard for GCM
    window.crypto.getRandomValues(iv);
    return {
      ivArray: iv,
      ivHex: bufferToHex(iv.buffer),
      byteLength
    };
  }

  async function encryptAesGcm(key, ivUint8, plaintext, additionalData = null) {
    const subtle = window.crypto.subtle;
    const encodedPlaintext = textEncoder.encode(plaintext);

    const gcmParams = {
      name: 'AES-GCM',
      iv: ivUint8,
      tagLength: 128 // 128-bit authentication tag
    };

    if (additionalData) {
      gcmParams.additionalData = textEncoder.encode(additionalData);
    }

    const encryptedBuffer = await subtle.encrypt(gcmParams, key, encodedPlaintext);
    const encryptedBytes = new Uint8Array(encryptedBuffer);

    const ciphertextBytes = encryptedBytes.slice(0, encryptedBytes.length - 16);
    const tagBytes = encryptedBytes.slice(encryptedBytes.length - 16);

    return {
      fullBuffer: encryptedBuffer,
      fullHex: bufferToHex(encryptedBuffer),
      fullBase64: bufferToBase64(encryptedBuffer),
      ciphertextHex: bufferToHex(ciphertextBytes.buffer),
      ciphertextBase64: bufferToBase64(ciphertextBytes.buffer),
      tagHex: bufferToHex(tagBytes.buffer),
      tagBase64: bufferToBase64(tagBytes.buffer),
      ciphertextBytes,
      tagBytes,
      plaintextLength: encodedPlaintext.length
    };
  }

  async function decryptAesGcm(key, ivUint8, ciphertextBytes, tagBytes, additionalData = null) {
    const subtle = window.crypto.subtle;

    const combinedBytes = new Uint8Array(ciphertextBytes.length + tagBytes.length);
    combinedBytes.set(ciphertextBytes, 0);
    combinedBytes.set(tagBytes, ciphertextBytes.length);

    const gcmParams = {
      name: 'AES-GCM',
      iv: ivUint8,
      tagLength: 128
    };

    if (additionalData) {
      gcmParams.additionalData = textEncoder.encode(additionalData);
    }

    try {
      const decryptedBuffer = await subtle.decrypt(gcmParams, key, combinedBytes);
      const decryptedText = textDecoder.decode(decryptedBuffer);
      return {
        success: true,
        plaintext: decryptedText,
        authenticated: true,
        message: 'Authentication Tag Verified. Ciphertext integrity confirmed.'
      };
    } catch (err) {
      return {
        success: false,
        plaintext: null,
        authenticated: false,
        errorName: err.name,
        errorMessage: 'OperationError: MAC / Authentication Tag Verification Failed! Data was modified in transit or secret key is invalid.'
      };
    }
  }

  function tamperByte(uint8Array, byteIndex, bitPosition = 0) {
    const copy = new Uint8Array(uint8Array);
    if (byteIndex >= 0 && byteIndex < copy.length) {
      copy[byteIndex] ^= (1 << bitPosition);
    }
    return copy;
  }

  // ==========================================
  // 4. Asymmetric Encryption: RSA-OAEP (2048-bit)
  // ==========================================
  async function generateRsaKeyPair(modulusLength = 2048) {
    const subtle = window.crypto.subtle;
    const keyPair = await subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256'
      },
      true,
      ['encrypt', 'decrypt']
    );

    const spkiBuffer = await subtle.exportKey('spki', keyPair.publicKey);
    const spkiBase64 = bufferToBase64(spkiBuffer);
    const publicPem = `-----BEGIN PUBLIC KEY-----\n${spkiBase64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;

    const pkcs8Buffer = await subtle.exportKey('pkcs8', keyPair.privateKey);
    const pkcs8Base64 = bufferToBase64(pkcs8Buffer);
    const privatePem = `-----BEGIN PRIVATE KEY-----\n${pkcs8Base64.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;

    return {
      keyPair,
      publicKeyPem: publicPem,
      privateKeyPem: privatePem,
      modulusLength,
      hashAlgorithm: 'SHA-256'
    };
  }

  async function encryptRsaOaep(publicKey, plaintext) {
    const subtle = window.crypto.subtle;
    const encoded = textEncoder.encode(plaintext);

    if (encoded.length > 190) {
      throw new Error(`Plaintext is ${encoded.length} bytes. Max capacity for 2048-bit RSA-OAEP-SHA256 is 190 bytes.`);
    }

    const encryptedBuffer = await subtle.encrypt(
      { name: 'RSA-OAEP' },
      publicKey,
      encoded
    );

    return {
      ciphertextBuffer: encryptedBuffer,
      ciphertextHex: bufferToHex(encryptedBuffer),
      ciphertextBase64: bufferToBase64(encryptedBuffer),
      byteLength: encryptedBuffer.byteLength
    };
  }

  async function decryptRsaOaep(privateKey, ciphertextBuffer) {
    const subtle = window.crypto.subtle;
    try {
      const decryptedBuffer = await subtle.decrypt(
        { name: 'RSA-OAEP' },
        privateKey,
        ciphertextBuffer
      );
      return {
        success: true,
        plaintext: textDecoder.decode(decryptedBuffer)
      };
    } catch (err) {
      return {
        success: false,
        error: 'RSA Decryption Failed: Padding check error or mismatched private key.'
      };
    }
  }

  return {
    md5,
    sha256Sync,
    computeSubtleHash,
    digestAll,
    generateSalt,
    bufferToHex,
    hexToBuffer,
    bufferToBase64,
    base64ToBuffer,
    generateAesGcmKey,
    generateIv,
    encryptAesGcm,
    decryptAesGcm,
    tamperByte,
    generateRsaKeyPair,
    encryptRsaOaep,
    decryptRsaOaep
  };
});
