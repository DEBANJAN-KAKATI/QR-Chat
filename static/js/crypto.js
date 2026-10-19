/**
 * End-to-End Cryptography Engine for CipherDrop
 *
 * Pure-JavaScript so it works everywhere: phones that open the room over a plain
 * http://192.168.x.x LAN address are NOT a "secure context", so window.crypto.subtle
 * is undefined there. Both peers therefore use this same implementation.
 *
 *   Key derivation : HKDF-SHA256(room token + PIN, salt = room id)
 *   Cipher         : ChaCha20 (RFC 8439) + HMAC-SHA256 (encrypt-then-MAC)
 *   Randomness     : crypto.getRandomValues (available in every context)
 */
(function () {
    'use strict';

    // ---------------------------------------------------------------- SHA-256
    const K = new Uint32Array([
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]);

    class Sha256 {
        constructor() {
            this.h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
            this.w = new Uint32Array(64);
            this.buf = new Uint8Array(64);
            this.bufLen = 0;
            this.total = 0;
        }

        _block(d, off) {
            const w = this.w, h = this.h;
            for (let i = 0; i < 16; i++) {
                const j = off + i * 4;
                w[i] = (d[j] << 24) | (d[j + 1] << 16) | (d[j + 2] << 8) | d[j + 3];
            }
            for (let i = 16; i < 64; i++) {
                const a = w[i - 15], b = w[i - 2];
                const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
                const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
                w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
            }
            let A = h[0], B = h[1], C = h[2], D = h[3], E = h[4], F = h[5], G = h[6], H = h[7];
            for (let i = 0; i < 64; i++) {
                const S1 = ((E >>> 6) | (E << 26)) ^ ((E >>> 11) | (E << 21)) ^ ((E >>> 25) | (E << 7));
                const t1 = (H + S1 + ((E & F) ^ (~E & G)) + K[i] + w[i]) | 0;
                const S0 = ((A >>> 2) | (A << 30)) ^ ((A >>> 13) | (A << 19)) ^ ((A >>> 22) | (A << 10));
                const t2 = (S0 + ((A & B) ^ (A & C) ^ (B & C))) | 0;
                H = G; G = F; F = E; E = (D + t1) | 0;
                D = C; C = B; B = A; A = (t1 + t2) | 0;
            }
            h[0] += A; h[1] += B; h[2] += C; h[3] += D;
            h[4] += E; h[5] += F; h[6] += G; h[7] += H;
        }

        update(data) {
            let i = 0;
            const n = data.length;
            this.total += n;
            if (this.bufLen > 0) {
                while (i < n && this.bufLen < 64) this.buf[this.bufLen++] = data[i++];
                if (this.bufLen === 64) { this._block(this.buf, 0); this.bufLen = 0; }
            }
            for (; i + 64 <= n; i += 64) this._block(data, i);
            while (i < n) this.buf[this.bufLen++] = data[i++];
            return this;
        }

        digest() {
            const bits = this.total * 8;
            const pad = new Uint8Array(((this.bufLen < 56) ? 56 : 120) - this.bufLen + 8);
            pad[0] = 0x80;
            const hi = Math.floor(bits / 0x100000000), lo = bits >>> 0;
            const p = pad.length;
            pad[p - 8] = hi >>> 24; pad[p - 7] = hi >>> 16; pad[p - 6] = hi >>> 8; pad[p - 5] = hi;
            pad[p - 4] = lo >>> 24; pad[p - 3] = lo >>> 16; pad[p - 2] = lo >>> 8; pad[p - 1] = lo;
            this.total -= pad.length; // padding is not message data
            this.update(pad);
            const out = new Uint8Array(32);
            for (let i = 0; i < 8; i++) {
                out[i * 4] = this.h[i] >>> 24; out[i * 4 + 1] = this.h[i] >>> 16;
                out[i * 4 + 2] = this.h[i] >>> 8; out[i * 4 + 3] = this.h[i];
            }
            return out;
        }
    }

    function sha256(data) { return new Sha256().update(data).digest(); }

    // ---------------------------------------------------------------- HMAC / HKDF
    function hmacSha256(key, ...parts) {
        if (key.length > 64) key = sha256(key);
        const ipad = new Uint8Array(64), opad = new Uint8Array(64);
        for (let i = 0; i < 64; i++) {
            const k = key[i] || 0;
            ipad[i] = k ^ 0x36; opad[i] = k ^ 0x5c;
        }
        const inner = new Sha256().update(ipad);
        for (const p of parts) inner.update(p);
        return new Sha256().update(opad).update(inner.digest()).digest();
    }

    function hkdf(ikm, salt, info, length) {
        const prk = hmacSha256(salt, ikm);
        const out = new Uint8Array(length);
        let prev = new Uint8Array(0), pos = 0;
        for (let i = 1; pos < length; i++) {
            prev = hmacSha256(prk, prev, info, new Uint8Array([i]));
            out.set(prev.subarray(0, Math.min(32, length - pos)), pos);
            pos += 32;
        }
        return out;
    }

    // ---------------------------------------------------------------- ChaCha20 (RFC 8439)
    function chacha20Xor(key, nonce, counter, input) {
        const s = new Uint32Array(16), x = new Uint32Array(16);
        const ks = new Uint8Array(x.buffer);
        const kv = new DataView(key.buffer, key.byteOffset, 32);
        const nv = new DataView(nonce.buffer, nonce.byteOffset, 12);
        s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
        for (let i = 0; i < 8; i++) s[4 + i] = kv.getUint32(i * 4, true);
        s[12] = counter;
        for (let i = 0; i < 3; i++) s[13 + i] = nv.getUint32(i * 4, true);

        const out = new Uint8Array(input.length);
        for (let pos = 0; pos < input.length; pos += 64) {
            let x0 = s[0], x1 = s[1], x2 = s[2], x3 = s[3], x4 = s[4], x5 = s[5], x6 = s[6], x7 = s[7],
                x8 = s[8], x9 = s[9], x10 = s[10], x11 = s[11], x12 = s[12], x13 = s[13], x14 = s[14], x15 = s[15];
            for (let r = 0; r < 10; r++) {
                x0 = (x0 + x4) | 0; x12 ^= x0; x12 = (x12 << 16) | (x12 >>> 16);
                x8 = (x8 + x12) | 0; x4 ^= x8; x4 = (x4 << 12) | (x4 >>> 20);
                x0 = (x0 + x4) | 0; x12 ^= x0; x12 = (x12 << 8) | (x12 >>> 24);
                x8 = (x8 + x12) | 0; x4 ^= x8; x4 = (x4 << 7) | (x4 >>> 25);
                x1 = (x1 + x5) | 0; x13 ^= x1; x13 = (x13 << 16) | (x13 >>> 16);
                x9 = (x9 + x13) | 0; x5 ^= x9; x5 = (x5 << 12) | (x5 >>> 20);
                x1 = (x1 + x5) | 0; x13 ^= x1; x13 = (x13 << 8) | (x13 >>> 24);
                x9 = (x9 + x13) | 0; x5 ^= x9; x5 = (x5 << 7) | (x5 >>> 25);
                x2 = (x2 + x6) | 0; x14 ^= x2; x14 = (x14 << 16) | (x14 >>> 16);
                x10 = (x10 + x14) | 0; x6 ^= x10; x6 = (x6 << 12) | (x6 >>> 20);
                x2 = (x2 + x6) | 0; x14 ^= x2; x14 = (x14 << 8) | (x14 >>> 24);
                x10 = (x10 + x14) | 0; x6 ^= x10; x6 = (x6 << 7) | (x6 >>> 25);
                x3 = (x3 + x7) | 0; x15 ^= x3; x15 = (x15 << 16) | (x15 >>> 16);
                x11 = (x11 + x15) | 0; x7 ^= x11; x7 = (x7 << 12) | (x7 >>> 20);
                x3 = (x3 + x7) | 0; x15 ^= x3; x15 = (x15 << 8) | (x15 >>> 24);
                x11 = (x11 + x15) | 0; x7 ^= x11; x7 = (x7 << 7) | (x7 >>> 25);
                x0 = (x0 + x5) | 0; x15 ^= x0; x15 = (x15 << 16) | (x15 >>> 16);
                x10 = (x10 + x15) | 0; x5 ^= x10; x5 = (x5 << 12) | (x5 >>> 20);
                x0 = (x0 + x5) | 0; x15 ^= x0; x15 = (x15 << 8) | (x15 >>> 24);
                x10 = (x10 + x15) | 0; x5 ^= x10; x5 = (x5 << 7) | (x5 >>> 25);
                x1 = (x1 + x6) | 0; x12 ^= x1; x12 = (x12 << 16) | (x12 >>> 16);
                x11 = (x11 + x12) | 0; x6 ^= x11; x6 = (x6 << 12) | (x6 >>> 20);
                x1 = (x1 + x6) | 0; x12 ^= x1; x12 = (x12 << 8) | (x12 >>> 24);
                x11 = (x11 + x12) | 0; x6 ^= x11; x6 = (x6 << 7) | (x6 >>> 25);
                x2 = (x2 + x7) | 0; x13 ^= x2; x13 = (x13 << 16) | (x13 >>> 16);
                x8 = (x8 + x13) | 0; x7 ^= x8; x7 = (x7 << 12) | (x7 >>> 20);
                x2 = (x2 + x7) | 0; x13 ^= x2; x13 = (x13 << 8) | (x13 >>> 24);
                x8 = (x8 + x13) | 0; x7 ^= x8; x7 = (x7 << 7) | (x7 >>> 25);
                x3 = (x3 + x4) | 0; x14 ^= x3; x14 = (x14 << 16) | (x14 >>> 16);
                x9 = (x9 + x14) | 0; x4 ^= x9; x4 = (x4 << 12) | (x4 >>> 20);
                x3 = (x3 + x4) | 0; x14 ^= x3; x14 = (x14 << 8) | (x14 >>> 24);
                x9 = (x9 + x14) | 0; x4 ^= x9; x4 = (x4 << 7) | (x4 >>> 25);
            }
            x[0] = x0 + s[0]; x[1] = x1 + s[1]; x[2] = x2 + s[2]; x[3] = x3 + s[3];
            x[4] = x4 + s[4]; x[5] = x5 + s[5]; x[6] = x6 + s[6]; x[7] = x7 + s[7];
            x[8] = x8 + s[8]; x[9] = x9 + s[9]; x[10] = x10 + s[10]; x[11] = x11 + s[11];
            x[12] = x12 + s[12]; x[13] = x13 + s[13]; x[14] = x14 + s[14]; x[15] = x15 + s[15];
            const n = Math.min(64, input.length - pos);
            for (let i = 0; i < n; i++) out[pos + i] = input[pos + i] ^ ks[i];
            s[12]++;
        }
        return out;
    }

    // ---------------------------------------------------------------- helpers
    const te = new TextEncoder(), td = new TextDecoder();

    function concat(...arrs) {
        let len = 0;
        for (const a of arrs) len += a.length;
        const out = new Uint8Array(len);
        let o = 0;
        for (const a of arrs) { out.set(a, o); o += a.length; }
        return out;
    }

    function constTimeEqual(a, b) {
        if (a.length !== b.length) return false;
        let d = 0;
        for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
        return d === 0;
    }

    function bytesToB64(bytes) {
        let bin = '';
        for (let i = 0; i < bytes.length; i += 0x8000) {
            bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
        }
        return btoa(bin);
    }

    function b64ToBytes(b64) {
        const bin = atob(b64);
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    }

    const TAG_LEN = 16;

    class CipherEngine {
        constructor() { this.wipe(); }

        get ready() { return !!this.encKey; }

        /** Derives the shared room keys. Both peers get identical keys from the QR link (+ PIN). */
        deriveRoomKey(roomId, roomToken, secretPin = '') {
            const ikm = te.encode(`${roomToken}:${(secretPin || '').trim()}`);
            const okm = hkdf(ikm, te.encode(`CipherDrop-v2:${roomId}`), te.encode('room-keys'), 96);
            this.encKey = okm.slice(0, 32);
            this.macKey = okm.slice(32, 64);
            const fp = sha256(okm.subarray(64, 96));
            okm.fill(0);
            this._fingerprintDisplay(fp);
        }

        _fingerprintDisplay(bytes) {
            const hex = Array.from(bytes.slice(0, 8)).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join('');
            this.fingerprint = hex.match(/.{4}/g).join('-');
            const emojis = ['🛡️', '⚡', '🔐', '🛸', '💎', '🛰️', '🧬', '🔮', '🔥', '🪐', '🌀', '⚓', '🎯', '🕹️', '🚀', '👁️',
                            '🦊', '🐙', '🌵', '🍀', '🌙', '⭐', '🎲', '🧊', '🎸', '🍉', '🦋', '🐳', '🌋', '🗝️', '🧭', '🎈'];
            this.emojiFingerprint = Array.from(bytes.slice(8, 12)).map(b => emojis[b % emojis.length]).join(' ');
        }

        /** Seals raw bytes. `aad` (optional) is authenticated but not encrypted. Output: nonce|ciphertext|tag. */
        sealBytes(plain, nonce = crypto.getRandomValues(new Uint8Array(12)), aad = new Uint8Array(0)) {
            if (!this.encKey) throw new Error('Encryption key not established.');
            const ct = chacha20Xor(this.encKey, nonce, 1, plain);
            const tag = hmacSha256(this.macKey, aad, nonce, ct).subarray(0, TAG_LEN);
            return concat(nonce, ct, tag);
        }

        openBytes(sealed, aad = new Uint8Array(0)) {
            if (!this.encKey) throw new Error('Decryption key not established.');
            if (sealed.length < 12 + TAG_LEN) throw new Error('Ciphertext too short.');
            const nonce = sealed.subarray(0, 12);
            const ct = sealed.subarray(12, sealed.length - TAG_LEN);
            const tag = sealed.subarray(sealed.length - TAG_LEN);
            const expect = hmacSha256(this.macKey, aad, nonce, ct).subarray(0, TAG_LEN);
            if (!constTimeEqual(tag, expect)) throw new Error('Message authentication failed (tampered or wrong key).');
            return chacha20Xor(this.encKey, nonce, 1, ct);
        }

        /** Encrypts any JSON-serialisable object to a base64 string. */
        encryptJson(obj) { return bytesToB64(this.sealBytes(te.encode(JSON.stringify(obj)))); }
        decryptJson(b64) { return JSON.parse(td.decode(this.openBytes(b64ToBytes(b64)))); }

        /** Memory zeroization: destroys active key material. */
        wipe() {
            if (this.encKey) this.encKey.fill(0);
            if (this.macKey) this.macKey.fill(0);
            this.encKey = null;
            this.macKey = null;
            this.fingerprint = null;
            this.emojiFingerprint = null;
        }
    }

    window.cipherEngine = new CipherEngine();
    window.cipherPrimitives = { sha256, hmacSha256, hkdf, chacha20Xor, bytesToB64, b64ToBytes, concat };
})();
