/**
 * High-Speed Encrypted File Transfer Engine (Xender / AirDrop style)
 *
 * - Files go as raw binary WebSocket frames (no base64 / JSON bloat).
 * - Every 256 KB chunk is sealed with ChaCha20 + HMAC, so the relay never sees file contents.
 * - Sliding-window flow control driven by receiver ACKs: the sender never floods RAM,
 *   and the speed / progress shown is what the other device has actually received.
 *
 * Binary frame layout:  [8 bytes file id][4 bytes chunk index BE][nonce | ciphertext | tag]
 */
(function () {
    'use strict';

    const CHUNK_SIZE = 256 * 1024;
    const WINDOW_CHUNKS = 32;              // max un-acked chunks in flight (8 MB)
    const MAX_BUFFERED = 8 * 1024 * 1024;  // don't let the socket buffer grow past this
    const ACK_EVERY = 4;
    const HEADER_LEN = 12;

    const SAFE_PREVIEW = /^(image\/(png|jpeg|gif|webp|bmp|avif)|video\/(mp4|webm|ogg|quicktime)|audio\/[\w.+-]+)$/;

    function hex(bytes) { return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(''); }
    function unhex(str) { return new Uint8Array(str.match(/../g).map(h => parseInt(h, 16))); }

    function formatBytes(bytes) {
        if (!bytes) return '0 B';
        const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.min(sizes.length - 1, Math.floor(Math.log(bytes) / Math.log(k)));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(i ? 1 : 0)) + ' ' + sizes[i];
    }

    function formatEta(seconds) {
        if (!isFinite(seconds) || seconds <= 0) return '';
        if (seconds < 60) return `${Math.ceil(seconds)}s left`;
        return `${Math.floor(seconds / 60)}m ${Math.ceil(seconds % 60)}s left`;
    }

    class TransferEngine {
        constructor() {
            this.transport = null;       // { sendJson(obj), sendBinary(u8), bufferedAmount(), isOpen() }
            this.onUpdate = () => {};    // (transfer) => void  - progress / state changes
            this.onReceived = () => {};  // (transfer) => void  - inbound file fully assembled
            this.transfers = new Map();  // id -> transfer
            this.queue = [];
            this.sending = false;
            this.objectUrls = new Set();
        }

        formatBytes(b) { return formatBytes(b); }

        // ------------------------------------------------------------------ helpers
        _touch(t, bytesDone) {
            const now = performance.now();
            t.done = bytesDone;
            if (!t._lastT) { t._lastT = now; t._lastB = 0; }
            const dt = (now - t._lastT) / 1000;
            if (dt >= 0.4 || bytesDone >= t.size) {
                const inst = (bytesDone - t._lastB) / Math.max(dt, 0.001);
                t.speed = t.speed ? t.speed * 0.6 + inst * 0.4 : inst;
                t._lastT = now; t._lastB = bytesDone;
                t.eta = t.speed > 0 ? (t.size - bytesDone) / t.speed : Infinity;
                this.onUpdate(t);
            }
        }

        describe(t) {
            const pct = t.size ? Math.min(100, Math.floor((t.done / t.size) * 100)) : 100;
            return {
                percent: pct,
                speed: t.speed ? `${formatBytes(t.speed)}/s` : '…',
                eta: formatEta(t.eta),
                progress: `${formatBytes(t.done)} / ${formatBytes(t.size)}`,
            };
        }

        safeMime(mime) { return SAFE_PREVIEW.test(mime || '') ? mime : 'application/octet-stream'; }

        // ------------------------------------------------------------------ sending
        enqueue(file, relPath) {
            const id = hex(crypto.getRandomValues(new Uint8Array(8)));
            const t = {
                id, direction: 'out', file,
                name: relPath || file.name, size: file.size, mime: file.type || 'application/octet-stream',
                chunks: Math.max(1, Math.ceil(file.size / CHUNK_SIZE)),
                done: 0, acked: 0, speed: 0, eta: Infinity, state: 'queued', startedAt: 0,
            };
            this.transfers.set(id, t);
            this.queue.push(t);
            this.onUpdate(t);
            this._pump();
            return t;
        }

        async _pump() {
            if (this.sending) return;
            this.sending = true;
            try {
                while (this.queue.length) {
                    const t = this.queue.shift();
                    if (t.state !== 'queued') continue;
                    try {
                        await this._send(t);
                    } catch (e) {
                        if (t.state === 'active') { t.state = 'failed'; t.error = e.message; this.onUpdate(t); }
                    }
                }
            } finally {
                this.sending = false;
            }
        }

        _waitForRoom(t) {
            return new Promise(resolve => {
                const check = () => {
                    if (t.state !== 'active' || !this.transport || !this.transport.isOpen()) return resolve();
                    const inFlight = t.sentChunks - t.ackedChunks;
                    if (inFlight < WINDOW_CHUNKS && this.transport.bufferedAmount() < MAX_BUFFERED) return resolve();
                    t._wake = check;
                    setTimeout(() => { if (t._wake === check) check(); }, 50);
                };
                check();
            });
        }

        async _send(t) {
            const tr = this.transport;
            if (!tr || !tr.isOpen()) throw new Error('Not connected to the other device.');
            t.state = 'active';
            t.startedAt = performance.now();
            t.sentChunks = 0;
            t.ackedChunks = 0;
            const idBytes = unhex(t.id);

            tr.sendJson({
                type: 'file_header', file_id: t.id,
                data: window.cipherEngine.encryptJson({
                    name: t.name, size: t.size, mime: t.mime, chunks: t.chunks, chunkSize: CHUNK_SIZE,
                }),
            });
            this.onUpdate(t);

            for (let i = 0; i < t.chunks; i++) {
                await this._waitForRoom(t);
                if (t.state !== 'active') return;
                if (!tr.isOpen()) throw new Error('Connection lost during transfer.');

                const plain = new Uint8Array(await t.file.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE).arrayBuffer());
                const head = new Uint8Array(HEADER_LEN);
                head.set(idBytes, 0);
                new DataView(head.buffer).setUint32(8, i);
                const sealed = window.cipherEngine.sealBytes(plain, undefined, head);
                const frame = new Uint8Array(HEADER_LEN + sealed.length);
                frame.set(head, 0);
                frame.set(sealed, HEADER_LEN);
                tr.sendBinary(frame);
                t.sentChunks = i + 1;
            }

            tr.sendJson({ type: 'file_complete', file_id: t.id });

            // Wait until the receiver confirms the final chunk (or the transfer is cancelled / socket dies)
            await new Promise(resolve => {
                const check = () => {
                    if (t.ackedChunks >= t.chunks || t.state !== 'active' || !tr.isOpen()) return resolve();
                    t._wake = check;
                    setTimeout(() => { if (t._wake === check) check(); }, 200);
                };
                check();
            });
            if (t.state === 'active') {
                if (t.ackedChunks >= t.chunks) {
                    t.state = 'done';
                    t.done = t.size;
                    t.elapsed = (performance.now() - t.startedAt) / 1000;
                    t.url = URL.createObjectURL(t.file);
                    this.objectUrls.add(t.url);
                } else {
                    t.state = 'failed';
                    t.error = 'Connection lost before the other side confirmed.';
                }
                this.onUpdate(t);
            }
        }

        handleAck(msg) {
            const t = this.transfers.get(msg.file_id);
            if (!t || t.direction !== 'out') return;
            t.ackedChunks = Math.max(t.ackedChunks || 0, msg.acked | 0);
            this._touch(t, Math.min(t.size, t.ackedChunks * CHUNK_SIZE));
            if (t._wake) { const w = t._wake; t._wake = null; w(); }
        }

        // ------------------------------------------------------------------ receiving
        handleHeader(msg) {
            let meta;
            try {
                meta = window.cipherEngine.decryptJson(msg.data);
            } catch (e) {
                return null;
            }
            const t = {
                id: msg.file_id, direction: 'in',
                name: String(meta.name || 'file').slice(0, 255), size: Number(meta.size) || 0,
                mime: String(meta.mime || ''), chunks: Number(meta.chunks) || 1,
                parts: [], gotChunks: 0, done: 0, speed: 0, eta: Infinity,
                state: 'active', startedAt: performance.now(),
            };
            this.transfers.set(t.id, t);
            this.onUpdate(t);
            return t;
        }

        handleBinary(buffer) {
            const frame = new Uint8Array(buffer);
            if (frame.length < HEADER_LEN) return;
            const head = frame.subarray(0, HEADER_LEN);
            const id = hex(head.subarray(0, 8));
            const index = new DataView(frame.buffer, frame.byteOffset).getUint32(8);
            const t = this.transfers.get(id);
            if (!t || t.direction !== 'in' || t.state !== 'active') return;
            if (index !== t.gotChunks) { this._fail(t, 'Chunks arrived out of order.'); return; }

            let plain;
            try {
                plain = window.cipherEngine.openBytes(frame.subarray(HEADER_LEN), head);
            } catch (e) {
                this._fail(t, 'A chunk failed its integrity check.');
                return;
            }
            t.parts.push(new Blob([plain]));
            t.gotChunks++;
            this._touch(t, Math.min(t.size, t.done + plain.length));

            if (t.gotChunks % ACK_EVERY === 0 || t.gotChunks === t.chunks) {
                this.transport && this.transport.sendJson({ type: 'file_ack', file_id: id, acked: t.gotChunks });
            }
        }

        handleComplete(msg) {
            const t = this.transfers.get(msg.file_id);
            if (!t || t.direction !== 'in' || t.state !== 'active') return;
            if (t.gotChunks !== t.chunks) { this._fail(t, 'File arrived incomplete.'); return; }
            const blob = new Blob(t.parts, { type: this.safeMime(t.mime) });
            t.parts = null;
            t.url = URL.createObjectURL(blob);
            this.objectUrls.add(t.url);
            t.done = t.size;
            t.state = 'done';
            t.elapsed = (performance.now() - t.startedAt) / 1000;
            this.onUpdate(t);
            this.onReceived(t);
        }

        _fail(t, reason) {
            t.state = 'failed';
            t.error = reason;
            t.parts = null;
            this.transport && this.transport.sendJson({ type: 'file_cancel', file_id: t.id, reason });
            this.onUpdate(t);
        }

        // ------------------------------------------------------------------ cancel / wipe
        cancel(id, notifyPeer = true) {
            const t = this.transfers.get(id);
            if (!t || (t.state !== 'active' && t.state !== 'queued')) return;
            t.state = 'cancelled';
            t.parts = null;
            if (notifyPeer && this.transport) this.transport.sendJson({ type: 'file_cancel', file_id: id });
            if (t._wake) { const w = t._wake; t._wake = null; w(); }
            this.onUpdate(t);
        }

        handleCancel(msg) { this.cancel(msg.file_id, false); }

        /** Connection dropped: fail everything in flight (the room is about to be gone anyway). */
        abortAll(reason = 'Connection lost.') {
            for (const t of this.transfers.values()) {
                if (t.state === 'active' || t.state === 'queued') {
                    t.state = 'failed'; t.error = reason; t.parts = null;
                    if (t._wake) { const w = t._wake; t._wake = null; w(); }
                    this.onUpdate(t);
                }
            }
            this.queue = [];
        }

        /** Purges every buffer and revokes every blob URL on room vaporize. */
        wipe() {
            for (const t of this.transfers.values()) { t.state = 'cancelled'; t.parts = null; t.file = null; }
            this.transfers.clear();
            this.queue = [];
            for (const url of this.objectUrls) URL.revokeObjectURL(url);
            this.objectUrls.clear();
        }
    }

    window.transferEngine = new TransferEngine();
})();
