/**
 * CipherDrop - app orchestrator
 * Ephemeral 1-to-1 QR rooms, E2EE chat and fast encrypted file transfer.
 */
(function () {
    'use strict';

    const $ = (id) => document.getElementById(id);
    const SESSION_KEY = 'cipherdrop.session';
    const isTouch = window.matchMedia('(pointer: coarse)').matches;

    // ------------------------------------------------------------------ state
    let S = null;                 // current room session (persisted in sessionStorage so a refresh can reconnect)
    let ws = null;
    let burned = false;
    let reconnectAttempts = 0;
    let reconnectTimer = null;
    let pingTimer = null;
    let roomTimerInt = null;
    let graceTimerInt = null;
    let typingSentAt = 0;
    let typingStopTimer = null;
    let peerTypingTimer = null;
    let msgTtl = 0;
    let unread = 0;
    let lastNudge = 0;
    let netInfo = null;
    let hostWantsChat = false;    // host clicked "Open chat now" before the peer arrived
    const msgEls = new Map();     // message id -> row element
    const pendingRead = new Set();
    const transferEls = new Map();

    const views = ['create', 'share', 'unlock', 'chamber', 'burned'];
    let currentView = null;

    const NET_KINDS = {
        wifi:      { icon: 'i-wifi',    label: 'WI-FI',     hint: 'Both devices must be on this same Wi-Fi network.' },
        hotspot:   { icon: 'i-hotspot', label: 'HOTSPOT',   hint: 'The other device joins this device\'s hotspot. No internet or mobile data needed.' },
        bluetooth: { icon: 'i-bt',      label: 'BLUETOOTH', hint: 'The other device reaches you over Bluetooth tethering (PAN). Best for chat and small files.' },
        ethernet:  { icon: 'i-lan',     label: 'LAN',       hint: 'The other device must be on the same local network.' },
        lan:       { icon: 'i-lan',     label: 'LAN',       hint: 'The other device must be on the same local network.' },
        virtual:   { icon: 'i-lan',     label: 'VIRTUAL',   hint: 'Virtual/VPN adapter. Phones usually can\'t reach this one, so pick Wi-Fi, Hotspot or Bluetooth.' },
        loopback:  { icon: 'i-lan',     label: 'LOCAL',     hint: 'Only works on this computer (for testing in two tabs).' },
    };

    // ------------------------------------------------------------------ utils
    function escapeHtml(str) {
        return String(str ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[c]));
    }

    function linkify(escaped) {
        return escaped.replace(/\bhttps?:\/\/[^\s<]+[^\s<.,;:!?)\]'"]/g,
            url => `<a href="${url}" target="_blank" rel="noopener noreferrer">${url}</a>`);
    }

    function icon(id, cls = 'ic') { return `<svg class="${cls}"><use href="#${id}"/></svg>`; }

    function fmtClock(sec) {
        sec = Math.max(0, Math.floor(sec));
        const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
        const mm = String(m).padStart(2, '0'), ss = String(s).padStart(2, '0');
        return h ? `${h}:${mm}:${ss}` : `${mm}:${ss}`;
    }

    function randomId() { return Array.from(crypto.getRandomValues(new Uint8Array(8)), b => b.toString(16).padStart(2, '0')).join(''); }

    function showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        $('toastContainer').appendChild(toast);
        setTimeout(() => { toast.classList.add('out'); setTimeout(() => toast.remove(), 300); }, 3800);
    }
    window.showToast = showToast;

    function switchView(name) {
        views.forEach(v => $('view-' + v).classList.toggle('active', v === name));
        currentView = name;
        document.body.dataset.view = name;
    }

    function openModal(id) { $(id).classList.add('active'); }
    function closeModal(id) { $(id).classList.remove('active'); }
    document.querySelectorAll('.modal-backdrop').forEach(m => {
        m.addEventListener('click', (e) => {
            if (e.target === m || e.target.closest('[data-close]')) m.classList.remove('active');
        });
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') document.querySelectorAll('.modal-backdrop.active, .popover.open').forEach(m => m.classList.remove('active', 'open'));
    });

    function saveSession() { try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(S)); } catch (e) {} }
    function loadSession() { try { return JSON.parse(sessionStorage.getItem(SESSION_KEY) || 'null'); } catch (e) { return null; } }
    function clearSession() { try { sessionStorage.removeItem(SESSION_KEY); } catch (e) {} }

    // ------------------------------------------------------------------ network info
    function kindForIp(ip) {
        const iface = netInfo && netInfo.interfaces.find(i => i.ip === ip);
        if (iface) return iface.kind;
        if (ip === 'localhost' || ip.startsWith('127.')) return 'loopback';
        return 'wifi';
    }

    function setNetPill(ip) {
        const kind = kindForIp(ip);
        const k = NET_KINDS[kind] || NET_KINDS.lan;
        $('currentIpDisplay').textContent = `${ip}${netInfo ? ':' + netInfo.port : ''}`;
        $('netModeIcon').innerHTML = `<use href="#${k.icon}"/>`;
        if (netInfo) {
            $('netOnlineTag').textContent = netInfo.online ? 'ONLINE' : 'OFFLINE MODE';
            $('netOnlineTag').className = 'net-online ' + (netInfo.online ? 'on' : 'off');
        }
    }

    function renderIfaceList() {
        const list = $('ifaceList');
        if (!netInfo) { list.innerHTML = '<div class="hint">Could not read adapters.</div>'; return; }
        list.innerHTML = netInfo.interfaces.map(i => {
            const k = NET_KINDS[i.kind] || NET_KINDS.lan;
            return `<div class="iface ${i.kind}">
                ${icon(k.icon)}
                <div class="iface-main"><div class="iface-type">${escapeHtml(i.type)}${i.is_primary ? ' <span class="tag">recommended</span>' : ''}</div>
                <div class="iface-name">${escapeHtml(i.name || '')}</div></div>
                <code>${escapeHtml(i.ip)}</code></div>`;
        }).join('') + (netInfo.interfaces.some(i => i.kind === 'bluetooth') ? '' :
            '<div class="hint">No Bluetooth PAN adapter is active. Follow the Bluetooth steps above, then re-scan.</div>');
    }

    async function loadNetworkInfo() {
        try {
            const res = await fetch('/api/network-info', { cache: 'no-store' });
            netInfo = await res.json();
            $('statusDot').classList.remove('offline');

            const sel = $('selectNetworkIp');
            const prev = sel.value;
            sel.innerHTML = '';
            // When this page was itself opened over a LAN address, that address is the one that works
            const pageHost = location.hostname;
            const pageIface = netInfo.interfaces.find(i => i.ip === pageHost);
            netInfo.interfaces.forEach(iface => {
                const opt = document.createElement('option');
                opt.value = iface.ip;
                opt.dataset.kind = iface.kind;
                opt.textContent = `${iface.type} · ${iface.ip}${iface.name ? ' (' + iface.name + ')' : ''}${iface.is_primary ? ' ★' : ''}`;
                sel.appendChild(opt);
            });
            sel.value = prev && netInfo.interfaces.some(i => i.ip === prev) ? prev : (pageIface ? pageIface.ip : netInfo.primary_ip);
            onNetSelect();
            setNetPill(pageIface || pageHost === 'localhost' || pageHost.startsWith('127.') ? (pageIface ? pageIface.ip : netInfo.primary_ip) : pageHost);
            renderIfaceList();
        } catch (e) {
            $('currentIpDisplay').textContent = 'Server unreachable';
            $('statusDot').classList.add('offline');
        }
    }

    function onNetSelect() {
        const opt = $('selectNetworkIp').selectedOptions[0];
        const k = NET_KINDS[(opt && opt.dataset.kind) || 'wifi'] || NET_KINDS.lan;
        $('netKindBadge').textContent = k.label;
        $('netKindHint').textContent = k.hint;
        $('netKindHint').classList.toggle('warn', opt && ['virtual', 'loopback'].includes(opt.dataset.kind));
    }
    $('selectNetworkIp').addEventListener('change', onNetSelect);

    // ------------------------------------------------------------------ create room
    const ADJ = ['Silent', 'Neon', 'Shadow', 'Quiet', 'Cosmic', 'Frost', 'Hidden', 'Velvet', 'Crimson', 'Lunar', 'Rapid', 'Ghost'];
    const NOUN = ['Fox', 'Owl', 'Raven', 'Lynx', 'Comet', 'Cipher', 'Otter', 'Wolf', 'Falcon', 'Moth', 'Panda', 'Viper'];
    function randomAlias() {
        const r = crypto.getRandomValues(new Uint8Array(3));
        return `${ADJ[r[0] % ADJ.length]}${NOUN[r[1] % NOUN.length]}${r[2] % 90 + 10}`;
    }
    $('inputCreatorAlias').value = randomAlias();
    $('btnRandomAlias').addEventListener('click', () => { $('inputCreatorAlias').value = randomAlias(); });
    $('btnTogglePin').addEventListener('click', () => {
        const i = $('inputSecretPin');
        i.type = i.type === 'password' ? 'text' : 'password';
    });

    let ttlMinutes = 30;
    $('ttlSegment').addEventListener('click', (e) => {
        const b = e.target.closest('button[data-ttl]');
        if (!b) return;
        $('ttlSegment').querySelectorAll('button').forEach(x => x.classList.toggle('active', x === b));
        ttlMinutes = Number(b.dataset.ttl);
    });

    $('createRoomForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const alias = $('inputCreatorAlias').value.trim() || randomAlias();
        const recipient = $('inputTargetRecipient').value.trim();
        const pin = $('inputSecretPin').value.trim();
        if (!recipient) { showToast('Enter the name of the person this room is for.', 'error'); return; }
        if (recipient.toLowerCase() === alias.toLowerCase()) { showToast('Recipient name must be different from your nickname.', 'error'); return; }

        const btn = $('btnSpawnChamber');
        btn.disabled = true;
        try {
            const res = await fetch('/api/create-room', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ creator_alias: alias, target_recipient: recipient, secret_pin: pin,
                                       selected_ip: $('selectNetworkIp').value, ttl_minutes: ttlMinutes }),
            });
            const data = await res.json();
            if (!res.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Could not create room.');

            S = {
                roomId: data.room_id, token: data.token, role: 'creator', key: data.host_key,
                alias: data.creator_alias, pin, creatorAlias: data.creator_alias,
                targetRecipient: data.target_recipient, roomUrl: data.room_url, qr: data.qr_data_url,
                hasPin: data.has_pin, netIp: $('selectNetworkIp').value,
                expiresAt: Date.now() + data.expires_in * 1000,
            };
            saveSession();
            window.soundEngine.playUnlock();
            showShareHub();
            startSession();
        } catch (err) {
            showToast(err.message, 'error');
        } finally {
            btn.disabled = false;
        }
    });

    // ------------------------------------------------------------------ share hub (host)
    function showShareHub() {
        $('shareTargetName').textContent = S.targetRecipient;
        $('waitTargetName').textContent = S.targetRecipient;
        $('qrImageDisplay').src = S.qr;
        $('qrAgainImg').src = S.qr;
        $('shareUrlInput').value = S.roomUrl;
        $('ckIp').textContent = S.netIp || 'this device';
        $('ckPin').style.display = S.hasPin ? '' : 'none';

        const kind = kindForIp(S.netIp || '');
        const k = NET_KINDS[kind] || NET_KINDS.lan;
        $('shareNetChip').innerHTML = `${icon(k.icon, 'ic sm')}<span>${escapeHtml(k.label)}</span>`;

        const waText = `🔐 I made you a private, self-destructing CipherDrop room.\n` +
                       `Join the same Wi-Fi / hotspot as me, then open:\n${S.roomUrl}` +
                       (S.hasPin ? `\n(I'll tell you the PIN separately.)` : '');
        $('btnShareWhatsapp').href = `https://wa.me/?text=${encodeURIComponent(waText)}`;
        $('btnNativeShare').style.display = navigator.share ? '' : 'none';
        $('btnNativeShare').onclick = () => navigator.share({ title: 'CipherDrop room', text: waText }).catch(() => {});
        $('btnShowQrAgain').style.display = '';
        switchView('share');
    }

    $('btnCopyUrl').addEventListener('click', () => copyText($('shareUrlInput').value));
    function copyText(text) {
        const done = () => showToast('Link copied.', 'success');
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(done).catch(fallback);
        } else fallback();
        function fallback() {
            const i = $('shareUrlInput');
            i.select(); i.setSelectionRange(0, 99999);
            try { document.execCommand('copy'); done(); } catch (e) { showToast('Select the link and copy it manually.', 'error'); }
        }
    }

    $('btnDownloadQr').addEventListener('click', () => {
        const a = document.createElement('a');
        a.href = S.qr;
        a.download = `cipherdrop-room-${S.roomId.slice(0, 6)}.png`;
        a.click();
    });

    $('btnEnterAsHost').addEventListener('click', () => { hostWantsChat = true; switchView('chamber'); $('chatTextInput').focus(); });
    $('btnCancelRoom').addEventListener('click', () => askBurn('Cancel and destroy this room?', 'The QR code and link stop working right away.'));
    $('btnShowQrAgain').addEventListener('click', () => openModal('qrAgainModal'));

    function logIntrusion(name, attempts) {
        const line = `Someone tried to unlock as “${name || '?'}” (${attempts}/3)`;
        const el = document.createElement('div');
        el.className = 'intrusion';
        el.innerHTML = `${icon('i-alert', 'ic sm')}<span>${escapeHtml(line)}</span>`;
        $('intrusionLog').prepend(el);
        appendSystem(`⚠️ ${escapeHtml(line)}`, 'danger');
        window.soundEngine.playAlert();
        showToast(line, 'error');
    }

    // ------------------------------------------------------------------ unlock (recipient)
    async function showUnlock(roomId, token) {
        try {
            const res = await fetch(`/api/room-info/${encodeURIComponent(roomId)}?token=${encodeURIComponent(token)}`, { cache: 'no-store' });
            if (!res.ok) { burn('This room has already been erased, or the link is wrong.', true); return; }
            const info = await res.json();
            S = { roomId, token, role: 'recipient', creatorAlias: info.creator_alias, hasPin: info.has_pin };
            $('unlockHeaderSubtitle').innerHTML =
                `<b>${escapeHtml(info.creator_alias)}</b> made a private room for one specific person. Type your name to prove it's you.`;
            $('unlockPinGroup').style.display = info.has_pin ? '' : 'none';
            $('inputUnlockPin').required = info.has_pin;
            switchView('unlock');
            $('inputUnlockName').focus();
        } catch (e) {
            burn('Could not reach the room. Are you on the same Wi-Fi / hotspot as the sender?', true);
        }
    }

    $('unlockForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const name = $('inputUnlockName').value.trim();
        const pin = $('inputUnlockPin').value.trim();
        if (!name) return;
        const btn = $('btnUnlockSubmit');
        btn.disabled = true;
        try {
            const res = await fetch('/api/verify-access', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ room_id: S.roomId, token: S.token, claimed_name: name, pin }),
            });
            const data = await res.json();
            if (!res.ok) {
                const msg = typeof data.detail === 'string' ? data.detail : 'Access denied.';
                window.soundEngine.playAlert();
                const box = $('unlockAlertBox');
                box.style.display = 'flex';
                box.innerHTML = `${icon('i-alert', 'ic')}<div>${escapeHtml(msg)}</div>`;
                box.classList.remove('shake'); void box.offsetWidth; box.classList.add('shake');
                if (res.status === 404 || msg.startsWith('SECURITY PURGE')) setTimeout(() => burn(msg, true), 1400);
                return;
            }
            Object.assign(S, {
                key: data.guest_key, alias: name, pin, targetRecipient: data.target_recipient,
                creatorAlias: data.creator_alias, expiresAt: Date.now() + data.expires_in * 1000,
            });
            saveSession();
            window.soundEngine.playUnlock();
            showToast('Unlocked. Your identity was verified.', 'success');
            switchView('chamber');
            startSession();
        } catch (err) {
            showToast('Could not reach the room: ' + err.message, 'error');
        } finally {
            btn.disabled = false;
        }
    });

    // ------------------------------------------------------------------ session / websocket
    function startSession() {
        burned = false;
        try {
            window.cipherEngine.deriveRoomKey(S.roomId, S.token, S.pin || '');
            $('badgeEmojiFingerprint').textContent = window.cipherEngine.emojiFingerprint;
            $('modalEmojiBlock').textContent = window.cipherEngine.emojiFingerprint;
            $('modalHexCode').textContent = window.cipherEngine.fingerprint;
        } catch (e) {
            showToast('Encryption setup failed: ' + e.message, 'error');
            return;
        }
        $('peerAvatarIcon').textContent = '?';
        $('remotePeerName').textContent = S.role === 'creator' ? S.targetRecipient : S.creatorAlias;
        $('peerAvatarIcon').textContent = ($('remotePeerName').textContent || '?').charAt(0).toUpperCase();
        startRoomTimer();
        connect();
    }

    function wsSend(obj) {
        if (ws && ws.readyState === WebSocket.OPEN) { ws.send(JSON.stringify(obj)); return true; }
        return false;
    }

    window.transferEngine.transport = {
        sendJson: wsSend,
        sendBinary: (u8) => { if (ws && ws.readyState === WebSocket.OPEN) ws.send(u8); },
        bufferedAmount: () => (ws ? ws.bufferedAmount : 0),
        isOpen: () => !!ws && ws.readyState === WebSocket.OPEN,
    };

    function connect() {
        clearTimeout(reconnectTimer);
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        const sock = new WebSocket(`${proto}//${location.host}/ws/${encodeURIComponent(S.roomId)}`);
        sock.binaryType = 'arraybuffer';
        ws = sock;
        setSubStatus('Connecting…');

        sock.onopen = () => {
            sock.send(JSON.stringify({ type: 'auth', role: S.role, token: S.token, key: S.key, alias: S.alias }));
        };

        sock.onmessage = (ev) => {
            if (sock !== ws) return;
            if (typeof ev.data !== 'string') { window.transferEngine.handleBinary(ev.data); return; }
            let data;
            try { data = JSON.parse(ev.data); } catch (e) { return; }
            handleMessage(data);
        };

        sock.onclose = (ev) => {
            if (sock !== ws || burned) return;
            clearInterval(pingTimer);
            setPeerOnline(false, true);
            if (ev.code === 4000) return burn('The room was erased.');
            if (ev.code === 4003) return burn('Access to this room was denied.');
            if (ev.code === 4004) return burn('This room no longer exists.');
            if (ev.code === 4001) {
                showBanner('This room is open in another tab or window. This one is paused.', 'warn');
                setSubStatus('Paused (opened elsewhere)');
                return;
            }
            window.transferEngine.abortAll('Connection dropped.');
            scheduleReconnect();
        };
    }

    function scheduleReconnect() {
        reconnectAttempts++;
        const delay = Math.min(8000, 600 * Math.pow(1.7, reconnectAttempts));
        if (reconnectAttempts > 12) {
            burn('Lost connection to the room for too long. It has been erased.');
            return;
        }
        showBanner(`Connection lost. Reconnecting (attempt ${reconnectAttempts})…`, 'warn');
        setSubStatus('Reconnecting…');
        reconnectTimer = setTimeout(connect, delay);
    }

    function handleMessage(d) {
        const te = window.transferEngine;
        switch (d.type) {
            case 'auth_success':
                reconnectAttempts = 0;
                hideBanner();
                S.expiresAt = Date.now() + d.expires_in * 1000;
                S.graceSeconds = d.grace;
                if (S.role === 'recipient') S.targetRecipient = d.target_recipient;
                saveSession();
                clearInterval(pingTimer);
                pingTimer = setInterval(() => wsSend({ type: 'ping' }), 20000);
                if (d.peer) {
                    setPeer(d.peer.alias);
                    setPeerOnline(true);
                    if (currentView !== 'chamber') switchView('chamber');
                } else {
                    setPeerOnline(false);
                    setSubStatus(S.role === 'creator' ? `Waiting for ${S.targetRecipient} to scan…` : `Waiting for ${S.creatorAlias}…`);
                    if (S.role === 'creator' && !hostWantsChat && currentView !== 'chamber') showShareHub();
                }
                if (S.role === 'creator' && d.failed_attempts) $('intrusionLog').dataset.count = d.failed_attempts;
                appendSystem(`Connected securely as <b>${escapeHtml(d.alias)}</b>.`);
                break;

            case 'peer_joined':
                setPeer(d.alias);
                setPeerOnline(true);
                window.soundEngine.playUnlock();
                appendSystem(`<b>${escapeHtml(d.alias)}</b> joined. Compare the safety code ${escapeHtml(window.cipherEngine.emojiFingerprint)} to be sure.`, 'ok');
                showToast(`${d.alias} joined the room`, 'success');
                if (currentView !== 'chamber') { switchView('chamber'); $('chatTextInput').focus(); }
                break;

            case 'peer_returned':
                setPeer(d.alias);
                setPeerOnline(true);
                stopGraceCountdown();
                hideBanner();
                appendSystem(`<b>${escapeHtml(d.alias)}</b> reconnected.`, 'ok');
                break;

            case 'peer_left':
                setPeerOnline(false);
                startGraceCountdown(d.alias, d.grace);
                appendSystem(`<b>${escapeHtml(d.alias)}</b> left the chat.`);
                te.abortAll('The other device disconnected.');
                break;

            case 'intrusion':
                logIntrusion(d.claimed_name, d.attempts);
                break;

            case 'msg':
                onIncomingMessage(d);
                break;

            case 'receipt':
                markReceipt(d.id, d.state);
                break;

            case 'undelivered':
                markReceipt(d.id, 'failed');
                break;

            case 'typing':
                showPeerTyping(d.is_typing);
                break;

            case 'nudge':
                onNudge();
                break;

            case 'file_header': {
                const t = te.handleHeader(d);
                if (t) { showPeerTyping(false); window.soundEngine.playTone(660, 'sine', 0.06, 0.08); }
                break;
            }
            case 'file_ack': te.handleAck(d); break;
            case 'file_complete': te.handleComplete(d); break;
            case 'file_cancel': te.handleCancel(d); break;

            case 'room_vaporized':
                burn(d.reason || 'The room was erased.');
                break;

            case 'pong':
                if (typeof d.expires_in === 'number') S.expiresAt = Date.now() + d.expires_in * 1000;
                break;
        }
    }

    // ------------------------------------------------------------------ presence UI
    function setPeer(alias) {
        $('remotePeerName').textContent = alias;
        $('peerAvatarIcon').textContent = (alias || '?').charAt(0).toUpperCase();
    }

    function setPeerOnline(online, selfDropped = false) {
        $('chamberPeerDot').classList.toggle('offline', !online);
        $('peerAvatarIcon').classList.toggle('online', online);
        const host = location.hostname;
        const k = NET_KINDS[kindForIp(host)] || NET_KINDS.lan;
        if (online) setSubStatus(`Online · via ${k.label.toLowerCase()} · end-to-end encrypted`);
        else if (!selfDropped) setSubStatus('Offline');
    }

    function setSubStatus(text) { $('chamberSubStatus').textContent = text; }

    function showPeerTyping(on) {
        clearTimeout(peerTypingTimer);
        $('typingIndicator').innerHTML = on ? `<span class="dots"><i></i><i></i><i></i></span> ${escapeHtml($('remotePeerName').textContent)} is typing` : '';
        if (on) peerTypingTimer = setTimeout(() => showPeerTyping(false), 4000);
    }

    function showBanner(text, kind = 'warn') {
        const b = $('connBanner');
        b.className = `banner ${kind}`;
        b.innerHTML = `${icon('i-alert', 'ic sm')}<span>${text}</span>`;
        b.style.display = 'flex';
    }
    function hideBanner() { $('connBanner').style.display = 'none'; }

    function startGraceCountdown(alias, grace) {
        stopGraceCountdown();
        const end = Date.now() + (grace || 45) * 1000;
        const tick = () => {
            const left = Math.ceil((end - Date.now()) / 1000);
            if (left <= 0) { stopGraceCountdown(); return; }
            showBanner(`<b>${escapeHtml(alias)}</b> disconnected. The room erases itself in <b>${left}s</b> unless they come back.`, 'danger');
        };
        tick();
        graceTimerInt = setInterval(tick, 1000);
    }
    function stopGraceCountdown() { clearInterval(graceTimerInt); graceTimerInt = null; }

    function startRoomTimer() {
        clearInterval(roomTimerInt);
        const tick = () => {
            if (!S || !S.expiresAt) return;
            const left = (S.expiresAt - Date.now()) / 1000;
            const txt = fmtClock(left);
            $('roomTimer').textContent = txt;
            $('shareTimer').textContent = txt;
            const urgent = left < 60;
            $('roomTimerChip').classList.toggle('urgent', urgent);
            $('shareTimerChip').classList.toggle('urgent', urgent);
        };
        tick();
        roomTimerInt = setInterval(tick, 1000);
    }

    // ------------------------------------------------------------------ chat messages
    const feed = $('chatFeed');
    function scrollFeed(force = false) {
        const nearBottom = feed.scrollHeight - feed.scrollTop - feed.clientHeight < 160;
        if (force || nearBottom) feed.scrollTop = feed.scrollHeight;
    }

    function appendSystem(html, kind = '') {
        const el = document.createElement('div');
        el.className = `system-bubble ${kind}`;
        el.innerHTML = html;
        feed.appendChild(el);
        scrollFeed();
    }

    function timeStr(ts) { return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); }

    function appendText({ id, dir, sender, text, ts, ttl }) {
        const row = document.createElement('div');
        row.className = `msg-row ${dir}`;
        row.dataset.id = id;
        const emojiOnly = /^\p{Extended_Pictographic}[\p{Extended_Pictographic}‍️\s]{0,10}$/u.test(text);
        row.innerHTML = `
            <div class="msg-bubble${emojiOnly ? ' big-emoji' : ''}">
                <div class="msg-text">${linkify(escapeHtml(text))}</div>
                <div class="msg-time">
                    ${ttl ? `<span class="ttl-badge" title="Disappears">${icon('i-timer', 'ic xs')}${ttl < 60 ? ttl + 's' : ttl / 60 + 'm'}</span>` : ''}
                    ${timeStr(ts)}
                    ${dir === 'sent' ? `<span class="ticks" data-state="sent">${icon('i-check', 'ic xs')}</span>` : ''}
                </div>
            </div>`;
        row.title = sender;
        feed.appendChild(row);
        msgEls.set(id, row);
        scrollFeed(dir === 'sent');
        if (ttl) scheduleVanish(row, ttl);
        return row;
    }

    function scheduleVanish(row, ttl) {
        setTimeout(() => {
            row.classList.add('vanish');
            setTimeout(() => { row.remove(); msgEls.delete(row.dataset.id); }, 600);
        }, ttl * 1000);
    }

    function markReceipt(id, state) {
        const row = msgEls.get(id);
        if (!row) return;
        const t = row.querySelector('.ticks');
        if (!t) return;
        const rank = { sent: 0, delivered: 1, read: 2, failed: 3 };
        if ((rank[state] ?? 0) <= (rank[t.dataset.state] ?? 0) && state !== 'failed') return;
        t.dataset.state = state;
        t.innerHTML = state === 'failed' ? `${icon('i-alert', 'ic xs')} not delivered`
                    : icon(state === 'sent' ? 'i-check' : 'i-checks', 'ic xs');
    }

    function sendMessage() {
        const input = $('chatTextInput');
        const text = input.value.trim();
        if (!text) return;
        if (!ws || ws.readyState !== WebSocket.OPEN) { showToast('Not connected right now. Wait for reconnect.', 'error'); return; }
        const id = randomId();
        const ts = Date.now();
        let data;
        try {
            data = window.cipherEngine.encryptJson({ kind: 'text', text, ts, ttl: msgTtl });
        } catch (e) { showToast('Encryption failed: ' + e.message, 'error'); return; }
        wsSend({ type: 'msg', id, data });
        input.value = '';
        autoGrow();
        stopTyping();
        window.soundEngine.playSend();
        appendText({ id, dir: 'sent', sender: S.alias, text, ts, ttl: msgTtl });
    }

    function onIncomingMessage(d) {
        let m;
        try {
            m = window.cipherEngine.decryptJson(d.data);
        } catch (e) {
            appendSystem('⚠️ A message failed its integrity check and was dropped (wrong PIN or tampering).', 'danger');
            return;
        }
        showPeerTyping(false);
        if (m.kind !== 'text' || typeof m.text !== 'string') return;
        const ttl = [0, 10, 60, 300].includes(m.ttl) ? m.ttl : 0;
        appendText({ id: d.id, dir: 'received', sender: $('remotePeerName').textContent, text: m.text.slice(0, 4000), ts: Number(m.ts) || Date.now(), ttl });
        window.soundEngine.playReceive();
        wsSend({ type: 'receipt', id: d.id, state: 'delivered' });
        if (document.visibilityState === 'visible' && currentView === 'chamber') {
            wsSend({ type: 'receipt', id: d.id, state: 'read' });
        } else {
            pendingRead.add(d.id);
            unread++;
            document.title = `(${unread}) CipherDrop`;
        }
    }

    function flushReads() {
        if (document.visibilityState !== 'visible') return;
        pendingRead.forEach(id => wsSend({ type: 'receipt', id, state: 'read' }));
        pendingRead.clear();
        unread = 0;
        document.title = 'CipherDrop — Private QR Chat';
    }

    // Composer behaviour
    const input = $('chatTextInput');
    function autoGrow() {
        input.style.height = 'auto';
        input.style.height = Math.min(input.scrollHeight, 140) + 'px';
    }
    input.addEventListener('input', () => { autoGrow(); notifyTyping(); });
    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey && !isTouch) { e.preventDefault(); sendMessage(); }
    });
    $('btnSendMessage').addEventListener('click', () => { sendMessage(); input.focus(); });

    function notifyTyping() {
        const now = Date.now();
        if (now - typingSentAt > 1500) { wsSend({ type: 'typing', is_typing: true }); typingSentAt = now; }
        clearTimeout(typingStopTimer);
        typingStopTimer = setTimeout(stopTyping, 2500);
    }
    function stopTyping() {
        clearTimeout(typingStopTimer);
        if (typingSentAt) { wsSend({ type: 'typing', is_typing: false }); typingSentAt = 0; }
    }

    // Popovers: attach / emoji / disappearing timer
    const popovers = { btnAttachFile: 'attachMenu', btnEmoji: 'emojiMenu', btnMsgTtl: 'ttlMenu' };
    Object.entries(popovers).forEach(([btn, pop]) => {
        $(btn).addEventListener('click', (e) => {
            e.stopPropagation();
            const open = !$(pop).classList.contains('open');
            Object.values(popovers).forEach(p => $(p).classList.remove('open'));
            $(pop).classList.toggle('open', open);
        });
    });
    document.addEventListener('click', (e) => {
        if (!e.target.closest('.popover')) Object.values(popovers).forEach(p => $(p).classList.remove('open'));
    });

    const EMOJIS = ['😀', '😂', '🥹', '😍', '😎', '🤔', '😅', '😭', '😡', '🥳', '😴', '🤫', '👍', '👎', '🙏', '👏', '🔥', '❤️', '💯', '✨', '🎉', '👀', '🔐', '👻', '✅', '❌', '⚡', '🚀', '📎', '📷', '🎧', '☕'];
    $('emojiMenu').innerHTML = EMOJIS.map(e => `<button data-emoji="${e}">${e}</button>`).join('');
    $('emojiMenu').addEventListener('click', (e) => {
        const b = e.target.closest('[data-emoji]');
        if (!b) return;
        const pos = input.selectionStart ?? input.value.length;
        input.value = input.value.slice(0, pos) + b.dataset.emoji + input.value.slice(input.selectionEnd ?? pos);
        input.focus();
        input.selectionStart = input.selectionEnd = pos + b.dataset.emoji.length;
        autoGrow();
    });

    $('ttlMenu').addEventListener('click', (e) => {
        const b = e.target.closest('[data-msgttl]');
        if (!b) return;
        msgTtl = Number(b.dataset.msgttl);
        $('ttlMenu').querySelectorAll('[data-msgttl]').forEach(x => x.classList.toggle('active', x === b));
        $('ttlDot').classList.toggle('on', msgTtl > 0);
        $('ttlMenu').classList.remove('open');
        appendSystem(msgTtl ? `⏱️ Your new messages now disappear ${b.textContent.toLowerCase()} after sending.` : '⏱️ Disappearing messages off.');
    });

    $('btnNudge').addEventListener('click', () => {
        if (Date.now() - lastNudge < 3000) return;
        lastNudge = Date.now();
        if (wsSend({ type: 'nudge' })) appendSystem('👋 You nudged them.');
    });
    function onNudge() {
        appendSystem(`👋 <b>${escapeHtml($('remotePeerName').textContent)}</b> nudged you!`, 'ok');
        if (navigator.vibrate) navigator.vibrate([120, 60, 120]);
        window.soundEngine.playUnlock();
        const c = $('chamberDropZone');
        c.classList.remove('shake'); void c.offsetWidth; c.classList.add('shake');
    }

    // ------------------------------------------------------------------ file transfer UI
    $('attachMenu').addEventListener('click', (e) => {
        const b = e.target.closest('[data-pick]');
        if (!b) return;
        $('attachMenu').classList.remove('open');
        ({ files: $('filePickerInput'), media: $('mediaPickerInput'), folder: $('folderPickerInput') })[b.dataset.pick].click();
    });
    ['filePickerInput', 'mediaPickerInput', 'folderPickerInput'].forEach(id => {
        $(id).addEventListener('change', (e) => {
            sendFiles(e.target.files);
            e.target.value = '';
        });
    });

    function sendFiles(fileList) {
        const files = Array.from(fileList || []);
        if (!files.length) return;
        if (!ws || ws.readyState !== WebSocket.OPEN) { showToast('Not connected right now.', 'error'); return; }
        if ($('chamberPeerDot').classList.contains('offline')) { showToast('Wait until the other person is online to send files.', 'error'); return; }
        files.forEach(f => window.transferEngine.enqueue(f, f.webkitRelativePath || f.name));
        if (files.length > 1) showToast(`Queued ${files.length} files`, 'info');
    }

    // Drag & drop + paste
    const zone = $('chamberDropZone');
    let dragDepth = 0;
    zone.addEventListener('dragenter', (e) => { if (e.dataTransfer.types.includes('Files')) { dragDepth++; zone.classList.add('dragging'); } });
    zone.addEventListener('dragleave', () => { if (--dragDepth <= 0) { dragDepth = 0; zone.classList.remove('dragging'); } });
    zone.addEventListener('dragover', (e) => e.preventDefault());
    zone.addEventListener('drop', (e) => {
        e.preventDefault();
        dragDepth = 0;
        zone.classList.remove('dragging');
        sendFiles(e.dataTransfer.files);
    });
    document.addEventListener('paste', (e) => {
        if (currentView !== 'chamber') return;
        const files = Array.from(e.clipboardData?.files || []);
        if (files.length) { e.preventDefault(); sendFiles(files); }
    });

    function fileIconFor(mime) {
        if (/^image\//.test(mime)) return 'i-image';
        return 'i-file';
    }

    window.transferEngine.onUpdate = (t) => {
        $('transfersPanel').style.display = '';
        let el = transferEls.get(t.id);
        if (!el) {
            el = document.createElement('div');
            el.className = 'transfer-item';
            el.innerHTML = `
                <div class="t-icon">${icon(fileIconFor(t.mime))}</div>
                <div class="t-main">
                    <div class="t-row"><span class="t-name"></span><span class="t-dir"></span></div>
                    <div class="progress-track"><div class="progress-bar"></div></div>
                    <div class="t-row t-meta"><span class="t-progress"></span><span class="t-speed"></span></div>
                </div>
                <button class="btn-icon sm t-cancel" title="Cancel">${icon('i-x')}</button>`;
            el.querySelector('.t-name').textContent = t.name;
            el.querySelector('.t-dir').textContent = t.direction === 'out' ? '↑ sending' : '↓ receiving';
            el.querySelector('.t-cancel').addEventListener('click', () => window.transferEngine.cancel(t.id));
            $('transferList').prepend(el);
            transferEls.set(t.id, el);
        }
        const d = window.transferEngine.describe(t);
        el.dataset.state = t.state;
        el.querySelector('.progress-bar').style.width = d.percent + '%';
        const meta = el.querySelector('.t-progress');
        const speed = el.querySelector('.t-speed');
        if (t.state === 'queued') { meta.textContent = `Queued · ${window.transferEngine.formatBytes(t.size)}`; speed.textContent = ''; }
        else if (t.state === 'active') { meta.textContent = `${d.percent}% · ${d.progress}`; speed.textContent = `⚡ ${d.speed}  ${d.eta}`; }
        else if (t.state === 'done') {
            const avg = t.elapsed > 0 ? `${window.transferEngine.formatBytes(t.size / t.elapsed)}/s avg` : '';
            meta.textContent = `Done · ${window.transferEngine.formatBytes(t.size)}`; speed.textContent = avg;
        }
        else if (t.state === 'cancelled') { meta.textContent = 'Cancelled'; speed.textContent = ''; }
        else if (t.state === 'failed') { meta.textContent = 'Failed: ' + (t.error || ''); speed.textContent = ''; }

        if (t.state === 'done' && !t._posted) {
            t._posted = true;
            appendFile(t);
            if (t.direction === 'out') window.soundEngine.playSend();
        }
    };

    window.transferEngine.onReceived = (t) => {
        window.soundEngine.playReceive();
        showToast(`Received ${t.name}`, 'success');
        if (document.visibilityState !== 'visible') { unread++; document.title = `(${unread}) CipherDrop`; }
    };

    $('btnClearTransfers').addEventListener('click', () => {
        for (const [id, el] of transferEls) {
            if (['done', 'failed', 'cancelled'].includes(el.dataset.state)) { el.remove(); transferEls.delete(id); }
        }
        if (!transferEls.size) $('transfersPanel').style.display = 'none';
    });

    function appendFile(t) {
        const te = window.transferEngine;
        const safeMime = te.safeMime(t.mime);
        const dir = t.direction === 'out' ? 'sent' : 'received';
        const speed = t.elapsed > 0 ? ` · ${te.formatBytes(t.size / t.elapsed)}/s` : '';
        const row = document.createElement('div');
        row.className = `msg-row ${dir}`;
        let media = '';
        if (/^image\//.test(safeMime)) media = `<img class="file-preview-img" alt="">`;
        else if (/^video\//.test(safeMime)) media = `<video class="file-preview-vid" controls preload="metadata"></video>`;
        else if (/^audio\//.test(safeMime)) media = `<audio controls preload="metadata" class="file-preview-aud"></audio>`;
        row.innerHTML = `
            <div class="msg-bubble file-bubble">
                ${media}
                <div class="file-card">
                    <div class="file-icon">${icon(fileIconFor(safeMime))}</div>
                    <div class="file-info"><div class="file-name"></div><div class="file-meta">${te.formatBytes(t.size)}${speed}</div></div>
                    <a class="btn-icon sm" title="Save file">${icon('i-download')}</a>
                </div>
                <div class="msg-time">${icon('i-lock', 'ic xs')} encrypted · ${timeStr(Date.now())}</div>
            </div>`;
        row.querySelector('.file-name').textContent = t.name;
        const a = row.querySelector('a');
        a.href = t.url;
        a.download = t.name.split('/').pop();
        const m = row.querySelector('img, video, audio');
        if (m) {
            m.src = t.url;
            if (m.tagName === 'IMG') {
                m.addEventListener('click', () => { $('viewerImg').src = t.url; openModal('imageViewer'); });
                m.addEventListener('load', () => scrollFeed());
            }
        }
        feed.appendChild(row);
        scrollFeed(true);
    }

    // ------------------------------------------------------------------ privacy
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden' && currentView === 'chamber') {
            $('privacyShield').classList.add('on');
        } else {
            flushReads();
        }
    });
    $('privacyShield').addEventListener('click', () => { $('privacyShield').classList.remove('on'); flushReads(); });

    // ------------------------------------------------------------------ burn
    function askBurn(title, text) {
        $('confirmTitle').textContent = title || 'End chat & erase everything?';
        $('confirmText').textContent = text || 'The room, every message and every file is destroyed for both of you, right now. This can\'t be undone.';
        openModal('confirmModal');
    }
    $('btnPanicVaporize').addEventListener('click', () => askBurn());
    $('btnConfirmBurn').addEventListener('click', () => {
        closeModal('confirmModal');
        const reason = `${S.alias || 'Someone'} ended the chat. Everything was erased.`;
        if (!wsSend({ type: 'end_chat', reason }) && S && S.key) {
            fetch('/api/vaporize', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ room_id: S.roomId, key: S.key, reason }), keepalive: true,
            }).catch(() => {});
        }
        burn('You ended the chat. Everything was erased.');
    });

    function burn(reason, quiet = false) {
        if (burned) return;
        burned = true;
        if (!quiet) window.soundEngine.playVaporize();
        clearTimeout(reconnectTimer);
        clearInterval(pingTimer);
        clearInterval(roomTimerInt);
        stopGraceCountdown();
        window.cipherEngine.wipe();
        window.transferEngine.wipe();
        if (ws) { const w = ws; ws = null; try { w.close(); } catch (e) {} }

        // Wipe DOM traces of the conversation
        feed.querySelectorAll('.msg-row, .system-bubble:not(:first-child)').forEach(n => n.remove());
        msgEls.clear(); pendingRead.clear();
        transferEls.forEach(el => el.remove()); transferEls.clear();
        $('transfersPanel').style.display = 'none';
        $('intrusionLog').innerHTML = '';
        ['qrImageDisplay', 'qrAgainImg', 'viewerImg'].forEach(id => $(id).removeAttribute('src'));
        $('shareUrlInput').value = '';
        $('chatTextInput').value = '';
        $('btnShowQrAgain').style.display = 'none';
        hideBanner();
        document.querySelectorAll('.modal-backdrop.active').forEach(m => m.classList.remove('active'));
        S = null;
        clearSession();
        hostWantsChat = false;
        document.title = 'CipherDrop — Private QR Chat';
        history.replaceState({}, document.title, '/');

        $('burnReason').textContent = reason || 'All keys, messages and files have been wiped.';
        switchView('burned');
    }

    $('btnNewRoom').addEventListener('click', () => {
        burned = false;
        $('inputTargetRecipient').value = '';
        $('inputSecretPin').value = '';
        switchView('create');
        loadNetworkInfo();
    });

    // ------------------------------------------------------------------ header controls
    function openGuide() { renderIfaceList(); openModal('netGuideModal'); }
    $('btnNetGuide').addEventListener('click', openGuide);
    $('networkPill').addEventListener('click', openGuide);
    $('btnOpenGuide2').addEventListener('click', openGuide);
    $('btnRefreshIfaces').addEventListener('click', async () => { await loadNetworkInfo(); showToast('Adapters re-scanned.', 'info'); });
    $('brandHome').addEventListener('click', (e) => {
        if (S && !burned) { e.preventDefault(); showToast('Use "End & erase" to leave the room.', 'info'); }
    });

    $('btnAudioToggle').addEventListener('click', () => {
        const muted = window.soundEngine.toggleMute();
        $('audioIcon').innerHTML = `<use href="#${muted ? 'i-volx' : 'i-vol'}"/>`;
        if (!muted) window.soundEngine.playTone(880, 'sine', 0.1, 0.15);
    });

    // ------------------------------------------------------------------ boot
    async function boot() {
        await loadNetworkInfo();
        const params = new URLSearchParams(location.search);
        const roomId = params.get('room');
        const token = params.get('token') || '';
        const saved = loadSession();

        if (saved && saved.key && (!roomId || saved.roomId === roomId)) {
            // Refresh / reconnect: resume the same room with our private key
            S = saved;
            appendSystem('↻ Rejoined. Earlier messages are not kept (zero-trace).');
            if (S.role === 'creator') showShareHub(); else switchView('chamber');
            startSession();
            return;
        }
        if (roomId) { clearSession(); await showUnlock(roomId, token); return; }
        switchView('create');
    }

    boot();
})();
