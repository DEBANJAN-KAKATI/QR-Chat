# ⚡ CipherDrop

> **Anonymous, self-destructing QR chat and fast file transfer over Wi-Fi, hotspot or Bluetooth.**
> Inspired by [BitChat](https://github.com/permissionlesstech/bitchat) (offline, encrypted, ephemeral chat) and
> [Xender-for-PC](https://github.com/emmanuelekopimo/xender-for-pc) (fast local file transfer with no internet).

---

## How it works

1. **Create** a room for one person (X). You get a personalised QR code and a link.
2. **Share** it. X scans the QR or taps the link you sent on WhatsApp. X must be on the same Wi-Fi, hotspot or Bluetooth network as you.
3. **Unlock.** X types their name (and the PIN, if you set one). The name is never shown on the unlock page, so Y or Z can't just copy it. Every wrong try is reported to you live, and **3 wrong tries destroy the room**.
4. **Chat and send files** directly between the two devices, end-to-end encrypted.
5. **Burn.** When either person presses **End & erase**, or leaves for more than 45 s, the room, keys, messages and files are wiped for both sides. The link and QR stop working. Every room also has a hard lifetime (5 min to 2 h).

## Features

| | |
|---|---|
| 🔐 **End-to-end encryption** | ChaCha20 + HMAC-SHA256, keys from HKDF(room token + PIN). Pure JS, so it also works on phones opening the plain `http://192.168.x.x` link, where the browser's WebCrypto is unavailable. |
| 🎯 **Locked to one person** | Recipient name + optional PIN. The first device that unlocks claims the room. The creator gets a private host key, so nobody can pretend to be the host. |
| 🔥 **Zero trace** | RAM only, no database, no disk, no access log. Auto-destroys when the chat ends, on the timer, or after intruder attempts. |
| ⚡ **Fast file drop** | Binary WebSocket stream, 256 KB encrypted chunks, ACK-based flow control, live speed and ETA, queue, cancel, multiple files or a whole folder, drag-and-drop and paste. |
| 📶 **Works offline** | Wi-Fi, PC/phone hotspot, or Bluetooth PAN tethering. The app auto-detects and labels each adapter. |
| 💬 **Chat extras** | Read receipts (✓ / ✓✓), typing indicator, disappearing messages (10 s, 1 min, 5 min), emoji picker, nudge (vibrates phones), clickable links, inline image/video/audio previews. |
| 🛡️ **Safety code** | Emoji + hex fingerprint to compare out loud with your peer. |
| 🙈 **Privacy shield** | The chat blurs when you switch away from the tab. |
| ↻ **Reconnect** | A refresh or brief Wi-Fi drop rejoins the same room automatically, within the 45 s grace window. |

## Quick start (Windows)

Double-click **`run.bat`**, or:

```bash
pip install -r requirements.txt
python app.py
```

Open `http://localhost:8000` on this PC. The first time, allow Python through Windows Firewall on **Private** networks, or phones won't reach it.

## No internet? Pick a link

| Mode | Setup | Speed |
|---|---|---|
| **Same Wi-Fi** | Both devices on one router | 10–60 MB/s |
| **Hotspot** | Windows *Settings → Network → Mobile hotspot* (or a phone hotspot). Other device joins it. Pick the **Hotspot** adapter when creating the room. | 10–40 MB/s |
| **Bluetooth** | Pair phone ↔ PC, turn on *Bluetooth tethering* on the phone, then on Windows: *Bluetooth devices → phone → Join a Personal Area Network → Connect using → Access point*. Pick the **Bluetooth PAN** adapter. | ~0.1–0.3 MB/s (chat and small files) |

**Why not direct browser Bluetooth?** Browsers can only connect *to* Bluetooth gadgets (Web Bluetooth). They can't advertise to each other the way the native BitChat app does. Bluetooth tethering gives both devices a real network link instead, and that works in every browser.

## Security notes

- The relay server is the host's own computer. Messages and files cross it only as encrypted blobs and are never stored. The server does handle the room token and checks the PIN, so the encryption protects you from everyone *except* whoever runs the server, which is normally you, the host.
- **Set a PIN and say it out loud.** The PIN is mixed into the encryption key, so a link that leaks (a forwarded WhatsApp message, a photo of the QR) is useless without it.
- Received files with risky types (HTML, SVG, scripts…) are downgraded to plain downloads and never rendered inline.
- Holding the link alone is not enough to unlock, impersonate the host, or destroy the room.
