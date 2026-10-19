/**
 * Procedural Audio Synthesizer for QR-CipherChat
 * Uses Web Audio API to create cyberpunk tactical sound effects without external audio files.
 */
class SoundEngine {
    constructor() {
        this.ctx = null;
        this.muted = false;
    }

    init() {
        if (!this.ctx) {
            const AudioContext = window.AudioContext || window.webkitAudioContext;
            if (AudioContext) {
                this.ctx = new AudioContext();
            }
        }
        if (this.ctx && this.ctx.state === 'suspended') {
            this.ctx.resume();
        }
    }

    playTone(freq, type = 'sine', duration = 0.08, gainVal = 0.15) {
        if (this.muted) return;
        this.init();
        if (!this.ctx) return;

        try {
            const osc = this.ctx.createOscillator();
            const gain = this.ctx.createGain();

            osc.type = type;
            osc.frequency.setValueAtTime(freq, this.ctx.currentTime);

            gain.gain.setValueAtTime(gainVal, this.ctx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.0001, this.ctx.currentTime + duration);

            osc.connect(gain);
            gain.connect(this.ctx.destination);

            osc.start();
            osc.stop(this.ctx.currentTime + duration);
        } catch (e) {
            // Audio context policy fallback
        }
    }

    // Message sent sound: crisp high-tech double chirp
    playSend() {
        this.playTone(880, 'sine', 0.05, 0.1);
        setTimeout(() => this.playTone(1320, 'sine', 0.06, 0.12), 40);
    }

    // Message received sound: soft dual harmonic
    playReceive() {
        this.playTone(1046, 'sine', 0.06, 0.12);
        setTimeout(() => this.playTone(1567, 'sine', 0.08, 0.1), 50);
    }

    // Verified / unlock success: rising tri-tone
    playUnlock() {
        this.playTone(523.25, 'triangle', 0.07, 0.15);
        setTimeout(() => this.playTone(659.25, 'triangle', 0.07, 0.15), 70);
        setTimeout(() => this.playTone(1046.50, 'sine', 0.14, 0.2), 140);
    }

    // Intruder alert / error: harsh saw tone
    playAlert() {
        this.playTone(220, 'sawtooth', 0.15, 0.25);
        setTimeout(() => this.playTone(165, 'sawtooth', 0.25, 0.3), 100);
    }

    // Vaporize / Self-Destruct sound: digital glitch descending into white noise
    playVaporize() {
        if (this.muted) return;
        this.init();
        if (!this.ctx) return;

        try {
            const now = this.ctx.currentTime;
            const osc = this.ctx.createOscillator();
            const gain = this.ctx.createGain();

            osc.type = 'sawtooth';
            osc.frequency.setValueAtTime(600, now);
            osc.frequency.exponentialRampToValueAtTime(40, now + 0.6);

            gain.gain.setValueAtTime(0.3, now);
            gain.gain.linearRampToValueAtTime(0.001, now + 0.6);

            osc.connect(gain);
            gain.connect(this.ctx.destination);

            osc.start();
            osc.stop(now + 0.6);
        } catch (e) {}
    }

    toggleMute() {
        this.muted = !this.muted;
        return this.muted;
    }
}

window.soundEngine = new SoundEngine();
