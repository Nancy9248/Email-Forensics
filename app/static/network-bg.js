/* ============================================================================
 * Email Threat Forensics — Premium Quantum Cryptography Visual Engine
 * A state-of-the-art, breathtaking visual experience featuring:
 *  - Quantum Particle Nebula & Ambient Energy Dust
 *  - Oscillating Quantum Waveform (Sine/Cosine Cryptographic Lattice)
 *  - Cascading Hex & SHA-256 Code Rain with Real-time Glyph Decryption
 *  - Glowing Hexagonal/Diamond Block Nodes & Laser Key Exchanges
 *  - Dual Concentric Radar Optics with Rotating Degree Reticles
 *  - Interactive Holographic Decryption Field & Dynamic HUD Reticle
 * ============================================================================ */

(function () {
    'use strict';

    const canvas = document.getElementById("bg-canvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let width = 0;
    let height = 0;
    let animId = null;

    // Cryptographic Character Sets & Keywords
    const HEX_CHARS = "0123456789ABCDEFabcdef";
    const CIPHER_TOKENS = [
        "0x4F9B", "SHA256", "AES-GCM", "RSA-4096", "ECC-25519", "NONCE", 
        "HASH", "ENTROPY", "KEY_VALID", "ECDSA", "SALT", "HMAC", "IV_8F", "0xFF01",
        "101101", "0x3C2A", "BLOCK_#89", "PADDING", "CIPHER", "CURVE25519", "Q_KEY"
    ];

    // Engine Configuration
    const CONFIG = {
        streamCount: 38,
        nodeCount: 26,
        sparkCount: 45,
        maxLinkDistSq: 170 * 170,
        colorCyan: "0, 240, 255",
        colorEmerald: "0, 255, 157",
        colorMagenta: "255, 0, 128",
        colorGold: "255, 184, 0",
        colorBlue: "59, 130, 246",
        mouseRadiusSq: 190 * 190
    };

    let streams = [];
    let nodes = [];
    let sparks = [];
    let packets = [];
    let ringAngle1 = 0;
    let ringAngle2 = Math.PI;
    let wavePhase = 0;
    let mouse = { x: -1000, y: -1000, active: false };

    function randChoice(arr) {
        return arr[Math.floor(Math.random() * arr.length)];
    }

    function randHex(len) {
        let res = "";
        for (let i = 0; i < len; i++) {
            res += HEX_CHARS[Math.floor(Math.random() * HEX_CHARS.length)];
        }
        return res;
    }

    // Draw regular polygon (e.g. Hexagon / Diamond)
    function drawPolygon(x, y, radius, sides, angle = 0) {
        ctx.beginPath();
        for (let i = 0; i < sides; i++) {
            const a = angle + (i * Math.PI * 2) / sides;
            const px = x + Math.cos(a) * radius;
            const py = y + Math.sin(a) * radius;
            if (i === 0) ctx.moveTo(px, py);
            else ctx.lineTo(px, py);
        }
        ctx.closePath();
    }

    function resize() {
        width = canvas.width = window.innerWidth;
        height = canvas.height = window.innerHeight;
        initStreams();
        initNodes();
        initSparks();
    }

    // 1. Initialize Cascading Streams
    function initStreams() {
        streams = [];
        const count = Math.min(CONFIG.streamCount, Math.floor(width / 40));

        for (let i = 0; i < count; i++) {
            const items = [];
            const length = 12 + Math.floor(Math.random() * 16);
            for (let j = 0; j < length; j++) {
                items.push({
                    text: Math.random() < 0.35 ? randChoice(CIPHER_TOKENS) : randHex(4),
                    isDecrypted: Math.random() < 0.2
                });
            }

            streams.push({
                x: (i + 0.5) * (width / count) + (Math.random() - 0.5) * 15,
                y: Math.random() * height,
                speed: 0.5 + Math.random() * 0.9,
                items: items,
                fontSize: 10 + Math.floor(Math.random() * 3),
                opacity: 0.12 + Math.random() * 0.18
            });
        }
    }

    // 2. Initialize Block Nodes
    function initNodes() {
        nodes = [];
        packets = [];
        const count = Math.min(CONFIG.nodeCount, Math.floor((width * height) / 28000));

        for (let i = 0; i < count; i++) {
            const isAlert = Math.random() < 0.15;
            nodes.push({
                x: Math.random() * width,
                y: Math.random() * height,
                vx: (Math.random() - 0.5) * 0.35,
                vy: (Math.random() - 0.5) * 0.35,
                radius: isAlert ? 7 : Math.random() * 2 + 5,
                sides: isAlert ? 4 : 6,
                angle: Math.random() * Math.PI,
                rotSpeed: (Math.random() - 0.5) * 0.02,
                hashLabel: "0x" + randHex(4),
                isAlert: isAlert,
                pulse: Math.random() * Math.PI * 2
            });
        }
    }

    // 3. Initialize Quantum Ambient Energy Sparks
    function initSparks() {
        sparks = [];
        for (let i = 0; i < CONFIG.sparkCount; i++) {
            sparks.push({
                x: Math.random() * width,
                y: Math.random() * height,
                vy: -(0.2 + Math.random() * 0.5),
                vx: (Math.random() - 0.5) * 0.2,
                radius: Math.random() * 1.8 + 0.6,
                alpha: Math.random() * 0.5 + 0.2,
                hue: Math.random() < 0.6 ? CONFIG.colorCyan : CONFIG.colorEmerald
            });
        }
    }

    function maybeSpawnPacket(n1, n2, distSq) {
        if (packets.length >= 16) return;
        if (Math.random() > 0.022) return;

        packets.push({
            x1: n1.x, y1: n1.y,
            x2: n2.x, y2: n2.y,
            progress: 0,
            speed: (1.4 + Math.random() * 0.8) / Math.sqrt(distSq),
            label: Math.random() < 0.5 ? "KEY_EXCHANGE" : "0x" + randHex(2),
            isAlert: n1.isAlert || n2.isAlert
        });
    }

    // Render Loop
    function render() {
        ctx.clearRect(0, 0, width, height);

        // A. Ambient Quantum Energy Nebula Gradient
        const bgGradient = ctx.createRadialGradient(width * 0.5, height * 0.4, 100, width * 0.5, height * 0.5, width * 0.8);
        bgGradient.addColorStop(0, "rgba(10, 20, 35, 0.4)");
        bgGradient.addColorStop(0.5, "rgba(7, 13, 22, 0.2)");
        bgGradient.addColorStop(1, "rgba(4, 7, 12, 0.0)");
        ctx.fillStyle = bgGradient;
        ctx.fillRect(0, 0, width, height);

        // B. Fine Cryptographic Matrix Grid Lines
        ctx.strokeStyle = "rgba(0, 240, 255, 0.035)";
        ctx.lineWidth = 0.5;
        const gridStep = 80;
        ctx.beginPath();
        for (let x = 0; x < width; x += gridStep) {
            ctx.moveTo(x, 0); ctx.lineTo(x, height);
        }
        for (let y = 0; y < height; y += gridStep) {
            ctx.moveTo(0, y); ctx.lineTo(width, y);
        }
        ctx.stroke();

        // C. Draw Oscillating Quantum Cryptographic Waveform (Bottom Screen)
        wavePhase += 0.015;
        ctx.lineWidth = 1.2;
        ctx.beginPath();
        for (let x = 0; x < width; x += 10) {
            const y1 = height * 0.88 + Math.sin(x * 0.008 + wavePhase) * 22 + Math.cos(x * 0.015 - wavePhase * 0.5) * 10;
            if (x === 0) ctx.moveTo(x, y1);
            else ctx.lineTo(x, y1);
        }
        ctx.strokeStyle = "rgba(0, 240, 255, 0.08)";
        ctx.stroke();

        ctx.beginPath();
        for (let x = 0; x < width; x += 10) {
            const y2 = height * 0.90 + Math.sin(x * 0.006 - wavePhase * 0.8) * 18 + Math.cos(x * 0.012 + wavePhase) * 12;
            if (x === 0) ctx.moveTo(x, y2);
            else ctx.lineTo(x, y2);
        }
        ctx.strokeStyle = "rgba(0, 255, 157, 0.06)";
        ctx.stroke();

        // D. Floating Quantum Sparks
        for (let i = 0; i < sparks.length; i++) {
            const sp = sparks[i];
            sp.y += sp.vy;
            sp.x += Math.sin(sp.y * 0.02) * 0.3;

            if (sp.y < -10) {
                sp.y = height + 10;
                sp.x = Math.random() * width;
            }

            ctx.beginPath();
            ctx.arc(sp.x, sp.y, sp.radius, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(${sp.hue}, ${sp.alpha * 0.4})`;
            ctx.fill();
        }

        // E. Rotating Dual Cryptographic Optics Reticle (Top-Right Anchor)
        ringAngle1 += 0.002;
        ringAngle2 -= 0.0015;

        const ringCX = width * 0.84;
        const ringCY = height * 0.25;
        const ringR1 = Math.min(230, width * 0.18);
        const ringR2 = ringR1 * 0.75;
        const ringR3 = ringR1 * 0.45;

        ctx.save();
        ctx.translate(ringCX, ringCY);

        // Outer Ring
        ctx.save();
        ctx.rotate(ringAngle1);
        ctx.strokeStyle = "rgba(0, 240, 255, 0.12)";
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.arc(0, 0, ringR1, 0, Math.PI * 2);
        ctx.stroke();

        // Degree Ticks
        for (let a = 0; a < Math.PI * 2; a += Math.PI / 18) {
            const tx1 = Math.cos(a) * (ringR1 - 6);
            const ty1 = Math.sin(a) * (ringR1 - 6);
            const tx2 = Math.cos(a) * (ringR1 + 6);
            const ty2 = Math.sin(a) * (ringR1 + 6);
            ctx.beginPath();
            ctx.moveTo(tx1, ty1); ctx.lineTo(tx2, ty2);
            ctx.stroke();
        }
        ctx.restore();

        // Middle Dashed Ring
        ctx.save();
        ctx.rotate(ringAngle2);
        ctx.strokeStyle = "rgba(0, 255, 157, 0.10)";
        ctx.setLineDash([8, 10]);
        ctx.beginPath();
        ctx.arc(0, 0, ringR2, 0, Math.PI * 2);
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.restore();

        // Inner Solid Ring with Glow
        ctx.strokeStyle = "rgba(255, 184, 0, 0.12)";
        ctx.beginPath();
        ctx.arc(0, 0, ringR3, 0, Math.PI * 2);
        ctx.stroke();

        // Crosshair Lines
        ctx.strokeStyle = "rgba(0, 240, 255, 0.08)";
        ctx.beginPath();
        ctx.moveTo(-ringR1 - 20, 0); ctx.lineTo(ringR1 + 20, 0);
        ctx.moveTo(0, -ringR1 - 20); ctx.lineTo(0, ringR1 + 20);
        ctx.stroke();

        ctx.fillStyle = "rgba(0, 240, 255, 0.35)";
        ctx.font = '10px "SFMono-Regular", Consolas, monospace';
        ctx.fillText("QUANTUM_KEY_EXCHANGE // LATTICE_V5", ringR1 - 100, ringR1 + 24);

        ctx.restore();

        // F. Cascading Cryptographic Text Streams
        ctx.font = '11px "SFMono-Regular", Consolas, monospace';
        for (let i = 0; i < streams.length; i++) {
            const s = streams[i];
            s.y += s.speed;
            if (s.y > height + s.items.length * s.fontSize) {
                s.y = -s.items.length * s.fontSize;
                s.x = (i + 0.5) * (width / streams.length) + (Math.random() - 0.5) * 15;
            }

            for (let j = 0; j < s.items.length; j++) {
                const item = s.items[j];
                const itemY = s.y - j * s.fontSize * 1.45;
                if (itemY < -20 || itemY > height + 20) continue;

                // Character Mutation (Real-Time Decryption Look)
                if (Math.random() < 0.009) {
                    item.text = Math.random() < 0.35 ? randChoice(CIPHER_TOKENS) : randHex(4);
                }

                // Check distance to cursor for Decryption Lens
                const dx = s.x - mouse.x;
                const dy = itemY - mouse.y;
                const distSq = dx * dx + dy * dy;
                const inMouseRange = mouse.active && distSq < CONFIG.mouseRadiusSq;

                if (inMouseRange) {
                    ctx.fillStyle = j === 0 ? "rgba(255, 184, 0, 0.95)" : "rgba(0, 255, 157, 0.9)";
                    ctx.shadowColor = "#00FF9D";
                    ctx.shadowBlur = 6;
                } else if (j === 0) {
                    ctx.fillStyle = `rgba(${CONFIG.colorCyan}, ${s.opacity * 2.5})`;
                    ctx.shadowColor = "#00F0FF";
                    ctx.shadowBlur = 4;
                } else {
                    ctx.fillStyle = `rgba(${CONFIG.colorCyan}, ${s.opacity})`;
                    ctx.shadowBlur = 0;
                }

                ctx.fillText(item.text, s.x, itemY);
                ctx.shadowBlur = 0;
            }
        }

        // G. Update & Draw Cryptographic Polygon Nodes (Hexagons & Diamonds)
        for (let i = 0; i < nodes.length; i++) {
            const n = nodes[i];
            n.x += n.vx;
            n.y += n.vy;
            n.angle += n.rotSpeed;

            if (n.x < 0 || n.x > width) n.vx *= -1;
            if (n.y < 0 || n.y > height) n.vy *= -1;

            n.pulse += 0.03;
            const pulseScale = 1 + Math.sin(n.pulse) * 0.35;

            // Outer Pulse Ring
            ctx.beginPath();
            ctx.arc(n.x, n.y, n.radius * 2.4 * pulseScale, 0, Math.PI * 2);
            ctx.fillStyle = n.isAlert ? "rgba(255, 0, 128, 0.06)" : "rgba(0, 240, 255, 0.05)";
            ctx.fill();

            // Polygon Node (Hexagon / Diamond)
            drawPolygon(n.x, n.y, n.radius * pulseScale, n.sides, n.angle);
            ctx.strokeStyle = n.isAlert ? `rgba(${CONFIG.colorMagenta}, 0.85)` : `rgba(${CONFIG.colorEmerald}, 0.75)`;
            ctx.lineWidth = 1.2;
            ctx.stroke();
            ctx.fillStyle = n.isAlert ? "rgba(255, 0, 128, 0.25)" : "rgba(0, 240, 255, 0.25)";
            ctx.fill();

            // Hash Label below node
            ctx.fillStyle = "rgba(139, 147, 167, 0.5)";
            ctx.font = '9px "SFMono-Regular", Consolas, monospace';
            ctx.fillText(n.hashLabel, n.x - 16, n.y + n.radius + 14);
            ctx.font = '11px "SFMono-Regular", Consolas, monospace';
        }

        // H. Draw Interconnected Laser Key Paths & Packets
        for (let i = 0; i < nodes.length; i++) {
            for (let j = i + 1; j < nodes.length; j++) {
                const n1 = nodes[i];
                const n2 = nodes[j];
                const dx = n1.x - n2.x;
                const dy = n1.y - n2.y;
                const distSq = dx * dx + dy * dy;

                if (distSq < CONFIG.maxLinkDistSq) {
                    const alpha = (1 - distSq / CONFIG.maxLinkDistSq) * 0.24;
                    const isAlertLine = n1.isAlert || n2.isAlert;
                    const colorRGB = isAlertLine ? CONFIG.colorMagenta : CONFIG.colorEmerald;

                    ctx.strokeStyle = `rgba(${colorRGB}, ${alpha})`;
                    ctx.lineWidth = isAlertLine ? 1.4 : 0.8;
                    ctx.beginPath();
                    ctx.moveTo(n1.x, n1.y);
                    ctx.lineTo(n2.x, n2.y);
                    ctx.stroke();

                    maybeSpawnPacket(n1, n2, distSq);
                }
            }
        }

        // I. Update & Draw Key Exchange Packets
        for (let i = packets.length - 1; i >= 0; i--) {
            const p = packets[i];
            p.progress += p.speed;

            if (p.progress >= 1) {
                packets.splice(i, 1);
                continue;
            }

            const currX = p.x1 + (p.x2 - p.x1) * p.progress;
            const currY = p.y1 + (p.y2 - p.y1) * p.progress;

            ctx.fillStyle = p.isAlert ? `rgba(${CONFIG.colorMagenta}, 0.95)` : `rgba(${CONFIG.colorGold}, 0.95)`;
            ctx.shadowColor = p.isAlert ? "#FF007F" : "#FFB800";
            ctx.shadowBlur = 6;
            ctx.font = '9px "SFMono-Regular", Consolas, monospace';
            ctx.fillText(p.label, currX - 10, currY - 4);
            ctx.shadowBlur = 0;
            ctx.font = '11px "SFMono-Regular", Consolas, monospace';
        }

        // J. Interactive Holographic Decryption Reticle (Mouse Field)
        if (mouse.active) {
            const radius = Math.sqrt(CONFIG.mouseRadiusSq);

            // Outer Dashed Decryption Circle
            ctx.strokeStyle = "rgba(0, 255, 157, 0.45)";
            ctx.lineWidth = 1;
            ctx.setLineDash([6, 6]);
            ctx.beginPath();
            ctx.arc(mouse.x, mouse.y, radius, 0, Math.PI * 2);
            ctx.stroke();
            ctx.setLineDash([]);

            // Inner Rotating Compass Ring
            ctx.strokeStyle = "rgba(0, 240, 255, 0.35)";
            ctx.beginPath();
            ctx.arc(mouse.x, mouse.y, radius * 0.6, 0, Math.PI * 2);
            ctx.stroke();

            // Crosshair Precision Markings
            ctx.strokeStyle = "rgba(255, 184, 0, 0.7)";
            ctx.beginPath();
            ctx.moveTo(mouse.x - 14, mouse.y); ctx.lineTo(mouse.x + 14, mouse.y);
            ctx.moveTo(mouse.x, mouse.y - 14); ctx.lineTo(mouse.x, mouse.y + 14);
            ctx.stroke();

            // Holographic HUD Tag
            ctx.fillStyle = "rgba(0, 255, 157, 0.95)";
            ctx.shadowColor = "#00FF9D";
            ctx.shadowBlur = 4;
            ctx.font = '10px "SFMono-Regular", Consolas, monospace';
            ctx.fillText(`QUANTUM_DECRYPT // X:${Math.round(mouse.x)} Y:${Math.round(mouse.y)}`, mouse.x + 16, mouse.y - 16);
            ctx.shadowBlur = 0;
            ctx.font = '11px "SFMono-Regular", Consolas, monospace';
        }

        animId = requestAnimationFrame(render);
    }

    // Event Listeners
    window.addEventListener("resize", resize);

    window.addEventListener("mousemove", (e) => {
        mouse.x = e.clientX;
        mouse.y = e.clientY;
        mouse.active = true;
    });

    window.addEventListener("mouseleave", () => {
        mouse.active = false;
    });

    // Start Engine
    resize();
    render();
})();