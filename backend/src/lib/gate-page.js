/**
 * Gate Page Generator — Animated "Invite Only" Page
 *
 * Returns a self-contained HTML string for the invite-only gate page.
 * All CSS animations are pure keyframes — no JS dependencies.
 * Matches the SysAdmin Toolkit dark theme aesthetic.
 */

export function generateGatePage(title = 'Invite Only', message = '') {
    const escapedTitle = escapeHtml(title);
    const escapedMessage = escapeHtml(message);

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${escapedTitle} — SysAdmin Toolkit</title>
    <meta name="robots" content="noindex, nofollow">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        :root {
            --bg-deep: #07080f;
            --bg-card: rgba(17, 19, 30, 0.85);
            --border: rgba(99, 102, 241, 0.15);
            --glow: rgba(99, 102, 241, 0.3);
            --text-primary: #e2e4f0;
            --text-muted: #6b7094;
            --accent: #6366f1;
            --accent2: #a855f7;
            --accent3: #06b6d4;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-deep);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
            position: relative;
        }

        /* ── Background Stars ── */
        .stars {
            position: fixed;
            inset: 0;
            z-index: 0;
            pointer-events: none;
        }
        .star {
            position: absolute;
            width: 3px;
            height: 3px;
            background: rgba(255, 255, 255, 0.4);
            border-radius: 50%;
            animation: twinkle var(--dur, 3s) ease-in-out infinite alternate;
        }
        @keyframes twinkle {
            0% { opacity: 0.15; transform: scale(0.8); }
            100% { opacity: 0.8; transform: scale(1.2); }
        }

        /* ── Floating Shields ── */
        .floating-emoji {
            position: fixed;
            font-size: var(--size, 2rem);
            opacity: 0.08;
            animation: floatUp var(--dur, 12s) linear infinite;
            z-index: 0;
            pointer-events: none;
        }
        @keyframes floatUp {
            0% { transform: translateY(100vh) rotate(0deg); opacity: 0; }
            10% { opacity: 0.08; }
            90% { opacity: 0.08; }
            100% { transform: translateY(-100vh) rotate(360deg); opacity: 0; }
        }

        /* ── Gradient Orbs ── */
        .orb {
            position: fixed;
            border-radius: 50%;
            filter: blur(80px);
            opacity: 0.15;
            z-index: 0;
            pointer-events: none;
            animation: orbPulse 8s ease-in-out infinite alternate;
        }
        .orb-1 {
            width: 400px; height: 400px;
            background: var(--accent);
            top: -100px; left: -100px;
        }
        .orb-2 {
            width: 350px; height: 350px;
            background: var(--accent2);
            bottom: -80px; right: -80px;
            animation-delay: -3s;
        }
        .orb-3 {
            width: 250px; height: 250px;
            background: var(--accent3);
            top: 50%; left: 50%;
            transform: translate(-50%, -50%);
            animation-delay: -5s;
            opacity: 0.08;
        }
        @keyframes orbPulse {
            0% { transform: scale(1); opacity: 0.1; }
            100% { transform: scale(1.2); opacity: 0.2; }
        }

        /* ── Main Container ── */
        .gate-container {
            position: relative;
            z-index: 10;
            text-align: center;
            max-width: 520px;
            width: 90%;
            padding: 20px;
        }

        /* ── Guard Character ── */
        .guard {
            position: relative;
            width: 160px;
            height: 180px;
            margin: 0 auto 30px;
            animation: guardBounce 3s ease-in-out infinite;
        }
        @keyframes guardBounce {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-12px); }
        }

        /* Shield body */
        .guard-shield {
            position: absolute;
            bottom: 20px;
            left: 50%;
            transform: translateX(-50%);
            width: 100px;
            height: 120px;
            background: linear-gradient(135deg, #6366f1 0%, #4f46e5 50%, #3730a3 100%);
            clip-path: polygon(50% 100%, 0% 25%, 0% 0%, 100% 0%, 100% 25%);
            border-radius: 4px 4px 0 0;
            box-shadow: 0 8px 40px rgba(99, 102, 241, 0.3);
        }
        .guard-shield::after {
            content: '🔒';
            position: absolute;
            top: 28%;
            left: 50%;
            transform: translateX(-50%);
            font-size: 2rem;
            filter: drop-shadow(0 2px 8px rgba(0,0,0,0.3));
        }

        /* Guard face */
        .guard-face {
            position: absolute;
            top: 0;
            left: 50%;
            transform: translateX(-50%);
            width: 64px;
            height: 64px;
            background: linear-gradient(135deg, #fbbf24 0%, #f59e0b 100%);
            border-radius: 50%;
            box-shadow: 0 4px 20px rgba(251, 191, 36, 0.2);
        }
        /* Eyes */
        .guard-face::before {
            content: '';
            position: absolute;
            top: 22px;
            left: 15px;
            width: 8px;
            height: 10px;
            background: #1e1b4b;
            border-radius: 50%;
            box-shadow: 26px 0 0 #1e1b4b;
            animation: blink 4s ease-in-out infinite;
        }
        @keyframes blink {
            0%, 96%, 100% { transform: scaleY(1); }
            98% { transform: scaleY(0.1); }
        }
        /* Smile */
        .guard-face::after {
            content: '';
            position: absolute;
            bottom: 14px;
            left: 50%;
            transform: translateX(-50%);
            width: 20px;
            height: 8px;
            border-bottom: 3px solid #1e1b4b;
            border-radius: 0 0 12px 12px;
        }

        /* Guard helmet */
        .guard-helmet {
            position: absolute;
            top: -8px;
            left: 50%;
            transform: translateX(-50%);
            width: 72px;
            height: 32px;
            background: linear-gradient(135deg, #6366f1 0%, #4338ca 100%);
            border-radius: 36px 36px 8px 8px;
            box-shadow: 0 2px 10px rgba(99, 102, 241, 0.3);
        }
        .guard-helmet::after {
            content: '';
            position: absolute;
            top: -8px;
            left: 50%;
            transform: translateX(-50%);
            width: 14px;
            height: 14px;
            background: #fbbf24;
            border-radius: 50%;
            box-shadow: 0 0 12px rgba(251, 191, 36, 0.5);
        }

        /* ── Card ── */
        .gate-card {
            background: var(--bg-card);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 40px 36px 36px;
            position: relative;
            overflow: hidden;
            animation: cardAppear 0.8s ease-out;
        }
        .gate-card::before {
            content: '';
            position: absolute;
            inset: -1px;
            border-radius: 20px;
            padding: 1px;
            background: linear-gradient(135deg, rgba(99,102,241,0.3), transparent 50%, rgba(168,85,247,0.3));
            -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
            -webkit-mask-composite: xor;
            mask-composite: exclude;
            pointer-events: none;
            animation: borderGlow 4s ease-in-out infinite alternate;
        }
        @keyframes borderGlow {
            0% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        @keyframes cardAppear {
            from { opacity: 0; transform: translateY(30px) scale(0.95); }
            to { opacity: 1; transform: translateY(0) scale(1); }
        }

        /* ── Badge ── */
        .gate-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: rgba(99, 102, 241, 0.1);
            border: 1px solid rgba(99, 102, 241, 0.2);
            border-radius: 24px;
            padding: 6px 16px;
            font-size: 0.72rem;
            font-weight: 700;
            color: var(--accent);
            text-transform: uppercase;
            letter-spacing: 0.1em;
            margin-bottom: 20px;
            animation: badgePulse 2s ease-in-out infinite;
        }
        .gate-badge-dot {
            width: 6px;
            height: 6px;
            background: var(--accent);
            border-radius: 50%;
            animation: dotPulse 1.5s ease-in-out infinite;
        }
        @keyframes dotPulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.4; transform: scale(0.7); }
        }
        @keyframes badgePulse {
            0%, 100% { box-shadow: 0 0 0 0 rgba(99, 102, 241, 0); }
            50% { box-shadow: 0 0 0 6px rgba(99, 102, 241, 0.08); }
        }

        /* ── Title ── */
        .gate-title {
            font-size: 2rem;
            font-weight: 900;
            background: linear-gradient(135deg, #6366f1 0%, #a855f7 40%, #06b6d4 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: -0.03em;
            line-height: 1.2;
            margin-bottom: 16px;
        }

        /* ── Message ── */
        .gate-message {
            color: var(--text-muted);
            font-size: 0.92rem;
            line-height: 1.7;
            margin-bottom: 28px;
            max-width: 400px;
            margin-left: auto;
            margin-right: auto;
        }

        /* ── Animated Lock Row ── */
        .lock-row {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            padding: 14px 24px;
            background: rgba(99, 102, 241, 0.05);
            border: 1px solid rgba(99, 102, 241, 0.1);
            border-radius: 12px;
            margin-bottom: 20px;
        }
        .lock-icon {
            font-size: 1.3rem;
            animation: lockWiggle 2.5s ease-in-out infinite;
        }
        @keyframes lockWiggle {
            0%, 100% { transform: rotate(0deg); }
            15% { transform: rotate(-12deg); }
            30% { transform: rotate(8deg); }
            45% { transform: rotate(-5deg); }
            60% { transform: rotate(0deg); }
        }
        .lock-text {
            font-size: 0.78rem;
            font-weight: 600;
            color: var(--text-muted);
            letter-spacing: 0.03em;
        }

        /* ── Footer ── */
        .gate-footer {
            font-size: 0.72rem;
            color: rgba(107, 112, 148, 0.5);
            margin-top: 8px;
        }
        .gate-footer a {
            color: rgba(99, 102, 241, 0.5);
            text-decoration: none;
            transition: color 0.2s;
        }
        .gate-footer a:hover { color: var(--accent); }

        /* ── Bouncing Dots ── */
        .dots {
            display: flex;
            justify-content: center;
            gap: 6px;
            margin-top: 24px;
        }
        .dot {
            width: 8px;
            height: 8px;
            background: var(--accent);
            border-radius: 50%;
            opacity: 0.4;
            animation: dotBounce 1.4s ease-in-out infinite;
        }
        .dot:nth-child(2) { animation-delay: 0.2s; background: var(--accent2); }
        .dot:nth-child(3) { animation-delay: 0.4s; background: var(--accent3); }
        @keyframes dotBounce {
            0%, 80%, 100% { transform: translateY(0); opacity: 0.4; }
            40% { transform: translateY(-10px); opacity: 1; }
        }

        /* ── Wave ── */
        .wave-container {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            height: 80px;
            z-index: 1;
            overflow: hidden;
            pointer-events: none;
        }
        .wave {
            position: absolute;
            bottom: -5px;
            left: -10%;
            width: 120%;
            height: 60px;
            background: linear-gradient(135deg, rgba(99,102,241,0.08), rgba(168,85,247,0.05));
            border-radius: 50% 50% 0 0 / 100% 100% 0 0;
            animation: waveFloat 6s ease-in-out infinite;
        }
        .wave-2 {
            animation-delay: -2s;
            opacity: 0.5;
            height: 50px;
            bottom: 0;
        }
        @keyframes waveFloat {
            0%, 100% { transform: translateX(0) translateY(0); }
            50% { transform: translateX(2%) translateY(-8px); }
        }

        /* ── Responsive ── */
        @media (max-width: 480px) {
            .gate-title { font-size: 1.6rem; }
            .gate-card { padding: 30px 24px 28px; }
            .guard { transform: scale(0.85); margin-bottom: 20px; }
        }
    </style>
</head>
<body>
    <!-- Background Orbs -->
    <div class="orb orb-1"></div>
    <div class="orb orb-2"></div>
    <div class="orb orb-3"></div>

    <!-- Stars -->
    <div class="stars">
        ${generateStars(40)}
    </div>

    <!-- Floating Emojis -->
    <div class="floating-emoji" style="left:5%;--dur:14s;--size:2.5rem;animation-delay:-2s;">🛡️</div>
    <div class="floating-emoji" style="left:20%;--dur:18s;--size:1.8rem;animation-delay:-5s;">🔒</div>
    <div class="floating-emoji" style="left:40%;--dur:16s;--size:2rem;animation-delay:-8s;">🔐</div>
    <div class="floating-emoji" style="left:65%;--dur:20s;--size:2.2rem;animation-delay:-3s;">🛡️</div>
    <div class="floating-emoji" style="left:80%;--dur:15s;--size:1.6rem;animation-delay:-10s;">🔑</div>
    <div class="floating-emoji" style="left:92%;--dur:17s;--size:2rem;animation-delay:-7s;">🔒</div>

    <!-- Wave -->
    <div class="wave-container">
        <div class="wave"></div>
        <div class="wave wave-2"></div>
    </div>

    <!-- Main Content -->
    <div class="gate-container">
        <!-- Guard Character -->
        <div class="guard">
            <div class="guard-helmet"></div>
            <div class="guard-face"></div>
            <div class="guard-shield"></div>
        </div>

        <!-- Card -->
        <div class="gate-card">
            <div class="gate-badge">
                <span class="gate-badge-dot"></span>
                Access Restricted
            </div>

            <h1 class="gate-title">${escapedTitle}</h1>

            <p class="gate-message">${escapedMessage || 'This site is currently invite-only. If you believe you should have access, please contact the administrator.'}</p>

            <div class="lock-row">
                <span class="lock-icon">🔐</span>
                <span class="lock-text">Authentication required to proceed</span>
            </div>

            <div class="dots">
                <div class="dot"></div>
                <div class="dot"></div>
                <div class="dot"></div>
            </div>
        </div>

        <p class="gate-footer">
            Powered by <a href="/">SysAdmin Toolkit</a>
        </p>
    </div>
</body>
</html>`;
}

function generateStars(count) {
    let html = '';
    for (let i = 0; i < count; i++) {
        const x = Math.floor(Math.random() * 100);
        const y = Math.floor(Math.random() * 100);
        const dur = (2 + Math.random() * 4).toFixed(1);
        const delay = (Math.random() * 5).toFixed(1);
        const size = (1 + Math.random() * 3).toFixed(0);
        html += `<div class="star" style="left:${x}%;top:${y}%;width:${size}px;height:${size}px;--dur:${dur}s;animation-delay:${delay}s;"></div>\n`;
    }
    return html;
}

function escapeHtml(str) {
    if (!str) return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}
