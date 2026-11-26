import { chromium } from 'playwright';
import fs from 'fs';
import path from 'path';

// Common CSS Styles shared across all concepts
const commonHead = (title, customStyles = '') => `
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@500;600;700;800&family=Plus+Jakarta+Sans:wght@700;800;900&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
    <style>
        :root {
            --bg-base: #06080f;
            --bg-panel: #0d111a;
            --bg-surface: #131926;
            --bg-card: #111827;
            --border-subtle: rgba(255, 255, 255, 0.08);
            --border-highlight: rgba(99, 102, 241, 0.35);
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent-brand: #6366f1;
            --accent-cyan: #06b6d4;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --accent-amber: #f59e0b;
            --accent-purple: #a855f7;
            --font-sans: 'Inter', -apple-system, sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: var(--bg-base);
            color: var(--text-primary);
            font-family: var(--font-sans);
            font-size: 13px;
            padding: 24px;
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
        }
        .container { max-width: 1440px; margin: 0 auto; }
        .concept-header-banner {
            background: linear-gradient(135deg, rgba(99,102,241,0.15) 0%, rgba(6,182,212,0.08) 100%);
            border: 1px solid rgba(99,102,241,0.3);
            border-radius: 12px;
            padding: 16px 22px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
        }
        .concept-title { font-size: 1.25rem; font-weight: 800; color: #fff; display: flex; align-items: center; gap: 10px; }
        .concept-badge { background: #6366f1; color: #fff; font-size: 0.72rem; font-weight: 800; padding: 3px 10px; border-radius: 999px; text-transform: uppercase; }
        .concept-desc { font-size: 0.82rem; color: var(--text-secondary); margin-top: 4px; }
        
        /* 7-Card Micro Strip */
        .kpi-7-strip { display: grid; grid-template-columns: repeat(7, 1fr); gap: 10px; margin-bottom: 16px; }
        .kpi-card { background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 11px 8px; text-align: center; }
        .kpi-val { font-size: 1.45rem; font-weight: 800; letter-spacing: -0.03em; line-height: 1.1; }
        .kpi-lbl { font-size: 0.65rem; font-weight: 800; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em; margin-top: 4px; }

        /* Scrubber & Filter Ribbon */
        .filter-ribbon-box { background: var(--bg-panel); border: 1px solid var(--border-subtle); border-radius: 12px; padding: 14px 18px; margin-bottom: 20px; }
        .timeline-row { display: flex; align-items: center; justify-content: space-between; gap: 14px; margin-bottom: 12px; flex-wrap: wrap; }
        .hist-slider-wrap { flex: 1; height: 38px; background: rgba(0,0,0,0.5); border: 1px solid var(--border-subtle); border-radius: 8px; position: relative; display: flex; align-items: flex-end; padding: 4px 6px; }
        .hist-bars { display: flex; align-items: flex-end; gap: 3px; position: absolute; bottom: 4px; left: 6px; right: 6px; height: 26px; }
        .hbar { flex: 1; background: #334155; opacity: 0.45; border-radius: 2px 2px 0 0; }
        .hbar.in-win { background: #6366f1; opacity: 1; }
        .hbar.spike { background: #ef4444; }
        .hbar.spike.in-win { box-shadow: 0 0 8px rgba(239,68,68,0.85); opacity: 1; }
        .slider-handle-zip { position: absolute; top: 4px; bottom: 4px; width: 14px; background: #1e293b; border: 2px solid #818cf8; border-radius: 5px; z-index: 5; }
        .time-badge { width: 285px; background: var(--bg-surface); border: 1px solid var(--border-highlight); border-radius: 6px; padding: 6px 12px; font-family: var(--font-mono); font-size: 0.76rem; font-weight: 700; display: flex; justify-content: space-between; align-items: center; }
        .time-pill { font-size: 0.7rem; background: rgba(99,102,241,0.2); color: #818cf8; padding: 2px 7px; border-radius: 4px; font-weight: 800; }
        .dropdowns-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
        .f-select { background: var(--bg-surface); border: 1px solid var(--border-subtle); color: var(--text-primary); font-size: 0.76rem; padding: 6px 10px; border-radius: 6px; font-weight: 600; }
        
        /* 4-Pillars */
        .pillar-grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 20px; }
        .pillar-card { background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: 10px; overflow: hidden; }
        .pillar-head { padding: 10px 14px; background: rgba(255,255,255,0.02); border-bottom: 1px solid var(--border-subtle); font-weight: 800; font-size: 0.84rem; display: flex; justify-content: space-between; align-items: center; }
        .pillar-body { padding: 8px 12px; }
        .p-row { display: flex; justify-content: space-between; align-items: center; padding: 6px 0; border-bottom: 1px solid rgba(255,255,255,0.03); font-size: 0.78rem; }
        .p-row:last-child { border-bottom: none; }
        .ip-badge { font-family: var(--font-mono); color: #818cf8; font-weight: 700; }
        .cnt-badge { font-weight: 800; color: #fff; }

        ${customStyles}
    </style>
</head>
<body>
<div class="container">
`;

const commonFooter = `
</div>
</body>
</html>
`;

// Define all 10 concepts
const concepts = [
    {
        id: 1,
        name: "concept_01_tactical_incident_cockpit",
        title: "Concept 1: The Tactical Incident Cockpit",
        badge: "Bold & High-Urgency IR",
        desc: "Designed for live active cyber incident response. High-contrast threat indicators, instant 1-click mitigation dock, and ranked attack vectors.",
        render: () => `
        ${commonHead("Concept 1: Tactical Incident Cockpit", `
            .threat-alert-box { background: linear-gradient(90deg, rgba(239,68,68,0.15) 0%, rgba(245,158,11,0.08) 100%); border: 1px solid rgba(239,68,68,0.4); border-radius: 10px; padding: 14px 20px; margin-bottom: 18px; display: flex; justify-content: space-between; align-items: center; }
            .threat-score-gauge { display: flex; align-items: center; gap: 12px; }
            .score-circle { width: 44px; height: 44px; border-radius: 50%; background: #ef4444; color: #fff; font-size: 1.15rem; font-weight: 900; display: flex; align-items: center; justify-content: center; box-shadow: 0 0 15px rgba(239,68,68,0.6); }
            .dual-warfare-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px; }
            .fw-gen-panel { background: #0b0f19; border: 1px solid rgba(239,68,68,0.3); border-radius: 10px; padding: 14px; }
            .fw-code-box { background: #060911; border: 1px solid rgba(255,255,255,0.08); border-radius: 6px; padding: 12px; font-family: var(--font-mono); font-size: 0.75rem; color: #fca5a5; max-height: 180px; overflow-y: auto; }
        `)}
            <div class="concept-header-banner">
                <div>
                    <div class="concept-title"><i class="bi bi-shield-slash-fill" style="color:#ef4444;"></i> Concept 1: The Tactical Incident Cockpit <span class="concept-badge">SOC Tactical</span></div>
                    <div class="concept-desc">High-urgency attack vector radar with active threat scoring and live 1-click firewall generator integrated side-by-side.</div>
                </div>
                <button style="background:#ef4444;color:#fff;border:none;border-radius:6px;padding:8px 16px;font-weight:800;font-size:0.8rem;cursor:pointer;"><i class="bi bi-fire"></i> 1-Click Mitigate All Threats</button>
            </div>

            <!-- Threat Alert Radar -->
            <div class="threat-alert-box">
                <div class="threat-score-gauge">
                    <div class="score-circle">88</div>
                    <div>
                        <div style="font-size:0.95rem;font-weight:800;color:#f87171;">CRITICAL INCIDENT DETECTED: Multi-Vector Layer-7 Flood</div>
                        <div style="font-size:0.75rem;color:var(--text-secondary);margin-top:2px;">137 spoofed bots, 4,210 xmlrpc.php POST floods, and 14 Tor exit nodes active in current window.</div>
                    </div>
                </div>
                <div style="display:flex;gap:8px;">
                    <span style="background:rgba(239,68,68,0.2);color:#fca5a5;border:1px solid rgba(239,68,68,0.4);padding:4px 10px;border-radius:6px;font-size:0.72rem;font-weight:700;">🚨 137 Spoofed Bots</span>
                    <span style="background:rgba(245,158,11,0.2);color:#fde68a;border:1px solid rgba(245,158,11,0.4);padding:4px 10px;border-radius:6px;font-size:0.72rem;font-weight:700;">⚠️ 3,820 4xx/5xx Drops</span>
                </div>
            </div>

            <!-- 7-Metric Strip -->
            <div class="kpi-7-strip">
                <div class="kpi-card" style="border-top:3px solid #6366f1;"><div class="kpi-val" style="color:#fff;">47,304</div><div class="kpi-lbl">TOTAL REQUESTS</div></div>
                <div class="kpi-card" style="border-top:3px solid #818cf8;"><div class="kpi-val" style="color:#818cf8;">19,913</div><div class="kpi-lbl">UNIQUE IPS</div></div>
                <div class="kpi-card" style="border-top:3px solid #06b6d4;"><div class="kpi-val" style="color:#22d3ee;">14</div><div class="kpi-lbl">COUNTRIES</div></div>
                <div class="kpi-card" style="border-top:3px solid #a855f7;"><div class="kpi-val" style="color:#c084fc;">64</div><div class="kpi-lbl">ASNS</div></div>
                <div class="kpi-card" style="border-top:3px solid #10b981;"><div class="kpi-val" style="color:#34d399;">68.2%</div><div class="kpi-lbl">HUMAN TRAFFIC</div></div>
                <div class="kpi-card" style="border-top:3px solid #38bdf8;"><div class="kpi-val" style="color:#38bdf8;">14,942</div><div class="kpi-lbl">VERIFIED (31.6%)</div></div>
                <div class="kpi-card" style="border-top:3px solid #ef4444;background:rgba(239,68,68,0.06);border-color:rgba(239,68,68,0.3);"><div class="kpi-val" style="color:#f87171;">137</div><div class="kpi-lbl" style="color:#fca5a5;">SPOOFED (0.3%)</div></div>
            </div>

            <!-- Dual Warfare Split -->
            <div class="dual-warfare-grid">
                <!-- Left: Top Attacking IPs Checklist -->
                <div class="pillar-card">
                    <div class="pillar-head"><span><i class="bi bi-radar" style="color:#ef4444;margin-right:6px;"></i> Top Hostile Attack Vectors</span><span style="font-size:0.72rem;color:var(--text-muted);">Ranked by Abuse</span></div>
                    <div class="pillar-body">
                        <div class="p-row"><span><input type="checkbox" checked style="margin-right:6px;" /> <strong class="ip-badge">185.220.101.5</strong> (Tor Exit Node)</span><span class="cnt-badge" style="color:#f87171;">4,120 reqs</span></div>
                        <div class="p-row"><span><input type="checkbox" checked style="margin-right:6px;" /> <strong class="ip-badge">45.154.255.88</strong> (Fake Googlebot)</span><span class="cnt-badge" style="color:#f87171;">2,840 reqs</span></div>
                        <div class="p-row"><span><input type="checkbox" checked style="margin-right:6px;" /> <strong class="ip-badge">194.26.29.112</strong> (XMLRPC Brute Force)</span><span class="cnt-badge" style="color:#f87171;">1,950 reqs</span></div>
                        <div class="p-row"><span><input type="checkbox" checked style="margin-right:6px;" /> <strong class="ip-badge">89.248.165.74</strong> (Env/Git Scanner)</span><span class="cnt-badge" style="color:#f87171;">1,420 reqs</span></div>
                    </div>
                </div>

                <!-- Right: Realtime Generated Firewall Directives -->
                <div class="fw-gen-panel">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                        <span style="font-weight:800;font-size:0.84rem;color:#f87171;"><i class="bi bi-shield-check"></i> Live Firewall Directives (Nginx / Cloudflare WAF)</span>
                        <button style="background:#1e293b;border:1px solid #475569;color:#fff;border-radius:4px;padding:3px 8px;font-size:0.7rem;cursor:pointer;"><i class="bi bi-clipboard"></i> Copy All</button>
                    </div>
                    <div class="fw-code-box">
# Auto-Generated Threat Mitigation Rules
deny 185.220.101.5;   # Tor Exit Node Flood
deny 45.154.255.88;    # Spoofed Crawler IP
deny 194.26.29.112;    # XMLRPC Exploit Attack
location ~* /(xmlrpc\.php|\.env|\.git) { deny all; return 403; }
                    </div>
                </div>
            </div>
        ${commonFooter}
        `
    },
    {
        id: 2,
        name: "concept_02_clean_minimalist_studio",
        title: "Concept 2: The Clean Minimalist Studio",
        badge: "Minimalist & Spacious",
        desc: "Inspired by Apple and Linear. Maximum breathing room, ultra-clean typography, subtle slate borders, and zero visual clutter.",
        render: () => `
        ${commonHead("Concept 2: Clean Minimalist Studio", `
            .clean-canvas-card { background: #0a0d14; border: 1px solid rgba(255,255,255,0.06); border-radius: 12px; padding: 20px; margin-bottom: 20px; }
            .metric-pill-bar { display: flex; align-items: center; justify-content: space-between; background: #0d121c; border: 1px solid rgba(255,255,255,0.06); border-radius: 999px; padding: 8px 24px; margin-bottom: 24px; }
            .mpill { display: flex; align-items: center; gap: 8px; font-size: 0.8rem; }
            .mpill strong { font-size: 1.1rem; color: #fff; font-weight: 800; }
        `)}
            <div class="concept-header-banner" style="background:transparent;border-color:rgba(255,255,255,0.08);">
                <div>
                    <div class="concept-title"><i class="bi bi-circle-square" style="color:#818cf8;"></i> Concept 2: The Clean Minimalist Studio <span class="concept-badge" style="background:#475569;">Linear Minimal</span></div>
                    <div class="concept-desc">Generous whitespace, elegant subtle borders, and razor-sharp typographic hierarchy for focused incident triage.</div>
                </div>
            </div>

            <!-- Single Minimalist Pill Bar -->
            <div class="metric-pill-bar">
                <div class="mpill"><span style="color:var(--text-muted);">Requests:</span><strong>47,304</strong></div>
                <div style="width:1px;height:18px;background:rgba(255,255,255,0.1);"></div>
                <div class="mpill"><span style="color:var(--text-muted);">Unique IPs:</span><strong style="color:#818cf8;">19,913</strong></div>
                <div style="width:1px;height:18px;background:rgba(255,255,255,0.1);"></div>
                <div class="mpill"><span style="color:var(--text-muted);">Human:</span><strong style="color:#34d399;">68.2%</strong></div>
                <div style="width:1px;height:18px;background:rgba(255,255,255,0.1);"></div>
                <div class="mpill"><span style="color:var(--text-muted);">Verified Bots:</span><strong style="color:#38bdf8;">14,942</strong></div>
                <div style="width:1px;height:18px;background:rgba(255,255,255,0.1);"></div>
                <div class="mpill"><span style="color:var(--text-muted);">Threats:</span><strong style="color:#f87171;">137 spoofed</strong></div>
            </div>

            <!-- Master Timeline & Scrubber -->
            <div class="clean-canvas-card">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;">
                    <span style="font-weight:700;font-size:0.9rem;color:#fff;"><i class="bi bi-graph-up" style="color:#818cf8;margin-right:6px;"></i> Traffic Velocity & Threat Scrubber</span>
                    <div class="time-badge" style="width:auto;gap:12px;"><i class="bi bi-clock"></i> 07:31:33 → 14:14:44 <span class="time-pill">6h 43m span</span></div>
                </div>
                <!-- Mini Histogram -->
                <div class="hist-slider-wrap" style="height:44px;margin-bottom:14px;">
                    <div class="hist-bars">
                        <div class="hbar" style="height:35%;"></div><div class="hbar in-win" style="height:65%;"></div><div class="hbar in-win spike" style="height:100%;"></div><div class="hbar in-win" style="height:55%;"></div><div class="hbar" style="height:25%;"></div>
                    </div>
                    <div class="slider-handle-zip" style="left:20%;"></div>
                    <div class="slider-handle-zip" style="left:80%;"></div>
                </div>
            </div>

            <!-- 4 Minimal Pillars -->
            <div class="pillar-grid-4">
                <div class="pillar-card"><div class="pillar-head"><span>Top Client IPs</span><i class="bi bi-globe"></i></div><div class="pillar-body"><div class="p-row"><code>185.220.101.5</code><strong>4,120</strong></div><div class="p-row"><code>40.77.167.1</code><strong>3,410</strong></div></div></div>
                <div class="pillar-card"><div class="pillar-head"><span>Targeted Endpoints</span><i class="bi bi-link-45deg"></i></div><div class="pillar-body"><div class="p-row"><code>/products</code><strong>12,400</strong></div><div class="p-row"><code>/xmlrpc.php</code><strong style="color:#f87171;">4,120</strong></div></div></div>
                <div class="pillar-card"><div class="pillar-head"><span>Networks & ASNs</span><i class="bi bi-diagram-3"></i></div><div class="pillar-body"><div class="p-row"><span>AS15169 Google</span><strong>14,200</strong></div><div class="p-row"><span>AS9009 Tor</span><strong style="color:#f87171;">4,120</strong></div></div></div>
                <div class="pillar-card"><div class="pillar-head"><span>Bot Intelligence</span><i class="bi bi-shield-check"></i></div><div class="pillar-body"><div class="p-row"><span style="color:#34d399;">Googlebot</span><strong>10,400</strong></div><div class="p-row"><span style="color:#f87171;">Fake Crawler</span><strong>137</strong></div></div></div>
            </div>
        ${commonFooter}
        `
    },
    {
        id: 3,
        name: "concept_03_sysadmin_telemetry_pro",
        title: "Concept 3: The SysAdmin Telemetry Pro",
        badge: "Technical & Metric Heavy",
        desc: "Datadog / Grafana powerhouse. Includes Bandwidth Egress (MB), HTTP/2 vs HTTP/3 protocol ratios, and upstream latency distributions.",
        render: () => `
        ${commonHead("Concept 3: SysAdmin Telemetry Pro", `
            .telemetry-3way-grid { display: grid; grid-template-columns: 1.5fr 1fr 1fr; gap: 14px; margin-bottom: 20px; }
            .tele-panel { background: #0c101a; border: 1px solid rgba(255,255,255,0.08); border-radius: 10px; padding: 14px; }
            .proto-bar-wrap { display: flex; height: 8px; border-radius: 4px; overflow: hidden; margin: 10px 0; }
        `)}
            <div class="concept-header-banner">
                <div>
                    <div class="concept-title"><i class="bi bi-cpu-fill" style="color:#22d3ee;"></i> Concept 3: The SysAdmin Telemetry Pro <span class="concept-badge" style="background:#0891b2;">Datadog Enterprise</span></div>
                    <div class="concept-desc">Comprehensive system telemetry tracking bandwidth egress, HTTP protocol versioning, and status distribution.</div>
                </div>
                <div style="font-family:var(--font-mono);font-size:0.75rem;background:#1e293b;padding:5px 12px;border-radius:6px;border:1px solid #475569;">Egress Bandwidth: <strong style="color:#38bdf8;">1.42 GB</strong></div>
            </div>

            <!-- 7-Metric Strip -->
            <div class="kpi-7-strip">
                <div class="kpi-card" style="border-top:3px solid #6366f1;"><div class="kpi-val">47,304</div><div class="kpi-lbl">TOTAL REQUESTS</div></div>
                <div class="kpi-card" style="border-top:3px solid #818cf8;"><div class="kpi-val" style="color:#818cf8;">19,913</div><div class="kpi-lbl">UNIQUE IPS</div></div>
                <div class="kpi-card" style="border-top:3px solid #06b6d4;"><div class="kpi-val" style="color:#22d3ee;">14</div><div class="kpi-lbl">COUNTRIES</div></div>
                <div class="kpi-card" style="border-top:3px solid #a855f7;"><div class="kpi-val" style="color:#c084fc;">64</div><div class="kpi-lbl">ASNS</div></div>
                <div class="kpi-card" style="border-top:3px solid #10b981;"><div class="kpi-val" style="color:#34d399;">68.2%</div><div class="kpi-lbl">HUMAN TRAFFIC</div></div>
                <div class="kpi-card" style="border-top:3px solid #38bdf8;"><div class="kpi-val" style="color:#38bdf8;">14,942</div><div class="kpi-lbl">VERIFIED (31.6%)</div></div>
                <div class="kpi-card" style="border-top:3px solid #ef4444;"><div class="kpi-val" style="color:#f87171;">137</div><div class="kpi-lbl" style="color:#fca5a5;">SPOOFED (0.3%)</div></div>
            </div>

            <!-- 3-Way Technical Telemetry Grid -->
            <div class="telemetry-3way-grid">
                <div class="tele-panel">
                    <div style="font-weight:800;font-size:0.84rem;margin-bottom:8px;"><i class="bi bi-hdd-network" style="color:#38bdf8;"></i> Bandwidth & Protocol Split</div>
                    <div class="proto-bar-wrap">
                        <div style="width:72%;background:#6366f1;" title="HTTP/2.0 (72%)"></div>
                        <div style="width:20%;background:#06b6d4;" title="HTTP/1.1 (20%)"></div>
                        <div style="width:8%;background:#a855f7;" title="HTTP/3.0 (8%)"></div>
                    </div>
                    <div style="display:flex;justify-content:space-between;font-size:0.72rem;color:var(--text-muted);">
                        <span><strong style="color:#6366f1;">HTTP/2</strong> 72%</span>
                        <span><strong style="color:#06b6d4;">HTTP/1.1</strong> 20%</span>
                        <span><strong style="color:#a855f7;">HTTP/3</strong> 8%</span>
                    </div>
                </div>

                <div class="tele-panel">
                    <div style="font-weight:800;font-size:0.84rem;margin-bottom:8px;"><i class="bi bi-pie-chart" style="color:#10b981;"></i> Status Codes Distribution</div>
                    <div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;font-size:0.75rem;">
                        <span><i class="bi bi-check-circle" style="color:#10b981;"></i> 2xx Success:</span><strong>42,120 (89.1%)</strong>
                    </div>
                    <div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;font-size:0.75rem;">
                        <span><i class="bi bi-exclamation-triangle" style="color:#ef4444;"></i> 4xx/5xx Errors:</span><strong style="color:#f87171;">3,820 (8.1%)</strong>
                    </div>
                </div>

                <div class="tele-panel">
                    <div style="font-weight:800;font-size:0.84rem;margin-bottom:8px;"><i class="bi bi-speedometer2" style="color:#f59e0b;"></i> Upstream Performance</div>
                    <div style="display:flex;justify-content:space-between;font-size:0.75rem;padding:4px 0;"><span>P50 Latency:</span><strong style="color:#34d399;">42 ms</strong></div>
                    <div style="display:flex;justify-content:space-between;font-size:0.75rem;padding:4px 0;"><span>P95 Outliers:</span><strong style="color:#f59e0b;">380 ms</strong></div>
                </div>
            </div>
        ${commonFooter}
        `
    },
    {
        id: 4,
        name: "concept_04_split_screen_warfare_deck",
        title: "Concept 4: The Split-Screen Warfare Deck",
        badge: "50/50 Dual-Pane Split",
        desc: "Side-by-side warfare deck. Left pane: live telemetry and traffic inspection; Right pane: persistent live firewall generator.",
        render: () => `
        ${commonHead("Concept 4: Split-Screen Warfare Deck", `
            .warfare-split { display: grid; grid-template-columns: 1.1fr 0.9fr; gap: 16px; margin-bottom: 20px; }
            .war-left, .war-right { background: #0c101a; border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 16px; }
        `)}
            <div class="concept-header-banner">
                <div>
                    <div class="concept-title"><i class="bi bi-layout-split" style="color:#818cf8;"></i> Concept 4: The Split-Screen Warfare Deck <span class="concept-badge">Zero-Tab Triage</span></div>
                    <div class="concept-desc">Investigate on the left, generate firewall defense on the right simultaneously without switching views.</div>
                </div>
            </div>

            <div class="warfare-split">
                <!-- Left: Triage Telemetry -->
                <div class="war-left">
                    <div style="font-weight:800;font-size:0.88rem;color:#fff;margin-bottom:12px;"><i class="bi bi-activity" style="color:#22d3ee;"></i> 1. Live Traffic Stream & Inspection</div>
                    <div class="kpi-7-strip" style="grid-template-columns:repeat(4,1fr);gap:8px;">
                        <div class="kpi-card"><div class="kpi-val" style="font-size:1.15rem;">47,304</div><div class="kpi-lbl">TOTAL</div></div>
                        <div class="kpi-card"><div class="kpi-val" style="font-size:1.15rem;color:#818cf8;">19,913</div><div class="kpi-lbl">IPS</div></div>
                        <div class="kpi-card"><div class="kpi-val" style="font-size:1.15rem;color:#34d399;">68.2%</div><div class="kpi-lbl">HUMAN</div></div>
                        <div class="kpi-card"><div class="kpi-val" style="font-size:1.15rem;color:#f87171;">137</div><div class="kpi-lbl">SPOOFED</div></div>
                    </div>
                    <div class="pillar-card" style="margin-top:12px;">
                        <div class="pillar-head"><span>Targeted Exploit Endpoints</span></div>
                        <div class="pillar-body">
                            <div class="p-row"><code>/xmlrpc.php</code><strong style="color:#f87171;">4,120</strong></div>
                            <div class="p-row"><code>/wp-login.php</code><strong style="color:#f87171;">2,310</strong></div>
                        </div>
                    </div>
                </div>

                <!-- Right: Live Mitigation Generator -->
                <div class="war-right" style="border-color:rgba(239,68,68,0.3);background:#090d16;">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                        <span style="font-weight:800;font-size:0.88rem;color:#f87171;"><i class="bi bi-shield-slash"></i> 2. Threat Mitigation & Firewall Builder</span>
                        <span style="font-size:0.72rem;background:#ef4444;color:#fff;padding:2px 8px;border-radius:4px;font-weight:700;">4 Rules Active</span>
                    </div>
                    <div style="background:#06080f;border:1px solid rgba(255,255,255,0.08);border-radius:8px;padding:12px;font-family:var(--font-mono);font-size:0.75rem;color:#fca5a5;">
# Instant Defense Ruleset
deny 185.220.101.5;
deny 45.154.255.88;
deny 194.26.29.112;
location = /xmlrpc.php { deny all; return 403; }
                    </div>
                    <button style="width:100%;background:#6366f1;color:#fff;border:none;border-radius:6px;padding:9px;font-weight:800;font-size:0.8rem;margin-top:12px;cursor:pointer;"><i class="bi bi-download"></i> Download Production Nginx .conf</button>
                </div>
            </div>
        ${commonFooter}
        `
    },
    {
        id: 5,
        name: "concept_05_threat_radar_geodefense",
        title: "Concept 5: Threat Radar & Geo-Defense Center",
        badge: "Map-First Incident Command",
        desc: "Geographic attack vector first. Interactive world map with real-time country risk scores and instant country geo-fencing.",
        render: () => `
        ${commonHead("Concept 5: Threat Radar & Geo-Defense Center", `
            .geomap-hero-container { height: 260px; background: radial-gradient(circle at 50% 40%, #151d2f 0%, #080c14 100%); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; position: relative; margin-bottom: 20px; display: flex; align-items: center; justify-content: center; overflow: hidden; }
        `)}
            <div class="concept-header-banner">
                <div>
                    <div class="concept-title"><i class="bi bi-globe-americas" style="color:#06b6d4;"></i> Concept 5: Threat Radar & Geo-Defense Center <span class="concept-badge" style="background:#0891b2;">Geo-Defense</span></div>
                    <div class="concept-desc">Geographic incident triage isolating hostile sovereign origins with instant country geo-fence rules.</div>
                </div>
            </div>

            <!-- Full-Width GeoMap Hero -->
            <div class="geomap-hero-container">
                <div style="text-align:center;">
                    <i class="bi bi-globe-central-south" style="font-size:3.5rem;color:rgba(6,182,212,0.4);"></i>
                    <div style="font-weight:800;font-size:0.95rem;color:#22d3ee;margin-top:6px;">Interactive Threat Vector Map Mounted</div>
                    <div style="font-size:0.75rem;color:var(--text-muted);">Top Incident Origins: 🇷🇺 Russia (14.2k) · 🇨🇳 China (9.1k) · 🇺🇸 USA (8.4k)</div>
                </div>
            </div>

            <!-- 7-Metric Strip -->
            <div class="kpi-7-strip">
                <div class="kpi-card" style="border-top:3px solid #6366f1;"><div class="kpi-val">47,304</div><div class="kpi-lbl">TOTAL REQUESTS</div></div>
                <div class="kpi-card" style="border-top:3px solid #818cf8;"><div class="kpi-val" style="color:#818cf8;">19,913</div><div class="kpi-lbl">UNIQUE IPS</div></div>
                <div class="kpi-card" style="border-top:3px solid #06b6d4;"><div class="kpi-val" style="color:#22d3ee;">14</div><div class="kpi-lbl">COUNTRIES</div></div>
                <div class="kpi-card" style="border-top:3px solid #a855f7;"><div class="kpi-val" style="color:#c084fc;">64</div><div class="kpi-lbl">ASNS</div></div>
                <div class="kpi-card" style="border-top:3px solid #10b981;"><div class="kpi-val" style="color:#34d399;">68.2%</div><div class="kpi-lbl">HUMAN TRAFFIC</div></div>
                <div class="kpi-card" style="border-top:3px solid #38bdf8;"><div class="kpi-val" style="color:#38bdf8;">14,942</div><div class="kpi-lbl">VERIFIED</div></div>
                <div class="kpi-card" style="border-top:3px solid #ef4444;"><div class="kpi-val" style="color:#f87171;">137</div><div class="kpi-lbl">SPOOFED</div></div>
            </div>
        ${commonFooter}
        `
    },
    {
        id: 6,
        name: "concept_06_multinode_cluster_command",
        title: "Concept 6: The Multi-Node Cluster Command",
        badge: "AWS / Auto-Scaling Clusters",
        desc: "Designed for auto-scaled clusters (Magento / EC2 behind ALB). Switch between individual web nodes or triage consolidated cluster telemetry.",
        render: () => `
        ${commonHead("Concept 6: Multi-Node Cluster Command", `
            .cluster-selector-bar { display: flex; align-items: center; justify-content: space-between; background: #0c101a; border: 1px solid rgba(255,255,255,0.08); border-radius: 10px; padding: 10px 16px; margin-bottom: 20px; }
            .node-pill-group { display: flex; gap: 6px; }
            .node-pill { background: #131a29; border: 1px solid var(--border-subtle); color: var(--text-secondary); padding: 5px 12px; border-radius: 6px; font-size: 0.76rem; font-weight: 700; cursor: pointer; display: flex; align-items: center; gap: 6px; }
            .node-pill.active { background: rgba(99,102,241,0.25); border-color: #818cf8; color: #fff; }
        `)}
            <div class="concept-header-banner">
                <div>
                    <div class="concept-title"><i class="bi bi-hdd-stack-fill" style="color:#a855f7;"></i> Concept 6: The Multi-Node Cluster Command <span class="concept-badge" style="background:#7c3aed;">ASG Multi-Node</span></div>
                    <div class="concept-desc">Multi-server log aggregation for AWS EC2 Auto-Scaling groups with private IP tagging and per-node triage.</div>
                </div>
            </div>

            <!-- Cluster Node Switcher Bar -->
            <div class="cluster-selector-bar">
                <div style="display:flex;align-items:center;gap:10px;">
                    <span style="font-weight:800;font-size:0.75rem;color:var(--text-muted);text-transform:uppercase;"><i class="bi bi-diagram-3-fill color-purple"></i> Active Cluster Nodes:</span>
                    <div class="node-pill-group">
                        <div class="node-pill active"><i class="bi bi-hdd-network"></i> All Nodes (Aggregated 47.3k)</div>
                        <div class="node-pill"><i class="bi bi-server"></i> Node 1 (10.0.1.24 · 18.2k)</div>
                        <div class="node-pill"><i class="bi bi-server"></i> Node 2 (10.0.1.58 · 16.1k)</div>
                        <div class="node-pill"><i class="bi bi-server"></i> Node 3 (10.0.1.92 · 13.0k)</div>
                    </div>
                </div>
                <button style="background:#1e293b;border:1px solid #475569;color:#fff;border-radius:6px;padding:5px 12px;font-size:0.75rem;font-weight:700;"><i class="bi bi-plus-circle"></i> Append SSH Stream</button>
            </div>

            <!-- 7-Metric Strip -->
            <div class="kpi-7-strip">
                <div class="kpi-card" style="border-top:3px solid #6366f1;"><div class="kpi-val">47,304</div><div class="kpi-lbl">TOTAL REQUESTS</div></div>
                <div class="kpi-card" style="border-top:3px solid #818cf8;"><div class="kpi-val" style="color:#818cf8;">19,913</div><div class="kpi-lbl">UNIQUE IPS</div></div>
                <div class="kpi-card" style="border-top:3px solid #06b6d4;"><div class="kpi-val" style="color:#22d3ee;">14</div><div class="kpi-lbl">COUNTRIES</div></div>
                <div class="kpi-card" style="border-top:3px solid #a855f7;"><div class="kpi-val" style="color:#c084fc;">64</div><div class="kpi-lbl">ASNS</div></div>
                <div class="kpi-card" style="border-top:3px solid #10b981;"><div class="kpi-val" style="color:#34d399;">68.2%</div><div class="kpi-lbl">HUMAN TRAFFIC</div></div>
                <div class="kpi-card" style="border-top:3px solid #38bdf8;"><div class="kpi-val" style="color:#38bdf8;">14,942</div><div class="kpi-lbl">VERIFIED</div></div>
                <div class="kpi-card" style="border-top:3px solid #ef4444;"><div class="kpi-val" style="color:#f87171;">137</div><div class="kpi-lbl">SPOOFED</div></div>
            </div>
        ${commonFooter}
        `
    },
    {
        id: 7,
        name: "concept_07_executive_overview_digest",
        title: "Concept 7: The Executive Traffic Digest",
        badge: "C-Level & Lead SysAdmin",
        desc: "Executive traffic health digest. Displays Clean Traffic Index (92%), Bot vs Human cost impact estimate, and 1-click PDF executive export.",
        render: () => `
        ${commonHead("Concept 7: Executive Traffic Digest", `
            .exec-hero-card { background: linear-gradient(135deg, #0e1526 0%, #090e1a 100%); border: 1px solid rgba(99,102,241,0.25); border-radius: 12px; padding: 22px; margin-bottom: 20px; display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; }
            .exec-metric-box { border-right: 1px solid rgba(255,255,255,0.06); padding-right: 16px; }
            .exec-metric-box:last-child { border-right: none; }
        `)}
            <div class="concept-header-banner">
                <div>
                    <div class="concept-title"><i class="bi bi-file-earmark-bar-graph-fill" style="color:#10b981;"></i> Concept 7: The Executive Traffic Digest <span class="concept-badge" style="background:#059669;">Executive Digest</span></div>
                    <div class="concept-desc">High-level traffic quality index, business impact metrics, and 1-click executive PDF report generation.</div>
                </div>
                <button style="background:#10b981;color:#fff;border:none;border-radius:6px;padding:8px 16px;font-weight:800;font-size:0.8rem;cursor:pointer;"><i class="bi bi-file-pdf"></i> Export Executive Report</button>
            </div>

            <!-- Executive Hero Card -->
            <div class="exec-hero-card">
                <div class="exec-metric-box">
                    <div style="font-size:0.75rem;color:var(--text-muted);font-weight:700;text-transform:uppercase;">Overall Traffic Health</div>
                    <div style="font-size:2rem;font-weight:900;color:#34d399;margin-top:4px;">92.4% Clean</div>
                    <div style="font-size:0.75rem;color:var(--text-secondary);margin-top:4px;">High legitimate user conversion index</div>
                </div>
                <div class="exec-metric-box">
                    <div style="font-size:0.75rem;color:var(--text-muted);font-weight:700;text-transform:uppercase;">Bot Traffic Overhead</div>
                    <div style="font-size:2rem;font-weight:900;color:#38bdf8;margin-top:4px;">31.6% Official</div>
                    <div style="font-size:0.75rem;color:var(--text-secondary);margin-top:4px;">Google, Bing, Applebot indexing correctly</div>
                </div>
                <div class="exec-metric-box">
                    <div style="font-size:0.75rem;color:var(--text-muted);font-weight:700;text-transform:uppercase;">Mitigated Threat Volume</div>
                    <div style="font-size:2rem;font-weight:900;color:#f87171;margin-top:4px;">3,820 Dropped</div>
                    <div style="font-size:0.75rem;color:var(--text-secondary);margin-top:4px;">Estimated 18% server RAM load saved</div>
                </div>
            </div>

            <!-- 7-Metric Strip -->
            <div class="kpi-7-strip">
                <div class="kpi-card" style="border-top:3px solid #6366f1;"><div class="kpi-val">47,304</div><div class="kpi-lbl">TOTAL REQUESTS</div></div>
                <div class="kpi-card" style="border-top:3px solid #818cf8;"><div class="kpi-val" style="color:#818cf8;">19,913</div><div class="kpi-lbl">UNIQUE IPS</div></div>
                <div class="kpi-card" style="border-top:3px solid #06b6d4;"><div class="kpi-val" style="color:#22d3ee;">14</div><div class="kpi-lbl">COUNTRIES</div></div>
                <div class="kpi-card" style="border-top:3px solid #a855f7;"><div class="kpi-val" style="color:#c084fc;">64</div><div class="kpi-lbl">ASNS</div></div>
                <div class="kpi-card" style="border-top:3px solid #10b981;"><div class="kpi-val" style="color:#34d399;">68.2%</div><div class="kpi-lbl">HUMAN TRAFFIC</div></div>
                <div class="kpi-card" style="border-top:3px solid #38bdf8;"><div class="kpi-val" style="color:#38bdf8;">14,942</div><div class="kpi-lbl">VERIFIED</div></div>
                <div class="kpi-card" style="border-top:3px solid #ef4444;"><div class="kpi-val" style="color:#f87171;">137</div><div class="kpi-lbl">SPOOFED</div></div>
            </div>
        ${commonFooter}
        `
    },
    {
        id: 8,
        name: "concept_08_timeline_forensics_scrub",
        title: "Concept 8: The Timeline-Centric Forensics Scrub",
        badge: "Precision Forensics",
        desc: "Audio/Video studio scrubber style. Multi-layer timeline canvas with sub-second zoom and micro-interval inspector.",
        render: () => `
        ${commonHead("Concept 8: Timeline-Centric Forensics Scrub", `
            .forensics-timeline-box { background: #080c14; border: 1px solid rgba(99,102,241,0.3); border-radius: 12px; padding: 18px; margin-bottom: 20px; }
            .scrub-track-layer { height: 140px; background: radial-gradient(circle at 50% 50%, rgba(99,102,241,0.06), transparent 70%); border-radius: 8px; border: 1px solid rgba(255,255,255,0.04); position: relative; margin-bottom: 12px; }
        `)}
            <div class="concept-header-banner">
                <div>
                    <div class="concept-title"><i class="bi bi-clock-history" style="color:#818cf8;"></i> Concept 8: The Timeline-Centric Forensics Scrub <span class="concept-badge" style="background:#4338ca;">Forensics Pro</span></div>
                    <div class="concept-desc">Multi-layer temporal canvas isolating burst attacks, error waves, and traffic velocity with micro-second zoom.</div>
                </div>
            </div>

            <!-- Master Forensics Canvas -->
            <div class="forensics-timeline-box">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
                    <span style="font-weight:800;font-size:0.88rem;color:#fff;"><i class="bi bi-sliders2-vertical"></i> Multi-Layer Temporal Inspector</span>
                    <div class="time-badge" style="width:auto;"><i class="bi bi-clock"></i> 10:15:00 → 11:30:00 <span class="time-pill">Active Burst Window</span></div>
                </div>
                <div class="scrub-track-layer">
                    <div style="position:absolute;top:10px;left:14px;font-size:0.75rem;color:var(--text-muted);">Layers: <span style="color:#818cf8;">● RPS Velocity</span> · <span style="color:#ef4444;">● 4xx/5xx Errors</span> · <span style="color:#34d399;">● 2xx Success</span></div>
                    <!-- Histogram Scrubber Inside -->
                    <div class="hist-slider-wrap" style="position:absolute;bottom:10px;left:14px;right:14px;height:40px;">
                        <div class="hist-bars">
                            <div class="hbar" style="height:35%;"></div><div class="hbar in-win" style="height:65%;"></div><div class="hbar in-win spike" style="height:100%;"></div><div class="hbar in-win" style="height:55%;"></div><div class="hbar" style="height:25%;"></div>
                        </div>
                        <div class="slider-handle-zip" style="left:30%;"></div>
                        <div class="slider-handle-zip" style="left:75%;"></div>
                    </div>
                </div>
            </div>

            <!-- 7-Metric Strip -->
            <div class="kpi-7-strip">
                <div class="kpi-card" style="border-top:3px solid #6366f1;"><div class="kpi-val">47,304</div><div class="kpi-lbl">TOTAL REQUESTS</div></div>
                <div class="kpi-card" style="border-top:3px solid #818cf8;"><div class="kpi-val" style="color:#818cf8;">19,913</div><div class="kpi-lbl">UNIQUE IPS</div></div>
                <div class="kpi-card" style="border-top:3px solid #06b6d4;"><div class="kpi-val" style="color:#22d3ee;">14</div><div class="kpi-lbl">COUNTRIES</div></div>
                <div class="kpi-card" style="border-top:3px solid #a855f7;"><div class="kpi-val" style="color:#c084fc;">64</div><div class="kpi-lbl">ASNS</div></div>
                <div class="kpi-card" style="border-top:3px solid #10b981;"><div class="kpi-val" style="color:#34d399;">68.2%</div><div class="kpi-lbl">HUMAN TRAFFIC</div></div>
                <div class="kpi-card" style="border-top:3px solid #38bdf8;"><div class="kpi-val" style="color:#38bdf8;">14,942</div><div class="kpi-lbl">VERIFIED</div></div>
                <div class="kpi-card" style="border-top:3px solid #ef4444;"><div class="kpi-val" style="color:#f87171;">137</div><div class="kpi-lbl">SPOOFED</div></div>
            </div>
        ${commonFooter}
        `
    },
    {
        id: 9,
        name: "concept_09_glassmorphism_cyber_dock",
        title: "Concept 9: The Glassmorphism Cyber Dock",
        badge: "Next-Gen Cyber Aesthetics",
        desc: "Modern frosted glass with subtle translucent blur, glowing cyber borders, and neon telemetry pills.",
        render: () => `
        ${commonHead("Concept 9: Glassmorphism Cyber Dock", `
            .glass-dock-card { background: rgba(18, 24, 38, 0.7); backdrop-filter: blur(12px); border: 1px solid rgba(255,255,255,0.1); border-radius: 14px; padding: 18px; margin-bottom: 20px; box-shadow: 0 8px 32px rgba(0,0,0,0.6); }
            .cyber-glow-pill { background: rgba(99,102,241,0.12); border: 1px solid rgba(99,102,241,0.4); box-shadow: 0 0 15px rgba(99,102,241,0.25); border-radius: 999px; padding: 8px 20px; display: inline-flex; align-items: center; gap: 8px; }
        `)}
            <div class="concept-header-banner" style="background:rgba(99,102,241,0.1);backdrop-filter:blur(10px);">
                <div>
                    <div class="concept-title"><i class="bi bi-droplet-half" style="color:#22d3ee;"></i> Concept 9: The Glassmorphism Cyber Dock <span class="concept-badge" style="background:linear-gradient(90deg,#6366f1,#06b6d4);">Glass Cyber</span></div>
                    <div class="concept-desc">Translucent layered depth, neon border reflections, and frosted glass telemetry panels.</div>
                </div>
            </div>

            <!-- Glass Dock Strip -->
            <div class="glass-dock-card">
                <div class="kpi-7-strip" style="margin-bottom:0;">
                    <div class="kpi-card" style="background:rgba(255,255,255,0.02);border-top:3px solid #6366f1;"><div class="kpi-val">47,304</div><div class="kpi-lbl">TOTAL REQUESTS</div></div>
                    <div class="kpi-card" style="background:rgba(255,255,255,0.02);border-top:3px solid #818cf8;"><div class="kpi-val" style="color:#818cf8;">19,913</div><div class="kpi-lbl">UNIQUE IPS</div></div>
                    <div class="kpi-card" style="background:rgba(255,255,255,0.02);border-top:3px solid #06b6d4;"><div class="kpi-val" style="color:#22d3ee;">14</div><div class="kpi-lbl">COUNTRIES</div></div>
                    <div class="kpi-card" style="background:rgba(255,255,255,0.02);border-top:3px solid #a855f7;"><div class="kpi-val" style="color:#c084fc;">64</div><div class="kpi-lbl">ASNS</div></div>
                    <div class="kpi-card" style="background:rgba(255,255,255,0.02);border-top:3px solid #10b981;"><div class="kpi-val" style="color:#34d399;">68.2%</div><div class="kpi-lbl">HUMAN TRAFFIC</div></div>
                    <div class="kpi-card" style="background:rgba(255,255,255,0.02);border-top:3px solid #38bdf8;"><div class="kpi-val" style="color:#38bdf8;">14,942</div><div class="kpi-lbl">VERIFIED</div></div>
                    <div class="kpi-card" style="background:rgba(239,68,68,0.06);border-top:3px solid #ef4444;"><div class="kpi-val" style="color:#f87171;">137</div><div class="kpi-lbl">SPOOFED</div></div>
                </div>
            </div>

            <!-- 4 Glass Pillars -->
            <div class="pillar-grid-4">
                <div class="pillar-card" style="background:rgba(18,24,38,0.7);backdrop-filter:blur(10px);"><div class="pillar-head"><span>Top Client IPs</span><i class="bi bi-globe" style="color:#818cf8;"></i></div><div class="pillar-body"><div class="p-row"><code>185.220.101.5</code><strong>4,120</strong></div><div class="p-row"><code>40.77.167.1</code><strong>3,410</strong></div></div></div>
                <div class="pillar-card" style="background:rgba(18,24,38,0.7);backdrop-filter:blur(10px);"><div class="pillar-head"><span>Targeted Endpoints</span><i class="bi bi-link-45deg" style="color:#22d3ee;"></i></div><div class="pillar-body"><div class="p-row"><code>/products</code><strong>12,400</strong></div><div class="p-row"><code>/xmlrpc.php</code><strong style="color:#f87171;">4,120</strong></div></div></div>
                <div class="pillar-card" style="background:rgba(18,24,38,0.7);backdrop-filter:blur(10px);"><div class="pillar-head"><span>Networks & ASNs</span><i class="bi bi-diagram-3" style="color:#c084fc;"></i></div><div class="pillar-body"><div class="p-row"><span>AS15169 Google</span><strong>14,200</strong></div><div class="p-row"><span>AS9009 Tor</span><strong style="color:#f87171;">4,120</strong></div></div></div>
                <div class="pillar-card" style="background:rgba(18,24,38,0.7);backdrop-filter:blur(10px);"><div class="pillar-head"><span>Bot Intelligence</span><i class="bi bi-shield-check" style="color:#34d399;"></i></div><div class="pillar-body"><div class="p-row"><span style="color:#34d399;">Googlebot</span><strong>10,400</strong></div><div class="p-row"><span style="color:#f87171;">Fake Crawler</span><strong>137</strong></div></div></div>
            </div>
        ${commonFooter}
        `
    },
    {
        id: 10,
        name: "concept_10_tabbed_modular_workspace",
        title: "Concept 10: The Tabbed Modular Workspace",
        badge: "Clean Multi-View Workflow",
        desc: "Professional desktop application workflow with dedicated module tabs. Zero vertical scrolling fatigue with deep view specialization.",
        render: () => `
        ${commonHead("Concept 10: Tabbed Modular Workspace", `
            .workspace-tab-nav { display: flex; gap: 4px; border-bottom: 1px solid var(--border-subtle); margin-bottom: 20px; padding-bottom: 0; }
            .wtab { background: transparent; border: none; border-bottom: 3px solid transparent; color: var(--text-secondary); padding: 10px 18px; font-weight: 700; font-size: 0.82rem; cursor: pointer; display: flex; align-items: center; gap: 8px; transition: all 0.15s ease; }
            .wtab.active { color: #fff; border-bottom-color: #6366f1; background: rgba(99,102,241,0.06); }
            .wtab-badge { font-size: 0.68rem; background: rgba(239,68,68,0.2); color: #fca5a5; padding: 1px 6px; border-radius: 999px; }
        `)}
            <div class="concept-header-banner">
                <div>
                    <div class="concept-title"><i class="bi bi-folder-check" style="color:#38bdf8;"></i> Concept 10: The Tabbed Modular Workspace <span class="concept-badge" style="background:#0284c7;">Desktop App</span></div>
                    <div class="concept-desc">Organized into discrete operational tabs eliminating scrolling overload and specializing each tool view.</div>
                </div>
            </div>

            <!-- Workspace Top Tabs -->
            <div class="workspace-tab-nav">
                <button class="wtab active"><i class="bi bi-speedometer2"></i> 1. Traffic Overview</button>
                <button class="wtab"><i class="bi bi-shield-slash"></i> 2. Threat Mitigation <span class="wtab-badge">137</span></button>
                <button class="wtab"><i class="bi bi-globe"></i> 3. Geo & ASN Defense</button>
                <button class="wtab"><i class="bi bi-robot"></i> 4. Bot Classification</button>
                <button class="wtab"><i class="bi bi-table"></i> 5. Log Explorer (47.3k)</button>
            </div>

            <!-- 7-Metric Strip -->
            <div class="kpi-7-strip">
                <div class="kpi-card" style="border-top:3px solid #6366f1;"><div class="kpi-val">47,304</div><div class="kpi-lbl">TOTAL REQUESTS</div></div>
                <div class="kpi-card" style="border-top:3px solid #818cf8;"><div class="kpi-val" style="color:#818cf8;">19,913</div><div class="kpi-lbl">UNIQUE IPS</div></div>
                <div class="kpi-card" style="border-top:3px solid #06b6d4;"><div class="kpi-val" style="color:#22d3ee;">14</div><div class="kpi-lbl">COUNTRIES</div></div>
                <div class="kpi-card" style="border-top:3px solid #a855f7;"><div class="kpi-val" style="color:#c084fc;">64</div><div class="kpi-lbl">ASNS</div></div>
                <div class="kpi-card" style="border-top:3px solid #10b981;"><div class="kpi-val" style="color:#34d399;">68.2%</div><div class="kpi-lbl">HUMAN TRAFFIC</div></div>
                <div class="kpi-card" style="border-top:3px solid #38bdf8;"><div class="kpi-val" style="color:#38bdf8;">14,942</div><div class="kpi-lbl">VERIFIED</div></div>
                <div class="kpi-card" style="border-top:3px solid #ef4444;"><div class="kpi-val" style="color:#f87171;">137</div><div class="kpi-lbl">SPOOFED</div></div>
            </div>

            <!-- 4 Focused Pillars -->
            <div class="pillar-grid-4">
                <div class="pillar-card"><div class="pillar-head"><span>Top Client IPs</span><i class="bi bi-globe"></i></div><div class="pillar-body"><div class="p-row"><code>185.220.101.5</code><strong>4,120</strong></div><div class="p-row"><code>40.77.167.1</code><strong>3,410</strong></div></div></div>
                <div class="pillar-card"><div class="pillar-head"><span>Targeted Endpoints</span><i class="bi bi-link-45deg"></i></div><div class="pillar-body"><div class="p-row"><code>/products</code><strong>12,400</strong></div><div class="p-row"><code>/xmlrpc.php</code><strong style="color:#f87171;">4,120</strong></div></div></div>
                <div class="pillar-card"><div class="pillar-head"><span>Networks & ASNs</span><i class="bi bi-diagram-3"></i></div><div class="pillar-body"><div class="p-row"><span>AS15169 Google</span><strong>14,200</strong></div><div class="p-row"><span>AS9009 Tor</span><strong style="color:#f87171;">4,120</strong></div></div></div>
                <div class="pillar-card"><div class="pillar-head"><span>Bot Intelligence</span><i class="bi bi-shield-check"></i></div><div class="pillar-body"><div class="p-row"><span style="color:#34d399;">Googlebot</span><strong>10,400</strong></div><div class="p-row"><span style="color:#f87171;">Fake Crawler</span><strong>137</strong></div></div></div>
            </div>
        ${commonFooter}
        `
    }
];

async function generateAllConcepts() {
    console.log(`Starting generation of 10 UI Concept Screenshots...`);
    const browser = await chromium.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
    });

    const page = await browser.newPage({
        viewport: { width: 1440, height: 950 },
        deviceScaleFactor: 2
    });

    for (const c of concepts) {
        const filePath = `/tmp/${c.name}.html`;
        fs.writeFileSync(filePath, c.render());
        await page.goto(`file://${filePath}`, { waitUntil: 'load' });
        await page.waitForTimeout(400);

        const outImgPath = `/home/ubuntu/.hermes/cache/images/${c.name}.png`;
        await page.screenshot({ path: outImgPath, fullPage: true });
        console.log(`[${c.id}/10] Generated: ${outImgPath}`);
        fs.unlinkSync(filePath);
    }

    await browser.close();
    console.log(`All 10 UI Concepts successfully generated and captured!`);
}

generateAllConcepts();
