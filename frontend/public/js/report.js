/**
 * Client-Side HTML Report Generator — Premium Edition
 *
 * Generates a fully self-contained, interactive HTML report matching
 * the dashboard UI quality. Features:
 *   - Download modal with compact-mode checkbox & progress steps
 *   - Inline Chart.js for interactive hover charts
 *   - Country/ASN/Bot expandable detail rows
 *   - Conditional AbuseIPDB results with per-IP access logs
 *   - Compact mode: logs as JSON, rendered on-demand (~300 KB)
 *   - Full mode: logs as pre-rendered HTML tables (~2+ MB)
 *   - Premium dark-theme CSS, print-friendly
 *   - Zero external dependencies
 */

const Report = (() => {
    /* ══════════════════════════════════════════════════════════════
       State
       ══════════════════════════════════════════════════════════════ */
    let _chartJsSource = null;
    let _data = null;
    let _parseResult = null;
    let _options = {};

    /* Pre-fetch Chart.js source for inline embedding */
    const CHART_JS_URL = 'https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js';
    // This source is inlined into exported reports, so it must be the exact published file.
    const CHART_JS_INTEGRITY = 'sha384-vsrfeLOOY6KuIYKDlmVH5UiBmgIdB1oEf7p01YgWHuqmOHfZr374+odEv96n9tNC';
    (async function prefetchChartJs() {
        try {
            const r = await fetch(CHART_JS_URL, { integrity: CHART_JS_INTEGRITY });
            _chartJsSource = await r.text();
        } catch (e) { console.warn('[Report] Chart.js pre-cache failed:', e.message); }
    })();

    /* Compact preference — persisted in localStorage */
    function getCompactPref() {
        try {
            const v = localStorage.getItem('report_compact_pref');
            return v === null ? true : v === 'true';
        } catch { return true; }
    }
    function setCompactPref(val) {
        try { localStorage.setItem('report_compact_pref', String(val)); } catch {}
    }

    /* ══════════════════════════════════════════════════════════════
       Utilities
       ══════════════════════════════════════════════════════════════ */
    function n(v) { return (v || 0).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ','); }
    function esc(s) { return s ? String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;') : ''; }
    function pct(part, total) { return total ? (part / total * 100).toFixed(1) : '0.0'; }
    function statusColor(c) { return c >= 500 ? '#ef4444' : c >= 400 ? '#f59e0b' : c >= 300 ? '#6366f1' : '#10b981'; }
    function abuseColor(s) { return s > 50 ? '#ef4444' : s > 0 ? '#f59e0b' : '#10b981'; }
    function abuseBg(s) { return s > 50 ? 'rgba(239,68,68,0.12)' : s > 0 ? 'rgba(245,158,11,0.12)' : 'rgba(16,185,129,0.12)'; }
    function fmtTime(ts) { if (!ts) return '—'; const d = new Date(ts); return isNaN(d.getTime()) ? '—' : d.toISOString().replace('T', ' ').slice(0, 19); }
    function ipId(ip) { return ip.replace(/[.:]/g, '-'); }
    function yieldUI() { return new Promise(r => setTimeout(r, 60)); }

    /* ══════════════════════════════════════════════════════════════
       Download Modal
       ══════════════════════════════════════════════════════════════ */

    const STEPS = [
        'Embedding Chart.js library',
        'Building summary & HTTP metrics',
        'Generating charts & tables',
        'Processing access logs',
        'Assembling final HTML',
    ];

    function mountModal() {
        if (document.getElementById('download-modal-backdrop')) return;
        const el = document.createElement('div');
        el.innerHTML = `
        <div id="download-modal-backdrop" style="
            display:none;position:fixed;inset:0;z-index:10000;
            background:rgba(7,8,15,0.75);backdrop-filter:blur(6px);
            align-items:center;justify-content:center;
        ">
            <div id="download-modal" style="
                background:var(--bg-card);border:1px solid var(--border-color);
                border-radius:18px;padding:32px 36px;max-width:480px;width:90%;
                box-shadow:0 24px 80px rgba(0,0,0,0.5);position:relative;
            ">
                <!-- Header -->
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;">
                    <div style="display:flex;align-items:center;gap:10px;">
                        <div style="width:38px;height:38px;border-radius:10px;background:var(--signal-tint);display:flex;align-items:center;justify-content:center;color:var(--accent-primary);font-size:1.1rem;">
                            <i class="bi bi-download"></i>
                        </div>
                        <h3 style="margin:0;font-size:1.1rem;font-weight:700;color:var(--text-primary);">Download Report</h3>
                    </div>
                    <button id="dl-modal-close" style="background:none;border:none;color:var(--text-muted);font-size:1.3rem;cursor:pointer;padding:4px;line-height:1;">
                        <i class="bi bi-x-lg"></i>
                    </button>
                </div>

                <!-- Options Form -->
                <div id="dl-form-section">
                    <label id="dl-compact-label" style="
                        display:flex;align-items:flex-start;gap:12px;
                        padding:14px 16px;background:var(--bg-secondary);
                        border:1px solid var(--border-color);border-radius:10px;
                        cursor:pointer;margin-bottom:20px;transition:all 0.2s;
                    ">
                        <input type="checkbox" id="dl-compact-cb" checked style="
                            accent-color:var(--accent-primary);width:18px;height:18px;
                            margin-top:2px;flex-shrink:0;cursor:pointer;
                        ">
                        <div>
                            <div style="font-weight:600;font-size:0.88rem;color:var(--text-primary);margin-bottom:3px;">
                                Compact file <span style="font-size:0.72rem;font-weight:400;color:var(--accent-green);">(recommended)</span>
                            </div>
                            <div style="font-size:0.78rem;color:var(--text-muted);line-height:1.5;">
                                Compresses access logs as data, renders on demand.<br>
                                Significantly smaller file size (~300 KB vs ~2+ MB).
                            </div>
                        </div>
                    </label>

                    <div style="display:flex;gap:10px;">
                        <button id="dl-start-btn" style="
                            flex:1;padding:12px;border-radius:10px;border:none;
                            background:var(--accent-primary);color:var(--signal-on-primary);font-weight:700;
                            font-size:0.92rem;cursor:pointer;display:flex;
                            align-items:center;justify-content:center;gap:8px;
                            transition:all 0.25s;
                        ">
                            <i class="bi bi-download"></i> Generate & Download
                        </button>
                        <button id="dl-csv-btn" style="
                            padding:12px 18px;border-radius:10px;
                            border:1px solid var(--border-color);
                            background:var(--bg-secondary);color:var(--text-primary);font-weight:600;
                            font-size:0.92rem;cursor:pointer;display:flex;
                            align-items:center;justify-content:center;gap:8px;
                            transition:all 0.25s;
                        ">
                            <i class="bi bi-filetype-csv"></i> CSV
                        </button>
                    </div>
                </div>

                <!-- Progress Section -->
                <div id="dl-progress-section" style="display:none;">
                    <div style="margin-bottom:16px;">
                        <div style="display:flex;justify-content:space-between;margin-bottom:8px;">
                            <span id="dl-progress-label" style="font-size:0.85rem;font-weight:600;color:var(--text-primary);">Preparing...</span>
                            <span id="dl-progress-pct" style="font-size:0.85rem;font-weight:700;color:var(--accent-primary);">0%</span>
                        </div>
                        <div style="width:100%;height:6px;background:var(--bg-secondary);border-radius:3px;overflow:hidden;">
                            <div id="dl-progress-bar" style="width:0%;height:100%;background:var(--gradient-primary);border-radius:3px;transition:width 0.3s ease;"></div>
                        </div>
                    </div>
                    <div id="dl-steps"></div>
                </div>

                <!-- Done Section -->
                <div id="dl-done-section" style="display:none;text-align:center;padding:10px 0;">
                    <div style="width:52px;height:52px;border-radius:50%;background:var(--signal-tint);display:flex;align-items:center;justify-content:center;color:var(--accent-primary);font-size:1.5rem;margin:0 auto 12px;">
                        <i class="bi bi-check-circle-fill"></i>
                    </div>
                    <p style="margin:0 0 4px;color:var(--text-primary);font-weight:600;font-size:0.95rem;">Report downloaded!</p>
                    <p id="dl-file-size" style="margin:0;color:var(--text-muted);font-size:0.78rem;"></p>
                </div>
            </div>
        </div>`;
        const mountTarget = document.querySelector('.signal-workspace') || document.body;
        mountTarget.appendChild(el.firstElementChild);

        // Bind events
        document.getElementById('dl-modal-close').addEventListener('click', closeModal);
        document.getElementById('download-modal-backdrop').addEventListener('click', (e) => {
            if (e.target.id === 'download-modal-backdrop') closeModal();
        });
        document.getElementById('dl-start-btn').addEventListener('click', runDownload);
        document.getElementById('dl-csv-btn').addEventListener('click', function() {
            if (!_data) return;
            const dateStr = new Date().toISOString().split('T')[0];
            const csvRows = [];

            // Summary Section
            csvRows.push({
                Section: 'Summary',
                Category: 'Overview',
                Item: 'Total Requests',
                Value: _data.total_requests || 0,
                Details: `Unique IPs: ${_data.unique_ips || 0}, Countries: ${_data.unique_countries || 0}, ASNs: ${_data.unique_asns || 0}`
            });

            // Top IPs
            if (Array.isArray(_data.top_ips)) {
                _data.top_ips.forEach(r => {
                    csvRows.push({
                        Section: 'Top IPs',
                        Category: r.country || 'Unknown',
                        Item: r.ip,
                        Value: r.hits,
                        Details: `ASN: ${r.asn || ''} ${r.asn_org || ''}`.trim()
                    });
                });
            }

            // Country Hits
            if (Array.isArray(_data.country_hits)) {
                _data.country_hits.forEach(r => {
                    csvRows.push({
                        Section: 'Country Distribution',
                        Category: r.country_code || '',
                        Item: r.country || 'Unknown',
                        Value: r.hits,
                        Details: `Unique IPs: ${r.unique_ips || 0}`
                    });
                });
            }

            // ASN Hits
            if (Array.isArray(_data.asn_hits)) {
                _data.asn_hits.forEach(r => {
                    csvRows.push({
                        Section: 'ASN Distribution',
                        Category: `AS${r.asn || 0}`,
                        Item: r.asn_org || 'Unknown',
                        Value: r.hits,
                        Details: `Unique IPs: ${r.unique_ips || 0}`
                    });
                });
            }

            // Top URLs / Paths
            if (_data.http_metrics && Array.isArray(_data.http_metrics.top_urls)) {
                _data.http_metrics.top_urls.forEach(r => {
                    csvRows.push({
                        Section: 'Top URLs',
                        Category: 'HTTP',
                        Item: r.url,
                        Value: r.count,
                        Details: `${r.percentage || ''}% of requests`
                    });
                });
            }

            // Status Codes
            if (_data.http_metrics && Array.isArray(_data.http_metrics.status_hits)) {
                _data.http_metrics.status_hits.forEach(r => {
                    csvRows.push({
                        Section: 'Status Codes',
                        Category: 'HTTP Status',
                        Item: String(r.code),
                        Value: r.count,
                        Details: `${r.percentage || ''}%`
                    });
                });
            }

            // Bot Hits & Verification
            if (Array.isArray(_data.bot_groups)) {
                _data.bot_groups.forEach(g => {
                    csvRows.push({
                        Section: 'Bot Traffic',
                        Category: g.group_name || 'Bot Group',
                        Item: `Status: ${g.verification_status || 'unverified'}`,
                        Value: g.requests,
                        Details: `${g.unique_ips} IPs (${g.pct}%) | Verified: ${g.verified_requests || 0}, Spoofed: ${g.spoofed_requests || 0}`,
                    });
                });
            }

            // Spoofed Bot Attackers
            if (Array.isArray(_data.spoofed_bot_attackers)) {
                _data.spoofed_bot_attackers.forEach(att => {
                    csvRows.push({
                        Section: 'Spoofed Bot Attackers',
                        Category: att.bot_name || 'Fake Bot',
                        Item: att.ip,
                        Value: att.hits,
                        Details: `${att.country} | ${att.asn} (${att.asn_org}) | ${att.reason}`,
                    });
                });
            }

            if (csvRows.length === 0) csvRows.push(flattenObject(_data));
            exportToCSV(csvRows, `nginx-report-${dateStr}`);
            closeModal();
        });

        // Persist checkbox changes
        document.getElementById('dl-compact-cb').addEventListener('change', (e) => {
            setCompactPref(e.target.checked);
        });
    }

    function openModal(data, parseResult, options = {}) {
        mountModal();
        _data = data;
        _parseResult = parseResult;
        _options = options || {};

        // Reset UI
        document.getElementById('dl-form-section').style.display = 'block';
        document.getElementById('dl-progress-section').style.display = 'none';
        document.getElementById('dl-done-section').style.display = 'none';
        document.getElementById('dl-start-btn').disabled = false;

        // Restore preferences
        document.getElementById('dl-compact-cb').checked = getCompactPref();

        document.getElementById('download-modal-backdrop').style.display = 'flex';
    }

    function closeModal() {
        document.getElementById('download-modal-backdrop').style.display = 'none';
    }

    /* ── Progress helpers ── */
    function renderStepList(activeIdx) {
        const container = document.getElementById('dl-steps');
        container.innerHTML = STEPS.map((label, i) => {
            let icon, color;
            if (i < activeIdx) { icon = '✓'; color = 'var(--accent-primary)'; }
            else if (i === activeIdx) { icon = '●'; color = 'var(--accent-primary)'; }
            else { icon = '○'; color = 'var(--border-color)'; }
            return `<div style="display:flex;align-items:center;gap:10px;padding:6px 0;font-size:0.82rem;">
                <span style="color:${color};font-size:0.9rem;width:16px;text-align:center;flex-shrink:0;${i === activeIdx ? 'animation:dlPulse 1s infinite' : ''}">${icon}</span>
                <span style="color:${i <= activeIdx ? 'var(--text-secondary)' : '#3a3f52'};${i < activeIdx ? 'text-decoration:line-through;opacity:0.6' : ''}">${label}</span>
            </div>`;
        }).join('');
    }

    function updateProgress(stepIdx, pctVal) {
        const p = Math.round(pctVal);
        document.getElementById('dl-progress-bar').style.width = p + '%';
        document.getElementById('dl-progress-pct').textContent = p + '%';
        document.getElementById('dl-progress-label').textContent = STEPS[stepIdx] || 'Finalizing...';
        renderStepList(stepIdx);
    }

    /* ══════════════════════════════════════════════════════════════
       Download Logic
       ══════════════════════════════════════════════════════════════ */

    async function runDownload() {
        const compact = document.getElementById('dl-compact-cb').checked;
        setCompactPref(compact);

        // Switch to progress view
        document.getElementById('dl-form-section').style.display = 'none';
        document.getElementById('dl-progress-section').style.display = 'block';
        document.getElementById('dl-done-section').style.display = 'none';

        const data = _data;
        const parseResult = _parseResult;
        const generatedAt = new Date().toLocaleString();

        try {
            // Step 0: Chart.js
            updateProgress(0, 5);
            if (!_chartJsSource) {
                try { const r = await fetch(CHART_JS_URL); _chartJsSource = await r.text(); } catch {}
            }
            updateProgress(0, 20);
            await yieldUI();

            // Step 1: Build header, cards, metrics
            updateProgress(1, 25);
            await yieldUI();
            const header = buildHeader(parseResult, generatedAt);
            const statCards = buildStatCards(data);
            const httpMetrics = buildHttpMetrics(data);
            updateProgress(1, 40);
            await yieldUI();

            // Step 2: Charts & tables
            updateProgress(2, 45);
            await yieldUI();
            const requestRateSection = buildRequestRateSection(data);
            const charts = buildCharts(data);
            const countryTable = buildCountryTable(data);
            const asnTable = buildAsnTable(data);
            const topIps = buildTopIpsTable(data);
            const botSection = buildBotSection(data);
            updateProgress(2, 60);
            await yieldUI();

            // Step 3: Abuse + logs
            updateProgress(3, 65);
            await yieldUI();
            const abuseSection = buildAbuseSection(data, compact);
            const logDataBlock = compact ? buildLogDataJSON(data) : '';
            updateProgress(3, 80);
            await yieldUI();

            // Step 4: Assemble
            updateProgress(4, 85);
            await yieldUI();
            const footer = buildFooter(generatedAt);
            const chartJsBlock = _chartJsSource
                ? `<script>${_chartJsSource.replace(/<\/script>/gi, '<\\/script>')}<\/script>`
                : '<!-- Chart.js could not be embedded -->';
            const logJsonBlock = compact && logDataBlock
                ? `<script type="application/json" id="_log_json">${logDataBlock.replace(/<\/script>/gi, '<\\/script>')}<\/script>`
                : '';

            const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Traffic Log Report — ${esc(generatedAt)}</title>
    <style>${buildCSS()}</style>
</head>
<body>
<div class="container">
${header}
${statCards}
${httpMetrics}
${requestRateSection}
${charts}
${countryTable}
${asnTable}
${topIps}
${botSection}
${abuseSection}
${footer}
</div>
${chartJsBlock}
${logJsonBlock}
<script>${buildChartInitJS(data)}<\/script>
<script>${buildInteractiveJS(compact)}<\/script>
<style>@keyframes dlPulse{0%,100%{opacity:1}50%{opacity:0.3}}</style>
</body>
</html>`;

            updateProgress(4, 100);
            await yieldUI();

            // Trigger download
            const blob = new Blob([html], { type: 'text/html' });
            const dateStr = new Date().toISOString().split('T')[0];
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `nginx-report-${dateStr}.html`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            // Show done
            const sizeKB = Math.round(blob.size / 1024);
            const sizeStr = sizeKB > 1024 ? (sizeKB / 1024).toFixed(1) + ' MB' : sizeKB + ' KB';
            document.getElementById('dl-progress-section').style.display = 'none';
            document.getElementById('dl-done-section').style.display = 'block';
            document.getElementById('dl-file-size').textContent = `File size: ${sizeStr}${compact ? ' (compact)' : ' (full)'}`;
            setTimeout(closeModal, 2000);

        } catch (e) {
            console.error('[Report] Download failed:', e);
            document.getElementById('dl-progress-label').textContent = 'Error: ' + e.message;
            document.getElementById('dl-progress-label').style.color = '#ef4444';
        }
    }

    /* ══════════════════════════════════════════════════════════════
       CSS Builder
       ══════════════════════════════════════════════════════════════ */
    function buildCSS() {
        return `
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;background:#0a0b14;color:#e8ecf4;padding:40px 20px;line-height:1.6}
.container{max-width:1200px;margin:0 auto}
a{color:#818cf8;text-decoration:none}a:hover{text-decoration:underline}
.report-header{text-align:center;margin-bottom:36px}
.report-title{font-size:2rem;font-weight:800;background:linear-gradient(135deg,#6366f1,#a855f7);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:8px}
.report-subtitle{color:#5a6478;font-size:0.85rem;margin-bottom:6px}
.report-badge{display:inline-flex;align-items:center;gap:6px;background:rgba(99,102,241,0.08);border:1px solid rgba(99,102,241,0.15);border-radius:24px;padding:5px 14px;font-size:0.72rem;font-weight:600;color:#818cf8;text-transform:uppercase;letter-spacing:0.08em;margin-top:10px}
.report-period{color:#94a3b8;font-size:0.85rem;margin-top:12px}
.report-period strong{color:#cbd5e1}
.stat-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:30px}
.stat-card{background:#12141f;border:1px solid #1e2235;border-radius:14px;padding:24px 16px;text-align:center;position:relative;overflow:hidden;transition:transform 0.3s,box-shadow 0.3s}
.stat-card:hover{transform:translateY(-4px);box-shadow:0 12px 40px rgba(0,0,0,0.3)}
.stat-card::before{content:'';position:absolute;top:0;left:0;width:100%;height:3px}
.sc-blue::before{background:linear-gradient(90deg,#6366f1,#818cf8)}
.sc-cyan::before{background:linear-gradient(90deg,#06b6d4,#22d3ee)}
.sc-green::before{background:linear-gradient(90deg,#059669,#10b981)}
.sc-amber::before{background:linear-gradient(90deg,#d97706,#f59e0b)}
.sc-purple::before{background:linear-gradient(90deg,#7c3aed,#a855f7)}
.stat-icon{font-size:1.5rem;margin-bottom:8px;opacity:0.85}
.stat-value{font-size:2.1rem;font-weight:800;line-height:1.1;letter-spacing:-0.03em}
.stat-label{font-size:0.72rem;color:#5a6478;text-transform:uppercase;letter-spacing:0.1em;margin-top:6px;font-weight:600}
.section{background:#12141f;border:1px solid #1e2235;border-radius:14px;margin-bottom:20px;overflow:hidden;transition:border-color 0.3s}
.section:hover{border-color:rgba(99,102,241,0.15)}
.section-header{padding:14px 20px;border-bottom:1px solid #1e2235;font-weight:650;font-size:1rem;display:flex;align-items:center;gap:8px}
table{width:100%;border-collapse:collapse}
thead th{background:rgba(12,14,22,0.5);padding:12px 16px;text-align:left;font-size:0.72rem;text-transform:uppercase;letter-spacing:0.08em;color:#5a6478;font-weight:600;border-bottom:2px solid #1e2235;white-space:nowrap}
tbody td{padding:10px 16px;border-bottom:1px solid rgba(30,34,53,0.5);font-size:0.88rem;vertical-align:middle}
tbody tr:hover{background:rgba(99,102,241,0.03)}
.text-right{text-align:right}
.ip-code{font-family:'SF Mono','Fira Code',ui-monospace,monospace;font-size:0.8rem;background:rgba(239,68,68,0.08);color:#fca5a5;padding:3px 8px;border-radius:5px;border:1px solid rgba(239,68,68,0.08)}
.asn-code{font-family:'SF Mono','Fira Code',ui-monospace,monospace;font-size:0.8rem;background:rgba(168,85,247,0.1);color:#a855f7;padding:3px 8px;border-radius:5px;border:1px solid rgba(168,85,247,0.1)}
.country-flag{font-size:0.72rem;background:rgba(16,185,129,0.08);color:#10b981;padding:3px 7px;border-radius:5px;margin-right:5px;font-family:'SF Mono','Fira Code',ui-monospace,monospace;font-weight:500}
.hits-badge{font-family:'SF Mono','Fira Code',ui-monospace,monospace;font-weight:600;font-size:0.85rem;color:#22d3ee}
.hits-danger{color:#ef4444}
.traffic-bar-wrap{position:relative;height:24px;background:rgba(255,255,255,0.03);border-radius:6px;overflow:hidden;min-width:100px}
.traffic-bar{position:absolute;top:0;left:0;height:100%;border-radius:6px;transition:width 1s ease}
.traffic-bar-blue{background:linear-gradient(90deg,rgba(99,102,241,0.35),rgba(99,102,241,0.1))}
.traffic-bar-purple{background:linear-gradient(90deg,rgba(168,85,247,0.35),rgba(168,85,247,0.1))}
.traffic-pct{position:absolute;top:50%;left:10px;transform:translateY(-50%);font-size:0.73rem;font-weight:600;font-family:'SF Mono','Fira Code',ui-monospace,monospace;color:#94a3b8;z-index:1}
.expand-row{cursor:pointer;transition:background 0.15s}
.expand-row:hover{background:rgba(99,102,241,0.05)!important}
.expand-chevron{float:right;transition:transform 0.3s;font-size:0.8rem;color:#5a6478}
.detail-row{background:#0c0e16}
.detail-container{padding:16px 24px}
.detail-title{font-size:0.82rem;font-weight:600;color:#94a3b8;margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid rgba(99,102,241,0.08)}
.detail-pills{display:flex;flex-wrap:wrap;gap:8px}
.ip-pill{display:inline-flex;align-items:center;gap:6px;padding:5px 10px;background:rgba(99,102,241,0.04);border:1px solid rgba(99,102,241,0.08);border-radius:8px;font-size:0.78rem}
.ip-pill .ip-code{font-size:0.75rem;padding:2px 6px}
.ip-pill-hits{color:#22d3ee;font-size:0.72rem;font-weight:600}
.metrics-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;padding:20px}
.metric-box{background:#0e1019;border-radius:10px;padding:16px}
.metric-label{font-size:0.8rem;color:#5a6478;margin-bottom:8px}
.metric-chips{display:flex;flex-wrap:wrap;gap:8px}
.metric-chip{background:#12141f;border:1px solid #1e2235;border-radius:6px;padding:6px 10px;font-size:0.75rem}
.metric-chip-key{font-weight:600;color:#94a3b8}
.metric-chip-val{margin-left:5px;font-weight:700}
.paths-list{max-height:180px;overflow-y:auto}
.path-row{display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.04);font-size:0.78rem}
.path-row:last-child{border-bottom:none}
.path-idx{color:#5a6478;min-width:18px;text-align:right;font-size:0.7rem}
.path-val{font-family:'SF Mono','Fira Code',ui-monospace,monospace;color:#22d3ee;font-size:0.75rem;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.path-count{color:#a855f7;font-weight:700;font-size:0.75rem;min-width:50px;text-align:right}
.path-pct{color:#5a6478;font-size:0.65rem;min-width:38px;text-align:right}
.resp-row{display:flex;justify-content:space-between;margin-bottom:4px;font-size:0.85rem}
.resp-val{font-weight:600}
.charts-row{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:30px}
.chart-card{background:#12141f;border:1px solid #1e2235;border-radius:14px;overflow:hidden}
.chart-card-header{padding:14px 20px;border-bottom:1px solid #1e2235;font-weight:600;font-size:1rem}
.chart-body{padding:20px;height:350px;position:relative}
.chart-layout{display:grid;grid-template-columns:minmax(0,1fr) minmax(180px,210px);gap:16px;align-items:center;height:100%}
.chart-canvas-wrap{position:relative;min-height:240px;height:100%}
.chart-legend{display:flex;flex-direction:column;gap:8px;max-height:100%;overflow-y:auto;padding-right:4px}
.legend-item{display:flex;align-items:flex-start;gap:10px;padding:7px 10px;border:1px solid rgba(99,102,241,0.08);border-radius:10px;background:rgba(99,102,241,0.03)}
.legend-swatch{width:10px;height:10px;border-radius:50%;margin-top:5px;flex-shrink:0}
.legend-name{font-size:0.78rem;font-weight:600;color:#e8ecf4}
.legend-meta{font-size:0.68rem;color:#5a6478}
.sub-bot-table{width:100%;border-collapse:collapse;margin-bottom:12px}
.sub-bot-table td{padding:8px 16px;border-bottom:1px solid rgba(99,102,241,0.08);font-size:0.85rem}
.abuse-score{font-weight:700;font-size:0.82rem;padding:3px 10px;border-radius:6px;display:inline-block;min-width:44px;text-align:center}
.log-toggle-btn{background:none;border:1px solid #1e2235;color:#94a3b8;padding:4px 10px;border-radius:6px;cursor:pointer;font-size:0.72rem;font-family:inherit;transition:all 0.2s}
.log-toggle-btn:hover{border-color:#6366f1;color:#818cf8}
.access-log-wrap{margin:8px 16px 16px;background:#0c0e16;border:1px solid #1e2235;border-radius:10px;overflow:hidden}
.access-log-table{width:100%;border-collapse:collapse}
.access-log-table th{background:rgba(12,14,22,0.8);padding:8px 12px;font-size:0.68rem;text-transform:uppercase;letter-spacing:0.06em;color:#5a6478;font-weight:600;border-bottom:1px solid #1e2235}
.access-log-table td{padding:6px 12px;border-bottom:1px solid rgba(30,34,53,0.3);font-size:0.78rem}
.access-log-table tr:hover{background:rgba(99,102,241,0.03)}
.log-method{font-weight:600;font-size:0.72rem;color:#818cf8}
.log-status{font-weight:700;font-size:0.75rem;padding:2px 8px;border-radius:4px;display:inline-block}
.log-path{font-family:'SF Mono','Fira Code',ui-monospace,monospace;font-size:0.72rem;color:#94a3b8;max-width:350px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.log-size{font-family:'SF Mono','Fira Code',ui-monospace,monospace;font-size:0.72rem;color:#5a6478}
.log-time{font-size:0.72rem;color:#5a6478;white-space:nowrap}
.log-alert-row td{background:rgba(239,68,68,0.03)}
.log-more-note{padding:10px 16px;text-align:center;color:#5a6478;font-size:0.75rem;border-top:1px solid #1e2235}
.report-footer{text-align:center;color:#5a6478;font-size:0.78rem;margin-top:40px;padding-top:20px;border-top:1px solid #1e2235}
.scroll-wrap{max-height:600px;overflow-y:auto}
.scroll-wrap::-webkit-scrollbar{width:5px}
.scroll-wrap::-webkit-scrollbar-track{background:transparent}
.scroll-wrap::-webkit-scrollbar-thumb{background:#1e2235;border-radius:4px}
@media print{
body{background:#fff!important;color:#1a1e2e!important;padding:20px}
.container{max-width:100%}
.stat-card,.section,.chart-card{background:#fff!important;border-color:#e2e8f0!important;box-shadow:none!important;-webkit-print-color-adjust:exact;print-color-adjust:exact;break-inside:avoid}
.stat-card:hover,.section:hover{transform:none!important}
.stat-label,.report-subtitle{color:#64748b!important}
.stat-value{color:#1e293b!important}
.section-header{background:#f8fafc!important;color:#1e293b!important}
thead th{background:#f1f5f9!important;color:#475569!important}
tbody td{border-color:#e2e8f0!important;color:#334155!important}
.ip-code{background:rgba(220,38,38,0.06)!important;color:#b91c1c!important;border-color:rgba(220,38,38,0.15)!important}
.asn-code{background:rgba(124,58,237,0.08)!important;color:#6d28d9!important;border-color:rgba(124,58,237,0.15)!important}
.country-flag{background:rgba(5,150,105,0.08)!important;color:#047857!important}
.hits-badge{color:#0e7490!important}
.hits-danger{color:#b91c1c!important}
.detail-row{background:#f8fafc!important}
.detail-container{background:#f8fafc!important}
.report-title{-webkit-text-fill-color:#4f46e5!important}
.scroll-wrap{max-height:none!important;overflow:visible!important}
.traffic-bar-wrap{background:rgba(0,0,0,0.04)!important}
.traffic-bar-blue{background:linear-gradient(90deg,rgba(79,70,229,0.25),rgba(79,70,229,0.08))!important}
.traffic-bar-purple{background:linear-gradient(90deg,rgba(124,58,237,0.25),rgba(124,58,237,0.08))!important}
.traffic-pct{color:#475569!important}
.metric-box{background:#f8fafc!important;border:1px solid #e2e8f0!important}
.metric-chip{background:#fff!important;border-color:#e2e8f0!important}
.metric-chip-key{color:#475569!important}
.legend-item{background:#f8fafc!important;border-color:#e2e8f0!important}
.ip-pill{background:#f8fafc!important;border-color:#e2e8f0!important}
.access-log-wrap{display:block!important;background:#fff!important;border-color:#e2e8f0!important}
.access-log-table th{background:#f1f5f9!important;color:#475569!important}
.access-log-table td{border-color:#e2e8f0!important;color:#334155!important}
.log-toggle-btn{display:none!important}
.expand-chevron{display:none!important}
.charts-row{break-inside:avoid}
.report-badge{border-color:#e2e8f0!important;background:rgba(79,70,229,0.06)!important}
.report-footer{color:#94a3b8!important}
.report-period{color:#475569!important}
.report-period strong{color:#1e293b!important}
}

@media(max-width:768px){
.charts-row{grid-template-columns:1fr}
.chart-layout{grid-template-columns:1fr}
.metrics-grid{grid-template-columns:1fr}
.stat-cards{grid-template-columns:repeat(auto-fit,minmax(140px,1fr))}
.stat-value{font-size:1.6rem}
}`;
    }

    /* ══════════════════════════════════════════════════════════════
       Section Builders
       ══════════════════════════════════════════════════════════════ */

    function buildHeader(parseResult, generatedAt) {
        const counts = parseResult?.skipCounts;
        const exclusions = counts ? `<p class="report-period">Analysis exclusions: internal requests ${parseResult.options.skipInternal ? 'excluded' : 'included'}; ordinary 403 responses ${parseResult.options.skip403 ? 'excluded (recognized crawlers retained)' : 'included'}.<br>Skipped: ${n(counts.privateIP)} private/local IP · ${n(counts.healthCheck)} health-check path · ${n(counts.forbidden)} ordinary 403 · ${n(counts.invalid)} invalid.</p>` : '';
        const period = parseResult?.logStart
            ? `<p class="report-period">📅 Log Period: <strong>${esc(parseResult.logStart)}</strong> → <strong>${esc(parseResult.logEnd)}</strong> (${parseResult.logSpanMinutes} min)</p>`
            : '';
        const nodeCount = _options?.nodeCount || parseResult?.nodeCount || 1;
        const nodeBadge = nodeCount > 1
            ? `<div class="report-badge" style="background:rgba(16,185,129,0.1);color:#34d399;border-color:rgba(16,185,129,0.25);">🌐 Multi-Node Cluster (${nodeCount} web nodes merged)</div>`
            : '<div class="report-badge">📄 Self-Contained Report · Interactive Charts</div>';
        return `<div class="report-header">
    <h1 class="report-title">🛡️ Traffic Log Analysis Report</h1>
    <p class="report-subtitle">Generated: ${esc(generatedAt)} · SysAdmin Toolkit</p>
    ${nodeBadge}
    ${period}
    ${exclusions}
</div>`;
    }

    function buildStatCards(data) {
        const total = data.total_requests;
        const humanPct = total ? Math.round(data.human_requests / total * 100) : 0;
        const verifiedCount = data.verified_bots_count || 0;
        const spoofedCount = data.spoofed_bots_count || 0;
        const verifiedPct = total ? Math.round(verifiedCount / total * 1000) / 10 : 0;
        const spoofedPct = total ? Math.round(spoofedCount / total * 1000) / 10 : 0;

        return `<div class="stat-cards">
    <div class="stat-card sc-blue"><div class="stat-icon">⚡</div><div class="stat-value" style="color:#6366f1">${n(total)}</div><div class="stat-label">Total Requests</div></div>
    <div class="stat-card sc-cyan"><div class="stat-icon">🖥️</div><div class="stat-value" style="color:#22d3ee">${n(data.unique_ips)}</div><div class="stat-label">Unique IPs</div></div>
    <div class="stat-card sc-green"><div class="stat-icon">🌍</div><div class="stat-value" style="color:#10b981">${n(data.unique_countries)}</div><div class="stat-label">Countries</div></div>
    <div class="stat-card sc-amber"><div class="stat-icon">📡</div><div class="stat-value" style="color:#f59e0b">${n(data.unique_asns)}</div><div class="stat-label">ASNs</div></div>
    <div class="stat-card sc-purple"><div class="stat-icon">👥</div><div class="stat-value" style="color:#a855f7">${humanPct}%</div><div class="stat-label">Human Traffic</div></div>
    <div class="stat-card" style="border-top:3px solid #10b981"><div class="stat-icon">🛡️</div><div class="stat-value" style="color:#10b981">${n(verifiedCount)}</div><div class="stat-label">Verified Bots (${verifiedPct}%)</div></div>
    <div class="stat-card" style="border-top:3px solid ${spoofedCount > 0 ? '#ef4444' : '#1e2235'}"><div class="stat-icon">🚨</div><div class="stat-value" style="color:${spoofedCount > 0 ? '#ef4444' : '#5a6478'}">${n(spoofedCount)}</div><div class="stat-label">Spoofed Bots (${spoofedPct}%)</div></div>
</div>`;
    }

    function buildHttpMetrics(data) {
        const m = data.http_metrics;
        if (!m) return '';
        const statusChips = Object.entries(m.status_categories).map(([cat, count]) =>
            `<div class="metric-chip"><span class="metric-chip-key">${esc(cat)}</span><span class="metric-chip-val" style="color:#6366f1">${n(count)}</span></div>`
        ).join('');
        const methodChips = m.method_hits.map(h =>
            `<div class="metric-chip"><span class="metric-chip-key">${esc(h.method)}</span><span class="metric-chip-val" style="color:#10b981">${n(h.count)}</span></div>`
        ).join('');
        const pathRows = (m.top_paths || []).slice(0, 20).map((p, i) =>
            `<div class="path-row"><span class="path-idx">${i+1}</span><code class="path-val">${esc(p.path)}</code><span class="path-count">${n(p.count)}</span><span class="path-pct">${p.percentage}%</span></div>`
        ).join('') || '<div style="padding:10px;text-align:center;color:#5a6478;font-size:0.8rem">No path data</div>';
        const rs = m.response_size;
        return `<div class="section" style="margin-bottom:20px">
    <div class="section-header">📊 HTTP Metrics</div>
    <div class="metrics-grid">
        <div class="metric-box"><div class="metric-label">Status Categories</div><div class="metric-chips">${statusChips}</div></div>
        <div class="metric-box"><div class="metric-label">Request Methods</div><div class="metric-chips">${methodChips}</div></div>
    </div>
    <div class="metrics-grid" style="padding-top:0">
        <div class="metric-box"><div class="metric-label">Top Paths <span style="font-size:0.7rem;opacity:0.7">(by hit count)</span></div><div class="paths-list">${pathRows}</div></div>
        <div class="metric-box"><div class="metric-label">Response Size</div><div style="font-size:0.85rem">
            <div class="resp-row"><span>Total:</span><span class="resp-val">${n(rs.total)} bytes</span></div>
            <div class="resp-row"><span>Average:</span><span class="resp-val">${n(Math.round(rs.average))} bytes</span></div>
            <div class="resp-row"><span>Median:</span><span class="resp-val">${n(rs.median)} bytes</span></div>
            <div class="resp-row"><span>Range:</span><span class="resp-val">${n(rs.min)} – ${n(rs.max)} bytes</span></div>
        </div></div>
    </div>
</div>`;
    }

    function buildRequestRateSection(data) {
        const rr = data.request_rate;
        if (!rr || rr.total_buckets === 0) return '';
        const sev = rr.burst_severity;
        const badgeColor = sev === 'critical' ? '#ef4444' : (sev === 'elevated' ? '#f59e0b' : '#10b981');
        const badgeBg = sev === 'critical' ? 'rgba(239,68,68,0.15)' : (sev === 'elevated' ? 'rgba(245,158,11,0.15)' : 'rgba(16,185,129,0.15)');

        return `<div class="section" style="margin-bottom:20px">
    <div class="section-header" style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
        <span>⚡ Request Rate (RPS) & Traffic Spike Detection</span>
        <span style="font-size:0.75rem;color:#94a3b8;font-weight:normal">${esc(rr.start_time)} → ${esc(rr.end_time)} (${esc(rr.bucket_label)} buckets • ${rr.total_buckets} points)</span>
    </div>
    <div class="stat-cards" style="grid-template-columns:repeat(auto-fit,minmax(140px,1fr));margin-bottom:14px;padding:12px 16px 0">
        <div class="stat-card" style="border-top-color:#ef4444;padding:16px 10px"><div class="stat-label">Peak Rate</div><div class="stat-value" style="color:#ef4444;font-size:1.3rem">${rr.peak_rps} <span style="font-size:0.75rem;color:#94a3b8">req/s</span></div><div style="font-size:0.7rem;color:#94a3b8">at ${esc(rr.peak_time_str)} (${n(rr.peak_count)} reqs)</div></div>
        <div class="stat-card" style="border-top-color:#6366f1;padding:16px 10px"><div class="stat-label">Average Rate</div><div class="stat-value" style="color:#6366f1;font-size:1.3rem">${rr.avg_rps} <span style="font-size:0.75rem;color:#94a3b8">req/s</span></div><div style="font-size:0.7rem;color:#94a3b8">over ${n(rr.duration_seconds)}s window</div></div>
        <div class="stat-card" style="border-top-color:${badgeColor};padding:16px 10px"><div class="stat-label">Traffic Burst</div><div class="stat-value" style="font-size:0.92rem;padding:4px 0"><span style="background:${badgeBg};color:${badgeColor};padding:3px 8px;border-radius:6px;font-size:0.78rem;font-weight:700">${esc(rr.burst_label)}</span></div><div style="font-size:0.7rem;color:#94a3b8">${rr.spike_ratio}x baseline surge</div></div>
        <div class="stat-card" style="border-top-color:#f59e0b;padding:16px 10px"><div class="stat-label">Peak Errors</div><div class="stat-value" style="color:#f59e0b;font-size:1.3rem">${rr.peak_error_rate}%</div><div style="font-size:0.7rem;color:#94a3b8">4xx/5xx at peak burst</div></div>
    </div>
    <div class="chart-card" style="margin-bottom:0;border:none;border-radius:0">
        <div class="chart-body" style="height:250px;padding:12px 16px"><canvas id="report-rps-chart"></canvas></div>
    </div>
</div>`;
    }

    function buildCharts(data) {
        const colors = ['#6366f1','#a855f7','#06b6d4','#10b981','#f59e0b','#ef4444','#ec4899','#8b5cf6','#14b8a6','#f97316'];
        const top = data.country_hits.slice(0, 10);
        const legend = top.map((c, i) =>
            `<div class="legend-item"><span class="legend-swatch" style="background:${colors[i]}"></span><div><div class="legend-name">${esc(c.country)}</div><div class="legend-meta">${n(c.hits)} hits · ${pct(c.hits, data.total_requests)}%</div></div></div>`
        ).join('');
        return `<div class="charts-row">
    <div class="chart-card"><div class="chart-card-header">🌍 Country Distribution</div><div class="chart-body"><div class="chart-layout"><div class="chart-canvas-wrap"><canvas id="report-country-chart"></canvas></div><div class="chart-legend">${legend}</div></div></div></div>
    <div class="chart-card"><div class="chart-card-header">🏢 ASN Distribution</div><div class="chart-body"><canvas id="report-asn-chart"></canvas></div></div>
</div>`;
    }

    function buildCountryTable(data) {
        const total = data.total_requests;
        const rows = data.country_hits.map(c => {
            const p = pct(c.hits, total);
            const key = 'c-' + esc(c.country).replace(/[\s'"]/g, '_');
            const pills = (c.ip_details || []).map(d => `<div class="ip-pill"><span class="ip-code">${esc(d.ip)}</span><span class="ip-pill-hits">${n(d.hits)} hits</span></div>`).join('');
            return `<tr class="expand-row" data-detail-key="${key}"><td><span class="country-flag">${esc(c.country_code)}</span> ${esc(c.country)} <span class="expand-chevron">▸</span></td><td class="text-right"><span class="hits-badge">${n(c.hits)}</span></td><td class="text-right">${n(c.unique_ips)}</td><td><div class="traffic-bar-wrap"><div class="traffic-bar traffic-bar-blue" style="width:${p}%"></div><span class="traffic-pct">${p}%</span></div></td></tr>
<tr data-detail-id="${key}" style="display:none" class="detail-row"><td colspan="4" style="padding:0;border:none"><div class="detail-container"><div class="detail-title">IPs from ${esc(c.country)}</div><div class="detail-pills">${pills}</div></div></td></tr>`;
        }).join('');
        return `<div class="section" style="margin-bottom:20px"><div class="section-header">🌍 Country Breakdown</div><div class="scroll-wrap"><table><thead><tr><th>Country</th><th class="text-right">Hits</th><th class="text-right">Unique IPs</th><th style="min-width:120px">Traffic</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
    }

    function buildAsnTable(data) {
        const total = data.total_requests;
        const rows = data.asn_hits.map(a => {
            const p = pct(a.hits, total);
            const key = 'a-' + esc(a.asn);
            const pills = (a.ip_details || []).map(d => `<div class="ip-pill"><span class="ip-code">${esc(d.ip)}</span><span class="ip-pill-hits">${n(d.hits)} hits</span></div>`).join('');
            return `<tr class="expand-row" data-detail-key="${key}"><td><span class="asn-code">AS${esc(a.asn)}</span> <span class="expand-chevron">▸</span></td><td style="font-size:0.88rem">${esc(a.asn_org)}</td><td class="text-right"><span class="hits-badge">${n(a.hits)}</span></td><td class="text-right">${n(a.unique_ips)}</td><td><div class="traffic-bar-wrap"><div class="traffic-bar traffic-bar-purple" style="width:${p}%"></div><span class="traffic-pct">${p}%</span></div></td></tr>
<tr data-detail-id="${key}" style="display:none" class="detail-row"><td colspan="5" style="padding:0;border:none"><div class="detail-container"><div class="detail-title">IPs in AS${esc(a.asn)}</div><div class="detail-pills">${pills}</div></div></td></tr>`;
        }).join('');
        return `<div class="section" style="margin-bottom:20px"><div class="section-header">🏢 ASN Breakdown</div><div class="scroll-wrap"><table><thead><tr><th>ASN</th><th>Organization</th><th class="text-right">Hits</th><th class="text-right">Unique IPs</th><th style="min-width:120px">Traffic</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
    }

    function buildTopIpsTable(data) {
        const rows = data.top_ips.slice(0, 30).map((ip, i) =>
            `<tr><td style="color:#5a6478;font-size:0.8rem">${i+1}</td><td><span class="ip-code">${esc(ip.ip)}</span></td><td class="text-right"><span class="hits-badge${ip.hits > 100 ? ' hits-danger' : ''}">${n(ip.hits)}</span></td><td><span class="country-flag">${esc(ip.country_code)}</span> ${esc(ip.country)}</td><td><span class="asn-code">AS${ip.asn}</span> <span style="font-size:0.82rem;color:#94a3b8;margin-left:4px">${esc(ip.asn_org)}</span></td></tr>`
        ).join('');
        return `<div class="section" style="margin-bottom:20px"><div class="section-header">🎯 Top IPs (by hits)</div><div class="scroll-wrap"><table><thead><tr><th>#</th><th>IP Address</th><th class="text-right">Hits</th><th>Country</th><th>ASN / Org</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
    }

    function buildBotSection(data) {
        const total = data.total_requests;
        const humanPct = total ? Math.round(data.human_requests / total * 100) : 0;
        const botPct = 100 - humanPct;
        const groups = data.bot_groups || [];
        const spoofedCount = data.spoofed_bots_count || 0;

        let alertBanner = '';
        if (spoofedCount > 0) {
            alertBanner = `<div style="background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.35);border-radius:10px;padding:14px 18px;margin-bottom:16px;">
                <div style="font-weight:700;color:#f87171;font-size:0.92rem;">🚨 Fake Bot Alert: Detected ${n(spoofedCount)} requests impersonating official crawlers from untrusted IPs</div>
                <div style="font-size:0.8rem;color:#94a3b8;margin-top:3px;">${(data.spoofed_bot_ips || []).length} unique IP(s) claim search engine identity but failed official CIDR verification.</div>
            </div>`;
        }

        if (groups.length === 0) {
            return `<div class="section" style="margin-bottom:20px"><div class="section-header">🤖 Bot Traffic Analysis</div><div style="padding:30px 20px;text-align:center;color:#5a6478"><div style="font-size:2rem;margin-bottom:10px;opacity:0.4">🤖</div><p style="margin:0;font-size:0.95rem">No bot traffic detected in these logs.</p></div></div>`;
        }

        const rows = groups.map(g => {
            const key = 'b-' + esc(g.group_name).replace(/[\s'"]/g, '_');
            const statusBadge = g.verification_status === 'verified'
                ? `<span style="font-size:0.72rem;padding:2px 6px;border-radius:4px;background:rgba(16,185,129,0.15);color:#34d399;font-weight:600">Verified Genuine</span>`
                : g.verification_status === 'spoofed'
                ? `<span style="font-size:0.72rem;padding:2px 6px;border-radius:4px;background:rgba(239,68,68,0.15);color:#f87171;font-weight:600">Fake / Spoofed (${n(g.spoofed_requests || 0)})</span>`
                : g.verification_status === 'mixed'
                ? `<span style="font-size:0.72rem;padding:2px 6px;border-radius:4px;background:rgba(245,158,11,0.15);color:#fbbf24;font-weight:600">Mixed</span>`
                : `<span style="font-size:0.72rem;padding:2px 6px;border-radius:4px;background:rgba(100,116,139,0.15);color:#94a3b8;font-weight:600">Unverified</span>`;

            const subRows = g.has_sub_groups ? g.sub_bots.map(sb => {
                const subBadge = sb.verification_status === 'verified'
                    ? `<span style="font-size:0.68rem;color:#34d399">Verified</span>`
                    : sb.verification_status === 'spoofed'
                    ? `<span style="font-size:0.68rem;color:#f87171">Spoofed</span>`
                    : `<span style="font-size:0.68rem;color:#94a3b8">Unverified</span>`;
                return `<tr><td style="font-weight:500;font-size:0.85rem;color:#94a3b8">${esc(sb.bot_name)}</td><td>${subBadge}</td><td class="text-right"><span class="hits-badge">${n(sb.requests)}</span></td><td class="text-right" style="font-size:0.82rem">${sb.unique_ips} IPs</td><td class="text-right" style="font-size:0.82rem">${sb.pct}%</td></tr>`;
            }).join('') : '';

            const subTable = subRows ? `<div class="detail-title">Sub-bots in ${esc(g.group_name)}</div><table class="sub-bot-table"><thead><tr><th>Sub-Bot</th><th>Status</th><th class="text-right">Requests</th><th class="text-right">IPs</th><th class="text-right">%</th></tr></thead><tbody>${subRows}</tbody></table>` : '';
            const pills = g.sub_bots.flatMap(sb => sb.ip_details || []).sort((a,b) => b.hits - a.hits).map(d => {
                const tag = d.status === 'verified' ? '<span style="color:#34d399;font-weight:700;margin:0 3px">🟢</span>' : d.status === 'spoofed' ? '<span style="color:#f87171;font-weight:700;margin:0 3px">🔴</span>' : '';
                return `<div class="ip-pill"><span class="ip-code">${esc(d.ip)}</span>${tag}<span class="ip-pill-hits">${n(d.hits)} hits</span></div>`;
            }).join('');

            return `<tr class="expand-row" data-detail-key="${key}"><td style="font-weight:600">${esc(g.group_name)}${g.has_sub_groups ? ` <span style="font-size:0.7rem;color:#5a6478">(${g.sub_bots.length} sub-bots)</span>` : ''} <span class="expand-chevron">▸</span></td><td>${statusBadge}</td><td class="text-right"><span class="hits-badge">${n(g.requests)}</span></td><td class="text-right">${g.unique_ips}</td><td class="text-right">${g.pct}%</td></tr>
<tr data-detail-id="${key}" style="display:none" class="detail-row"><td colspan="5" style="padding:0;border:none"><div class="detail-container">${subTable}<div class="detail-title">${esc(g.group_name)} IPs</div><div class="detail-pills">${pills}</div></div></td></tr>`;
        }).join('');

        let attackersTable = '';
        if (data.spoofed_bot_attackers && data.spoofed_bot_attackers.length > 0) {
            const attRows = data.spoofed_bot_attackers.map((att, i) =>
                `<tr><td>${i+1}</td><td><span class="ip-code" style="color:#f87171">${esc(att.ip)}</span></td><td>${esc(att.bot_name)}</td><td class="text-right"><span class="hits-badge hits-danger">${n(att.hits)}</span></td><td>${esc(att.country)}</td><td>${esc(att.asn_org)}</td><td>${esc(att.reason)}</td></tr>`
            ).join('');
            attackersTable = `<div style="margin-top:20px"><div class="detail-title" style="color:#f87171">🚨 Detected Spoofed Bot Attackers</div><table><thead><tr><th>#</th><th>Spoofed IP</th><th>Claimed Bot</th><th class="text-right">Hits</th><th>Country</th><th>ASN / Org</th><th>Reason</th></tr></thead><tbody>${attRows}</tbody></table></div>`;
        }

        return `<div class="section" style="margin-bottom:20px"><div class="section-header">🤖 Bot Traffic Analysis & Spoofing Guard (${botPct}% of total)</div><div style="padding:16px 20px 0">${alertBanner}</div><div class="scroll-wrap"><table><thead><tr><th>Bot Group</th><th>Verification Status</th><th class="text-right">Requests</th><th class="text-right">Unique IPs</th><th class="text-right">% of Total</th></tr></thead><tbody>${rows}</tbody></table>${attackersTable}</div></div>`;
    }

    /* ── Abuse Section (compact vs full mode) ── */

    function buildAbuseSection(data, compact) {
        const hasAbuseData = (data.top_ips || []).some(ip => typeof ip.abuse_score === 'number');
        if (!hasAbuseData) return '';

        const abusiveIPs = [...data.top_ips]
            .filter(ip => typeof ip.abuse_score === 'number')
            .sort((a, b) => b.abuse_score - a.abuse_score);
        const logEntries = data.ip_log_entries;

        const rows = abusiveIPs.map((r, i) => {
            const entries = logEntries ? (logEntries.get(r.ip) || []) : [];
            const lid = 'logc-' + ipId(r.ip);
            const cnt = entries.length;

            let logBlock = '';
            if (!compact && cnt > 0) {
                // Full mode: pre-rendered HTML table
                logBlock = `<tr class="detail-row"><td colspan="8" style="padding:0;border:none">
                    <div id="${lid}" style="display:none" class="access-log-wrap"><table class="access-log-table">
                    <thead><tr><th>#</th><th>Date / Time</th><th>Method</th><th>Status</th><th>Request / Path</th><th>Size</th></tr></thead><tbody>
                    ${entries.slice(0, 200).map((e, j) => `<tr class="${e.status_code >= 400 ? 'log-alert-row' : ''}"><td>${j+1}</td><td class="log-time">${fmtTime(e.timestamp)}</td><td>${e.method ? `<span class="log-method">${esc(e.method)}</span>` : '—'}</td><td>${e.status_code ? `<span class="log-status" style="background:${statusColor(e.status_code)}22;color:${statusColor(e.status_code)}">${e.status_code}</span>` : '—'}</td><td class="log-path">${esc(e.url || e.raw_line || '—')}</td><td class="log-size">${e.response_size != null && !isNaN(e.response_size) ? n(e.response_size) + ' B' : '—'}</td></tr>`).join('')}
                    </tbody></table>${cnt > 200 ? `<div class="log-more-note">Showing first 200 of ${n(cnt)} entries</div>` : ''}</div>
                </td></tr>`;
            } else if (compact && cnt > 0) {
                // Compact mode: empty container, JS renders on demand
                logBlock = `<tr class="detail-row"><td colspan="8" style="padding:0;border:none"><div id="${lid}" style="display:none" class="access-log-wrap"></div></td></tr>`;
            }

            const btnAttr = compact ? `data-ip="${esc(r.ip)}"` : `data-target="${lid}"`;

            return `<tr style="border-bottom:1px solid rgba(30,34,53,0.5)">
                <td style="color:#5a6478;font-size:0.8rem">${i+1}</td>
                <td><span class="ip-code">${esc(r.ip)}</span></td>
                <td class="text-right"><span class="hits-badge">${n(r.hits)}</span></td>
                <td class="text-right"><span class="abuse-score" style="background:${abuseBg(r.abuse_score)};color:${abuseColor(r.abuse_score)}">${r.abuse_score}%</span></td>
                <td><span class="country-flag">${esc(r.country_code)}</span> ${esc(r.country)}</td>
                <td><span class="asn-code">AS${esc(r.asn)}</span> <span style="font-size:0.82rem;color:#94a3b8;margin-left:4px">${esc(r.asn_org)}</span></td>
                <td class="text-right"><a href="https://www.abuseipdb.com/check/${encodeURIComponent(r.ip)}" target="_blank" rel="noopener" style="font-size:0.78rem;font-weight:600">Check ↗</a></td>
                <td class="text-right">${cnt > 0 ? `<button class="log-toggle-btn" ${btnAttr}>📋 View Logs (${n(cnt)})</button>` : '<span style="color:#5a6478;font-size:0.72rem">No logs</span>'}</td>
            </tr>${logBlock}`;
        }).join('');

        return `<div class="section" style="margin-bottom:20px"><div class="section-header">🛡️ AbuseIPDB Results</div><div class="scroll-wrap"><table><thead><tr><th>#</th><th>IP</th><th class="text-right">Hits</th><th class="text-right">Abuse Score</th><th>Country</th><th>ASN / Org</th><th class="text-right">Know More</th><th class="text-right">Logs</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
    }

    /* ── Log Data JSON (compact mode only) ── */
    function buildLogDataJSON(data) {
        const hasAbuseData = (data.top_ips || []).some(ip => typeof ip.abuse_score === 'number');
        if (!hasAbuseData) return '';
        const logEntries = data.ip_log_entries;
        if (!logEntries) return '{}';

        const result = {};
        const abusiveIPs = data.top_ips.filter(ip => typeof ip.abuse_score === 'number');
        for (const ipObj of abusiveIPs) {
            const entries = logEntries.get(ipObj.ip) || [];
            if (entries.length === 0) continue;
            result[ipObj.ip] = entries.slice(0, 50).map(e => [
                fmtTime(e.timestamp),
                e.method || null,
                e.status_code || null,
                esc(e.url || e.raw_line || ''),
                e.response_size != null && !isNaN(e.response_size) ? e.response_size : null,
            ]);
        }
        return JSON.stringify(result);
    }

    function buildFooter(generatedAt) {
        return `<div class="report-footer"><p style="margin-bottom:4px">SysAdmin Toolkit · GeoIP by MaxMind GeoLite2</p><p>Report generated: ${esc(generatedAt)}</p></div>`;
    }

    /* ══════════════════════════════════════════════════════════════
       Inline JS Builders
       ══════════════════════════════════════════════════════════════ */

    function buildChartInitJS(data) {
        const colors = ['#6366f1','#a855f7','#06b6d4','#10b981','#f59e0b','#ef4444','#ec4899','#8b5cf6','#14b8a6','#f97316'];
        const tc = data.country_hits.slice(0, 10);
        const ta = data.asn_hits.slice(0, 10);
        const cd = JSON.stringify({ labels: tc.map(c => c.country), datasets: [{ data: tc.map(c => c.hits), backgroundColor: colors.slice(0, tc.length), borderWidth: 0 }] });
        const ad = JSON.stringify({ labels: ta.map(a => a.asn_org.length > 25 ? a.asn_org.substring(0, 25) + '...' : a.asn_org), datasets: [{ label: 'Hits', data: ta.map(a => a.hits), backgroundColor: colors.slice(0, ta.length), borderRadius: 6, borderSkipped: false }] });

        let rpsInit = '';
        if (data.request_rate && data.request_rate.total_buckets > 0) {
            const rr = data.request_rate;
            const rpsLabels = JSON.stringify(rr.labels);
            const rpsData = JSON.stringify(rr.buckets.map(b => b.rps));
            rpsInit = `var rc=document.getElementById('report-rps-chart');if(rc){new Chart(rc,{type:'line',data:{labels:${rpsLabels},datasets:[{label:'RPS',data:${rpsData},borderColor:'#6366f1',backgroundColor:'rgba(99,102,241,0.15)',borderWidth:2,fill:true,tension:0.25,pointRadius:0,pointHoverRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{color:'rgba(99,102,241,0.06)'},ticks:{color:'#94a3b8',maxTicksLimit:12}},y:{beginAtZero:true,grid:{color:'rgba(99,102,241,0.06)'},ticks:{color:'#94a3b8',callback:function(v){return v+' req/s'}}}}}});}`;
        }

        return `document.addEventListener('DOMContentLoaded',function(){if(typeof Chart==='undefined')return;${rpsInit}var cc=document.getElementById('report-country-chart');if(cc&&${tc.length}>0){new Chart(cc,{type:'doughnut',data:${cd},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}}}});}var ac=document.getElementById('report-asn-chart');if(ac&&${ta.length}>0){new Chart(ac,{type:'bar',data:${ad},options:{responsive:true,maintainAspectRatio:false,indexAxis:'y',plugins:{legend:{display:false}},scales:{x:{grid:{color:'rgba(99,102,241,0.06)'},ticks:{color:'#94a3b8'}},y:{grid:{display:false},ticks:{color:'#94a3b8',font:{size:11}}}}}});}});`;
    }

    function buildInteractiveJS(compact) {
        // Expand/collapse for country/ASN/bot rows (always present)
        let js = `document.addEventListener('DOMContentLoaded',function(){
document.querySelectorAll('.expand-row').forEach(function(row){
row.addEventListener('click',function(){
var key=this.getAttribute('data-detail-key');
var d=document.querySelector('[data-detail-id="'+key+'"]');
if(!d)return;var s=d.style.display!=='none';
d.style.display=s?'none':'table-row';
var c=this.querySelector('.expand-chevron');
if(c)c.textContent=s?'\\u25B8':'\\u25BE';});});
`;

        if (compact) {
            // Compact mode: render access logs on-demand from JSON
            js += `
var _ld=null;
function _getLD(){if(_ld)return _ld;var el=document.getElementById('_log_json');if(!el)return{};try{_ld=JSON.parse(el.textContent)}catch(e){_ld={}}return _ld;}
function _esc(s){return s?String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'):''}
document.querySelectorAll('.log-toggle-btn').forEach(function(btn){
btn.addEventListener('click',function(e){e.stopPropagation();
var ip=this.getAttribute('data-ip');if(!ip)return;
var cid='logc-'+ip.replace(/[.:]/g,'-');
var c=document.getElementById(cid);if(!c)return;
if(c.children.length===0){
var ld=_getLD();var ents=ld[ip]||[];
if(ents.length===0){c.innerHTML='<div style="padding:16px;text-align:center;color:#5a6478;font-size:0.82rem">No log entries found for this IP.</div>';
}else{var h='<table class="access-log-table"><thead><tr><th>#</th><th>Date / Time</th><th>Method</th><th>Status</th><th>Request / Path</th><th>Size</th></tr></thead><tbody>';
for(var i=0;i<ents.length;i++){var r=ents[i];var sc=r[2];var scC=sc>=500?'#ef4444':sc>=400?'#f59e0b':sc>=300?'#6366f1':'#10b981';
h+='<tr'+(sc>=400?' class="log-alert-row"':'')+'><td>'+(i+1)+'</td><td class="log-time">'+(r[0]||'\\u2014')+'</td><td>'+(r[1]?'<span class="log-method">'+_esc(r[1])+'</span>':'\\u2014')+'</td><td>'+(sc?'<span class="log-status" style="background:'+scC+'22;color:'+scC+'">'+sc+'</span>':'\\u2014')+'</td><td class="log-path">'+_esc(r[3]||'\\u2014')+'</td><td class="log-size">'+(r[4]!=null?r[4]+' B':'\\u2014')+'</td></tr>';}
h+='</tbody></table>';if(ents.length>=50)h+='<div class="log-more-note">Showing first 50 entries (compact mode)</div>';c.innerHTML=h;}}
var s=c.style.display!=='none';c.style.display=s?'none':'block';
this.textContent=s?this.textContent.replace('Hide','View'):this.textContent.replace('View','Hide');});});
`;
        } else {
            // Full mode: toggle pre-rendered log tables
            js += `
document.querySelectorAll('.log-toggle-btn').forEach(function(btn){
btn.addEventListener('click',function(e){e.stopPropagation();
var tid=this.getAttribute('data-target');
var t=document.getElementById(tid);if(!t)return;
var s=t.style.display!=='none';t.style.display=s?'none':'block';
this.textContent=s?this.textContent.replace('Hide','View'):this.textContent.replace('View','Hide');});});
`;
        }

        js += '});'; // close DOMContentLoaded
        return js;
    }

    /* ══════════════════════════════════════════════════════════════
       Utilities
       ══════════════════════════════════════════════════════════════ */
    function flattenObject(obj, prefix = '') {
        return Object.keys(obj).reduce((acc, k) => {
            const pre = prefix.length ? prefix + ' ' : '';
            if (typeof obj[k] === 'object' && obj[k] !== null && !Array.isArray(obj[k])) {
                Object.assign(acc, flattenObject(obj[k], pre + k));
            } else if (Array.isArray(obj[k])) {
                acc[pre + k] = JSON.stringify(obj[k]);
            } else {
                acc[pre + k] = obj[k];
            }
            return acc;
        }, {});
    }

    function exportToCSV(data, filename) {
        const rows = Array.isArray(data) ? data : [data];
        const flattenedData = rows.map(row => flattenObject(row));
        const headers = Array.from(new Set(flattenedData.flatMap(row => Object.keys(row))));
        const csvContent = [
            headers.join(','),
            ...flattenedData.map(row =>
                headers.map(h => {
                    const val = row[h] === undefined ? '' : String(row[h]);
                    return `"${val.replace(/"/g, '""')}"`;
                }).join(',')
            )
        ].join('\n');
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.setAttribute('href', url);
        link.setAttribute('download', `${filename}.csv`);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }

    function n(v) { return (v || 0).toString().replace(/\\B(?=(\\d{3})+(?!\\d))/g, ','); }

    return { openModal };
})();
window.Report = Report;
