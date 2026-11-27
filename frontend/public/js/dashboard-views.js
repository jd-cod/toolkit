/**
 * Traffic Analyzer — the dashboard's markup.
 *
 * Every function here returns HTML text for a part of the dashboard and
 * touches neither the page nor the dashboard's state. What a part needs
 * to know about the current view (filters, time window, page of the log
 * table) arrives as `view`, a snapshot made by dashboard.js.
 *
 * Text from a log is always passed through escapeHtml.
 */
const DashboardViews = (() => {
    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + (sizes[i] || 'B');
    }

    function numberWithCommas(n) {
        if (n === null || n === undefined) return '0';
        return n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    }

    function escapeHtml(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function statusColor(code) {
        if (code >= 500 && code <= 599) return 'var(--accent-red)';
        if (code >= 400 && code <= 499) return 'var(--accent-amber)';
        if (code >= 300 && code <= 399) return 'var(--accent-cyan)';
        if (code >= 200 && code <= 299) return 'var(--accent-green)';
        return 'var(--text-muted)';
    }

    // The two most frequent responses of a path, with the full split as a tooltip.
    function pathStatusHtml(p) {
        const split = Array.isArray(p.status_breakdown) ? p.status_breakdown : [];
        if (split.length === 0) return '<span style="color:var(--text-muted);">-</span>';
        const name = code => (code >= 100 && code <= 599 ? String(code) : 'none');
        const share = count => (p.count ? Math.round(count / p.count * 100) : 0);
        const all = split.map(s => `${name(s.code)}: ${numberWithCommas(s.count)}`).join(', ');
        const shown = split.slice(0, 2).map(s =>
            `<span style="color:${statusColor(s.code)};font-weight:700;">${name(s.code)}</span>${split.length > 1 ? `<span style="color:var(--text-muted);font-size:0.68rem;"> ${share(s.count)}%</span>` : ''}`
        ).join(' ');
        const more = split.length > 2 ? ` <span style="color:var(--text-muted);font-size:0.68rem;">+${split.length - 2}</span>` : '';
        return `<span title="${escapeHtml(all)}">${shown}${more}</span>`;
    }

    function formatSize(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    function formatDuration(ms, isTotal = false) {
        const seconds = Math.max(0, Math.round(ms / 1000));
        const hours = Math.floor(seconds / 3600);
        const mins = Math.floor(seconds / 60) % 60;
        const secs = seconds % 60;
        const text = [hours ? `${hours}h` : '', mins ? `${mins}m` : '', secs || !seconds ? `${secs}s` : ''].filter(Boolean).join(' ');
        return isTotal ? `${text} total` : text;
    }

    function formatTimelineTime(ms, includeDate = false) {
        const iso = new Date(ms).toISOString();
        return includeDate ? `${iso.slice(0, 10)} ${iso.slice(11, 19)}` : iso.slice(11, 19);
    }

    // The three largest names inside a bot group, e.g. "curl, python-requests".
    function botNamesHint(group) {
        const names = (group.sub_bots || []).slice(0, 3).map(b => b.bot_name || b.name).filter(n => n && n !== group.group_name);
        if (names.length === 0) return '';
        const more = (group.sub_bots || []).length - names.length;
        return ` <span style="font-size:0.68rem;color:var(--text-muted);">${escapeHtml(names.join(', '))}${more > 0 ? ` +${more}` : ''}</span>`;
    }

    /**
     * What the numbers on this page could not take into account: a GeoIP
     * database or crawler IP ranges that are not loaded. Without the notice,
     * "0 verified, 0 spoofed" and a column of "Unknown" read as findings.
     */
    function dataNotices(data, view) {
        const notices = [];
        const geo = typeof GeoIP !== 'undefined' && GeoIP.status ? GeoIP.status() : null;
        if (geo && (geo.country === 'failed' || geo.asn === 'failed')) {
            const what = geo.country === 'failed' && geo.asn === 'failed' ? 'Country and network data are'
                : (geo.country === 'failed' ? 'Country data is' : 'Network (ASN) data is');
            notices.push({
                id: 'geoip',
                text: `${what} unavailable: the GeoIP database could not be loaded. The affected values show as "Unknown"; everything else is analysed as usual.`,
                detail: [geo.errors.country, geo.errors.asn].filter(Boolean).join(' · '),
            });
        }

        for (const warning of (view.originalParseResult && view.originalParseResult.inputWarnings) || []) {
            notices.push({ id: 'input', text: warning, detail: '' });
        }

        const detector = typeof BotDetector !== 'undefined' ? BotDetector : null;
        if (detector && detector.rangeStatus && detector.getBotStats) {
            const missing = new Map();
            for (const group of (data && data.bot_groups) || []) {
                for (const bot of group.sub_bots || []) {
                    const known = (bot.verified_requests || 0) + (bot.spoofed_requests || 0) + (bot.unverified_requests || 0);
                    if (known > 0 && detector.rangeStatus(bot.bot_name) === 'missing') missing.set(bot.bot_name, (missing.get(bot.bot_name) || 0) + known);
                }
            }
            if (missing.size > 0) {
                const names = [...missing.entries()].sort((a, b) => b[1] - a[1]).map(([name]) => name);
                const requests = [...missing.values()].reduce((a, b) => a + b, 0);
                const shown = names.slice(0, 4).join(', ') + (names.length > 4 ? ` and ${names.length - 4} more` : '');
                notices.push({
                    id: 'bot-ranges',
                    text: detector.getBotStats().isLoaded
                        ? `Official IP ranges are not loaded for ${shown} (${numberWithCommas(requests)} requests). These crawlers cannot be confirmed as genuine here, so they are listed as unverified.`
                        : `The crawler IP range file could not be loaded. ${shown} (${numberWithCommas(requests)} requests) cannot be confirmed as genuine, so they are listed as unverified.`,
                    detail: '',
                });
            }
        }
        return notices;
    }

    function renderDataNoticesHtml(data, view) {
        const notices = dataNotices(data, view);
        if (!notices.length) return '';
        return `
            <div id="data-notices" role="status" style="margin-bottom:14px;display:flex;flex-direction:column;gap:8px;">
                ${notices.map(n => `
                <div class="data-notice" data-notice="${n.id}" ${n.detail ? `title="${escapeHtml(n.detail)}"` : ''} style="display:flex;align-items:flex-start;gap:10px;padding:10px 14px;border:1px solid color-mix(in srgb, var(--accent-amber) 45%, transparent);background:color-mix(in srgb, var(--accent-amber) 9%, transparent);border-radius:9px;font-size:0.8rem;color:var(--text-secondary);">
                    <i class="bi bi-exclamation-triangle-fill" aria-hidden="true" style="color:var(--accent-amber);margin-top:1px;"></i>
                    <span>${escapeHtml(n.text)}</span>
                </div>`).join('')}
            </div>`;
    }

    function renderExclusionsHtml(parseResult, view) {
        const counts = parseResult?.skipCounts || {};
        // Switching an exclusion reads the log again. Text and files can be
        // read again; a stream cannot, and its options stay as they were set
        // before the analysis.
        const fixed = !view.currentSources ? 'disabled title="Set before the analysis: start a new analysis to change this."' : '';
        return `
            <fieldset class="signal-nginx-options signal-dashboard-exclusions" id="dashboard-exclusions">
                <legend>Analysis exclusions</legend>
                <div class="signal-exclusion-toggles">
                    <label><input type="checkbox" id="dash-skip-403" ${view.currentSkip403 ? 'checked' : ''} ${fixed}> Ignore 403 responses</label>
                    <label><input type="checkbox" id="dash-skip-internal" ${view.currentSkipInternal ? 'checked' : ''} ${fixed}> Ignore internal requests</label>
                    <label for="dash-client-ip" title="Which address on a log line is the visitor. Automatic uses the forwarded address (X-Forwarded-For) when the connecting address is private, or when nearly every line carries one.">Client address
                        <select id="dash-client-ip" class="filter-select" style="width:auto;" ${fixed}>
                            <option value="auto" ${view.currentClientIp === 'auto' ? 'selected' : ''}>Automatic</option>
                            <option value="remote" ${view.currentClientIp === 'remote' ? 'selected' : ''}>Connecting address</option>
                            <option value="forwarded" ${view.currentClientIp === 'forwarded' ? 'selected' : ''}>X-Forwarded-For</option>
                        </select>
                    </label>
                </div>
                <p class="signal-exclusion-counts" id="exclusion-counts">Skipped: <strong>${numberWithCommas(counts.privateIP || 0)}</strong> private/local IP · <strong>${numberWithCommas(counts.healthCheck || 0)}</strong> health-check path · <strong>${numberWithCommas(counts.forbidden || 0)}</strong> ordinary 403 · <strong>${numberWithCommas(counts.invalid || 0)}</strong> invalid</p>
                <details class="signal-nginx-option-help"><summary>What is excluded?</summary><p>Internal requests: private, loopback, link-local, CGNAT and IPv6 unique-local IPs (including mapped IPv4), plus exact paths /health, /healthz, /healthcheck, /health-check, /health_check, /readyz, /livez and /_health. Query strings and trailing slashes are ignored. Every User-Agent and response status is covered. Unknown ASN alone is not an exclusion.</p><p>403 filtering retains recognized crawlers for bot analysis. Each skipped line is counted once: private/local IP first, then health-check path, then ordinary 403. Changing an exclusion recalculates the loaded log and resets result filters. The input time span still includes excluded rows.</p></details>
                <p id="dash-exclusion-status" role="status">${parseResult?.validLines > 0 && !parseResult.parsedCount ? (fixed ? 'All valid requests are excluded. Start a new analysis with the options changed to include them.' : 'All valid requests are excluded. Adjust the options above to include them.') : (fixed ? 'These options were set before the analysis and cannot be changed for this source.' : '')}</p>
            </fieldset>`;
    }

    function getTimeWindowHtml(startPct, endPct, activeMins, view) {
        const window = view.getSelectedTimeRange(startPct, endPct);
        if (!window) return '<span>No timestamped log entries</span>';
        const { startMs, endMs } = window;
        const range = view.getGlobalTimeRange();
        const includeDate = new Date(range.minTs).toISOString().slice(0, 10) !== new Date(range.maxTs).toISOString().slice(0, 10);
        const prefix = startPct <= 0 && endPct >= 100 ? 'All time · ' : activeMins > 0 ? 'Last ' : '';
        return `<span class="timeline-range-times"><time datetime="${new Date(startMs).toISOString()}">${formatTimelineTime(startMs, includeDate)}</time> → <time datetime="${new Date(endMs).toISOString()}">${formatTimelineTime(endMs, includeDate)}</time></span><span class="time-span-pill">${prefix}${formatDuration(endMs - startMs)}</span>`;
    }

    function render3ColumnIncidentMatrixHtml(data, totalRequests) {
        return `
        <!-- 3-Column Dense Incident Matrix -->
        <div class="incident-3col-grid" id="signal-investigation">
            <!-- ── Column 1: Top IPs + Top Bot Intelligence ── -->
            <div class="incident-matrix-col">
                <!-- Card 1.1: Top Attacking IPs -->
                <div class="card-table-wrap" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:16px;">
                    <div class="table-header" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                        <span style="font-weight:700;font-size:0.86rem;"><i class="bi bi-shield-exclamation" style="color:var(--accent-amber);margin-right:6px;"></i>1. Most Active IPs</span>
                        <span class="pill pill-rose" style="font-size:0.7rem;">${(data.top_ips || []).length} IPs</span>
                    </div>
                    <div style="max-height:260px;overflow-y:auto;">
                        <table class="table-clean" style="width:100%;border-collapse:collapse;font-size:0.76rem;">
                            <thead>
                                <tr style="border-bottom:1px solid var(--border-color);">
                                    <th style="padding:6px 8px;text-align:left;color:var(--text-muted);">Client IP</th>
                                    <th style="padding:6px 8px;text-align:right;color:var(--text-muted);">Hits</th>
                                    <th style="padding:6px 8px;text-align:right;color:var(--text-muted);">Logs</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${(data.top_ips || []).slice(0, 15).map(ip => `
                                    <tr class="cross-filter-ip-row" data-ip="${escapeHtml(ip.ip)}" style="border-bottom:1px solid rgba(255,255,255,0.03);cursor:pointer;">
                                        <td style="padding:6px 8px;"><span class="ip-code">${escapeHtml(ip.ip)}</span></td>
                                        <td style="padding:6px 8px;text-align:right;font-weight:700;color:var(--text-primary);">${numberWithCommas(ip.hits)}</td>
                                        <td style="padding:6px 8px;text-align:right;">
                                            <button class="btn-inspect-ip-logs" data-ip="${escapeHtml(ip.ip)}" title="Inspect Logs" style="background:none;border:none;color:var(--accent-cyan);cursor:pointer;padding:2px 4px;">
                                                <i class="bi bi-journal-text"></i>
                                            </button>
                                        </td>
                                    </tr>
                                `).join('')}
                                ${(!data.top_ips || data.top_ips.length === 0) ? '<tr><td colspan="3" style="text-align:center;color:var(--text-muted);padding:10px;">No IPs recorded</td></tr>' : ''}
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Card 1.2: Top Bot Intelligence -->
                <div class="card-table-wrap" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:16px;">
                    <div class="table-header" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                        <span style="font-weight:700;font-size:0.86rem;"><i class="bi bi-robot" style="color:var(--accent-green);margin-right:6px;"></i>2. Bot Intelligence</span>
                        <span class="pill pill-emerald" style="font-size:0.7rem;">${(data.bot_groups || []).length} bot groups</span>
                    </div>
                    <div style="max-height:260px;overflow-y:auto;">
                        <table class="table-clean" style="width:100%;border-collapse:collapse;font-size:0.76rem;">
                            <thead>
                                <tr style="border-bottom:1px solid var(--border-color);">
                                    <th style="padding:6px 8px;text-align:left;color:var(--text-muted);">Bot Classification</th>
                                    <th style="padding:6px 8px;text-align:right;color:var(--text-muted);">Hits</th>
                                    <th style="padding:6px 8px;text-align:right;color:var(--text-muted);">Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${(data.bot_groups || []).map(b => {
                                    let rowsHtml = '';
                                    if (b.verified_requests > 0) {
                                        rowsHtml += `
                                        <tr class="cross-filter-bot-row" data-bot="verified" data-bot-group="${escapeHtml(b.group_name)}" style="border-bottom:1px solid rgba(255,255,255,0.03);cursor:pointer;">
                                            <td style="padding:6px 8px;"><strong>${escapeHtml(b.group_name)}</strong></td>
                                            <td style="padding:6px 8px;text-align:right;font-weight:700;">${numberWithCommas(b.verified_requests)}</td>
                                            <td style="padding:6px 8px;text-align:right;"><span class="pill pill-emerald" style="font-size:0.68rem;">🟢 Verified</span></td>
                                        </tr>`;
                                    }
                                    if (b.spoofed_requests > 0) {
                                        rowsHtml += `
                                        <tr class="cross-filter-bot-row" data-bot="spoofed" data-bot-group="${escapeHtml(b.group_name)}" style="border-bottom:1px solid rgba(255,255,255,0.03);cursor:pointer;">
                                            <td style="padding:6px 8px;"><strong style="color:var(--accent-red);">Fake ${escapeHtml(b.group_name)}</strong> <span style="font-size:0.68rem;color:var(--text-muted);">(Impersonator)</span></td>
                                            <td style="padding:6px 8px;text-align:right;font-weight:700;color:var(--accent-red);">${numberWithCommas(b.spoofed_requests)}</td>
                                            <td style="padding:6px 8px;text-align:right;"><span class="pill pill-rose" style="font-size:0.68rem;">🔴 Spoof</span></td>
                                        </tr>`;
                                    }
                                    if (b.unverified_requests > 0) {
                                        rowsHtml += `
                                        <tr class="cross-filter-bot-row" data-bot="unverified" data-bot-group="${escapeHtml(b.group_name)}" style="border-bottom:1px solid rgba(255,255,255,0.03);cursor:pointer;">
                                            <td style="padding:6px 8px;"><strong>${escapeHtml(b.group_name)}</strong></td>
                                            <td style="padding:6px 8px;text-align:right;font-weight:700;">${numberWithCommas(b.unverified_requests)}</td>
                                            <td style="padding:6px 8px;text-align:right;"><span class="pill pill-muted" style="font-size:0.68rem;">⚪ Bot</span></td>
                                        </tr>`;
                                    }
                                    if (b.automated_requests > 0) {
                                        rowsHtml += `
                                        <tr class="cross-filter-bot-row" data-bot="automated" data-bot-group="${escapeHtml(b.group_name)}" style="border-bottom:1px solid rgba(255,255,255,0.03);cursor:pointer;">
                                            <td style="padding:6px 8px;"><strong>${escapeHtml(b.group_name)}</strong>${botNamesHint(b)}</td>
                                            <td style="padding:6px 8px;text-align:right;font-weight:700;">${numberWithCommas(b.automated_requests)}</td>
                                            <td style="padding:6px 8px;text-align:right;"><span class="pill pill-amber" style="font-size:0.68rem;white-space:nowrap;">🟠 Automated</span></td>
                                        </tr>`;
                                    }
                                    if (b.suspected_requests > 0) {
                                        rowsHtml += `
                                        <tr class="cross-filter-bot-row" data-bot="suspected" data-bot-group="${escapeHtml(b.group_name)}" style="border-bottom:1px solid rgba(255,255,255,0.03);cursor:pointer;">
                                            <td style="padding:6px 8px;"><strong>${escapeHtml(b.group_name)}</strong>${botNamesHint(b)}</td>
                                            <td style="padding:6px 8px;text-align:right;font-weight:700;">${numberWithCommas(b.suspected_requests)}</td>
                                            <td style="padding:6px 8px;text-align:right;"><span class="pill pill-amber" style="font-size:0.68rem;white-space:nowrap;">🟡 Suspected</span></td>
                                        </tr>`;
                                    }
                                    return rowsHtml;
                                }).join('')}
                                ${(!data.bot_groups || data.bot_groups.length === 0) ? '<tr><td colspan="3" style="text-align:center;color:var(--text-muted);padding:10px;">No bots detected</td></tr>' : ''}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- ── Column 2: Top Targeted Paths + Top Abusive IPs (AbuseIPDB) ── -->
            <div class="incident-matrix-col">
                <!-- Card 2.1: Top Targeted Paths -->
                <div class="card-table-wrap" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:16px;">
                    <div class="table-header" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                        <span style="font-weight:700;font-size:0.86rem;"><i class="bi bi-bullseye" style="color:var(--accent-amber);margin-right:6px;"></i>3. Targeted Paths</span>
                        <span class="pill pill-amber" style="font-size:0.7rem;">${numberWithCommas(data.http_metrics?.distinct_paths ?? (data.http_metrics?.top_paths || []).length)} Paths</span>
                    </div>
                    <div style="max-height:260px;overflow-y:auto;">
                        <table class="table-clean" style="width:100%;border-collapse:collapse;font-size:0.76rem;">
                            <thead>
                                <tr style="border-bottom:1px solid var(--border-color);">
                                    <th style="padding:6px 8px;text-align:left;color:var(--text-muted);">Endpoint Path</th>
                                    <th style="padding:6px 8px;text-align:right;color:var(--text-muted);">Hits</th>
                                    <th style="padding:6px 8px;text-align:right;color:var(--text-muted);">Share</th>
                                    <th style="padding:6px 8px;text-align:right;color:var(--text-muted);" title="Responses the server gave for this path, most frequent first">Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${(data.http_metrics?.top_paths || []).slice(0, 30).map(p => `
                                    <tr class="cross-filter-path-row" data-path="${escapeHtml('=' + p.path)}" style="border-bottom:1px solid rgba(255,255,255,0.03);cursor:pointer;">
                                        <td style="padding:6px 8px;word-break:break-all;"><code style="font-size:0.74rem;color:${p.attack ? 'var(--accent-red)' : 'var(--accent-cyan)'};"${p.attack ? ` title="Looks like an attack path (${escapeHtml(p.attack)})"` : ''}>${escapeHtml(p.path.length > 80 ? p.path.slice(0, 77) + '…' : p.path)}</code></td>
                                        <td style="padding:6px 8px;text-align:right;font-weight:700;">${numberWithCommas(p.count)}</td>
                                        <td style="padding:6px 8px;text-align:right;color:var(--text-muted);">${p.percentage}%</td>
                                        <td class="path-status-cell" style="padding:6px 8px;white-space:nowrap;text-align:right;">${pathStatusHtml(p)}</td>
                                    </tr>
                                `).join('')}
                                ${data.http_metrics?.other_paths?.count > 0 ? `
                                    <tr class="path-other-row" style="color:var(--text-muted);">
                                        <td style="padding:6px 8px;">${numberWithCommas(data.http_metrics.other_paths.paths)} other paths</td>
                                        <td style="padding:6px 8px;text-align:right;">${numberWithCommas(data.http_metrics.other_paths.count)}</td>
                                        <td style="padding:6px 8px;text-align:right;">${data.http_metrics.other_paths.percentage}%</td>
                                        <td></td>
                                    </tr>` : ''}
                                ${(!data.http_metrics?.top_paths || data.http_metrics.top_paths.length === 0) ? '<tr><td colspan="4" style="text-align:center;color:var(--text-muted);padding:10px;">No path data</td></tr>' : ''}
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Card 2.2: Top Abusive IPs (AbuseIPDB Integration) -->
                <div class="card-table-wrap" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:16px;position:relative;">
                    <div class="table-header" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                        <span style="font-weight:700;font-size:0.86rem;"><i class="bi bi-radioactive" style="color:var(--accent-red);margin-right:6px;"></i>4. Abusive IPs (AbuseIPDB)</span>
                        <button id="btn-scan-abuseipdb" class="btn btn-rose" style="padding:2px 8px;font-size:0.7rem;display:none;">
                            <i class="bi bi-search"></i> Check the rest
                        </button>
                    </div>
                    <div id="abuse-scan-note" role="status" hidden style="font-size:0.72rem;color:var(--accent-amber);margin-bottom:8px;"></div>
                    <div id="abuse-overlay" style="position:absolute;inset:0;background:rgba(0,0,0,0.4);backdrop-filter:blur(2px);border-radius:12px;display:flex;flex-direction:column;align-items:center;justify-content:center;z-index:10;gap:8px;">
                        <button id="btn-center-scan-abuse" class="btn btn-rose" style="padding:10px 24px;font-size:0.9rem;font-weight:700;border-radius:8px;box-shadow:0 4px 15px rgba(244,63,94,0.3);">
                            <i class="bi bi-search"></i> Scan Top 20 IPs
                        </button>
                        <span style="font-size:0.7rem;color:rgba(255,255,255,0.6);">Powered by AbuseIPdb</span>
                    </div>
                    <div style="max-height:260px;overflow-y:auto;">
                        <table class="table-clean" style="width:100%;border-collapse:collapse;font-size:0.76rem;">
                            <thead>
                                <tr style="border-bottom:1px solid var(--border-color);">
                                    <th style="padding:6px 8px;text-align:left;color:var(--text-muted);">IP Address</th>
                                    <th style="padding:6px 8px;text-align:left;color:var(--text-muted);">Confidence</th>
                                    <th style="padding:6px 8px;text-align:left;color:var(--text-muted);">Domain Name</th>
                                    <th style="padding:6px 8px;text-align:right;color:var(--text-muted);">Country</th>
                                </tr>
                            </thead>
                            <tbody id="abuse-table-rows">
                                ${(data.top_ips || []).slice(0, 20).map(ip => `
                                    <tr>
                                        <td style="padding:6px 8px;"><span class="ip-code">${escapeHtml(ip.ip)}</span></td>
                                        <td style="padding:6px 8px;"><span style="font-size:0.72rem;color:var(--text-muted);">Ready to scan</span></td>
                                        <td style="padding:6px 8px;font-size:0.72rem;color:var(--text-muted);">-</td>
                                        <td style="padding:6px 8px;font-size:0.72rem;text-align:right;">-</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- ── Column 3: Top ASNs & Networks + Top Referrers ── -->
            <div class="incident-matrix-col">
                <!-- Card 3.1: Top ASNs & Networks -->
                <div class="card-table-wrap" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:16px;">
                    <div class="table-header" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                        <span style="font-weight:700;font-size:0.86rem;"><i class="bi bi-diagram-3" style="color:var(--accent-purple);margin-right:6px;"></i>5. ASNs & Networks</span>
                        <span class="pill pill-cyan" style="font-size:0.7rem;">${(data.asn_hits || []).length} ASNs</span>
                    </div>
                    <div style="max-height:260px;overflow-y:auto;">
                        <table class="table-clean" style="width:100%;border-collapse:collapse;font-size:0.76rem;">
                            <thead>
                                <tr style="border-bottom:1px solid var(--border-color);">
                                    <th style="padding:6px 8px;text-align:left;color:var(--text-muted);">ASN Org</th>
                                    <th style="padding:6px 8px;text-align:right;color:var(--text-muted);">Hits</th>
                                    <th style="padding:6px 8px;text-align:right;color:var(--text-muted);">Share</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${(data.asn_hits || []).slice(0, 15).map(a => {
                                    const pct = totalRequests ? (a.hits / totalRequests * 100).toFixed(1) : 0;
                                    return `
                                    <tr class="cross-filter-asn-row" data-asn="${escapeHtml(a.asn)}" style="border-bottom:1px solid rgba(255,255,255,0.03);cursor:pointer;">
                                        <td style="padding:6px 8px;"><span class="asn-code">AS${escapeHtml(a.asn)}</span> <span style="font-size:0.74rem;color:var(--text-secondary);">${escapeHtml(a.asn_org)}</span></td>
                                        <td style="padding:6px 8px;text-align:right;font-weight:700;">${numberWithCommas(a.hits)}</td>
                                        <td style="padding:6px 8px;text-align:right;color:var(--text-muted);">${pct}%</td>
                                    </tr>
                                    `;
                                }).join('')}
                                ${(!data.asn_hits || data.asn_hits.length === 0) ? '<tr><td colspan="3" style="text-align:center;color:var(--text-muted);padding:10px;">No ASN data</td></tr>' : ''}
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Card 3.2: Top Inbound Referrers -->
                <div class="card-table-wrap" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:16px;">
                    <div class="table-header" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                        <span style="font-weight:700;font-size:0.86rem;"><i class="bi bi-link-45deg" style="color:var(--accent-cyan);margin-right:6px;"></i>6. Top Referrers</span>
                        <span class="pill pill-muted" style="font-size:0.7rem;">${numberWithCommas(data.referrer_site_count ?? (data.referrer_sites || []).length)} Sites</span>
                    </div>
                    <div style="max-height:260px;overflow-y:auto;">
                        <table class="table-clean" style="width:100%;border-collapse:collapse;font-size:0.76rem;">
                            <thead>
                                <tr style="border-bottom:1px solid var(--border-color);">
                                    <th style="padding:6px 8px;text-align:left;color:var(--text-muted);">Referring site</th>
                                    <th style="padding:6px 8px;text-align:right;color:var(--text-muted);">Hits</th>
                                    <th style="padding:6px 8px;text-align:right;color:var(--text-muted);">Share</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${(data.referrer_sites || []).slice(0, 15).map(r => `
                                    <tr class="referrer-site-row" data-site="${escapeHtml(r.site)}" style="border-bottom:1px solid rgba(255,255,255,0.03);">
                                        <td style="padding:6px 8px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHtml(r.site)}"><code>${escapeHtml(r.site)}</code></td>
                                        <td style="padding:6px 8px;text-align:right;font-weight:700;">${numberWithCommas(r.hits)}</td>
                                        <td style="padding:6px 8px;text-align:right;color:var(--text-muted);">${r.pct}%</td>
                                    </tr>
                                `).join('')}
                                ${(!data.referrer_sites || data.referrer_sites.length === 0) ? '<tr><td colspan="3" style="text-align:center;color:var(--text-muted);padding:10px;">Direct traffic only</td></tr>' : ''}
                                ${(data.direct_requests > 0 && (data.referrer_sites || []).length > 0) ? `
                                    <tr id="referrer-direct-row" style="color:var(--text-muted);">
                                        <td style="padding:6px 8px;">No referrer (direct, bookmarks, most bots)</td>
                                        <td style="padding:6px 8px;text-align:right;">${numberWithCommas(data.direct_requests)}</td>
                                        <td style="padding:6px 8px;text-align:right;">${totalRequests ? (data.direct_requests / totalRequests * 100).toFixed(1) : '0.0'}%</td>
                                    </tr>` : ''}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
        `;
    }

    function renderLogExplorerCardHtml(view) {
        return `
            <div class="log-explorer-card" id="nginx-log-explorer" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;overflow:hidden;margin-bottom:20px;">
                <div class="log-explorer-header" style="padding:12px 18px;border-bottom:1px solid var(--border-color);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;background:rgba(0,0,0,0.2);">
                    <div style="display:flex;align-items:center;gap:8px;">
                        <h5 style="margin:0;font-size:0.88rem;font-weight:700;">
                            <i class="bi bi-table" style="color:var(--accent-primary);margin-right:6px;"></i> Log Explorer
                        </h5>
                        <span style="font-size:0.74rem;color:var(--text-muted);">(${numberWithCommas(view.latestPageResult ? view.latestPageResult.totalRows : (view.latestSummary ? view.latestSummary.matchingCount : 0))} entries)</span>
                    </div>

                    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                        <input type="text" id="log-table-ip-subnet-search" placeholder="🔍 Filter IP / CIDR Subnet..." value="${escapeHtml(view.activeFilters.ipSearch)}" style="background:rgba(0,0,0,0.3);border:1px solid var(--border-color);color:var(--text-primary);padding:5px 12px;border-radius:6px;font-size:0.75rem;min-width:210px;outline:none;" />
                        <input type="text" id="log-table-path-search" placeholder="🔍 Filter Path / URI Keyword..." value="${escapeHtml(view.activeFilters.pathSearch)}" style="background:rgba(0,0,0,0.3);border:1px solid var(--border-color);color:var(--text-primary);padding:5px 12px;border-radius:6px;font-size:0.75rem;min-width:210px;outline:none;" />
                        
                        <div style="font-size:0.75rem;color:var(--text-muted);display:flex;align-items:center;gap:6px;">
                            Per page: 
                            <select id="explorer-per-page" style="background:var(--bg-secondary);border:1px solid var(--border-color);color:var(--text-primary);padding:3px 6px;border-radius:4px;font-size:0.75rem;">
                                <option value="10" ${view.explorerPerPage === 10 ? 'selected' : ''}>10</option>
                                <option value="25" ${view.explorerPerPage === 25 ? 'selected' : ''}>25</option>
                                <option value="50" ${view.explorerPerPage === 50 ? 'selected' : ''}>50</option>
                                <option value="100" ${view.explorerPerPage === 100 ? 'selected' : ''}>100</option>
                            </select>
                        </div>
                    </div>
                </div>
                <div class="log-explorer-table-wrap" style="overflow-x:auto;">
                    <table class="log-explorer-table" style="width:100%;border-collapse:collapse;font-size:0.78rem;">
                        <thead>
                            <tr style="background:rgba(0,0,0,0.25);border-bottom:1px solid var(--border-color);">
                                <th style="padding:9px 12px;text-align:left;">Time</th>
                                <th style="padding:9px 12px;text-align:left;">IP Address</th>
                                <th style="padding:9px 12px;text-align:left;">Method</th>
                                <th style="padding:9px 12px;text-align:left;">Path</th>
                                <th style="padding:9px 12px;text-align:left;">Status</th>
                                <th style="padding:9px 12px;text-align:left;">Country</th>
                                <th style="padding:9px 12px;text-align:left;">Protocol</th>
                                <th style="padding:9px 12px;text-align:left;">User-Agent / Bot Intelligence</th>
                            </tr>
                        </thead>
                        <tbody id="explorer-rows-body"></tbody>
                    </table>
                </div>
                <div class="signal-horizontal-scroll-hint"><i class="bi bi-arrows-expand" aria-hidden="true"></i> Swipe horizontally to see all log columns</div>
                <div id="explorer-pagination-wrap" style="padding:10px 16px;border-top:1px solid var(--border-color);display:flex;justify-content:space-between;align-items:center;"></div>
            </div>
        `;
    }

    function renderUnifiedTelemetryCardHtml(requestRate, view) {
        const rawBuckets = requestRate?.buckets || requestRate?.data_points || [];
        const buckets = Array.isArray(rawBuckets) ? rawBuckets : [];
        const hasErrors = buckets.some(b => ((b.status_4xx || 0) + (b.status_5xx || 0)) > 0);

        return `
        <div class="table-card" id="signal-traffic" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:16px 20px;margin-bottom:18px;">
            <!-- Card Header: Title + Chart Interval + Time Range -->
            <div style="display:flex;justify-content:space-between;align-items:center;padding-bottom:12px;margin-bottom:12px;border-bottom:1px solid rgba(255,255,255,0.05);flex-wrap:wrap;gap:10px;">
                <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
                    <h5 style="margin:0;font-size:0.88rem;font-weight:700;">
                        <i class="bi bi-graph-up" style="margin-right:6px;color:var(--accent-primary);"></i>Traffic Timeline
                    </h5>
                </div>
                <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;">
                    <!-- Chart intervals: 1 sec, 5 sec, 1 min, 15 min -->
                    <div role="group" aria-labelledby="chart-interval-label" style="display:flex;gap:3px;align-items:center;flex-wrap:wrap;">
                        <span id="chart-interval-label" title="Choose how requests are grouped on the chart" style="font-size:0.68rem;color:var(--text-muted);margin-right:2px;white-space:nowrap;text-transform:uppercase;font-weight:600;">Chart Interval:</span>
                        <button class="rps-res-btn ${view.activeRpsResolution === '1' ? 'active' : ''}" data-res="1" title="Group requests into 1-second intervals" style="background:${view.activeRpsResolution === '1' ? 'rgba(99,102,241,0.2)' : 'var(--bg-secondary)'};border:1px solid ${view.activeRpsResolution === '1' ? 'var(--accent-primary)' : 'var(--border-color)'};color:${view.activeRpsResolution === '1' ? '#fff' : 'var(--text-secondary)'};padding:2px 7px;border-radius:4px;font-size:0.7rem;font-weight:600;cursor:pointer;">1 sec</button>
                        <button class="rps-res-btn ${view.activeRpsResolution === '5' ? 'active' : ''}" data-res="5" title="Group requests into 5-second intervals" style="background:${view.activeRpsResolution === '5' ? 'rgba(99,102,241,0.2)' : 'var(--bg-secondary)'};border:1px solid ${view.activeRpsResolution === '5' ? 'var(--accent-primary)' : 'var(--border-color)'};color:${view.activeRpsResolution === '5' ? '#fff' : 'var(--text-secondary)'};padding:2px 7px;border-radius:4px;font-size:0.7rem;font-weight:600;cursor:pointer;">5 sec</button>
                        <button class="rps-res-btn ${view.activeRpsResolution === '60' ? 'active' : ''}" data-res="60" title="Group requests into 1-minute intervals" style="background:${view.activeRpsResolution === '60' ? 'rgba(99,102,241,0.2)' : 'var(--bg-secondary)'};border:1px solid ${view.activeRpsResolution === '60' ? 'var(--accent-primary)' : 'var(--border-color)'};color:${view.activeRpsResolution === '60' ? '#fff' : 'var(--text-secondary)'};padding:2px 7px;border-radius:4px;font-size:0.7rem;font-weight:600;cursor:pointer;">1 min</button>
                        <button class="rps-res-btn ${view.activeRpsResolution === '900' ? 'active' : ''}" data-res="900" title="Group requests into 15-minute intervals" style="background:${view.activeRpsResolution === '900' ? 'rgba(99,102,241,0.2)' : 'var(--bg-secondary)'};border:1px solid ${view.activeRpsResolution === '900' ? 'var(--accent-primary)' : 'var(--border-color)'};color:${view.activeRpsResolution === '900' ? '#fff' : 'var(--text-secondary)'};padding:2px 7px;border-radius:4px;font-size:0.7rem;font-weight:600;cursor:pointer;">15 min</button>
                        <span id="rps-resolution-note" aria-live="polite" style="font-size:0.68rem;color:var(--text-muted);"></span>
                    </div>

                    <!-- Shortcuts: 30m, 1h, 2h, Custom Stepper, All -->
                    <div class="shortcuts-cluster" role="group" aria-labelledby="time-range-label" style="display:flex;gap:4px;align-items:center;">
                        <span id="time-range-label" title="Filter backward from the latest log entry" style="font-size:0.68rem;color:var(--text-muted);margin-right:2px;white-space:nowrap;text-transform:uppercase;font-weight:600;">Time Range:</span>
                        <button class="shortcut-btn ${view.activeTimeMinutes === 30 ? 'active' : ''}" data-mins="30" title="Last 30 minutes of the loaded logs">Last 30m</button>
                        <button class="shortcut-btn ${view.activeTimeMinutes === 60 ? 'active' : ''}" data-mins="60" title="Last 1 hour of the loaded logs">1h</button>
                        <button class="shortcut-btn ${view.activeTimeMinutes === 120 ? 'active' : ''}" data-mins="120" title="Last 2 hours of the loaded logs">2h</button>
                        
                        <div class="stepper-box">
                            <button class="stepper-btn" id="stepper-minus" title="Decrease hours" aria-label="Decrease hours">-</button>
                            <input type="text" class="stepper-input" id="stepper-val" value="${view.customHoursVal}" title="Time range in hours" aria-label="Time range in hours" />
                            <button class="stepper-btn" id="stepper-plus" title="Increase hours" aria-label="Increase hours">+</button>
                        </div>

                        <button class="shortcut-btn ${view.activeTimeMinutes === 0 && view.sliderStartPct === 0 && view.sliderEndPct === 100 ? 'active' : ''}" id="btn-all-time" title="Use the full log period" style="font-weight:800;">All time</button>
                    </div>
                </div>
            </div>

            <!-- ══════════════════════════════════════════════════════════════
                 DESIGN 2: IN-CHART TRANSLUCENT OVERLAY SCRUBBER
                 ══════════════════════════════════════════════════════════════ -->
                <!-- Keep the legend clear of the floating range readout. -->
                <div class="in-chart-legend-overlay" id="in-chart-legend">
                    <div class="in-chart-legend-item total" id="legend-item-total" title="Total Traffic">
                        <span style="width:8px;height:3px;border-radius:1px;background:#6366f1;"></span>
                        <span>Total Traffic</span>
                    </div>
                    ${hasErrors ? `
                    <div class="in-chart-legend-item errors" id="legend-item-errors" title="Error responses (4xx, 5xx)">
                        <span style="width:8px;height:3px;border-radius:1px;background:#ef4444;"></span>
                        <span>Error responses (4xx, 5xx)</span>
                    </div>
                    ` : ''}
                </div>

            <div class="chart-overlay-canvas-wrap" id="timeline-slider-wrap">
                <canvas id="rps-chart"></canvas>

                <!-- 3. Scrubber Track (bounded from chartArea.left to chartArea.right) -->
                <div class="slider-scrubber-track" id="slider-scrubber-track">
                    <!-- Shaded Outside Curtains -->
                    <div class="slider-curtain-left" id="slider-curtain-left" style="width:${view.sliderStartPct}%;"></div>
                    <div class="slider-curtain-right" id="slider-curtain-right" style="width:${100 - view.sliderEndPct}%;"></div>

                    <!-- Active Window Highlight -->
                    <div class="slider-active-window" id="slider-active-window" style="left:${view.sliderStartPct}%;width:${view.sliderEndPct - view.sliderStartPct}%;"></div>

                    <!-- Tactile Zip Handles -->
                    <div class="slider-handle-in-chart slider-handle handle-start" id="handle-start" role="slider" tabindex="0" aria-label="Start time" aria-orientation="horizontal" style="left:calc(${view.sliderStartPct}% - 10px);"><time class="slider-handle-time"></time></div>
                    <div class="slider-handle-in-chart slider-handle handle-end" id="handle-end" role="slider" tabindex="0" aria-label="End time" aria-orientation="horizontal" style="left:calc(${view.sliderEndPct}% - 10px);"><time class="slider-handle-time"></time></div>

                    <!-- Floating Time Window Readout Capsule with Boundary Clamping -->
                    <div class="slider-floating-badge" id="time-window-readout" style="left:clamp(120px, ${(view.sliderStartPct + view.sliderEndPct) / 2}%, calc(100% - 120px));">
                        ${getTimeWindowHtml(view.sliderStartPct, view.sliderEndPct, view.activeTimeMinutes, view)}
                    </div>
                </div>
            </div>
        </div>
        `;
    }

    function renderFacetedFilterRibbonHtml(filterOptions, view) {
        const totalReqs = view.wholeLogRequests;
        const matchedReqs = view.latestSummary ? (view.latestSummary.matchingCount || 0) : totalReqs;

        return `
        <div class="master-filter-box" id="nginx-master-filter-box" style="margin-bottom:20px;padding:12px 16px;">
            <div class="faceted-filter-row" style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;">
                <div class="filter-selects-wrap" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                    <!-- 1. All HTTP Methods -->
                    <select class="filter-select" id="filter-method">
                        <option value="all" ${view.activeFilters.method === 'all' ? 'selected' : ''}>All HTTP Methods</option>
                        ${filterOptions.methods.map(m => `<option value="${escapeHtml(m)}" ${view.activeFilters.method === m ? 'selected' : ''}>${escapeHtml(m)}</option>`).join('')}
                    </select>

                    <!-- Status class or code -->
                    <select class="filter-select" id="filter-status" aria-label="Response status">
                        <option value="all" ${view.activeFilters.statusCategory === 'all' ? 'selected' : ''}>All Statuses</option>
                        ${(filterOptions.statuses?.classes || []).length ? `<optgroup label="Class">${filterOptions.statuses.classes.map(o => `<option value="${o.value}" ${view.activeFilters.statusCategory === o.value ? 'selected' : ''}>${o.label || o.value} (${numberWithCommas(o.count)})</option>`).join('')}</optgroup>` : ''}
                        ${(filterOptions.statuses?.codes || []).length ? `<optgroup label="Code">${filterOptions.statuses.codes.map(o => `<option value="${o.value}" ${view.activeFilters.statusCategory === o.value ? 'selected' : ''}>${o.value} (${numberWithCommas(o.count)})</option>`).join('')}</optgroup>` : ''}
                        ${view.activeFilters.statusCategory !== 'all' && ![...(filterOptions.statuses?.classes || []), ...(filterOptions.statuses?.codes || [])].some(o => o.value === view.activeFilters.statusCategory) ? `<option value="${escapeHtml(view.activeFilters.statusCategory)}" selected>${view.activeFilters.statusCategory === 'other' ? 'No status' : escapeHtml(view.activeFilters.statusCategory)}</option>` : ''}
                    </select>

                    <!-- 2. All Countries -->
                    <select class="filter-select" id="filter-country">
                        <option value="all" ${view.activeFilters.country === 'all' ? 'selected' : ''}>All Countries</option>
                        ${filterOptions.countries.map(c => `<option value="${c.country}" ${view.activeFilters.country === c.country ? 'selected' : ''}>${c.country} (${numberWithCommas(c.count)})</option>`).join('')}
                    </select>

                    <!-- 3. All Paths -->
                    <select class="filter-select" id="filter-path-select">
                        <option value="all" ${!view.activeFilters.pathSearch ? 'selected' : ''}>All Paths</option>
                        ${(filterOptions.paths || []).map(p => `<option value="${escapeHtml('^' + p.path)}" ${view.activeFilters.pathSearch === '^' + p.path ? 'selected' : ''}>${escapeHtml(p.path)} (${numberWithCommas(p.count)})</option>`).join('')}
                        ${view.activeFilters.pathSearch && !(filterOptions.paths || []).some(p => '^' + p.path === view.activeFilters.pathSearch) ? `<option value="${escapeHtml(view.activeFilters.pathSearch)}" selected>${escapeHtml(RequestPaths.describeFilter(view.activeFilters.pathSearch))}</option>` : ''}
                    </select>

                    <!-- 4. All ASNs -->
                    <select class="filter-select" id="filter-asn">
                        <option value="all" ${view.activeFilters.asn === 'all' ? 'selected' : ''}>All ASNs</option>
                        ${filterOptions.asns.map(a => `<option value="${a.asn}" ${view.activeFilters.asn === String(a.asn) ? 'selected' : ''}>${a.label} (${numberWithCommas(a.count)})</option>`).join('')}
                    </select>

                    <!-- 5. All Traffic -->
                    <select class="filter-select" id="filter-bot" style="${view.activeFilters.bot === 'spoofed' ? 'border-color:var(--accent-red);color:var(--accent-red);' : ''}">
                        <option value="all" ${view.activeFilters.bot === 'all' ? 'selected' : ''}>All Traffic</option>
                        <option value="human" ${view.activeFilters.bot === 'human' ? 'selected' : ''}>👤 Human Traffic Only</option>
                        <option value="all_bots" ${view.activeFilters.bot === 'all_bots' ? 'selected' : ''}>🤖 All Bots</option>
                        <option value="verified" ${view.activeFilters.bot === 'verified' ? 'selected' : ''}>🟢 Verified Bots${view.activeFilters.bot === 'verified' && view.activeFilters.botGroup ? ' · ' + escapeHtml(view.activeFilters.botGroup) : ''}</option>
                        <option value="spoofed" ${view.activeFilters.bot === 'spoofed' ? 'selected' : ''}>🔴 Fake / Spoofed Bots${view.activeFilters.bot === 'spoofed' && view.activeFilters.botGroup ? ' · ' + escapeHtml(view.activeFilters.botGroup) : ''}</option>
                        <option value="unverified" ${view.activeFilters.bot === 'unverified' ? 'selected' : ''}>⚪ Unverified Bots${view.activeFilters.bot === 'unverified' && view.activeFilters.botGroup ? ' · ' + escapeHtml(view.activeFilters.botGroup) : ''}</option>
                        <option value="automated" ${view.activeFilters.bot === 'automated' ? 'selected' : ''}>🟠 Other Bots &amp; Tools${view.activeFilters.bot === 'automated' && view.activeFilters.botGroup ? ' · ' + escapeHtml(view.activeFilters.botGroup) : ''}</option>
                        <option value="suspected" ${view.activeFilters.bot === 'suspected' ? 'selected' : ''}>🟡 Suspected Bots${view.activeFilters.bot === 'suspected' && view.activeFilters.botGroup ? ' · ' + escapeHtml(view.activeFilters.botGroup) : ''}</option>
                    </select>

                    <!-- Search Fields -->
                    <input type="text" class="search-field" id="filter-ip" placeholder="🔍 Search IP..." value="${escapeHtml(view.activeFilters.ipSearch)}" />
                    <input type="text" class="search-field" id="filter-path" placeholder="🔗 Search Path..." title="Text found anywhere in the URL. =/a/b matches that exact path, ^/a everything under /a." value="${escapeHtml(view.activeFilters.pathSearch)}" />
                    <input type="text" class="search-field" id="filter-ua" placeholder="🧭 Search User-Agent..." style="min-width:190px;" title="Text found anywhere in the User-Agent, in any letter case." aria-label="User-Agent contains" value="${escapeHtml(view.activeFilters.uaSearch || '')}" />
                </div>

                <!-- Match Counter -->
                <div style="display:flex;align-items:center;gap:8px;">
                    <div class="match-counter-pill" id="filter-matching-badge">
                        <i class="bi bi-funnel-fill" style="color:var(--accent-primary);"></i> Matching <strong>${numberWithCommas(matchedReqs)}</strong> / ${numberWithCommas(totalReqs)} requests
                    </div>
                    ${view.hasActiveFilters() ? `
                    <button class="clear-btn" id="filter-clear-btn" title="Reset All Filters">
                        <i class="bi bi-x-circle-fill"></i>
                    </button>
                    ` : ''}
                </div>
            </div>
        </div>
        `;
    }

    return {
        formatBytes, numberWithCommas, escapeHtml, statusColor,
        pathStatusHtml, formatSize, formatDuration, formatTimelineTime, botNamesHint,
        dataNotices, renderDataNoticesHtml, renderExclusionsHtml, getTimeWindowHtml,
        render3ColumnIncidentMatrixHtml, renderLogExplorerCardHtml, renderUnifiedTelemetryCardHtml, renderFacetedFilterRibbonHtml,
    };
})();

if (typeof window !== 'undefined') window.DashboardViews = DashboardViews;
if (typeof globalThis !== 'undefined') globalThis.DashboardViews = DashboardViews;
if (typeof module !== 'undefined' && module.exports) module.exports = DashboardViews;
