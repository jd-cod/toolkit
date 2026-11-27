/**
 * Nginx Analyzer Initializer — Next.js Island Controller
 *
 * Handles:
 *  - GeoIP initialization with progress bar
 *  - Native in-browser .gz / .log.gz decompression (DecompressionStream)
 *  - Multi-file batch uploads
 *  - Drag & Drop zone with active states
 *  - Global Cmd+V / Ctrl+V paste detection
 *  - 1-Click interactive sample datasets
 *  - Ephemeral terminal cURL session auto-loading (?session=XYZ)
 *  - Zero-retention expired session friendly notice
 *  - Web Worker off-thread parsing with fallback
 *  - Parse → Analyze → Render pipeline
 *
 * Depends on: GeoIP, LogParser, Analyzer, Dashboard, ShareModal, Report
 */

window.initNginxPage = function () {
    // Guard: only run on the nginx page
    if (!document.getElementById('nginx-analyze-btn')) return;

    // The selected tab is authoritative. Inactive drafts are retained for convenience,
    // but are never consulted by the ingestion handler (no URL > file > text fallback).
    const inputSection = document.getElementById('nginx-input-section');
    const analyzeButton = document.getElementById('nginx-analyze-btn');
    const inputOptions = inputSection.querySelector('.signal-nginx-options');
    const inputTabs = Array.from(inputSection.querySelectorAll('[data-input-tab]'));
    const inputModes = inputTabs.map(tab => tab.dataset.inputTab);
    const lifecycle = new AbortController();
    let inputBusy = false;

    function inputProblem() {
        const mode = inputSection.dataset.inputMode || 'upload';
        if (mode === 'server') {
            return '';
        } else if (mode === 'url') {
            const value = document.getElementById('nginx-gist-url').value.trim();
            if (!value) return 'Enter a public HTTP(S) log URL to start.';
            try {
                const url = new URL(value);
                if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) {
                    return 'Use an HTTP(S) URL without embedded credentials.';
                }
            } catch { return 'Enter a valid HTTP(S) URL.'; }
        } else if (mode === 'paste') {
            if (!document.getElementById('nginx-logtext').value.trim()) return 'Paste log lines to start your analysis.';
        } else {
            const files = Array.from(document.getElementById('nginx-logfile').files || []);
            if (!files.length) return 'Choose a file to start your analysis.';
            if (files.some(file => !/\.(log|txt|gz)$/i.test(file.name))) return 'Choose .log, .txt, or gzip (.gz) files.';
        }
        return '';
    }

    function updateInputState() {
        if (lifecycle.signal.aborted) return;
        const serverMode = inputSection.dataset.inputMode === 'server';
        const problem = inputProblem();
        analyzeButton.hidden = serverMode;
        analyzeButton.disabled = serverMode || inputBusy || Boolean(problem);
        if (inputOptions) inputOptions.hidden = serverMode;
        inputSection.setAttribute('aria-busy', String(inputBusy));
        document.querySelectorAll('[data-input-tab], .btn-sample').forEach(button => { button.disabled = inputBusy; });
        inputSection.querySelectorAll('input, textarea').forEach(input => { input.disabled = inputBusy; });
        const status = document.getElementById('nginx-input-status');
        if (status) status.textContent = inputBusy
            ? 'Processing your logs…'
            : (problem || (serverMode ? 'Run the command above, then open the link it prints.' : 'Ready to analyze the selected source.'));
    }

    function selectInputMode(mode, focus = false) {
        if (!inputModes.includes(mode)) return;
        inputSection.dataset.inputMode = mode;
        inputTabs.forEach(tab => {
            const selected = tab.dataset.inputTab === mode;
            tab.setAttribute('aria-selected', String(selected));
            tab.tabIndex = selected ? 0 : -1;
            if (selected && focus) tab.focus();
        });
        document.querySelectorAll('[data-input-panel]').forEach(panel => { panel.hidden = panel.dataset.inputPanel !== mode; });
        updateInputState();
    }
    window.__selectInputMode = selectInputMode;

    inputTabs.forEach(tab => {
        tab.addEventListener('click', () => { if (!inputBusy) selectInputMode(tab.dataset.inputTab); });
        tab.addEventListener('keydown', event => {
            if (inputBusy || !['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
            event.preventDefault();
            const index = inputModes.indexOf(tab.dataset.inputTab);
            const next = event.key === 'Home' ? 0 : event.key === 'End' ? inputModes.length - 1 : (index + (event.key === 'ArrowRight' ? 1 : inputModes.length - 1)) % inputModes.length;
            selectInputMode(inputModes[next], true);
        });
    });
    inputSection.addEventListener('input', updateInputState);
    inputSection.addEventListener('change', updateInputState);
    analyzeButton.dataset.engineReady = 'true';
    selectInputMode(inputSection.dataset.inputMode || 'upload');

    // Safely parse JSON from a fetch response
    async function safeJson(resp) {
        const text = await resp.text();
        try {
            return JSON.parse(text);
        } catch {
            return { error: text || `HTTP ${resp.status}` };
        }
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

    function sleep(ms) {
        return new Promise(r => setTimeout(r, ms));
    }

    // ─── Ingest Session Progress Dialog ───
    function createIngestProgressDialog() {
        const existing = document.getElementById('ingest-progress-modal');
        if (existing) existing.remove();

        const modal = document.createElement('div');
        modal.id = 'ingest-progress-modal';
        modal.style.cssText = 'position:fixed;inset:0;z-index:10000;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.65);backdrop-filter:blur(6px);padding:16px;';
        modal.innerHTML = `
            <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:16px;max-width:520px;width:100%;box-shadow:0 24px 60px rgba(0,0,0,0.5);overflow:hidden;animation:modalIn 0.2s ease-out;">
                <div style="padding:24px 28px 22px;">
                    <div style="display:flex;align-items:center;gap:12px;margin-bottom:18px;">
                        <div style="width:44px;height:44px;border-radius:12px;background:rgba(99,102,241,0.15);color:#6366f1;display:flex;align-items:center;justify-content:center;font-size:1.4rem;flex-shrink:0;">
                            <i class="bi bi-terminal-fill"></i>
                        </div>
                        <div>
                            <h3 style="margin:0;color:var(--text-primary);font-size:1.1rem;font-weight:700;">Loading Terminal Session</h3>
                            <div id="ingest-progress-subtitle" style="font-size:0.75rem;color:var(--text-muted);margin-top:2px;">Preparing...</div>
                        </div>
                    </div>

                    <!-- Main progress bar -->
                    <div style="margin-bottom:14px;">
                        <div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:6px;">
                            <span id="ingest-progress-stage" style="font-size:0.82rem;font-weight:600;color:var(--text-primary);">Connecting...</span>
                            <span id="ingest-progress-pct" style="font-size:0.82rem;font-weight:700;color:var(--accent-cyan);font-family:var(--font-mono);">0%</span>
                        </div>
                        <div style="width:100%;height:8px;background:var(--bg-secondary);border-radius:4px;overflow:hidden;">
                            <div id="ingest-progress-bar" style="width:0%;height:100%;background:var(--gradient-primary);border-radius:4px;transition:width 0.3s ease;"></div>
                        </div>
                        <div id="ingest-progress-detail" style="font-size:0.73rem;color:var(--text-muted);margin-top:5px;font-family:var(--font-mono);"></div>
                    </div>

                    <!-- File metadata -->
                    <div id="ingest-meta-box" style="background:var(--bg-body);border:1px solid var(--border-color);border-radius:10px;padding:10px 14px;margin-bottom:14px;display:none;">
                        <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px 16px;font-size:0.76rem;">
                            <div style="color:var(--text-muted);">📦 Compressed size</div>
                            <div id="ingest-meta-compressed" style="color:var(--text-secondary);font-family:var(--font-mono);text-align:right;">—</div>
                            <div style="color:var(--text-muted);">📄 Decompressed size</div>
                            <div id="ingest-meta-decompressed" style="color:var(--text-secondary);font-family:var(--font-mono);text-align:right;">—</div>
                            <div style="color:var(--text-muted);">📝 Log lines</div>
                            <div id="ingest-meta-lines" style="color:var(--text-secondary);font-family:var(--font-mono);text-align:right;">—</div>
                        </div>
                    </div>

                    <!-- Stage pipeline -->
                    <div style="background:var(--bg-body);border:1px solid var(--border-color);border-radius:10px;padding:10px 14px;">
                        <div style="font-size:0.7rem;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:8px;">Pipeline</div>
                        <div id="ingest-pipeline" style="display:flex;flex-direction:column;gap:5px;font-size:0.78rem;">
                            <div data-stage="meta" style="display:flex;align-items:center;gap:8px;color:var(--text-muted);"><span class="stage-icon">⏳</span> Fetching metadata</div>
                            <div data-stage="download" style="display:flex;align-items:center;gap:8px;color:var(--text-muted);"><span class="stage-icon">⏳</span> Downloading log data</div>
                            <div data-stage="parse" style="display:flex;align-items:center;gap:8px;color:var(--text-muted);"><span class="stage-icon">⏳</span> Parsing log entries</div>
                            <div data-stage="analyze" style="display:flex;align-items:center;gap:8px;color:var(--text-muted);"><span class="stage-icon">⏳</span> Analyzing traffic</div>
                            <div data-stage="render" style="display:flex;align-items:center;gap:8px;color:var(--text-muted);"><span class="stage-icon">⏳</span> Rendering dashboard</div>
                        </div>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
        return modal;
    }

    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    function updateIngestPipeline(activeStage) {
        const stages = ['meta', 'download', 'parse', 'analyze', 'render'];
        const pipeline = document.getElementById('ingest-pipeline');
        if (!pipeline) return;
        let reachedActive = false;
        for (const stage of stages) {
            const el = pipeline.querySelector(`[data-stage="${stage}"]`);
            if (!el) continue;
            const icon = el.querySelector('.stage-icon');
            if (stage === activeStage) {
                reachedActive = true;
                el.style.color = 'var(--accent-cyan)';
                el.style.fontWeight = '600';
                if (icon) icon.textContent = '🔄';
            } else if (!reachedActive) {
                el.style.color = 'var(--accent-green)';
                el.style.fontWeight = '600';
                if (icon) icon.textContent = '✅';
            } else {
                el.style.color = 'var(--text-muted)';
                el.style.fontWeight = 'normal';
                if (icon) icon.textContent = '⏳';
            }
        }
    }

    function markIngestPipelineComplete() {
        const pipeline = document.getElementById('ingest-pipeline');
        if (!pipeline) return;
        pipeline.querySelectorAll('[data-stage]').forEach(el => {
            el.style.color = 'var(--accent-green)';
            el.style.fontWeight = '600';
            const icon = el.querySelector('.stage-icon');
            if (icon) icon.textContent = '✅';
        });
    }

    function removeIngestProgressDialog() {
        const modal = document.getElementById('ingest-progress-modal');
        if (modal) {
            modal.style.transition = 'opacity 0.3s ease';
            modal.style.opacity = '0';
            setTimeout(() => modal.remove(), 300);
        }
    }

    // ─── GeoIP Initialization ───

    async function initGeoIP() {
        const progressBar = document.getElementById('geoip-progress-bar');
        const statusText = document.getElementById('geoip-status');

        try {
            // Background prefetch without displaying intrusive loader banner on page load.
            // If the user starts an analysis before ready, stage 1 unhides the loader.
            await GeoIP.init((pct, msg) => {
                if (progressBar) progressBar.style.width = pct + '%';
                if (statusText) statusText.textContent = msg;
            });

            if (window.BotDetector?.init) {
                await window.BotDetector.init();
            }
        } catch (e) {
            console.error('GeoIP init error:', e);
        }
    }

    initGeoIP();

    // ─── Native Decompression & File Reading ───
    async function readFileAsText(file) {
        const isGzip = file.name.toLowerCase().endsWith('.gz') ||
                       file.type === 'application/gzip' ||
                       file.type === 'application/x-gzip';

        if (isGzip) {
            if (typeof DecompressionStream !== 'undefined') {
                const ds = new DecompressionStream('gzip');
                const decompressedStream = file.stream().pipeThrough(ds);
                const response = new Response(decompressedStream);
                return await response.text();
            } else {
                throw new Error('Your browser does not support native DecompressionStream. Please extract the .gz file before uploading.');
            }
        }

        return await file.text();
    }

    async function readMultipleFilesAsText(fileList) {
        const texts = [];
        for (let i = 0; i < fileList.length; i++) {
            const file = fileList[i];
            const content = await readFileAsText(file);
            texts.push(content);
        }
        return texts.join('\n');
    }

    // ─── Polite Zero-Retention Session Expired Modal ───
    function showSessionExpiredNotice() {
        if (lifecycle.signal.aborted) return;
        const existingModal = document.getElementById('session-expired-modal');
        if (existingModal) existingModal.remove();

        // Clean up the ?session= query parameter from the browser URL
        const cleanUrl = window.location.pathname;
        window.history.replaceState({}, document.title, cleanUrl);

        const host = window.location.origin;
        const curlCmd = `tail -n 50000 /var/log/nginx/access.log | curl -F "file=@-" ${host}/api/ingest`;

        const modal = document.createElement('div');
        modal.id = 'session-expired-modal';
        modal.style.cssText = 'position:fixed;inset:0;z-index:10000;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.65);backdrop-filter:blur(6px);padding:16px;';
        modal.innerHTML = `
            <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:16px;max-width:520px;width:100%;box-shadow:0 24px 60px rgba(0,0,0,0.5);overflow:hidden;animation:modalIn 0.2s ease-out;">
                <div style="padding:24px 28px 22px;">
                    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
                        <div style="display:flex;align-items:center;gap:12px;">
                            <div style="width:40px;height:40px;border-radius:10px;background:rgba(245,158,11,0.15);color:#f59e0b;display:flex;align-items:center;justify-content:center;font-size:1.3rem;flex-shrink:0;">
                                <i class="bi bi-clock-history"></i>
                            </div>
                            <div>
                                <h3 style="margin:0;color:var(--text-primary);font-size:1.1rem;font-weight:700;">Link Expired or Already Viewed</h3>
                                <div style="font-size:0.75rem;color:var(--accent-green);font-weight:600;margin-top:2px;">
                                    <i class="bi bi-shield-check" style="margin-right:4px;"></i>Zero-Data Retention Policy
                                </div>
                            </div>
                        </div>
                        <button id="session-expired-close" style="background:none;border:none;color:var(--text-muted);font-size:1.4rem;cursor:pointer;padding:0;line-height:1;">&times;</button>
                    </div>

                    <div style="font-size:0.86rem;color:var(--text-secondary);line-height:1.5;margin-bottom:16px;">
                        This one-time link has expired or was already viewed. For your privacy, server logs are <strong>automatically deleted immediately after viewing</strong>.
                    </div>

                    <div style="background:var(--bg-body);border:1px solid var(--border-color);border-radius:10px;padding:12px 14px;margin-bottom:20px;">
                        <div style="font-size:0.75rem;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:6px;">
                            💡 Re-run this in your terminal to generate a fresh link:
                        </div>
                        <div style="background:#06070c;border:1px solid var(--border-color);border-radius:6px;padding:8px 10px;display:flex;align-items:center;justify-content:space-between;font-family:var(--font-mono);font-size:0.75rem;color:var(--accent-cyan);overflow-x:auto;">
                            <span style="white-space:nowrap;">${escapeHtml(curlCmd)}</span>
                            <button id="session-expired-copy" style="background:rgba(255,255,255,0.1);border:none;color:var(--text-primary);padding:4px 10px;border-radius:4px;font-size:0.72rem;cursor:pointer;margin-left:8px;flex-shrink:0;font-weight:600;">
                                Copy
                            </button>
                        </div>
                    </div>

                    <div style="display:flex;justify-content:flex-end;gap:10px;">
                        <button id="session-expired-ok" style="padding:9px 24px;border-radius:8px;border:none;background:var(--gradient-primary);color:#fff;font-size:0.84rem;font-weight:600;cursor:pointer;">
                            Got It
                        </button>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        const closeModal = () => modal.remove();
        modal.querySelector('#session-expired-close').addEventListener('click', closeModal);
        modal.querySelector('#session-expired-ok').addEventListener('click', closeModal);
        modal.addEventListener('click', (e) => { if (e.target === modal) closeModal(); });

        modal.querySelector('#session-expired-copy').addEventListener('click', () => {
            navigator.clipboard.writeText(curlCmd).then(() => {
                const btn = modal.querySelector('#session-expired-copy');
                btn.textContent = 'Copied!';
                btn.style.background = 'var(--accent-green)';
                btn.style.color = '#fff';
                setTimeout(() => {
                    btn.textContent = 'Copy';
                    btn.style.background = 'rgba(255,255,255,0.1)';
                    btn.style.color = 'var(--text-primary)';
                }, 2000);
            });
        });
    }

    // ─── Customer-Friendly Analysis Error Modal ───
    function showAnalysisError(stage, error, context = {}) {
        if (lifecycle.signal.aborted) return;
        console.error(`[AnalysisError] Stage: ${stage}`, error, context);

        const stageLabels = {
            geoip: 'GeoIP Database',
            remote_fetch: 'Remote URL Fetch',
            file_read: 'File Reading',
            size_check: 'Size Limit',
            parse: 'Log Format',
            analyze: 'Analysis Engine',
            render: 'Dashboard Display',
            sample_fetch: 'Sample Dataset',
        };

        const title = stageLabels[stage] || 'Analysis';

        let suggestion = '';
        const errMsg = (error.message || '').toLowerCase();
        if (errMsg.includes('maximum call stack') || errMsg.includes('out of memory')) {
            suggestion = 'The log data is too large for browser memory. Try extracting a smaller time slice using the cheat sheet below.';
        } else if (errMsg.includes('ssrf guard') || errMsg.includes('internal ip')) {
            suggestion = 'Security Guard: Private, internal (localhost), and cloud metadata IP addresses are blocked.';
        } else if (errMsg.includes('failed to fetch') || errMsg.includes('networkerror')) {
            suggestion = 'Network request failed. Please check your internet connection or verify the URL is publicly reachable.';
        } else if (stage === 'parse') {
            suggestion = 'Please ensure the log format follows standard Nginx combined or common access log format.';
        }

        const existingModal = document.getElementById('analysis-error-modal');
        if (existingModal) existingModal.remove();

        const modal = document.createElement('div');
        modal.id = 'analysis-error-modal';
        modal.style.cssText = 'position:fixed;inset:0;z-index:10000;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.65);backdrop-filter:blur(4px);padding:16px;';
        modal.innerHTML = `
            <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:16px;max-width:480px;width:100%;box-shadow:0 20px 60px rgba(0,0,0,0.4);overflow:hidden;">
                <div style="padding:24px 28px 20px;">
                    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
                        <h3 style="margin:0;color:var(--text-primary);font-size:1.15rem;font-weight:700;">
                            ⚠️ ${escapeHtml(title)} Issue
                        </h3>
                        <button id="analysis-error-close" style="background:none;border:none;color:var(--text-muted);font-size:1.4rem;cursor:pointer;padding:0;line-height:1;">&times;</button>
                    </div>

                    <div style="background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.2);border-radius:10px;padding:12px 16px;margin-bottom:16px;">
                        <div style="font-size:0.86rem;color:var(--text-primary);word-break:break-word;line-height:1.5;">
                            ${escapeHtml(error.message || String(error))}
                        </div>
                    </div>

                    ${suggestion ? `
                    <div style="background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.18);border-radius:10px;padding:12px 16px;margin-bottom:16px;">
                        <div style="font-size:0.75rem;font-weight:600;color:#f59e0b;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:4px;">💡 Recommendation</div>
                        <div style="font-size:0.82rem;color:var(--text-secondary);line-height:1.5;">${escapeHtml(suggestion)}</div>
                    </div>` : ''}

                    <div style="display:flex;justify-content:flex-end;gap:10px;">
                        <button id="analysis-error-dismiss" style="padding:8px 22px;border-radius:8px;border:none;background:var(--gradient-primary);color:#fff;font-size:0.84rem;font-weight:600;cursor:pointer;">OK</button>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        const closeModal = () => modal.remove();
        modal.querySelector('#analysis-error-close').addEventListener('click', closeModal);
        modal.querySelector('#analysis-error-dismiss').addEventListener('click', closeModal);
        modal.addEventListener('click', (e) => { if (e.target === modal) closeModal(); });
    }

    // ─── Main Execution Pipeline ───
    async function executeAnalysis(rawLogInput, inputSource, currentUrl, options) {
        if (lifecycle.signal.aborted) return;
        const btn = document.getElementById('nginx-analyze-btn');
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '<i class="bi bi-hourglass-split" style="margin-right:6px;"></i> Analyzing...';
        }

        const toggle = document.getElementById('nginx-skip-403');
        const skip403 = (options && options.skip403 !== undefined)
            ? Boolean(options.skip403)
            : (toggle ? toggle.checked : true);
        const internalToggle = document.getElementById('nginx-skip-internal');
        const skipInternal = (options && options.skipInternal !== undefined)
            ? Boolean(options.skipInternal)
            : (internalToggle ? internalToggle.checked : true);
        const parserOptions = { skip403, skipInternal };

        const diagCtx = {
            source: inputSource,
            gistUrl: currentUrl,
        };

        try {
            // Stage 1: GeoIP
            if (!GeoIP.isReady()) {
                const loader = document.getElementById('geoip-loader');
                if (loader) loader.classList.remove('hidden');
                await GeoIP.init((pct, msg) => {
                    if (lifecycle.signal.aborted) return;
                    const bar = document.getElementById('geoip-progress-bar');
                    const status = document.getElementById('geoip-status');
                    if (bar) bar.style.width = pct + '%';
                    if (status) status.textContent = msg;
                });
                if (window.BotDetector?.init) {
                    await window.BotDetector.init();
                }
                if (loader) loader.classList.add('hidden');
            }

            // Stage 2: Parse via streaming Worker
            if (btn) btn.innerHTML = '<i class="bi bi-hourglass-split" style="margin-right:6px;"></i> Streaming &amp; parsing logs...';
            await sleep(40);
            if (lifecycle.signal.aborted) return;

            GeoIP.clearCache();

            // When input is already a string in-memory (e.g. pasted logs, small samples),
            // run the in-memory parser for full bot verification and report compatibility.
            if (typeof rawLogInput === 'string') {
                if (btn) btn.innerHTML = '<i class="bi bi-hourglass-split" style="margin-right:6px;"></i> Parsing logs...';
                await sleep(40);
                if (lifecycle.signal.aborted) return;

                const parseResult = await LogParser.parseAsync(rawLogInput, parserOptions);
                if (parseResult.validLines === 0) {
                    showAnalysisError('parse', new Error('No valid access-log lines found. Check the IP addresses and log format.'), diagCtx);
                    if (btn) {
                        btn.disabled = false;
                        btn.innerHTML = '<i class="bi bi-lightning-charge-fill" style="margin-right:6px;"></i> Analyze Logs';
                    }
                    return;
                }

                if (btn) btn.innerHTML = `<i class="bi bi-hourglass-split" style="margin-right:6px;"></i> Analyzing ${parseResult.ips.length.toLocaleString()} requests...`;
                await sleep(40);
                if (lifecycle.signal.aborted) return;

                Analyzer.enrichLogEntries(parseResult.logEntries);
                const data = Analyzer.analyzeEnhancedLogs(parseResult.logEntries);
                Dashboard.render(data, rawLogInput, parseResult, {
                    source: inputSource,
                    gistUrl: currentUrl,
                    sourceLabel: options?.sourceLabel || '',
                    skip403,
                    skipInternal,
                });
                return;
            }

            // Streaming path for files and sessions
            const stream = (rawLogInput && typeof rawLogInput.getReader === 'function')
                ? rawLogInput
                : new Response(rawLogInput).body;

            const decompressedStream = typeof peekAndDecompressStream === 'function'
                ? await peekAndDecompressStream(stream)
                : stream;

            const worker = typeof Worker !== 'undefined' ? new Worker('/js/log-parser.worker.js?v=6.55') : null;

            let result = null;
            if (worker && typeof streamChunksToWorker === 'function') {
                result = await streamChunksToWorker(decompressedStream, worker, parserOptions, (prog) => {
                    const parsed = prog.parsedLines || prog.linesRead || 0;
                    if (btn && parsed > 0) {
                        btn.innerHTML = `<i class="bi bi-hourglass-split" style="margin-right:6px;"></i> Parsed ${parsed.toLocaleString()} lines...`;
                    }
                    const detail = document.getElementById('ingest-progress-detail');
                    if (detail) {
                        if (prog.type === 'geo_progress') {
                            detail.textContent = `Enriching GeoIP: ${prog.current.toLocaleString()} / ${prog.total.toLocaleString()} unique IPs...`;
                        } else if (parsed > 0) {
                            detail.textContent = `Parsed ${parsed.toLocaleString()} lines...`;
                        }
                    }
                });
            } else {
                const logText = await new Response(decompressedStream).text();
                const parseResult = await LogParser.parseAsync(logText, parserOptions);
                if (parseResult.validLines === 0) {
                    showAnalysisError('parse', new Error('No valid access-log lines found. Check the IP addresses and log format.'), diagCtx);
                    if (btn) {
                        btn.disabled = false;
                        btn.innerHTML = '<i class="bi bi-lightning-charge-fill" style="margin-right:6px;"></i> Analyze Logs';
                    }
                    return;
                }
                Analyzer.enrichLogEntries(parseResult.logEntries);
                const data = Analyzer.analyzeEnhancedLogs(parseResult.logEntries);
                Dashboard.render(data, logText, parseResult, {
                    source: inputSource,
                    gistUrl: currentUrl,
                    sourceLabel: options?.sourceLabel || '',
                    skip403,
                    skipInternal,
                });
                return;
            }

            if (!result || !result.summary || result.summary.matchingCount === 0) {
                showAnalysisError('parse', new Error('No valid access-log lines found. Check the IP addresses and log format.'), diagCtx);
                if (btn) {
                    btn.disabled = false;
                    btn.innerHTML = '<i class="bi bi-lightning-charge-fill" style="margin-right:6px;"></i> Analyze Logs';
                }
                return;
            }

            // Stage 3: Analyze
            if (btn) btn.innerHTML = `<i class="bi bi-hourglass-split" style="margin-right:6px;"></i> Analyzing ${result.summary.matchingCount.toLocaleString()} requests...`;
            await sleep(40);
            if (lifecycle.signal.aborted) return;

            const data = Analyzer.analyzeFromWorkerSummary(result.summary);

            const parseResult = {
                parsedLines: new Array(result.summary.matchingCount || 0),
                skippedLines: [],
                validLines: result.summary.matchingCount || 0,
                minTimestamp: result.summary.minTimeSec ? result.summary.minTimeSec * 1000 : 0,
                maxTimestamp: result.summary.maxTimeSec ? result.summary.maxTimeSec * 1000 : 0,
                logSpanMinutes: result.summary.minTimeSec && result.summary.maxTimeSec
                    ? Math.floor((result.summary.maxTimeSec - result.summary.minTimeSec) / 60)
                    : 0,
                logStart: result.summary.minTimeSec ? new Date(result.summary.minTimeSec * 1000).toUTCString() : '',
                logEnd: result.summary.maxTimeSec ? new Date(result.summary.maxTimeSec * 1000).toUTCString() : '',
            };

            // Stage 4: Render
            Dashboard.render(data, '', parseResult, {
                source: inputSource,
                gistUrl: currentUrl,
                sourceLabel: options?.sourceLabel || '',
                skip403,
                skipInternal,
                worker,
                summary: result.summary,
                pageResult: result.pageResult,
                sessionId: options?.sessionId || (currentUrl?.startsWith('session:') ? currentUrl.slice(8) : (typeof window !== 'undefined' ? window._activeNginxSessionId : null))
            });

        } catch (err) {
            if (!lifecycle.signal.aborted) showAnalysisError('analyze', err, diagCtx);
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = '<i class="bi bi-lightning-charge-fill" style="margin-right:6px;"></i> Analyze Logs';
            }
        }
    }

    // ─── Analyze Button Click Handler ───
    document.getElementById('nginx-analyze-btn')?.addEventListener('click', async () => {
        const mode = inputSection.dataset.inputMode || 'upload';
        if (mode === 'server' || inputBusy || inputProblem()) { updateInputState(); return; }
        inputBusy = true;
        updateInputState();
        const btn = document.getElementById('nginx-analyze-btn');
        btn.innerHTML = '<i class="bi bi-hourglass-split" style="margin-right:6px;"></i> Reading inputs...';

        let logText = '';
        let inputSource = 'text';
        let currentUrl = '';
        let sourceLabel = 'Pasted logs';

        try {
            const remoteUrl = document.getElementById('nginx-gist-url')?.value?.trim();
            if (mode === 'url') {
                sourceLabel = `Remote URL · ${new URL(remoteUrl).hostname}`;
                inputSource = 'url';
                currentUrl = remoteUrl;
                btn.innerHTML = '<i class="bi bi-hourglass-split" style="margin-right:6px;"></i> Fetching & storing remote URL...';

                const resp = await fetch('/api/storage/upload-external', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: remoteUrl }),
                });
                const result = await safeJson(resp);

                if (!resp.ok || result.error || !result.shareCode) {
                    showAnalysisError('remote_fetch', new Error(result.error || `HTTP ${resp.status}`), { gistUrl: remoteUrl, httpStatus: resp.status });
                    btn.disabled = false;
                    btn.innerHTML = '<i class="bi bi-lightning-charge-fill" style="margin-right:6px;"></i> Analyze Logs';
                    return;
                }

                // Download content via presigned URL
                const dlResp = await fetch(`/api/storage/download/${result.shareCode}`);
                const dlData = await safeJson(dlResp);
                if (dlData.downloadUrl) {
                    const rawResp = await fetch(dlData.downloadUrl);
                    if (rawResp.ok) {
                        logText = await rawResp.text();
                    } else {
                        throw new Error(`Failed to download from storage: HTTP ${rawResp.status}`);
                    }
                } else {
                    throw new Error('Failed to generate download URL');
                }
            }

            // File mode supports raw, gzip, and multiple files; never falls back.
            if (mode === 'upload') {
                const fileInput = document.getElementById('nginx-logfile');
                if (fileInput && fileInput.files.length > 0) {
                    inputSource = 'file';
                    sourceLabel = Array.from(fileInput.files).map(file => file.name).join(', ');
                    btn.innerHTML = '<i class="bi bi-hourglass-split" style="margin-right:6px;"></i> Streaming &amp; decompressing...';
                    if (fileInput.files.length === 1) {
                        await executeAnalysis(fileInput.files[0].stream(), inputSource, currentUrl, { sourceLabel });
                        return;
                    }
                    try {
                        logText = await readMultipleFilesAsText(fileInput.files);
                    } catch (readErr) {
                        showAnalysisError('file_read', readErr, { source: 'file' });
                        btn.disabled = false;
                        btn.innerHTML = '<i class="bi bi-lightning-charge-fill" style="margin-right:6px;"></i> Analyze Logs';
                        return;
                    }
                }
            }

            if (mode === 'paste') {
                const textContent = document.getElementById('nginx-logtext')?.value || '';
                inputSource = 'text';
                logText = textContent;
            }

            if (!logText.trim()) {
                showAnalysisError('parse', new Error('The selected source contains no log data. Choose a non-empty file, paste logs, or check the remote URL.'));
                btn.disabled = false;
                btn.innerHTML = '<i class="bi bi-lightning-charge-fill" style="margin-right:6px;"></i> Analyze Logs';
                return;
            }

            await executeAnalysis(logText, inputSource, currentUrl, { sourceLabel });

        } catch (e) {
            console.error('Error during log ingestion:', e);
            showAnalysisError(mode === 'url' ? 'remote_fetch' : 'analyze', e);
        } finally {
            inputBusy = false;
            btn.innerHTML = '<i class="bi bi-arrow-right" style="margin-right:6px;"></i> Analyze Logs';
            const loader = document.getElementById('geoip-loader');
            if (loader) loader.classList.add('hidden');
            updateInputState();
        }
    });

    // ─── 1-Click Interactive Sample Handlers ───
    document.querySelectorAll('.btn-sample').forEach((btn) => {
        btn.addEventListener('click', async () => {
            const sampleName = btn.dataset.sample;
            if (!sampleName || inputBusy) return;
            inputBusy = true;
            updateInputState();

            const analyzeBtn = document.getElementById('nginx-analyze-btn');
            if (analyzeBtn) {
                analyzeBtn.disabled = true;
                analyzeBtn.innerHTML = '<i class="bi bi-hourglass-split" style="margin-right:6px;"></i> Loading sample...';
            }

            try {
                const resp = await fetch(`/samples/${sampleName}`);
                if (!resp.ok) throw new Error(`Could not load sample file: HTTP ${resp.status}`);
                const sampleText = await resp.text();

                const textarea = document.getElementById('nginx-logtext');
                if (textarea) textarea.value = sampleText;
                selectInputMode('paste');

                await executeAnalysis(sampleText, 'sample', `/samples/${sampleName}`, { sourceLabel: sampleName });
            } catch (err) {
                showAnalysisError('sample_fetch', err, { sample: sampleName });
            } finally {
                inputBusy = false;
                if (analyzeBtn) analyzeBtn.innerHTML = '<i class="bi bi-arrow-right" style="margin-right:6px;"></i> Analyze Logs';
                updateInputState();
            }
        });
    });

    // ─── Drag & Drop Zone Interactions ───
    const dropzone = document.getElementById('nginx-dropzone');
    const fileInput = document.getElementById('nginx-logfile');
    const filenameLabel = document.getElementById('nginx-dropzone-filename');

    if (dropzone && fileInput) {
        ['dragenter', 'dragover'].forEach(name => {
            dropzone.addEventListener(name, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.add('dragover');
            });
        });

        ['dragleave', 'drop'].forEach(name => {
            dropzone.addEventListener(name, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.remove('dragover');
            });
        });

        dropzone.addEventListener('drop', event => {
            if (inputBusy || !event.dataTransfer?.files.length) return;
            fileInput.files = event.dataTransfer.files;
            fileInput.dispatchEvent(new Event('change', { bubbles: true }));
        });

        fileInput.addEventListener('change', () => {
            if (fileInput.files && fileInput.files.length > 0) {
                const names = Array.from(fileInput.files).map(f => f.name).join(', ');
                if (filenameLabel) {
                    filenameLabel.innerHTML = `✅ Selected <strong>${fileInput.files.length}</strong> file(s): <code style="color:var(--accent-cyan);">${escapeHtml(names)}</code>`;
                }
            }
        });
    }

    // ─── Global Paste Listener (Cmd+V / Ctrl+V) ───
    window.addEventListener('paste', (e) => {
        if (!inputSection.isConnected || inputBusy || document.body.dataset.nginxView === 'results') return;
        // Native paste into the textarea must not be inserted a second time.
        if (document.activeElement?.id === 'nginx-logtext') return;
        const activeTag = document.activeElement ? document.activeElement.tagName : '';
        if (['INPUT', 'TEXTAREA'].includes(activeTag) && document.activeElement.id !== 'nginx-logtext') {
            return; // Let user paste into text inputs normally
        }

        const pastedText = e.clipboardData?.getData('text');
        if (pastedText && pastedText.length > 50 && (pastedText.includes('HTTP/') || pastedText.includes('GET ') || pastedText.includes('POST '))) {
            const textarea = document.getElementById('nginx-logtext');
            if (textarea && !textarea.value.trim()) {
                e.preventDefault();
                textarea.value = pastedText;
                selectInputMode('paste');
                textarea.focus();
                textarea.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        }
    }, { signal: lifecycle.signal });

    // ─── Ephemeral Terminal cURL Session Auto-Loader (?session=XYZ) ───
    async function checkUrlSession() {
        const params = new URLSearchParams(window.location.search);
        const sessionId = params.get('session') || params.get('ingest');
        if (!sessionId) return;
        selectInputMode('server');
        inputBusy = true;
        updateInputState();

        const analyzeBtn = document.getElementById('nginx-analyze-btn');
        if (analyzeBtn) {
            analyzeBtn.disabled = true;
            analyzeBtn.innerHTML = '<i class="bi bi-hourglass-split" style="margin-right:6px;"></i> Loading session...';
        }

        // Show progress dialog
        createIngestProgressDialog();
        const progressBar = document.getElementById('ingest-progress-bar');
        const progressPct = document.getElementById('ingest-progress-pct');
        const progressStage = document.getElementById('ingest-progress-stage');
        const progressDetail = document.getElementById('ingest-progress-detail');
        const progressSubtitle = document.getElementById('ingest-progress-subtitle');
        const metaBox = document.getElementById('ingest-meta-box');

        try {
            // Stage 1: Fetch metadata (non-destructive)
            updateIngestPipeline('meta');
            if (progressStage) progressStage.textContent = 'Fetching session metadata...';

            let meta = null;
            try {
                const metaResp = await fetch(`/api/ingest/${encodeURIComponent(sessionId)}/meta`);
                if (metaResp.ok) {
                    meta = await metaResp.json();
                    // Populate metadata box
                    if (metaBox) {
                        metaBox.style.display = 'block';
                        const elCompressed = document.getElementById('ingest-meta-compressed');
                        const elDecompressed = document.getElementById('ingest-meta-decompressed');
                        const elLines = document.getElementById('ingest-meta-lines');
                        if (elCompressed) elCompressed.textContent = meta.compressedSize ? formatBytes(meta.compressedSize) : 'N/A (raw upload)';
                        if (elDecompressed) elDecompressed.textContent = formatBytes(meta.decompressedSize);
                        if (elLines) elLines.textContent = meta.lineCount ? meta.lineCount.toLocaleString() + ' lines' : '—';
                    }
                    if (progressSubtitle) {
                        progressSubtitle.textContent = meta.lineCount
                            ? `${formatBytes(meta.decompressedSize)} · ${meta.lineCount.toLocaleString()} lines`
                            : (meta.decompressedSize ? `${formatBytes(meta.decompressedSize)}` : `${formatBytes(meta.compressedSize)} compressed`);
                    }
                }
            } catch (metaErr) {
                // Non-critical: metadata fetch can fail, continue with download
                console.warn('Metadata fetch failed (non-critical):', metaErr);
            }

            // Stage 2: Download & stream log data directly into Web Worker
            updateIngestPipeline('download');
            if (progressStage) progressStage.textContent = 'Downloading & streaming log data...';

            const resp = await fetch(`/api/ingest/${encodeURIComponent(sessionId)}`);

            if (!resp.ok) {
                removeIngestProgressDialog();
                showSessionExpiredNotice();
                return;
            }

            // Zero data retention: the log is streaming to the browser, purge server copy immediately
            fetch(`/api/ingest/${encodeURIComponent(sessionId)}/purge`, { method: 'POST' }).catch(() => {});

            // Remove query param from browser address bar without reload
            const cleanUrl = window.location.pathname;
            window.history.replaceState({}, document.title, cleanUrl);

            updateIngestPipeline('parse');
            if (progressStage) progressStage.textContent = 'Parsing log entries in worker...';

            updateIngestPipeline('analyze');
            if (progressStage) progressStage.textContent = 'Analyzing traffic patterns...';

            if (typeof window !== 'undefined') {
                window._activeNginxSessionId = sessionId;
            }

            await executeAnalysis(resp.body, 'terminal_ingest', `session:${sessionId}`, {
                sourceLabel: `Terminal Ingest (${meta?.lineCount ? meta.lineCount.toLocaleString() + ' lines' : 'Stream'})`,
                sessionId: sessionId
            });

            // All done!
            markIngestPipelineComplete();
            if (progressStage) progressStage.textContent = 'Complete!';
            if (progressBar) progressBar.style.width = '100%';
            if (progressPct) progressPct.textContent = '100%';
            await sleep(600);
            removeIngestProgressDialog();

        } catch (err) {
            console.error('Session loading error:', err);
            removeIngestProgressDialog();
            showSessionExpiredNotice();
        } finally {
            inputBusy = false;
            if (analyzeBtn) analyzeBtn.innerHTML = '<i class="bi bi-arrow-right" style="margin-right:6px;"></i> Analyze Logs';
            updateInputState();
        }
    }

    checkUrlSession();
    const params = new URLSearchParams(window.location.search);
    if (!params.has('session') && !params.has('ingest')) {
        const sample = params.get('sample');
        const button = Array.from(document.querySelectorAll('.btn-sample')).find(item => item.dataset.sample === sample);
        if (button) button.click();
    }
    window.addEventListener('beforeunload', () => {
        if (typeof window !== 'undefined' && window._activeNginxSessionId) {
            navigator.sendBeacon(`/api/ingest/${encodeURIComponent(window._activeNginxSessionId)}/destroy`);
        }
    });

    return () => {
        lifecycle.abort();
        removeIngestProgressDialog();
        document.getElementById('analysis-error-modal')?.remove();
        document.getElementById('session-expired-modal')?.remove();
        if (typeof window !== 'undefined' && window._activeNginxSessionId) {
            fetch(`/api/ingest/${encodeURIComponent(window._activeNginxSessionId)}/destroy`, { method: 'POST', keepalive: true }).catch(() => {});
        }
    };
};
