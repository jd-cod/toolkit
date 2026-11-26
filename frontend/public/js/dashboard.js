/**
 * Dashboard UI — Client-Side
 * 
 * Single-page traffic analysis: timeline, metrics, investigation tables,
 * geography, and log explorer stay visible together for incident triage.
 */

const Dashboard = (() => {
    let currentData = null;
    let currentLogText = '';
    let currentInputSource = 'text'; // 'gist' (shared snapshot), 'text', 'file', or 'terminal_ingest'
    let currentGistUrl = '';
    let currentSourceLabel = '';
    let currentSkip403 = false;
    let currentSkipInternal = true;
    let exclusionRevision = 0;
    let countryChart = null;
    let asnChart = null;
    let rpsChart = null;
    let themeObserver = null;
    let currentReadOnly = false;
    let activeRpsResolution = '1'; // QA13: fixed resolution set — 1, 5, 60, 900 seconds
    let currentFwFormat = 'nginx'; // 'nginx' | 'cloudflare' | 'iptables' | 'awswaf' | 'ufw' | 'cisco'

    // Mitigation Checklist State
    let selectedMitigationIPs = new Set();
    let selectedMitigationASNs = new Set();
    let selectedMitigationCountries = new Set();
    let selectedMitigationPaths = new Set();

    // Filter Bar & Log Explorer state
    let originalEnrichedEntries = [];
    let originalParseResult = null;
    let originalTimeRange = null;
    let timelineDragEvents = null;
    let currentFilteredEntries = [];
    let activeFilters = {
        statusCategory: 'all',
        method: 'all',
        country: 'all',
        asn: 'all',
        bot: 'all',
        ipSearch: '',
        pathSearch: '',
        uaSearch: ''
    };
    let activeTimeMinutes = 0;
    let maxLogTimestamp = 0;
    let explorerPage = 1;
    let explorerPerPage = 25;
    let explorerSortField = 'timestamp';
    let explorerSortDir = 'desc';
    let _filterDebounceTimer = null;
    let activeWorker = null;
    let latestPageResult = null;
    let latestSummary = null;
    let activeSessionId = null;
    let currentNodeCount = 1;
    let queuePollTimer = null;
    let heartbeatTimer = null;
    let isModalPolling = false;
    let isMultiNodeSession = false;
    let isModalOpen = false;
    let dismissedChunkCount = 0;
    let queueItems = [];

    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + (sizes[i] || 'B');
    }

    function ensureAddLogsModal() {
        let modal = document.getElementById('add-logs-modal');
        if (modal) return modal;

        modal = document.createElement('div');
        modal.id = 'add-logs-modal';
        modal.style.cssText = 'display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.75);backdrop-filter:blur(4px);z-index:10002;align-items:center;justify-content:center;';
        modal.innerHTML = `
            <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:16px;max-width:820px;width:92%;max-height:88vh;display:flex;flex-direction:column;position:relative;overflow:hidden;box-shadow:0 24px 60px rgba(0,0,0,0.6);">
                <div style="padding:20px 24px 16px;border-bottom:1px solid var(--border-color);display:flex;justify-content:space-between;align-items:center;">
                    <div>
                        <h4 style="margin:0;font-size:1.1rem;font-weight:700;display:flex;align-items:center;gap:8px;color:var(--text-primary);">
                            <i class="bi bi-hdd-network-fill" style="color:var(--accent-primary);"></i> Add More Logs to Active Session
                        </h4>
                        <p style="margin:4px 0 0;font-size:0.78rem;color:var(--text-muted);">
                            Ingest from additional frontend nodes or append local log files to merge into your cluster-wide analysis.
                        </p>
                    </div>
                    <button id="add-logs-modal-close" style="background:none;border:none;color:var(--text-muted);font-size:1.4rem;cursor:pointer;line-height:1;" title="Close">&times;</button>
                </div>

                <!-- Modal Navigation Tabs -->
                <div class="signal-nginx-source-picker" style="display:grid;grid-template-columns:repeat(4,1fr);border-bottom:1px solid var(--border-color);background:var(--bg-card);">
                    <button id="add-logs-tab-curl" class="signal-nginx-source-option active" type="button" style="border-radius:0;border:none;border-right:1px solid var(--border-color);border-bottom:2px solid var(--accent-primary);background:var(--signal-tint);color:var(--text-primary);text-align:left;padding:12px 16px;cursor:pointer;">
                        <span class="signal-nginx-source-icon" style="background:var(--signal-tint);border:1px solid color-mix(in srgb, var(--accent-primary) 35%, var(--border-color));color:var(--accent-primary);"><i class="bi bi-terminal"></i></span>
                        <span class="signal-nginx-source-copy"><strong style="color:var(--text-primary);">cURL Ingest</strong><small style="color:var(--text-muted);">Multi-node queue</small></span>
                    </button>
                    <button id="add-logs-tab-file" class="signal-nginx-source-option" type="button" style="border-radius:0;border:none;border-right:1px solid var(--border-color);border-bottom:2px solid transparent;background:transparent;color:var(--text-secondary);text-align:left;padding:12px 16px;cursor:pointer;">
                        <span class="signal-nginx-source-icon" style="background:rgba(255,255,255,0.03);border:1px solid var(--border-color);color:var(--text-secondary);"><i class="bi bi-upload"></i></span>
                        <span class="signal-nginx-source-copy"><strong style="color:var(--text-primary);">Upload File</strong><small style="color:var(--text-muted);">.log or .gz</small></span>
                    </button>
                    <button id="add-logs-tab-paste" class="signal-nginx-source-option" type="button" style="border-radius:0;border:none;border-right:1px solid var(--border-color);border-bottom:2px solid transparent;background:transparent;color:var(--text-secondary);text-align:left;padding:12px 16px;cursor:pointer;">
                        <span class="signal-nginx-source-icon" style="background:rgba(255,255,255,0.03);border:1px solid var(--border-color);color:var(--text-secondary);"><i class="bi bi-code-slash"></i></span>
                        <span class="signal-nginx-source-copy"><strong style="color:var(--text-primary);">Paste Logs</strong><small style="color:var(--text-muted);">Clipboard lines</small></span>
                    </button>
                    <button id="add-logs-tab-url" class="signal-nginx-source-option" type="button" style="border-radius:0;border:none;border-bottom:2px solid transparent;background:transparent;color:var(--text-secondary);text-align:left;padding:12px 16px;cursor:pointer;">
                        <span class="signal-nginx-source-icon" style="background:rgba(255,255,255,0.03);border:1px solid var(--border-color);color:var(--text-secondary);"><i class="bi bi-link-45deg"></i></span>
                        <span class="signal-nginx-source-copy"><strong style="color:var(--text-primary);">Remote URL</strong><small style="color:var(--text-muted);">Direct HTTP log</small></span>
                    </button>
                </div>

                <!-- Tab Panels Body -->
                <div id="add-logs-modal-body" style="flex:1;overflow-y:auto;padding:20px 24px;">
                    <!-- Tab 1: cURL Ingest & Queue -->
                    <div id="add-logs-panel-curl" class="add-logs-panel" style="display:block;">
                        <div style="background:rgba(255,255,255,0.03);border:1px solid var(--border-color);border-radius:10px;padding:14px 16px;margin-bottom:18px;">
                            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                                <span style="font-size:0.8rem;font-weight:700;color:var(--text-secondary);">Run on next frontend node via SSH:</span>
                                <button id="btn-copy-add-curl" style="background:var(--signal-tint);border:1px solid color-mix(in srgb, var(--accent-primary) 35%, var(--border-color));color:var(--accent-primary);font-size:0.74rem;font-weight:600;padding:3px 10px;border-radius:6px;cursor:pointer;">
                                    <i class="bi bi-clipboard"></i> Copy Command
                                </button>
                            </div>
                            <code id="add-logs-curl-command" style="display:block;background:#06080e;border:1px solid var(--border-color);border-radius:6px;padding:10px 12px;font-family:var(--font-mono, monospace);font-size:0.78rem;color:var(--accent-primary);word-break:break-all;"></code>
                            <p style="margin:8px 0 0;font-size:0.72rem;color:var(--text-muted);">
                                <i class="bi bi-shield-check" style="color:var(--accent-primary);"></i> Zero-Retention transport: logs are held ephemerally until merged, then immediately deleted from R2.
                            </p>
                        </div>

                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                            <h5 style="margin:0;font-size:0.88rem;font-weight:700;display:flex;align-items:center;gap:6px;color:var(--text-primary);">
                                <i class="bi bi-inbox-fill" style="color:var(--accent-primary);"></i> Pending Ingest Approval Queue
                            </h5>
                            <button id="queue-merge-all-btn" style="display:none;background:var(--accent-primary);border:1px solid var(--accent-primary);color:var(--signal-on-primary);font-size:0.76rem;font-weight:700;padding:6px 14px;border-radius:6px;cursor:pointer;">
                                <i class="bi bi-check-all"></i> Accept &amp; Merge All
                            </button>
                        </div>

                        <div id="queue-items-container" style="display:flex;flex-direction:column;gap:10px;"></div>

                        <div id="queue-empty-state" style="text-align:center;padding:32px 16px;background:rgba(255,255,255,0.02);border:1px dashed var(--border-color);border-radius:10px;">
                            <i class="bi bi-terminal" style="font-size:1.8rem;color:var(--text-muted);margin-bottom:8px;display:block;"></i>
                            <span style="font-size:0.82rem;color:var(--text-secondary);font-weight:600;display:block;">Awaiting incoming uploads...</span>
                            <span style="font-size:0.74rem;color:var(--text-muted);">Execute the cURL command on any frontend node. Chunks will appear in this queue automatically.</span>
                        </div>
                    </div>

                    <!-- Tab 2: Upload File -->
                    <div id="add-logs-panel-file" class="add-logs-panel" style="display:none;">
                        <div style="border:2px dashed var(--border-color);border-radius:12px;padding:36px 20px;text-align:center;background:rgba(255,255,255,0.01);">
                            <i class="bi bi-cloud-arrow-up" style="font-size:2.2rem;color:var(--accent-primary);margin-bottom:12px;display:block;"></i>
                            <h5 style="margin:0 0 6px;font-size:0.95rem;font-weight:700;color:var(--text-primary);">Choose an access log file to append</h5>
                            <p style="margin:0 0 16px;font-size:0.76rem;color:var(--text-muted);">Supports raw .log, .txt, or compressed .gz rotations.</p>
                            <input type="file" id="add-logs-file-input" accept=".log,.txt,.gz" style="display:none;" />
                            <button type="button" id="btn-browse-add-logs-file" style="background:var(--signal-tint);border:1px solid var(--accent-primary);color:var(--accent-primary);font-size:0.84rem;font-weight:600;padding:9px 20px;border-radius:8px;cursor:pointer;">
                                Browse Log File
                            </button>
                            <div id="add-logs-file-name" style="margin-top:10px;font-size:0.78rem;color:var(--text-secondary);"></div>
                        </div>
                        <div style="margin-top:16px;text-align:right;">
                            <button id="btn-append-file" disabled style="background:var(--accent-primary);border:1px solid var(--accent-primary);color:var(--signal-on-primary);font-size:0.82rem;font-weight:700;padding:9px 20px;border-radius:8px;cursor:pointer;opacity:0.5;">
                                Append &amp; Merge File
                            </button>
                        </div>
                    </div>

                    <!-- Tab 3: Paste Logs -->
                    <div id="add-logs-panel-paste" class="add-logs-panel" style="display:none;">
                        <p style="margin:0 0 8px;font-size:0.8rem;color:var(--text-secondary);">Paste additional access log lines from another node:</p>
                        <textarea id="add-logs-paste-text" placeholder="Paste access log lines here (e.g. 192.168.1.1 - - [20/Sep/2026:10:00:00 +0000] &quot;GET / HTTP/1.1&quot; 200 1234)" style="width:100%;height:180px;background:var(--bg-main);border:1px solid var(--border-color);border-radius:8px;padding:12px;font-family:monospace;font-size:0.76rem;color:var(--text-primary);resize:vertical;"></textarea>
                        <div style="margin-top:14px;display:flex;justify-content:space-between;align-items:center;">
                            <span id="add-logs-paste-status" style="font-size:0.76rem;color:var(--text-muted);"></span>
                            <button id="btn-append-paste" style="background:var(--accent-primary);border:1px solid var(--accent-primary);color:var(--signal-on-primary);font-size:0.82rem;font-weight:700;padding:9px 20px;border-radius:8px;cursor:pointer;">
                                Append &amp; Merge Logs
                            </button>
                        </div>
                    </div>

                    <!-- Tab 4: Remote URL -->
                    <div id="add-logs-panel-url" class="add-logs-panel" style="display:none;">
                        <p style="margin:0 0 8px;font-size:0.8rem;color:var(--text-secondary);">Enter the URL of a public access log or rotation:</p>
                        <input type="url" id="add-logs-url-input" placeholder="https://example.com/logs/node2.log.gz" style="width:100%;background:var(--bg-main);border:1px solid var(--border-color);border-radius:8px;padding:10px 14px;font-size:0.82rem;color:var(--text-primary);margin-bottom:14px;" />
                        <div style="text-align:right;">
                            <button id="btn-append-url" style="background:var(--accent-primary);border:1px solid var(--accent-primary);color:var(--signal-on-primary);font-size:0.82rem;font-weight:700;padding:9px 20px;border-radius:8px;cursor:pointer;">
                                Fetch &amp; Merge URL
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        const mountTarget = document.querySelector('.signal-workspace') || document.body;
        mountTarget.appendChild(modal);

        // Bind events once for modal
        modal.querySelector('#add-logs-modal-close')?.addEventListener('click', () => closeAddLogsModal());
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeAddLogsModal();
        });

        // Tabs
        const addLogsTabs = [
            { btn: 'add-logs-tab-curl', panel: 'add-logs-panel-curl' },
            { btn: 'add-logs-tab-file', panel: 'add-logs-panel-file' },
            { btn: 'add-logs-tab-paste', panel: 'add-logs-panel-paste' },
            { btn: 'add-logs-tab-url', panel: 'add-logs-panel-url' }
        ];
        addLogsTabs.forEach(({ btn, panel }) => {
            modal.querySelector('#' + btn)?.addEventListener('click', () => {
                addLogsTabs.forEach(t => {
                    const b = modal.querySelector('#' + t.btn);
                    const p = modal.querySelector('#' + t.panel);
                    const isActive = t.btn === btn;
                    if (b) {
                        b.classList.toggle('active', isActive);
                        b.style.background = isActive ? 'var(--signal-tint)' : 'transparent';
                        b.style.borderBottom = isActive ? '2px solid var(--accent-primary)' : '2px solid transparent';
                        b.style.color = isActive ? 'var(--text-primary)' : 'var(--text-secondary)';
                        const icon = b.querySelector('.signal-nginx-source-icon');
                        if (icon) {
                            icon.style.background = isActive ? 'var(--signal-tint)' : 'rgba(255, 255, 255, 0.03)';
                            icon.style.color = isActive ? 'var(--accent-primary)' : 'var(--text-secondary)';
                            icon.style.borderColor = isActive ? 'color-mix(in srgb, var(--accent-primary) 35%, var(--border-color))' : 'var(--border-color)';
                        }
                    }
                    if (p) p.style.display = (t.panel === panel) ? 'block' : 'none';
                });
            });
        });

        // Copy cURL
        modal.querySelector('#btn-copy-add-curl')?.addEventListener('click', () => {
            const cmd = modal.querySelector('#add-logs-curl-command')?.textContent?.trim();
            if (cmd && navigator.clipboard) {
                navigator.clipboard.writeText(cmd);
                const copyBtn = modal.querySelector('#btn-copy-add-curl');
                if (copyBtn) copyBtn.innerHTML = '<i class="bi bi-check2"></i> Copied!';
                setTimeout(() => {
                    if (copyBtn) copyBtn.innerHTML = '<i class="bi bi-clipboard"></i> Copy Command';
                }, 2000);
            }
        });

        // Browse file button
        modal.querySelector('#btn-browse-add-logs-file')?.addEventListener('click', () => {
            modal.querySelector('#add-logs-file-input')?.click();
        });

        // File input
        const addLogsFileInput = modal.querySelector('#add-logs-file-input');
        const appendFileBtn = modal.querySelector('#btn-append-file');
        addLogsFileInput?.addEventListener('change', (e) => {
            const file = e.target.files?.[0];
            const nameEl = modal.querySelector('#add-logs-file-name');
            if (file) {
                if (nameEl) nameEl.textContent = `${file.name} (${formatBytes(file.size)})`;
                if (appendFileBtn) {
                    appendFileBtn.disabled = false;
                    appendFileBtn.style.opacity = '1';
                }
            }
        });
        appendFileBtn?.addEventListener('click', async () => {
            const file = addLogsFileInput?.files?.[0];
            if (!file) return;
            appendFileBtn.disabled = true;
            appendFileBtn.textContent = 'Appending...';
            try {
                await appendLogFile(file);
                closeAddLogsModal();
            } catch (err) {
                alert('Failed to append file: ' + (err.message || String(err)));
            } finally {
                appendFileBtn.disabled = false;
                appendFileBtn.textContent = 'Append & Merge File';
            }
        });

        // Paste input
        const appendPasteBtn = modal.querySelector('#btn-append-paste');
        appendPasteBtn?.addEventListener('click', async () => {
            const textarea = modal.querySelector('#add-logs-paste-text');
            const text = textarea?.value?.trim();
            if (!text) return;
            appendPasteBtn.disabled = true;
            appendPasteBtn.textContent = 'Appending...';
            try {
                await appendLogText(text);
                if (textarea) textarea.value = '';
                closeAddLogsModal();
            } catch (err) {
                alert('Failed to append logs: ' + (err.message || String(err)));
            } finally {
                appendPasteBtn.disabled = false;
                appendPasteBtn.textContent = 'Append & Merge Logs';
            }
        });

        // URL input
        const appendUrlBtn = modal.querySelector('#btn-append-url');
        appendUrlBtn?.addEventListener('click', async () => {
            const urlInput = modal.querySelector('#add-logs-url-input');
            const url = urlInput?.value?.trim();
            if (!url) return;
            appendUrlBtn.disabled = true;
            appendUrlBtn.textContent = 'Fetching...';
            try {
                await appendLogUrl(url);
                if (urlInput) urlInput.value = '';
                closeAddLogsModal();
            } catch (err) {
                alert('Failed to fetch URL: ' + (err.message || String(err)));
            } finally {
                appendUrlBtn.disabled = false;
                appendUrlBtn.textContent = 'Fetch & Merge URL';
            }
        });

        // Queue merge all
        modal.querySelector('#queue-merge-all-btn')?.addEventListener('click', async () => {
            await mergeAllChunks();
        });

        return modal;
    }

    function dismissToastNotification(manual = false) {
        const toast = document.getElementById('dash-ingest-toast');
        if (toast) toast.remove();
        if (manual) dismissedChunkCount = queueItems.length;
    }

    function renderToastNotification() {
        if (isModalOpen || queueItems.length === 0) {
            dismissToastNotification(false);
            return;
        }
        if (queueItems.length <= dismissedChunkCount) return;

        let toast = document.getElementById('dash-ingest-toast');
        if (!toast) {
            toast = document.createElement('div');
            toast.id = 'dash-ingest-toast';
            toast.className = 'signal-toast-notification';
            toast.style.cssText = 'position:fixed;bottom:24px;right:24px;z-index:10001;background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:14px 18px;box-shadow:0 14px 40px rgba(0,0,0,0.55);display:flex;align-items:center;gap:14px;max-width:480px;';
            const mount = document.querySelector('.signal-workspace') || document.body;
            mount.appendChild(toast);
        }

        const isSingle = queueItems.length === 1;
        const chunk = queueItems[0];
        const titleText = 'New Node Log Available';
        const subtitleText = isSingle
            ? `${escapeHtml(chunk.chunkId)} · ${chunk.lineCount ? numberWithCommas(chunk.lineCount) + ' requests ' : ''}(${formatBytes(chunk.compressedSize || chunk.size || 0)})`
            : `${queueItems.length} node logs waiting in queue`;

        toast.innerHTML = `
            <div style="width:38px;height:38px;border-radius:10px;background:var(--signal-tint, rgba(99,102,241,0.12));display:flex;align-items:center;justify-content:center;color:var(--accent-primary);font-size:18px;flex-shrink:0;">
                <i class="bi bi-bell-fill"></i>
            </div>
            <div style="flex:1;min-width:0;">
                <div style="font-size:0.86rem;font-weight:700;color:var(--text-primary);display:flex;align-items:center;gap:6px;">
                    ${titleText}
                </div>
                <div style="font-size:0.74rem;color:var(--text-muted);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
                    ${subtitleText}
                </div>
            </div>
            <div style="display:flex;align-items:center;gap:8px;flex-shrink:0;">
                <button id="toast-merge-btn" style="background:var(--accent-primary);border:1px solid var(--accent-primary);color:var(--signal-on-primary);font-size:0.78rem;font-weight:700;padding:7px 14px;border-radius:6px;cursor:pointer;white-space:nowrap;">
                    ${isSingle ? 'Accept &amp; Merge' : '<i class="bi bi-check-all"></i> Merge All'}
                </button>
                <button id="toast-queue-btn" style="background:none;border:1px solid var(--border-color);color:var(--text-secondary);font-size:0.78rem;font-weight:600;padding:7px 12px;border-radius:6px;cursor:pointer;white-space:nowrap;">
                    Queue
                </button>
                <button id="toast-close-btn" style="background:none;border:none;color:var(--text-muted);font-size:1.1rem;cursor:pointer;padding:2px 4px;line-height:1;" title="Dismiss notification">&times;</button>
            </div>
        `;

        toast.querySelector('#toast-merge-btn')?.addEventListener('click', async () => {
            const btn = toast.querySelector('#toast-merge-btn');
            if (btn) {
                btn.disabled = true;
                btn.textContent = 'Merging...';
            }
            try {
                if (isSingle) {
                    await mergeChunk(chunk.chunkId);
                } else {
                    await mergeAllChunks();
                }
                dismissToastNotification(false);
            } catch (err) {
                console.error('Failed to merge chunk from toast:', err);
                if (btn) {
                    btn.disabled = false;
                    btn.textContent = 'Retry';
                }
            }
        });

        toast.querySelector('#toast-queue-btn')?.addEventListener('click', () => {
            openAddLogsModal();
        });

        toast.querySelector('#toast-close-btn')?.addEventListener('click', () => {
            dismissToastNotification(true);
        });
    }

    function stopAdaptiveQueuePoller() {
        if (queuePollTimer) {
            clearTimeout(queuePollTimer);
            queuePollTimer = null;
        }
    }

    function scheduleNextQueuePoll(delayMs) {
        stopAdaptiveQueuePoller();
        if (!isMultiNodeSession) return;
        const delay = delayMs !== undefined ? delayMs : (isModalOpen ? 3000 : 10000);
        if (delay === 0) {
            pollApprovalQueue();
        } else {
            queuePollTimer = setTimeout(() => {
                pollApprovalQueue();
            }, delay);
        }
    }

    async function pollApprovalQueue() {
        if (!isMultiNodeSession) return;
        if (typeof document !== 'undefined' && document.visibilityState === 'hidden' && !isModalOpen) {
            scheduleNextQueuePoll(10000);
            return;
        }
        const sid = activeSessionId || (typeof window !== 'undefined' ? window._activeNginxSessionId : null);
        if (!sid) {
            scheduleNextQueuePoll(isModalOpen ? 3000 : 10000);
            return;
        }
        try {
            const res = await fetch(`/api/ingest/${sid}/queue`);
            if (res.ok) {
                const data = await res.json();
                if (data.success && Array.isArray(data.chunks)) {
                    queueItems = data.chunks;
                    renderQueueUI();
                    renderToastNotification();
                }
            }
        } catch (_) {}
        scheduleNextQueuePoll(isModalOpen ? 3000 : 10000);
    }

    function openAddLogsModal() {
        const modal = ensureAddLogsModal();
        if (!activeSessionId && typeof window !== 'undefined' && window._activeNginxSessionId) {
            activeSessionId = window._activeNginxSessionId;
        }
        const cmdEl = modal.querySelector('#add-logs-curl-command');
        if (cmdEl) {
            cmdEl.textContent = `curl -sSf "${window.location.origin}/ingest${activeSessionId ? `?session=${activeSessionId}` : ''}" | bash`;
        }
        modal.style.display = 'flex';
        isModalOpen = true;
        isModalPolling = true;
        isMultiNodeSession = true;
        dismissToastNotification(false);
        scheduleNextQueuePoll(0);
    }

    function closeAddLogsModal() {
        const modal = document.getElementById('add-logs-modal');
        if (modal) modal.style.display = 'none';
        isModalOpen = false;
        isModalPolling = false;
        scheduleNextQueuePoll(10000);
    }

    function renderQueueUI() {
        const container = document.getElementById('queue-items-container');
        const emptyState = document.getElementById('queue-empty-state');
        const mergeAllBtn = document.getElementById('queue-merge-all-btn');
        const badge = document.getElementById('dash-queue-badge');
        if (!container) return;

        if (badge) {
            if (queueItems.length > 0) {
                badge.innerHTML = `<i class="bi bi-bell-fill" style="margin-right:3px;font-size:0.65rem;"></i>${queueItems.length}`;
                badge.style.display = 'inline-block';
            } else {
                badge.style.display = 'none';
            }
        }

        if (queueItems.length === 0) {
            if (emptyState) emptyState.style.display = 'block';
            if (mergeAllBtn) mergeAllBtn.style.display = 'none';
            container.innerHTML = '';
            return;
        }

        if (emptyState) emptyState.style.display = 'none';
        if (mergeAllBtn) {
            mergeAllBtn.style.display = queueItems.length >= 2 ? 'inline-block' : 'none';
        }

        const isSingle = queueItems.length === 1;

        container.innerHTML = queueItems.map(chunk => `
            <div class="queue-chunk-card" data-chunk-id="${escapeHtml(chunk.chunkId)}" style="background:rgba(255,255,255,0.03);border:1px solid var(--border-color);border-radius:10px;padding:12px 16px;display:flex;justify-content:space-between;align-items:center;gap:12px;">
                <div>
                    <div style="font-size:0.84rem;font-weight:700;color:var(--text-primary);display:flex;align-items:center;gap:8px;">
                        <i class="bi bi-hdd-stack" style="color:var(--accent-primary);"></i>
                        <span>${escapeHtml(chunk.chunkId)}</span>
                        <span style="font-size:0.72rem;font-weight:600;color:var(--text-muted);background:rgba(255,255,255,0.06);padding:1px 6px;border-radius:4px;">
                            ${formatBytes(chunk.compressedSize || chunk.size || 0)}
                        </span>
                    </div>
                    <div style="font-size:0.74rem;color:var(--text-muted);margin-top:3px;">
                        ${chunk.lineCount ? `<span>${numberWithCommas(chunk.lineCount)} requests · </span>` : ''}
                        <span>Ready to merge</span>
                    </div>
                </div>
                <div style="display:flex;align-items:center;gap:8px;">
                    <button id="btn-merge-${escapeHtml(chunk.chunkId)}" class="btn-merge-chunk" data-chunk-id="${escapeHtml(chunk.chunkId)}" style="background:var(--accent-primary);border:1px solid var(--accent-primary);color:var(--signal-on-primary);font-size:0.76rem;font-weight:700;padding:6px 14px;border-radius:6px;cursor:pointer;">
                        ${isSingle ? 'Accept &amp; Merge' : 'Merge'}
                    </button>
                    <button id="btn-discard-${escapeHtml(chunk.chunkId)}" class="btn-discard-chunk" data-chunk-id="${escapeHtml(chunk.chunkId)}" style="background:none;border:1px solid rgba(243,137,139,0.35);color:var(--accent-red,#f3898b);font-size:0.76rem;font-weight:600;padding:6px 12px;border-radius:6px;cursor:pointer;">
                        Discard
                    </button>
                </div>
            </div>
        `).join('');

        // Bind per-chunk action buttons
        container.querySelectorAll('.btn-merge-chunk').forEach(btn => {
            btn.addEventListener('click', async () => {
                const cid = btn.dataset.chunkId;
                btn.disabled = true;
                btn.textContent = 'Merging...';
                try {
                    await mergeChunk(cid);
                } catch (err) {
                    console.error('Failed to merge chunk:', err);
                    alert('Failed to merge chunk: ' + (err.message || String(err)));
                    btn.disabled = false;
                    btn.textContent = isSingle ? 'Accept & Merge' : 'Merge';
                }
            });
        });

        container.querySelectorAll('.btn-discard-chunk').forEach(btn => {
            btn.addEventListener('click', async () => {
                const cid = btn.dataset.chunkId;
                btn.disabled = true;
                btn.textContent = 'Discarding...';
                try {
                    await discardChunk(cid);
                } catch (err) {
                    console.error('Failed to discard chunk:', err);
                    alert('Failed to discard chunk: ' + (err.message || String(err)));
                    btn.disabled = false;
                    btn.textContent = 'Discard';
                }
            });
        });
    }

    async function mergeChunk(chunkId) {
        const sid = activeSessionId || (typeof window !== 'undefined' ? window._activeNginxSessionId : null);
        if (!sid) throw new Error('No active session ID');
        const res = await fetch(`/api/ingest/${sid}/chunk/${chunkId}`);
        if (!res.ok) throw new Error('Failed to retrieve chunk download URL');
        const info = await res.json();
        if (!info.success || !info.downloadUrl) throw new Error('Invalid chunk response');

        const downloadRes = await fetch(info.downloadUrl);
        if (!downloadRes.ok) throw new Error('Failed to download chunk data');
        const stream = downloadRes.body;

        isMultiNodeSession = true;
        await appendLogStream(stream);

        // Strict Zero-Retention: purge chunk object immediately after merging into browser memory
        await fetch(`/api/ingest/${sid}/chunk/${chunkId}/purge`, { method: 'POST' }).catch(() => {});

        queueItems = queueItems.filter(q => q.chunkId !== chunkId);
        if (queueItems.length === 0) {
            dismissedChunkCount = 0;
            dismissToastNotification(false);
        }
        renderQueueUI();
        renderToastNotification();
    }

    async function discardChunk(chunkId) {
        const sid = activeSessionId || (typeof window !== 'undefined' ? window._activeNginxSessionId : null);
        if (!sid) return;
        await fetch(`/api/ingest/${sid}/chunk/${chunkId}/discard`, { method: 'POST' }).catch(() => {});
        queueItems = queueItems.filter(q => q.chunkId !== chunkId);
        if (queueItems.length === 0) {
            dismissedChunkCount = 0;
            dismissToastNotification(false);
        }
        renderQueueUI();
        renderToastNotification();
    }

    async function mergeAllChunks() {
        const mergeAllBtn = document.getElementById('queue-merge-all-btn');
        if (mergeAllBtn) {
            mergeAllBtn.disabled = true;
            mergeAllBtn.textContent = 'Merging all...';
        }
        const chunksToMerge = queueItems.slice();
        for (const chunk of chunksToMerge) {
            try {
                await mergeChunk(chunk.chunkId);
            } catch (err) {
                console.error('Error merging chunk ' + chunk.chunkId, err);
            }
        }
        if (mergeAllBtn) {
            mergeAllBtn.disabled = false;
            mergeAllBtn.innerHTML = '<i class="bi bi-check-all"></i> Accept &amp; Merge All';
        }
        dismissToastNotification(false);
        renderToastNotification();
    }

    async function appendLogStream(stream) {
        const decompressed = typeof peekAndDecompressStream === 'function'
            ? await peekAndDecompressStream(stream)
            : stream;

        if (activeWorker && typeof appendStreamToWorker === 'function') {
            const result = await appendStreamToWorker(decompressed, activeWorker, {
                skip403: currentSkip403,
                skipInternal: currentSkipInternal
            });
            currentNodeCount++;
            const mergedData = Analyzer.analyzeFromWorkerSummary(result.summary);
            latestSummary = result.summary;
            latestPageResult = result.pageResult;
            const mergedParseResult = {
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
            originalParseResult = mergedParseResult;
            render(mergedData, currentLogText, mergedParseResult, {
                preserveFilters: false,
                worker: activeWorker,
                summary: result.summary,
                pageResult: result.pageResult,
                nodeCount: currentNodeCount,
                sessionId: activeSessionId
            });
            return;
        }

        // In-memory fallback
        const text = await new Response(decompressed).text();
        await appendLogText(text);
    }

    async function appendLogText(text) {
        if (activeWorker && typeof appendStreamToWorker === 'function') {
            const blob = new Blob([text]);
            await appendLogStream(blob.stream());
            return;
        }

        // In-memory path
        currentLogText = (currentLogText ? currentLogText + '\n' : '') + text;
        const appendParse = await LogParser.parseAsync(text, {
            skip403: currentSkip403,
            skipInternal: currentSkipInternal
        });
        Analyzer.enrichLogEntries(appendParse.logEntries);
        originalEnrichedEntries = originalEnrichedEntries.concat(appendParse.logEntries);
        const mergedData = Analyzer.analyzeEnhancedLogs(originalEnrichedEntries);
        currentNodeCount++;

        const mergedParseResult = {
            ...(originalParseResult || {}),
            logEntries: originalEnrichedEntries,
            parsedLines: new Array(mergedData.total_requests),
            validLines: mergedData.total_requests,
            skippedLines: (originalParseResult?.skippedLines || []).concat(appendParse.skippedLines || [])
        };
        originalParseResult = mergedParseResult;

        render(mergedData, currentLogText, mergedParseResult, {
            preserveFilters: false,
            nodeCount: currentNodeCount,
            sessionId: activeSessionId
        });
    }

    async function appendLogFile(file) {
        const stream = file.stream();
        await appendLogStream(stream);
    }

    async function appendLogUrl(url) {
        const res = await fetch(url);
        if (!res.ok) throw new Error(`HTTP error ${res.status}`);
        await appendLogStream(res.body);
    }

    function numberWithCommas(n) {
        if (n === null || n === undefined) return '0';
        return n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    }

    function setNginxStandaloneView(view) {
        if (document.body?.dataset?.nginxPage === 'standalone') {
            document.body.dataset.nginxView = view;
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

    function chartPalette() {
        const styles = getComputedStyle(document.querySelector('.signal-workspace') || document.documentElement);
        const value = (name) => styles.getPropertyValue(name).trim();
        return {
            primary: value('--accent-primary'),
            error: value('--accent-red'),
            text: value('--text-secondary'),
            colors: ['--accent-primary', '--accent-blue', '--accent-purple', '--accent-amber', '--accent-red', '--accent-cyan', '--text-muted'].map(value),
        };
    }

    function computeThreatVectors(data) {
        let count = 0;
        if (data.spoofed_bot_ips && data.spoofed_bot_ips.length > 0) count += data.spoofed_bot_ips.length;
        if (data.http_metrics && data.http_metrics.top_paths) {
            const attackPaths = data.http_metrics.top_paths.filter(p => 
                p.path.includes('xmlrpc') || p.path.includes('.env') || p.path.includes('.git') || p.path.includes('wp-login') || p.path.includes('admin')
            );
            count += attackPaths.length;
        }
        if (data.asn_hits) {
            const torOrBotASNs = data.asn_hits.filter(a => 
                (a.asn_org || '').toLowerCase().includes('tor') || (a.asn_org || '').toLowerCase().includes('zwiebelfreunde')
            );
            count += torOrBotASNs.length;
        }
        return count;
    }

    function render(data, logText, parseResult, options = {}) {
        if (!themeObserver) {
            themeObserver = new MutationObserver(() => {
                const palette = chartPalette();
                if (rpsChart) {
                    rpsChart.data.datasets.forEach((dataset, index) => {
                        const color = index === 0 ? palette.primary : palette.error;
                        dataset.borderColor = color;
                        dataset.backgroundColor = color + '20';
                    });
                }
                if (countryChart) countryChart.data.datasets[0].backgroundColor = palette.colors;
                if (asnChart) asnChart.data.datasets[0].backgroundColor = [...palette.colors, ...palette.colors];
                [rpsChart, countryChart, asnChart].forEach(chart => {
                    if (!chart) return;
                    for (const scale of Object.values(chart.options.scales || {})) {
                        if (scale.ticks) scale.ticks.color = palette.text;
                        if (scale.title) scale.title.color = palette.text;
                    }
                    chart.update('none');
                });
                if (currentData) {
                    renderCountryLegend(currentData.country_hits.slice(0, 7), palette.colors, currentData.total_requests);
                }
            });
            themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
        }
        currentData = data;
        currentLogText = logText || '';
        currentInputSource = options.source || currentInputSource || 'text';
        currentGistUrl = options.gistUrl !== undefined ? options.gistUrl : currentGistUrl;

        if (options.worker) {
            activeWorker = options.worker;
            activeWorker.onmessage = (e) => {
                const msg = e.data || {};
                if (msg.reqId === 'ip_logs') {
                    renderIPLogsModal(msg.ip, msg.pageResult);
                } else if (msg.type === 'page_result') {
                    latestPageResult = msg.pageResult;
                    renderExplorerRowsAndPagination(msg.pageResult);
                } else if (msg.type === 'filter_result') {
                    latestSummary = msg.summary;
                    latestPageResult = msg.pageResult;
                    const filteredData = Analyzer.analyzeFromWorkerSummary(msg.summary);
                    render(filteredData, currentLogText, originalParseResult, {
                        preserveFilters: true,
                        worker: activeWorker,
                        summary: msg.summary,
                        pageResult: msg.pageResult
                    });
                }
            };
        }
        if (options.pageResult) {
            latestPageResult = options.pageResult;
        }
        if (options.summary) {
            latestSummary = options.summary;
        }
        if (!options.preserveFilters && !options.worker) {
            activeWorker = null;
            latestPageResult = null;
            latestSummary = null;
        }

        if (options.sessionId) {
            activeSessionId = options.sessionId;
            if (typeof window !== 'undefined') window._activeNginxSessionId = activeSessionId;
        } else if (typeof window !== 'undefined' && window._activeNginxSessionId) {
            activeSessionId = window._activeNginxSessionId;
        }

        if (options.nodeCount) {
            currentNodeCount = options.nodeCount;
            if (options.nodeCount > 1) {
                isMultiNodeSession = true;
            }
        } else if (!options.preserveFilters) {
            currentNodeCount = 1;
        }

        if (!options.preserveFilters) {
            exclusionRevision++;
            currentReadOnly = Boolean(options.readOnly || currentInputSource === 'gist');
            currentSourceLabel = options.sourceLabel || ({ file: 'Uploaded logs', sample: 'Sample dataset', url: 'Remote log', gist: 'Shared snapshot', terminal_ingest: 'Terminal session' }[currentInputSource]) || 'Pasted logs';
            currentSkip403 = parseResult?.options?.skip403 ?? options.skip403 ?? true;
            currentSkipInternal = parseResult?.options?.skipInternal ?? options.skipInternal ?? true;
        }

        if (!options.preserveFilters) {
            originalEnrichedEntries = (parseResult?.logEntries || []).slice();
            originalParseResult = parseResult;
            originalTimeRange = null;
            sliderStartPct = 0;
            sliderEndPct = 100;
            activeFilters = {
                statusCategory: 'all',
                method: 'all',
                country: 'all',
                asn: 'all',
                bot: 'all',
                ipSearch: '',
                pathSearch: '',
                uaSearch: ''
            };
            activeTimeMinutes = 0;
            maxLogTimestamp = parseResult?.maxTimestamp || 0;
            if (!maxLogTimestamp && originalEnrichedEntries.length > 0) {
                for (let i = 0; i < originalEnrichedEntries.length; i++) {
                    const t = originalEnrichedEntries[i].timestamp;
                    if (!t) continue;
                    const ms = t instanceof Date ? t.getTime() : (typeof t === 'number' ? t : new Date(t).getTime());
                    if (!isNaN(ms) && ms > maxLogTimestamp) maxLogTimestamp = ms;
                }
            }
            explorerPage = 1;
            explorerPerPage = 25;
            explorerSortField = 'timestamp';
            explorerSortDir = 'desc';
            activeRpsResolution = '1'; // QA13: fixed resolution set
            currentFilteredEntries = originalEnrichedEntries.slice();
            sortExplorerEntries();

            // Initialize default mitigation selections
            selectedMitigationIPs.clear();
            selectedMitigationASNs.clear();
            selectedMitigationCountries.clear();
            selectedMitigationPaths.clear();

            (data.spoofed_bot_ips || []).slice(0, 10).forEach(ip => selectedMitigationIPs.add(ip));
            if (data.top_ips && selectedMitigationIPs.size === 0) {
                data.top_ips.slice(0, 3).forEach(ipObj => selectedMitigationIPs.add(ipObj.ip));
            }
            if (data.asn_hits) {
                const tor = data.asn_hits.find(a => (a.asn_org || '').toLowerCase().includes('tor') || (a.asn_org || '').toLowerCase().includes('zwiebel'));
                if (tor) selectedMitigationASNs.add(String(tor.asn));
            }
            if (data.http_metrics && data.http_metrics.top_paths) {
                data.http_metrics.top_paths.forEach(p => {
                    if (p.path.includes('xmlrpc') || p.path.includes('.env') || p.path.includes('.git')) {
                        selectedMitigationPaths.add(p.path);
                    }
                });
            }
        } else if (data && activeRpsResolution !== 'auto') {
            // QA5: intentionally NOT recomputing request_rate from
            // currentFilteredEntries here — renderRequestRateChart reads the
            // full originalEnrichedEntries itself, so a re-render never
            // overwrites the chart data with a subset.
        }

        const filterOptions = getFilterOptions(originalEnrichedEntries, data);
        const container = document.getElementById('nginx-dashboard');
        setNginxStandaloneView('results');
        container.style.display = 'block';
        document.getElementById('nginx-input-section').style.display = 'none';
        document.getElementById('nginx-hero-section')?.style.setProperty('display', 'none');
        document.getElementById('nginx-tips-section')?.style.setProperty('display', 'none');
        document.getElementById('nginx-sample-bar')?.style.setProperty('display', 'none');
        document.querySelectorAll('.sample-bar').forEach(el => el.style.setProperty('display', 'none'));

        const totalRequests = data.total_requests;
        const skippedLines = parseResult ? parseResult.skippedLines.length : 0;
        const humanPct = totalRequests ? Math.round(data.human_requests / totalRequests * 100) : 0;
        const verifiedCount = data.verified_bots_count || 0;
        const spoofedCount = data.spoofed_bots_count || 0;
        const verifiedPct = totalRequests ? Math.round(verifiedCount / totalRequests * 1000) / 10 : 0;
        const spoofedPct = totalRequests ? Math.round(spoofedCount / totalRequests * 1000) / 10 : 0;
        const errorCount = (data.http_metrics?.status_categories?.['4xx'] || 0) + (data.http_metrics?.status_categories?.['5xx'] || 0);
        const errorPct = totalRequests ? (errorCount / totalRequests * 100).toFixed(1) : '0.0';

        container.innerHTML = `
            <header class="signal-dashboard-heading"><div><p class="signal-eyebrow">Traffic intelligence</p><h1>Traffic log overview</h1><p>The story behind your requests. Traffic, patterns, and what needs a closer look.</p></div></header>
            ${currentInputSource === 'terminal_ingest' ? `
            <div id="terminal-ingest-banner" style="
                background: rgba(16, 185, 129, 0.08);
                border: 1px solid rgba(16, 185, 129, 0.25);
                border-radius: 8px;
                padding: 8px 14px;
                margin-bottom: 16px;
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 10px;
                font-size: 0.82rem;
            ">
                <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                    <i class="bi bi-shield-check" style="color: #10b981; font-size: 1rem;"></i>
                    <span style="color: var(--text-primary); font-weight: 600;">Terminal Ingest:</span>
                    <span style="color: var(--text-secondary);">Server copy permanently deleted upon opening. Analysis runs 100% locally in your browser.</span>
                    <span style="font-size: 0.68rem; font-weight: 700; background: rgba(16,185,129,0.15); color: #34d399; padding: 1px 6px; border-radius: 4px; text-transform: uppercase;">Zero Retention</span>
                </div>
                <button onclick="document.getElementById('terminal-ingest-banner')?.remove()" style="
                    background: none; border: none; color: var(--text-muted);
                    font-size: 1.1rem; cursor: pointer; padding: 0 4px; line-height: 1;
                " title="Dismiss">&times;</button>
            </div>
            ` : ''}

            <!-- 1. Top Action & Status Bar -->
            <div class="signal-dashboard-toolbar" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid var(--border-color);flex-wrap:wrap;gap:12px;">
                <div class="signal-dashboard-actions" style="display:flex;align-items:center;gap:8px;">
                    <button id="dash-back-btn" class="btn" style="background:var(--accent-primary);border-color:var(--accent-primary);color:var(--signal-on-primary);padding:6px 14px;border-radius:8px;cursor:pointer;font-size:0.8rem;font-weight:700;">
                        <i class="bi bi-plus-lg" style="margin-right:4px;"></i> New Analysis
                    </button>
                    <button id="dash-add-logs-btn" class="btn" style="background:var(--signal-tint);border:1px solid color-mix(in srgb, var(--accent-primary) 35%, transparent);color:var(--accent-primary);padding:6px 14px;border-radius:8px;cursor:pointer;font-size:0.8rem;font-weight:700;display:inline-flex;align-items:center;gap:6px;">
                        <i class="bi bi-hdd-network-fill"></i> Add More Logs
                        <span id="dash-queue-badge" style="display:none;background:var(--accent-primary);color:var(--signal-on-primary);font-size:0.7rem;font-weight:700;padding:1px 6px;border-radius:10px;margin-left:4px;">0</span>
                    </button>
                    <button id="dash-download-btn" class="btn" style="background:none;border:1px solid var(--border-color);color:var(--text-secondary);padding:6px 14px;border-radius:8px;cursor:pointer;font-size:0.8rem;font-weight:600;">
                        <i class="bi bi-download" style="margin-right:4px;"></i> Download Report
                    </button>
                    <button id="dash-share-btn" class="btn" style="${currentInputSource === 'terminal_ingest' ? 'background:rgba(255,255,255,0.03);border:1px dashed var(--border-color);color:var(--text-muted);opacity:0.85;' : 'background:none;border:1px solid var(--border-color);color:var(--accent-primary);'}padding:6px 14px;border-radius:8px;cursor:pointer;font-size:0.8rem;font-weight:600;">
                        <i class="bi ${currentInputSource === 'terminal_ingest' ? 'bi-shield-lock' : 'bi-share-fill'}" style="margin-right:4px;"></i> ${currentInputSource === 'terminal_ingest' ? 'Share (Zero-Retention)' : 'Share Snapshot'}
                    </button>
                </div>
                <div style="font-size:0.78rem;color:var(--text-muted);display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
                    <span><strong style="color:var(--text-primary);">Parsed:</strong> ${numberWithCommas(parseResult ? parseResult.parsedLines.length : totalRequests)} lines</span>
                    <span style="color:rgba(255,255,255,0.2);">|</span>
                    <span><strong style="color:var(--text-primary);">Skipped:</strong> ${numberWithCommas(skippedLines)} lines</span>
                    ${parseResult?.logStart ? `
                    <span style="color:rgba(255,255,255,0.2);">|</span>
                    <span><i class="bi bi-clock" style="margin-right:4px;"></i>Span: <strong style="color:var(--text-secondary);">${escapeHtml(parseResult.logStart)}</strong> → <strong style="color:var(--text-secondary);">${escapeHtml(parseResult.logEnd)}</strong> (${Number(parseResult.logSpanMinutes) || 0}m)</span>
                    ` : ''}
                </div>
            </div>

            <div class="signal-dashboard-source">
                <i class="bi bi-file-earmark-text" aria-hidden="true"></i>
                <div>
                    <div style="display:flex;align-items:center;gap:8px;">
                        <strong>${escapeHtml(currentSourceLabel)}</strong>
                        <span id="dash-source-badge" style="background:var(--signal-tint);border:1px solid color-mix(in srgb, var(--accent-primary) 35%, transparent);color:var(--accent-primary);font-size:0.72rem;font-weight:700;padding:2px 8px;border-radius:6px;">${currentNodeCount > 1 ? `${currentNodeCount} nodes · ${numberWithCommas(totalRequests)} requests` : '1 node'}</span>
                    </div>
                    <span>${currentInputSource === 'sample' ? 'Example dataset' : 'Browser analysis'} · ${currentSkip403 ? '403 exclusion enabled' : 'All response statuses included'} · ${currentSkipInternal ? 'Internal requests excluded' : 'Internal requests included'}</span>
                </div>
                <span class="signal-dashboard-errors">${errorPct}% error responses <small>4xx + 5xx</small></span>
            </div>

            ${renderExclusionsHtml(parseResult)}

            ${renderFacetedFilterRibbonHtml(filterOptions)}

            <!-- 2. 7-Micro KPI Cards Row -->
            <div class="kpi-micro-cards-strip" id="signal-overview">
                <!-- 1. Total Requests -->
                <div class="stat-card kpi-micro-card kpi-card-total">
                    <div class="stat-value">${numberWithCommas(totalRequests)}</div>
                    <div class="stat-label">TOTAL REQUESTS</div>
                </div>

                <!-- 2. Unique IPs -->
                <div class="stat-card kpi-micro-card kpi-card-ips">
                    <div class="stat-value">${numberWithCommas(data.unique_ips)}</div>
                    <div class="stat-label">UNIQUE IPS</div>
                </div>

                <!-- 3. ASNs -->
                <div class="stat-card kpi-micro-card kpi-card-asns">
                    <div class="stat-value">${numberWithCommas(data.unique_asns || (data.asn_hits || []).length || 0)}</div>
                    <div class="stat-label">ASNS & NETWORKS</div>
                </div>

                <!-- 4. Countries -->
                <div class="stat-card kpi-micro-card kpi-card-countries">
                    <div class="stat-value">${numberWithCommas(data.unique_countries || (data.country_hits || []).length || 0)}</div>
                    <div class="stat-label">COUNTRIES</div>
                </div>

                <!-- 5. Human Traffic -->
                <div class="stat-card kpi-micro-card kpi-card-human">
                    <div class="stat-value">${humanPct}%</div>
                    <div class="stat-label">HUMAN TRAFFIC</div>
                </div>

                <!-- 6. Verified Bots -->
                <div class="stat-card kpi-micro-card kpi-card-verified">
                    <div class="stat-value">${numberWithCommas(verifiedCount)}</div>
                    <div class="stat-label">VERIFIED BOTS (${verifiedPct}%)</div>
                </div>

                <!-- 7. Spoofed Bots -->
                <div class="stat-card kpi-micro-card kpi-card-spoofed">
                    <div class="stat-value">${numberWithCommas(spoofedCount)}</div>
                    <div class="stat-label">SPOOFED BOTS (${spoofedPct}%)</div>
                </div>
            </div>

            <!-- 3. HTTP Methods & Bandwidth Egress Ribbon (Same Line) -->
            ${data.http_metrics ? `
            <div class="methods-bandwidth-ribbon">
                <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
                    <span style="font-size:0.72rem;color:var(--text-muted);font-weight:700;text-transform:uppercase;">Methods:</span>
                    ${(data.http_metrics.method_hits || []).map(m => {
                        const pct = totalRequests ? Math.round(m.count / totalRequests * 1000) / 10 : 0;
                        return `
                        <span style="font-size:0.76rem;background:rgba(255,255,255,0.05);padding:2px 8px;border-radius:4px;border:1px solid var(--border-color);">
                            <strong style="color:var(--text-primary);">${escapeHtml(m.method)}</strong>: <span style="color:var(--accent-green);font-weight:700;margin-left:2px;">${numberWithCommas(m.count)}</span> <span style="color:var(--text-muted);font-size:0.7rem;">(${pct}%)</span>
                        </span>
                        `;
                    }).join('')}
                </div>

                <div style="display:flex;align-items:center;gap:8px;">
                    <span style="font-size:0.72rem;color:var(--text-muted);font-weight:700;text-transform:uppercase;">Data Egress:</span>
                    <span class="pill pill-cyan" style="font-size:0.76rem;font-weight:700;"><i class="bi bi-lightning-charge-fill"></i> ${formatSize(data.http_metrics.response_size?.total || 0)} Transferred</span>
                </div>
            </div>
            ` : ''}

            <!-- 4. Unified Request Rate Chart & Draggable Timeline Scrubber (Merged Card) -->
            ${renderUnifiedTelemetryCardHtml(data.request_rate)}

            <!-- 6. Visual Charts: Country Donut + ASN Histogram (50/50 Split) -->
            <div class="signal-dashboard-charts" id="signal-networks" style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px;">
                <div class="chart-card" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:16px;">
                    <div class="chart-card-header" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                        <h5 style="margin:0;font-size:0.86rem;font-weight:700;"><i class="bi bi-pie-chart" style="color:var(--accent-primary);margin-right:6px;"></i>🌍 Country Distribution</h5>
                        <span style="font-size:0.72rem;color:var(--text-muted);">${data.unique_countries || (data.country_hits || []).length || 0} Nations</span>
                    </div>
                    <div class="chart-body">
                        <div class="country-distribution-layout">
                            <div class="country-chart-canvas-wrap"><canvas id="country-chart"></canvas></div>
                            <div id="country-chart-legend" class="country-chart-legend"></div>
                        </div>
                    </div>
                </div>
                <div class="chart-card" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:16px;">
                    <div class="chart-card-header" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                        <h5 style="margin:0;font-size:0.86rem;font-weight:700;"><i class="bi bi-bar-chart-line" style="color:var(--accent-cyan);margin-right:6px;"></i>🏢 ASN Distribution (Top Networks)</h5>
                        <span style="font-size:0.72rem;color:var(--text-muted);">${data.unique_asns || (data.asn_hits || []).length || 0} ASNs</span>
                    </div>
                    <div class="chart-body"><canvas id="asn-chart"></canvas></div>
                </div>
            </div>

            <!-- 7. 3-Column Dense Incident Matrix -->
            <h2 class="signal-panel-heading">Security signals <small>${computeThreatVectors(data)} active indicators</small></h2>
            ${render3ColumnIncidentMatrixHtml(data, totalRequests)}

            <!-- 8. Full Log Explorer Section -->
            ${renderLogExplorerCardHtml()}

            <!-- Floating Clear Active Filters Capsule Button -->
            <div id="floating-clear-filters-btn" class="floating-clear-pill" style="display:${hasActiveFilters() ? 'flex' : 'none'};">
                <span style="width:8px;height:8px;border-radius:50%;background:var(--accent-red);box-shadow:0 0 8px var(--accent-red);"></span>
                <span style="font-size:0.76rem;font-weight:700;color:#fff;">✕ Clear Active Filters (${getActiveFilterCount()} active · ${numberWithCommas(latestPageResult ? latestPageResult.totalRows : (latestSummary ? latestSummary.matchingCount : currentFilteredEntries.length))} hits)</span>
            </div>
            
            <!-- IP Access Log Modal (hidden) -->
            <div id="ip-log-modal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);z-index:10001;align-items:center;justify-content:center;">
                <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:16px;max-width:900px;width:92%;max-height:85vh;display:flex;flex-direction:column;position:relative;overflow:hidden;">
                    <div style="padding:20px 24px;border-bottom:1px solid var(--border-color);display:flex;justify-content:space-between;align-items:center;">
                        <h5 id="ip-log-modal-title" style="margin:0;font-weight:700;"></h5>
                        <button id="ip-log-modal-close" style="background:none;border:none;color:var(--text-muted);font-size:1.2rem;cursor:pointer;"><i class="bi bi-x-lg"></i></button>
                    </div>
                    <div id="ip-log-modal-body" style="flex:1;overflow-y:auto;padding:16px 24px;"></div>
                </div>
            </div>
        `;

        [countryChart, asnChart, rpsChart].forEach(chart => chart?.destroy());
        countryChart = asnChart = rpsChart = null;
        if (currentReadOnly) ['dash-back-btn', 'dash-share-btn', 'dash-download-btn'].forEach(id => { container.querySelector(`#${id}`).hidden = true; });
        ensureAddLogsModal();
        bindEvents(data, parseResult);
        // All result sections share one view; initialize every visualization immediately.
        renderRequestRateChart();
        renderCharts(data);
        updateExplorerView();
        updateMitigationFirewallPreview();
        renderQueueUI();
        renderToastNotification();
    }

    function switchStage(stageId) {
        const isAnalyse = stageId === 'stage-analyse';
        document.getElementById('stage-analyse')?.classList.toggle('active', isAnalyse);
        document.getElementById('stage-mitigate')?.classList.toggle('active', !isAnalyse);

        document.getElementById('card-btn-analyse')?.classList.toggle('active-analyse', isAnalyse);
        document.getElementById('card-btn-mitigate')?.classList.toggle('active-mitigate', !isAnalyse);

        const statusTag = document.getElementById('status-tag-analyse');
        if (statusTag) {
            statusTag.innerHTML = isAnalyse ? '<i class="bi bi-eye-fill"></i> Active' : 'Switch';
            statusTag.style.color = isAnalyse ? 'var(--accent-cyan)' : 'var(--text-muted)';
        }

        if (isAnalyse) {
            window.dispatchEvent(new Event('resize'));
        } else {
            updateMitigationFirewallPreview();
        }
    }

    function switchMitigateTab(tabId, btn) {
        document.querySelectorAll('.mitigate-tab-item').forEach(b => b.classList.remove('active'));
        if (btn) btn.classList.add('active');
        ['mit-tab-ips', 'mit-tab-asns', 'mit-tab-geo', 'mit-tab-paths'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.style.display = (id === tabId) ? 'block' : 'none';
        });
    }

    function generateFirewallCode() {
        const ips = [...selectedMitigationIPs];
        const asns = [...selectedMitigationASNs];
        const paths = [...selectedMitigationPaths];
        const countries = [...selectedMitigationCountries];

        if (currentFwFormat === 'nginx') {
            let out = `# ============================================================\n# Nginx Security & Threat Mitigation Rules\n# Generated by SysAdmin Toolkit Incident Commander\n# Scope: Selected Hostile IPs + Tor ASNs + Exploit Endpoints\n# ============================================================\n\n`;
            if (ips.length > 0) {
                out += `# 1. Deny Malicious Attacking IPs\n`;
                ips.forEach(ip => { out += `deny ${ip};\n`; });
                out += `\n`;
            }
            if (paths.length > 0) {
                out += `# 2. Block Abusive / Scanned Endpoints\n`;
                paths.forEach(p => {
                    out += `location = ${p} {\n    deny all;\n    access_log off;\n    return 444;\n}\n\n`;
                });
            }
            if (ips.length === 0 && paths.length === 0) {
                out += `# No specific rules selected. Check items in the left panel to generate rules.\n`;
            }
            return out;
        }

        if (currentFwFormat === 'cloudflare') {
            const clauses = [];
            if (ips.length > 0) clauses.push(`(ip.src in {${ips.join(' ')}})`);
            if (asns.length > 0) clauses.push(`(ip.geoip.asnum in {${asns.join(' ')}})`);
            if (paths.length > 0) clauses.push(`(http.request.uri.path in {${paths.map(p => `"${p}"`).join(' ')}})`);
            if (countries.length > 0) clauses.push(`(ip.geoip.country in {${countries.map(c => `"${c}"`).join(' ')}})`);
            return clauses.length > 0 ? clauses.join(' or \n') : `(http.request.uri.path eq "/xmlrpc.php")`;
        }

        if (currentFwFormat === 'iptables') {
            let out = `# Drop Malicious Attacking IPs via iptables\n`;
            ips.forEach(ip => { out += `iptables -A INPUT -s ${ip} -j DROP\n`; });
            if (ips.length === 0) out += `# Select IPs in the left panel to generate iptables rules\n`;
            return out;
        }

        if (currentFwFormat === 'awswaf') {
            const ipSet = {
                Name: "SysAdminToolkit-Blocked-IPSet",
                Scope: "REGIONAL",
                IPAddressVersion: "IPV4",
                Addresses: ips.map(ip => `${ip}/32`)
            };
            return JSON.stringify(ipSet, null, 2);
        }

        if (currentFwFormat === 'ufw') {
            let out = `# UFW Deny Rules\n`;
            ips.forEach(ip => { out += `ufw insert 1 deny from ${ip} to any comment 'Hostile IP'\n`; });
            if (ips.length === 0) out += `# Select IPs in the left panel to generate UFW rules\n`;
            return out;
        }

        if (currentFwFormat === 'cisco') {
            let out = `! Cisco IOS Extended Access-List\n`;
            ips.forEach(ip => { out += `access-list 100 deny ip host ${ip} any\n`; });
            if (ips.length === 0) out += `! Select IPs in the left panel to generate Cisco rules\n`;
            return out;
        }

        return '';
    }

    function updateMitigationFirewallPreview() {
        const preview = document.getElementById('fw-code-preview');
        if (preview) {
            preview.textContent = generateFirewallCode();
        }
    }

    function renderExclusionsHtml(parseResult) {
        const counts = parseResult?.skipCounts || {};
        return `
            <fieldset class="signal-nginx-options signal-dashboard-exclusions" id="dashboard-exclusions">
                <legend>Analysis exclusions</legend>
                <div class="signal-exclusion-toggles">
                    <label><input type="checkbox" id="dash-skip-403" ${currentSkip403 ? 'checked' : ''}> Ignore 403 responses</label>
                    <label><input type="checkbox" id="dash-skip-internal" ${currentSkipInternal ? 'checked' : ''}> Ignore internal requests</label>
                </div>
                <p class="signal-exclusion-counts" id="exclusion-counts">Skipped: <strong>${numberWithCommas(counts.privateIP || 0)}</strong> private/local IP · <strong>${numberWithCommas(counts.healthCheck || 0)}</strong> health-check path · <strong>${numberWithCommas(counts.forbidden || 0)}</strong> ordinary 403 · <strong>${numberWithCommas(counts.invalid || 0)}</strong> invalid</p>
                <details class="signal-nginx-option-help"><summary>What is excluded?</summary><p>Internal requests: private, loopback, link-local, CGNAT and IPv6 unique-local IPs (including mapped IPv4), plus exact paths /health, /healthz, /healthcheck, /health-check, /health_check, /readyz, /livez and /_health. Query strings and trailing slashes are ignored. Every User-Agent and response status is covered. Unknown ASN alone is not an exclusion.</p><p>403 filtering retains recognized crawlers for bot analysis. Each skipped line is counted once: private/local IP first, then health-check path, then ordinary 403. Changing an exclusion recalculates the loaded log and resets result filters. The input time span still includes excluded rows.</p></details>
                <p id="dash-exclusion-status" role="status">${parseResult?.validLines > 0 && !parseResult.parsedLines.length ? 'All valid requests are excluded. Adjust the options above to include them.' : ''}</p>
            </fieldset>`;
    }

    async function reanalyzeExclusions(focusId) {
        const revision = ++exclusionRevision;
        const skip403 = document.getElementById('dash-skip-403').checked;
        const skipInternal = document.getElementById('dash-skip-internal').checked;
        const fieldset = document.getElementById('dashboard-exclusions');
        fieldset.disabled = true;
        fieldset.setAttribute('aria-busy', 'true');
        document.getElementById('dash-exclusion-status').textContent = 'Recalculating exclusions…';
        try {
            const parseResult = await LogParser.parseAsync(currentLogText, { skip403, skipInternal });
            if (revision !== exclusionRevision) return;
            Analyzer.enrichLogEntries(parseResult.logEntries);
            const data = Analyzer.analyzeEnhancedLogs(parseResult.logEntries);
            for (const [id, value] of [['nginx-skip-403', skip403], ['nginx-skip-internal', skipInternal]]) {
                const input = document.getElementById(id);
                if (input) input.checked = value;
            }
            // Do not re-fetch a remote/one-time source: the original text is
            // already in memory. These are dataset policies, not view filters.
            render(data, currentLogText, parseResult, {
                source: currentInputSource, sourceLabel: currentSourceLabel,
                gistUrl: currentGistUrl, readOnly: currentReadOnly, skip403, skipInternal,
            });
            document.getElementById(focusId)?.focus({ preventScroll: true });
        } catch {
            if (revision !== exclusionRevision) return;
            fieldset.disabled = false;
            fieldset.removeAttribute('aria-busy');
            document.getElementById('dash-skip-403').checked = currentSkip403;
            document.getElementById('dash-skip-internal').checked = currentSkipInternal;
            document.getElementById('dash-exclusion-status').textContent = 'Could not recalculate exclusions. Please try again.';
        }
    }

    function bindEvents(data, parseResult) {
        for (const id of ['dash-skip-403', 'dash-skip-internal']) {
            document.getElementById(id)?.addEventListener('change', () => reanalyzeExclusions(id));
        }
        // AbuseIPDB Scan Button (hidden, kept for backwards compat)
        document.getElementById('btn-scan-abuseipdb')?.addEventListener('click', () => {
            scanTop10AbuseIPs(data.top_ips || []);
        });

        // Centered Abuse Scan Button
        document.getElementById('btn-center-scan-abuse')?.addEventListener('click', () => {
            const overlay = document.getElementById('abuse-overlay');
            if (overlay) overlay.style.display = 'none';
            scanTop10AbuseIPs((data.top_ips || []).slice(0, 20));
        });

        // Floating Clear Active Filters Button
        document.getElementById('floating-clear-filters-btn')?.addEventListener('click', () => {
            activeFilters = {
                statusCategory: 'all',
                method: 'all',
                country: 'all',
                asn: 'all',
                bot: 'all',
                ipSearch: '',
                pathSearch: '',
                uaSearch: ''
            };
            activeTimeMinutes = 0;
            sliderStartPct = 0;
            sliderEndPct = 100;
            applyAndRenderFilters();
        });

        // Log Explorer Subnet / IP Search
        const ipSubnetInput = document.getElementById('log-table-ip-subnet-search');
        if (ipSubnetInput) {
            ipSubnetInput.addEventListener('input', (e) => {
                logTableSubnetSearch = e.target.value.trim();
                activeFilters.ipSearch = logTableSubnetSearch;
                if (_filterDebounceTimer) clearTimeout(_filterDebounceTimer);
                _filterDebounceTimer = setTimeout(() => applyAndRenderFilters(), 150);
            });
        }

        // Log Explorer Path / URI Keyword Search
        const pathSearchInput = document.getElementById('log-table-path-search');
        if (pathSearchInput) {
            pathSearchInput.addEventListener('input', (e) => {
                logTablePathSearch = e.target.value.trim();
                activeFilters.pathSearch = logTablePathSearch;
                if (_filterDebounceTimer) clearTimeout(_filterDebounceTimer);
                _filterDebounceTimer = setTimeout(() => applyAndRenderFilters(), 150);
            });
        }

        // Back button
        document.getElementById('dash-back-btn')?.addEventListener('click', () => {
            stopAdaptiveQueuePoller();
            dismissToastNotification(false);
            isMultiNodeSession = false;
            isModalOpen = false;
            dismissedChunkCount = 0;
            // A pending worker result belongs to the dashboard being left, not
            // the next input draft. It must not render over New Analysis.
            exclusionRevision++;
            document.getElementById('nginx-dashboard').style.display = 'none';
            document.getElementById('nginx-input-section').style.display = 'block';
            document.getElementById('nginx-hero-section')?.style.setProperty('display', 'block');
            document.getElementById('nginx-tips-section')?.style.removeProperty('display');
            document.getElementById('nginx-sample-bar')?.style.setProperty('display', 'flex');
            document.querySelectorAll('.sample-bar').forEach(el => el.style.setProperty('display', 'flex'));
            setNginxStandaloneView('input');
            document.getElementById('nginx-tab-upload')?.focus();
            window.scrollTo({ top: 0, behavior: 'instant' });
        });

        // Download report
        document.getElementById('dash-download-btn')?.addEventListener('click', () => {
            if (currentData) Report.openModal(currentData, { ...originalParseResult, nodeCount: currentNodeCount }, { nodeCount: currentNodeCount });
        });

        // Share button
        document.getElementById('dash-share-btn')?.addEventListener('click', () => {
            if (currentData && typeof ShareModal !== 'undefined') {
                ShareModal.open(currentData, parseResult, {
                    logText: currentLogText,
                    gistUrl: currentGistUrl,
                    inputSource: currentInputSource,
                });
            }
        });

        // Parsed / Skipped toggles
        document.getElementById('toggle-parsed')?.addEventListener('click', () => {
            const panel = document.getElementById('parsed-panel');
            const chev = document.getElementById('chevron-parsed');
            if (panel) {
                const isHidden = panel.style.display === 'none';
                panel.style.display = isHidden ? 'block' : 'none';
                if (chev) chev.className = isHidden ? 'bi bi-chevron-up parse-chevron' : 'bi bi-chevron-down parse-chevron';
            }
        });

        document.getElementById('toggle-skipped')?.addEventListener('click', () => {
            const panel = document.getElementById('skipped-panel');
            const chev = document.getElementById('chevron-skipped');
            if (panel) {
                const isHidden = panel.style.display === 'none';
                panel.style.display = isHidden ? 'block' : 'none';
                if (chev) chev.className = isHidden ? 'bi bi-chevron-up parse-chevron' : 'bi bi-chevron-down parse-chevron';
            }
        });

        // Time filter buttons
        document.querySelectorAll('.time-filter-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const mins = parseInt(btn.dataset.minutes, 10);
                activeTimeMinutes = mins;
                applyAndRenderFilters();
            });
        });

        // IP log modal inspector buttons
        document.querySelectorAll('.btn-inspect-ip-logs').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                showIPLogs(btn.dataset.ip);
            });
        });

        // IP Log Modal close
        document.getElementById('ip-log-modal-close')?.addEventListener('click', () => {
            document.getElementById('ip-log-modal').style.display = 'none';
        });
        document.getElementById('ip-log-modal')?.addEventListener('click', (e) => {
            if (e.target.id === 'ip-log-modal') e.target.style.display = 'none';
        });

        // Add More Logs Modal
        document.getElementById('dash-add-logs-btn')?.addEventListener('click', () => {
            openAddLogsModal();
        });

        // Cross-filter clicks on 4-pillars
        document.querySelectorAll('.cross-filter-ip-row').forEach(row => {
            row.addEventListener('click', () => {
                const ip = row.dataset.ip;
                activeFilters.ipSearch = (activeFilters.ipSearch === ip) ? '' : ip;
                applyAndRenderFilters();
            });
        });
        document.querySelectorAll('.cross-filter-path-row').forEach(row => {
            row.addEventListener('click', () => {
                const path = row.dataset.path;
                activeFilters.pathSearch = (activeFilters.pathSearch === path) ? '' : path;
                applyAndRenderFilters();
            });
        });
        document.querySelectorAll('.cross-filter-asn-row').forEach(row => {
            row.addEventListener('click', () => {
                // data-asn is the BARE number, but the dropdown options and the
                // #filter-asn select both use the prefixed form. Store the
                // prefixed form so the select renders the active option and the
                // same row toggles back off on a second click.
                const bare = row.dataset.asn;
                const asn = /^AS/i.test(bare) ? bare : `AS${bare}`;
                activeFilters.asn = (activeFilters.asn === asn) ? 'all' : asn;
                applyAndRenderFilters();
            });
        });
        document.querySelectorAll('.cross-filter-bot-row').forEach(row => {
            row.addEventListener('click', () => {
                const bot = row.dataset.bot;
                const group = row.dataset.botGroup || '';
                const selected = activeFilters.bot === bot && activeFilters.botGroup === group;
                activeFilters.bot = selected ? 'all' : bot;
                activeFilters.botGroup = selected ? '' : group;
                applyAndRenderFilters();
            });
        });

        bindFilterEvents();
        bindExplorerTableEvents();
    }

    function renderRequestRateChart() {
        const ctx = document.getElementById('rps-chart')?.getContext('2d');
        // QA5: the timeline chart doubles as the scrubber background. It must
        // ALWAYS show the full-span dataset; the curtains are the only visual
        // filter. Rebuilding it from the time-filtered subset on every drag
        // made the graph morph under the handles.
        const resolution = (activeRpsResolution && activeRpsResolution !== 'auto') ? activeRpsResolution : undefined;
        const reqRate = (originalEnrichedEntries && originalEnrichedEntries.length > 0)
            ? Analyzer.computeRequestRate(originalEnrichedEntries, { resolution })
            : (currentData?.request_rate || { buckets: [] });
        const rawBuckets = reqRate?.buckets || reqRate?.data_points || [];
        const buckets = Array.isArray(rawBuckets) ? rawBuckets : [];
        const range = getGlobalTimeRange();
        if (!ctx || buckets.length === 0 || !range) return;

        if (rpsChart) rpsChart.destroy();

        const hasErrors = buckets.some(b => ((b.status_4xx || 0) + (b.status_5xx || 0)) > 0);
        const bucketSec = reqRate.bucket_seconds || 1;
        const bucketLabel = reqRate.bucket_label || `${bucketSec}s`;
        const resolutionNote = document.getElementById('rps-resolution-note');
        if (resolutionNote) resolutionNote.textContent = resolution && Number(resolution) !== bucketSec
            ? `Using ${bucketLabel} buckets (1,500-point limit)` : '';
        const palette = chartPalette();
        const points = value => buckets.map(b => ({
            x: Math.max(range.minTs, Math.min(range.maxTs, b.timestamp)),
            y: value(b),
        }));
        const crossesDays = new Date(range.minTs).toISOString().slice(0, 10) !== new Date(range.maxTs).toISOString().slice(0, 10);

        const datasets = [
            {
                label: 'Total Traffic',
                data: points(b => b.count !== undefined ? b.count : (b.rps * bucketSec)),
                borderColor: palette.primary,
                backgroundColor: palette.primary + '20',
                fill: true,
                tension: 0.35,
                borderWidth: 2,
                pointRadius: buckets.length > 70 ? 0 : 2.5,
                pointHoverRadius: 6,
                pointHoverBackgroundColor: '#ffffff',
                pointHoverBorderColor: palette.primary,
                pointHoverBorderWidth: 2
            }
        ];

        if (hasErrors) {
            datasets.push({
                label: 'Error responses (4xx, 5xx)',
                data: points(b => (b.status_4xx || 0) + (b.status_5xx || 0)),
                borderColor: palette.error,
                backgroundColor: palette.error + '20',
                fill: true,
                tension: 0.35,
                borderWidth: 1.5,
                pointRadius: 0,
                pointHoverRadius: 5,
                pointHoverBackgroundColor: '#ffffff',
                pointHoverBorderColor: palette.error,
                pointHoverBorderWidth: 2
            });
        }

        function syncScrubberTrack(chart) {
            if (!chart?.chartArea) return;
            const wrap = document.getElementById('timeline-slider-wrap');
            const ca = chart.chartArea;
            const leftPx = ca.left;
            const rightPx = Math.max(0, chart.width - ca.right);

            if (wrap) {
                wrap.style.setProperty('--chart-left', `${leftPx}px`);
                wrap.style.setProperty('--chart-right', `${rightPx}px`);
            }
            const track = document.getElementById('slider-scrubber-track');
            if (track) {
                track.style.left = `${leftPx}px`;
                track.style.width = `${ca.right - ca.left}px`;
                track.style.right = 'auto';
                track.style.top = `${ca.top}px`;
                track.style.height = `${ca.bottom - ca.top}px`;
                track.style.bottom = 'auto';
                updateTimelineSelection();
            }
        }

        rpsChart = new Chart(ctx, {
            type: 'line',
            data: {
                datasets: datasets
            },
            plugins: [{ id: 'timelineScrubberAlignment', afterLayout: syncScrubberTrack }],
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                layout: { padding: { top: 64, bottom: 8 } },
                interaction: {
                    mode: 'index',
                    intersect: false
                },
                hover: {
                    mode: 'index',
                    intersect: false
                },
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        enabled: true,
                        backgroundColor: '#090d16',
                        titleColor: '#94a3b8',
                        titleFont: { size: 11, weight: '700', family: "'JetBrains Mono', monospace" },
                        bodyColor: '#ffffff',
                        bodyFont: { size: 12, weight: '700', family: "'Inter', -apple-system, sans-serif" },
                        borderColor: 'rgba(99, 102, 241, 0.4)',
                        borderWidth: 1,
                        padding: { top: 8, bottom: 8, left: 12, right: 12 },
                        boxPadding: 4,
                        usePointStyle: true,
                        displayColors: true,
                        cornerRadius: 8,
                        callbacks: {
                            title: function(items) {
                                const idx = items[0].dataIndex;
                                const b = buckets[idx];
                                if (!b) return '';
                                const start = Math.max(range.minTs, b.timestamp);
                                const end = Math.min(range.maxTs, b.timestamp + bucketSec * 1000 - 1000);
                                return `${formatTimelineTime(start, true)} → ${formatTimelineTime(end, true)}`;
                            },
                            label: function(item) {
                                const idx = item.dataIndex;
                                const b = buckets[idx];
                                if (!b) return '';
                                if (item.datasetIndex === 0) {
                                    return ` Total Requests:  ${numberWithCommas(b.count)}`;
                                } else {
                                    const errs = (b.status_4xx || 0) + (b.status_5xx || 0);
                                    return ` HTTP 4xx/5xx Errors:  ${numberWithCommas(errs)}`;
                                }
                            },
                            footer: function() {
                                return '';
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        // A numeric time axis keeps every pixel on the same
                        // full-log clock as the scrubber, regardless of buckets.
                        type: 'linear',
                        min: range.minTs,
                        max: range.totalSpan ? range.maxTs : range.minTs + 1000,
                        afterBuildTicks: scale => {
                            const divisions = scale.chart.width < 600 ? 2 : 4;
                            scale.ticks = range.totalSpan
                                ? Array.from({ length: divisions + 1 }, (_, i) => ({ value: range.minTs + range.totalSpan * i / divisions }))
                                : [{ value: range.minTs }];
                        },
                        grid: { color: 'rgba(255,255,255,0.03)' },
                        ticks: {
                            color: palette.text, font: { size: 11 }, maxTicksLimit: 6,
                            callback: value => {
                                const text = formatTimelineTime(Number(value), crossesDays);
                                return crossesDays ? text.split(' ') : text;
                            }
                        },
                        title: { display: true, text: 'Time', color: palette.text, font: { size: 11 } }
                    },
                    y: {
                        grid: { color: 'rgba(255,255,255,0.03)' },
                        ticks: {
                            color: palette.text,
                            font: { size: 11 },
                            callback: function(val) {
                                return numberWithCommas(val) + ' reqs';
                            }
                        },
                        title: { display: true, text: `Requests / ${bucketLabel}`, color: palette.text, font: { size: 11 } }
                    }
                }
            }
        });

        syncScrubberTrack(rpsChart);
        updateTimelineSelection();

        // Bind In-Chart Legend Item Click Toggles
        const legTotal = document.getElementById('legend-item-total');
        if (legTotal) {
            legTotal.style.cursor = 'pointer';
            legTotal.onclick = () => {
                if (rpsChart && rpsChart.data.datasets[0]) {
                    const isHidden = !rpsChart.isDatasetVisible(0);
                    rpsChart.setDatasetVisibility(0, isHidden);
                    rpsChart.update();
                    legTotal.style.opacity = isHidden ? '1' : '0.45';
                    legTotal.style.textDecoration = isHidden ? 'none' : 'line-through';
                }
            };
        }
        const legErrors = document.getElementById('legend-item-errors');
        if (legErrors) {
            legErrors.style.cursor = 'pointer';
            legErrors.onclick = () => {
                if (rpsChart && rpsChart.data.datasets[1]) {
                    const isHidden = !rpsChart.isDatasetVisible(1);
                    rpsChart.setDatasetVisibility(1, isHidden);
                    rpsChart.update();
                    legErrors.style.opacity = isHidden ? '1' : '0.45';
                    legErrors.style.textDecoration = isHidden ? 'none' : 'line-through';
                }
            };
        }

        // Bind Resolution Buttons
        document.querySelectorAll('.rps-res-btn').forEach(btn => {
            btn.onclick = () => {
                document.querySelectorAll('.rps-res-btn').forEach(b => {
                    b.classList.remove('active');
                    b.style.borderColor = 'var(--border-color)';
                    b.style.color = 'var(--text-secondary)';
                    b.style.background = 'var(--bg-secondary)';
                });
                btn.classList.add('active');
                btn.style.borderColor = 'var(--accent-primary)';
                btn.style.color = '#fff';
                btn.style.background = 'rgba(99, 102, 241, 0.2)';

                activeRpsResolution = btn.dataset.res;
                if (currentData) {
                    // QA5: renderRequestRateChart reads the full
                    // originalEnrichedEntries itself, so no need to pre-compute
                    // request_rate from the filtered subset here.
                    renderRequestRateChart();
                }
            };
        });
    }

    function renderCharts(data) {
        const palette = chartPalette();
        // Country Chart
        const countryCtx = document.getElementById('country-chart')?.getContext('2d');
        if (countryCtx && data.country_hits) {
            if (countryChart) countryChart.destroy();
            const topCountries = data.country_hits.slice(0, 7);
            const colors = palette.colors;
            countryChart = new Chart(countryCtx, {
                type: 'doughnut',
                data: {
                    labels: topCountries.map(c => c.country),
                    datasets: [{
                        data: topCountries.map(c => c.hits),
                        backgroundColor: colors,
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    cutout: '70%'
                }
            });
            renderCountryLegend(topCountries, colors, data.total_requests);
        }

        // ASN Chart — restored classic horizontal multi-color Top-10 (origin/main style)
        const asnCtx = document.getElementById('asn-chart')?.getContext('2d');
        if (asnCtx && data.asn_hits) {
            if (asnChart) asnChart.destroy();
            const textColor = palette.text;
            const asnChartColors = [...palette.colors, ...palette.colors];
            const topASNs = data.asn_hits.slice(0, 10);
            asnChart = new Chart(asnCtx, {
                type: 'bar',
                data: {
                    labels: topASNs.map(a => {
                        const org = a.asn_org || `AS${a.asn}`;
                        const maxLabelLength = window.innerWidth <= 760 ? 16 : 25;
                        return org.length > maxLabelLength ? org.substring(0, maxLabelLength) + '...' : org;
                    }),
                    datasets: [{
                        label: 'Hits',
                        data: topASNs.map(a => a.hits),
                        backgroundColor: asnChartColors.slice(0, topASNs.length),
                        borderRadius: 6,
                        borderSkipped: false,
                    }],
                },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    indexAxis: 'y',
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { grid: { color: 'rgba(99,102,241,0.06)' }, ticks: { color: textColor } },
                        y: { grid: { display: false }, ticks: { color: textColor, font: { size: window.innerWidth <= 760 ? 9 : 11 } } },
                    },
                },
            });
        }
    }

    function renderCountryLegend(countries, colors, totalRequests) {
        const el = document.getElementById('country-chart-legend');
        if (!el) return;
        el.innerHTML = countries.map((c, i) => {
            const pct = totalRequests ? Math.round(c.hits / totalRequests * 100) : 0;
            return `
                <div class="legend-item" style="display:flex;align-items:center;gap:6px;font-size:0.75rem;margin-bottom:4px;">
                    <span style="width:8px;height:8px;border-radius:50%;background:${colors[i]};"></span>
                    <span style="color:var(--text-secondary);">${escapeHtml(c.country)}:</span>
                    <strong style="color:var(--text-primary);">${pct}%</strong>
                </div>
            `;
        }).join('');
    }

    function renderIPLogsModal(ip, pageResult) {
        const modal = document.getElementById('ip-log-modal');
        const title = document.getElementById('ip-log-modal-title');
        const body = document.getElementById('ip-log-modal-body');
        if (!modal || !body) return;
        const rows = pageResult?.rows || [];
        const totalRows = pageResult?.totalRows || rows.length;
        title.innerHTML = `<i class="bi bi-journal-text" style="margin-right:8px;"></i>Access Logs for <span class="ip-code">${escapeHtml(ip)}</span> <span style="font-size:0.8rem;color:var(--text-muted);">(${totalRows} entries)</span>`;
        body.innerHTML = `
            <div style="background:#05070a;padding:12px;border-radius:8px;font-family:var(--font-mono);font-size:0.74rem;max-height:55vh;overflow-y:auto;line-height:1.6;">
                ${rows.slice(0, 100).map((e, i) => `
                    <div style="padding:4px 0;border-bottom:1px solid rgba(255,255,255,0.03);">
                        <span style="color:var(--text-muted);margin-right:8px;">${i + 1}</span>
                        <span style="color:var(--accent-cyan);">${escapeHtml(e.method || '-')}</span>
                        <span style="color:var(--text-primary);">${escapeHtml(e.url || '-')}</span>
                        <span style="color:${(e.status_code || 0) >= 400 ? 'var(--accent-red)' : ((e.status_code || 0) > 0 ? 'var(--accent-green)' : 'var(--text-muted)')};font-weight:700;">${e.status_code && e.status_code > 0 ? e.status_code : '-'}</span>
                        <span style="color:var(--text-muted);font-size:0.7rem;">"${escapeHtml(e.user_agent || '-')}"</span>
                    </div>
                `).join('')}
                ${rows.length === 0 ? '<div style="color:var(--text-muted);">No log entries found for this IP.</div>' : ''}
            </div>
        `;
    }

    function showIPLogs(ip) {
        const modal = document.getElementById('ip-log-modal');
        const title = document.getElementById('ip-log-modal-title');
        const body = document.getElementById('ip-log-modal-body');
        if (!modal || !body) return;

        if (activeWorker) {
            title.innerHTML = `<i class="bi bi-journal-text" style="margin-right:8px;"></i>Access Logs for <span class="ip-code">${escapeHtml(ip)}</span>`;
            body.innerHTML = `<div style="padding:16px;color:var(--text-muted);font-family:var(--font-mono);font-size:0.75rem;">Loading logs for ${escapeHtml(ip)}...</div>`;
            modal.style.display = 'flex';
            activeWorker.postMessage({
                action: 'get_page',
                reqId: 'ip_logs',
                ip,
                pageNumber: 1,
                pageSize: 100,
                filters: { ipSearch: ip }
            });
            return;
        }

        const entries = originalEnrichedEntries.filter(e => e.ip === ip);
        renderIPLogsModal(ip, { rows: entries, totalRows: entries.length });
        modal.style.display = 'flex';
    }

    function formatSize(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    let sliderStartPct = 0;
    let sliderEndPct = 100;
    let customHoursVal = 1;

    function getFilterOptions(entries, data) {
        if (!entries || entries.length === 0) {
            return {
                methods: (data?.http_metrics?.method_hits || []).map(m => m.method).sort(),
                countries: (data?.country_hits || []).map(c => ({ country: c.country, count: c.hits })),
                asns: (data?.asn_hits || []).map(a => ({
                    asn: /^AS/i.test(String(a.asn)) ? String(a.asn) : 'AS' + a.asn,
                    count: a.hits,
                    label: `${/^AS/i.test(String(a.asn)) ? String(a.asn) : 'AS' + a.asn} - ${(a.asn_org || '').slice(0, 20)}`
                })),
                paths: (data?.http_metrics?.top_paths || []).slice(0, 25).map(p => ({ path: p.path, count: p.hits })),
                trafficStats: {
                    human: data?.human_requests || 0,
                    verified: data?.verified_bots_count || 0,
                    fake: data?.spoofed_bots_count || 0,
                    unverified: data?.unverified_bots_count || 0
                }
            };
        }
        const methods = new Set();
        const countries = new Map();
        const asns = new Map();
        const paths = new Map();
        let humanCount = 0;
        let verifiedBotCount = 0;
        let fakeBotCount = 0;
        let unverifiedBotCount = 0;

        entries.forEach(e => {
            if (e.method) methods.add(e.method);
            if (e.country && e.country !== 'Unknown') countries.set(e.country, (countries.get(e.country) || 0) + 1);
            // e.asn is ALREADY prefixed ('AS15169', see Analyzer.enrichLogEntries),
            // so the label must not add a second 'AS'.
            if (e.asn) {
                const rec = asns.get(e.asn) || { asn: e.asn, count: 0, label: `${e.asn} - ${(e.asn_org || '').slice(0, 20)}` };
                rec.count++;
                asns.set(e.asn, rec);
            }
            // Top Paths rows hold path SEGMENTS ('/products'), matched against
            // entry.url — there is no e.path field on a log entry.
            if (e.url) {
                const seg = (e.url.split('?')[0].match(/\/[a-zA-Z0-9_.-]+/) || [])[0];
                if (seg) paths.set(seg, (paths.get(seg) || 0) + 1);
            }
            if (e.bot_status === 'human' || (!e.is_bot && !e.bot_name)) {
                humanCount++;
            } else if (e.bot_status === 'verified') {
                verifiedBotCount++;
            } else if (e.bot_status === 'spoofed') {
                fakeBotCount++;
            } else {
                unverifiedBotCount++;
            }
        });

        const topPathsSorted = [...paths.entries()]
            .sort((a, b) => b[1] - a[1])
            .slice(0, 25)
            .map(([path, count]) => ({ path, count }));

        return {
            methods: [...methods].sort(),
            // Highest-hit country first, matching the ASN and Path dropdowns.
            countries: [...countries.entries()]
                .map(([country, count]) => ({ country, count }))
                .sort((a, b) => b.count - a.count),
            asns: [...asns.values()].sort((a, b) => b.count - a.count),
            paths: topPathsSorted,
            trafficStats: {
                human: humanCount,
                verified: verifiedBotCount,
                fake: fakeBotCount,
                unverified: unverifiedBotCount
            }
        };
    }

    function hasActiveFilters() {
        return activeFilters.statusCategory !== 'all' ||
            activeFilters.method !== 'all' ||
            activeFilters.country !== 'all' ||
            activeFilters.asn !== 'all' ||
            activeFilters.bot !== 'all' ||
            Boolean(activeFilters.pathSearch) ||
            Boolean(activeFilters.ipSearch) ||
            Boolean(activeFilters.uaSearch) ||
            activeTimeMinutes > 0 ||
            sliderStartPct > 0 ||
            sliderEndPct < 100;
    }

    function applyFilters(entries, filters, timeMinutes) {
        let result = entries;

        // Use the exact same second-aligned bounds as the handles and readout.
        if (sliderStartPct > 0 || sliderEndPct < 100) {
            const window = getSelectedTimeRange();
            if (window) {
                result = result.filter(e => {
                    const t = e.timestamp;
                    if (t == null) return false;
                    const ms = t instanceof Date ? t.getTime() : (typeof t === 'number' ? t : new Date(t).getTime());
                    return Number.isFinite(ms) && ms >= window.startMs && ms <= window.endMs;
                });
            }
        } else if (timeMinutes > 0 && maxLogTimestamp > 0) {
            const cutoff = maxLogTimestamp - (timeMinutes * 60 * 1000);
            result = result.filter(e => {
                const t = e.timestamp;
                if (!t) return true;
                const ms = t instanceof Date ? t.getTime() : (typeof t === 'number' ? t : new Date(t).getTime());
                return !isNaN(ms) && ms >= cutoff;
            });
        }

        if (filters.statusCategory !== 'all') {
            result = result.filter(e => {
                const s = e.status_code || 0;
                if (filters.statusCategory === '2xx') return s >= 200 && s < 300;
                if (filters.statusCategory === '3xx') return s >= 300 && s < 400;
                if (filters.statusCategory === '4xx') return s >= 400 && s < 500;
                if (filters.statusCategory === '5xx') return s >= 500 && s < 600;
                return true;
            });
        }

        if (filters.method !== 'all') result = result.filter(e => (e.method || '').toUpperCase() === filters.method.toUpperCase());
        if (filters.country !== 'all') result = result.filter(e => e.country === filters.country);
        // e.asn is stored prefixed ('AS15169'); the ASN table rows carry the
        // BARE number (data.asn="15169") because asn_hits is keyed on
        // GeoIP.lookupIP().asn. Normalise both before comparing.
        if (filters.asn !== 'all') {
            const want = String(filters.asn).replace(/^AS/i, '');
            result = result.filter(e => String(e.asn ?? '').replace(/^AS/i, '') === want);
        }
        
        if (filters.bot !== 'all') {
            if (filters.bot === 'human') result = result.filter(e => e.bot_status === 'human' || (!e.is_bot && !e.bot_name));
            else if (filters.bot === 'all_bots') result = result.filter(e => e.is_bot || (e.bot_group && e.bot_group !== 'Human Traffic'));
            else if (filters.bot === 'verified') result = result.filter(e => e.bot_status === 'verified');
            else if (filters.bot === 'spoofed') result = result.filter(e => e.bot_status === 'spoofed');
            else if (filters.bot === 'unverified') result = result.filter(e => e.bot_status === 'unverified' || e.bot_status === 'unverified_publisher');
            else result = result.filter(e => e.bot_group === filters.bot);
            if (filters.botGroup) result = result.filter(e => e.bot_group === filters.botGroup);
        }

        if (filters.pathSearch) {
            const term = filters.pathSearch.toLowerCase();
            result = result.filter(e => (e.url || '').toLowerCase().includes(term));
        }

        if (filters.ipSearch) {
            const term = filters.ipSearch.trim().toLowerCase();
            if (term.includes('/')) {
                // CIDR Subnet Match (e.g. 185.220.0.0/16)
                result = result.filter(e => {
                    if (!e.ip) return false;
                    try {
                        const [subIp, maskStr] = term.split('/');
                        const maskBits = parseInt(maskStr, 10);
                        if (isNaN(maskBits) || maskBits < 0 || maskBits > 32) return (e.ip || '').toLowerCase().includes(subIp);
                        const ipToInt = s => s.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
                        const targetInt = ipToInt(e.ip);
                        const subnetInt = ipToInt(subIp);
                        const mask = maskBits === 0 ? 0 : (~0 << (32 - maskBits)) >>> 0;
                        return (targetInt & mask) === (subnetInt & mask);
                    } catch {
                        return (e.ip || '').toLowerCase().includes(term);
                    }
                });
            } else {
                result = result.filter(e => (e.ip || '').toLowerCase().includes(term));
            }
        }

        if (filters.uaSearch) {
            const term = filters.uaSearch.toLowerCase();
            result = result.filter(e => (e.user_agent || '').toLowerCase().includes(term));
        }

        return result;
    }

    function getGlobalTimeRange() {
        if (originalTimeRange) return originalTimeRange;
        const parsedMin = originalParseResult?.minTimestamp || (latestSummary?.minTimeSec ? latestSummary.minTimeSec * 1000 : null);
        const parsedMax = originalParseResult?.maxTimestamp || (latestSummary?.maxTimeSec ? latestSummary.maxTimeSec * 1000 : null);
        if (Number.isFinite(parsedMin) && Number.isFinite(parsedMax) && parsedMax >= parsedMin) {
            originalTimeRange = { minTs: parsedMin, maxTs: parsedMax, totalSpan: parsedMax - parsedMin };
            return originalTimeRange;
        }
        if (!originalEnrichedEntries || originalEnrichedEntries.length === 0) return null;
        let minTs = Infinity;
        let maxTs = -Infinity;
        for (let i = 0; i < originalEnrichedEntries.length; i++) {
            const t = originalEnrichedEntries[i].timestamp;
            if (t == null) continue;
            const ms = t instanceof Date ? t.getTime() : (typeof t === 'number' ? t : new Date(t).getTime());
            if (!isNaN(ms)) {
                if (ms < minTs) minTs = ms;
                if (ms > maxTs) maxTs = ms;
            }
        }
        if (minTs === Infinity || maxTs === -Infinity) return null;
        originalTimeRange = { minTs, maxTs, totalSpan: maxTs - minTs };
        return originalTimeRange;
    }

    function formatDuration(ms, isTotal = false) {
        const seconds = Math.max(0, Math.round(ms / 1000));
        const hours = Math.floor(seconds / 3600);
        const mins = Math.floor(seconds / 60) % 60;
        const secs = seconds % 60;
        const text = [hours ? `${hours}h` : '', mins ? `${mins}m` : '', secs || !seconds ? `${secs}s` : ''].filter(Boolean).join(' ');
        return isTotal ? `${text} total` : text;
    }

    function getSelectedTimeRange(startPct = sliderStartPct, endPct = sliderEndPct) {
        const range = getGlobalTimeRange();
        if (!range) return null;
        const timestampAt = pct => Math.max(range.minTs, Math.min(range.maxTs,
            Math.round((range.minTs + range.totalSpan * pct / 100) / 1000) * 1000));
        return { startMs: timestampAt(startPct), endMs: timestampAt(endPct) };
    }

    function formatTimelineTime(ms, includeDate = false) {
        const iso = new Date(ms).toISOString();
        return includeDate ? `${iso.slice(0, 10)} ${iso.slice(11, 19)}` : iso.slice(11, 19);
    }

    function getTimeWindowHtml(startPct, endPct, activeMins) {
        const window = getSelectedTimeRange(startPct, endPct);
        if (!window) return '<span>No timestamped log entries</span>';
        const { startMs, endMs } = window;
        const range = getGlobalTimeRange();
        const includeDate = new Date(range.minTs).toISOString().slice(0, 10) !== new Date(range.maxTs).toISOString().slice(0, 10);
        const prefix = startPct <= 0 && endPct >= 100 ? 'All time · ' : activeMins > 0 ? 'Last ' : '';
        return `<span class="timeline-range-times"><time datetime="${new Date(startMs).toISOString()}">${formatTimelineTime(startMs, includeDate)}</time> → <time datetime="${new Date(endMs).toISOString()}">${formatTimelineTime(endMs, includeDate)}</time></span><span class="time-span-pill">${prefix}${formatDuration(endMs - startMs)}</span>`;
    }

    function positionTimeReadout() {
        const readout = document.getElementById('time-window-readout');
        const track = document.getElementById('slider-scrubber-track');
        if (!readout || !track || !track.clientWidth) return;
        const half = Math.min(50, readout.offsetWidth / 2 / track.clientWidth * 100);
        const mid = (sliderStartPct + sliderEndPct) / 2;
        readout.style.left = `${Math.max(half, Math.min(100 - half, mid))}%`;
    }

    function updateTimelineSelection() {
        const window = getSelectedTimeRange();
        const range = getGlobalTimeRange();
        const track = document.getElementById('slider-scrubber-track');
        if (track) track.classList.toggle('timeline-handles-close', track.clientWidth * (sliderEndPct - sliderStartPct) / 100 < 26);
        const left = document.getElementById('slider-curtain-left');
        const right = document.getElementById('slider-curtain-right');
        const active = document.getElementById('slider-active-window');
        if (left) left.style.width = `${sliderStartPct}%`;
        if (right) right.style.width = `${100 - sliderEndPct}%`;
        if (active) {
            active.style.left = `${sliderStartPct}%`;
            active.style.width = `${sliderEndPct - sliderStartPct}%`;
        }
        for (const side of ['start', 'end']) {
            const handle = document.getElementById(`handle-${side}`);
            if (!handle) continue;
            handle.style.left = `calc(${side === 'start' ? sliderStartPct : sliderEndPct}% - 10px)`;
            handle.setAttribute('aria-disabled', String(!range || !range.totalSpan));
            if (!window) continue;
            const ms = side === 'start' ? window.startMs : window.endMs;
            const label = formatTimelineTime(ms, true);
            handle.setAttribute('aria-valuemin', String(range.minTs));
            handle.setAttribute('aria-valuemax', String(range.maxTs));
            handle.setAttribute('aria-valuenow', String(ms));
            handle.setAttribute('aria-valuetext', label);
            handle.title = `${side === 'start' ? 'Start' : 'End'}: ${label}`;
            const time = handle.querySelector('time');
            time.dateTime = new Date(ms).toISOString();
            time.textContent = formatTimelineTime(ms);
        }
        const readout = document.getElementById('time-window-readout');
        if (readout) readout.innerHTML = getTimeWindowHtml(sliderStartPct, sliderEndPct, activeTimeMinutes);
        positionTimeReadout();
    }

    function renderLogExplorerCardHtml() {
        const totalCount = latestPageResult ? latestPageResult.totalRows : (latestSummary ? latestSummary.matchingCount : currentFilteredEntries.length);
        return `
            <div class="log-explorer-card" id="nginx-log-explorer" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;overflow:hidden;margin-bottom:20px;">
                <div class="log-explorer-header" style="padding:12px 18px;border-bottom:1px solid var(--border-color);display:flex;justify-content:space-between;align-items:center;">
                    <h5 style="margin:0;font-size:0.88rem;font-weight:700;">
                        <i class="bi bi-table" style="color:var(--accent-primary);margin-right:6px;"></i> Log Explorer
                        <span id="explorer-total-count" style="font-size:0.74rem;color:var(--text-muted);margin-left:6px;">(${numberWithCommas(totalCount)} entries)</span>
                    </h5>
                    <div style="font-size:0.75rem;color:var(--text-muted);">
                        Per page:
                        <select id="explorer-per-page" style="background:var(--bg-secondary);border:1px solid var(--border-color);color:var(--text-primary);padding:2px 6px;border-radius:4px;font-size:0.75rem;">
                            <option value="10" ${explorerPerPage === 10 ? 'selected' : ''}>10</option>
                            <option value="25" ${explorerPerPage === 25 ? 'selected' : ''}>25</option>
                            <option value="50" ${explorerPerPage === 50 ? 'selected' : ''}>50</option>
                            <option value="100" ${explorerPerPage === 100 ? 'selected' : ''}>100</option>
                        </select>
                    </div>
                </div>
                <div class="log-explorer-table-wrap" style="overflow-x:auto;">
                    <table class="log-explorer-table" style="width:100%;border-collapse:collapse;font-size:0.78rem;">
                        <thead>
                            <tr style="background:rgba(0,0,0,0.25);border-bottom:1px solid var(--border-color);">
                                <th style="padding:8px 12px;text-align:left;">Time</th>
                                <th style="padding:8px 12px;text-align:left;">IP Address</th>
                                <th style="padding:8px 12px;text-align:left;">Method</th>
                                <th style="padding:8px 12px;text-align:left;">Path</th>
                                <th style="padding:8px 12px;text-align:left;">Status</th>
                                <th style="padding:8px 12px;text-align:left;">Country</th>
                                <th style="padding:8px 12px;text-align:left;">User-Agent</th>
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

    function renderExplorerRowsAndPagination(pageResult) {
        const body = document.getElementById('explorer-rows-body');
        const pagWrap = document.getElementById('explorer-pagination-wrap');
        const countSpan = document.getElementById('explorer-total-count');
        if (!body) return;

        const rows = pageResult?.rows || [];
        const totalRows = pageResult?.totalRows || 0;
        const totalPages = pageResult?.totalPages || (Math.ceil(totalRows / (pageResult?.pageSize || explorerPerPage)) || 1);
        const currentPage = pageResult?.page || 1;

        if (countSpan) {
            countSpan.textContent = `(${numberWithCommas(totalRows)} entries)`;
        }

        if (rows.length === 0) {
            body.innerHTML = `<tr><td colspan="8" style="padding:24px;text-align:center;color:var(--text-muted);">No log entries match the current filters.</td></tr>`;
        } else {
            body.innerHTML = rows.map(e => `
                <tr style="border-bottom:1px solid rgba(255,255,255,0.03);">
                    <td style="padding:7px 12px;color:var(--text-muted);font-size:0.74rem;">${e.timestamp && e.timestamp !== '-' ? formatTimelineTime(new Date(e.timestamp).getTime(), true) : '-'}</td>
                    <td style="padding:7px 12px;"><span class="ip-code">${escapeHtml(e.ip)}</span></td>
                    <td style="padding:7px 12px;"><strong>${escapeHtml(e.method || '-')}</strong></td>
                    <td style="padding:7px 12px;"><code>${escapeHtml((e.url || '-').slice(0, 40))}</code></td>
                    <td style="padding:7px 12px;"><span style="color:${(e.status_code || 0) >= 400 ? 'var(--accent-red)' : ((e.status_code || 0) > 0 ? 'var(--accent-green)' : 'var(--text-muted)')};font-weight:700;">${e.status_code && e.status_code > 0 ? e.status_code : '-'}</span></td>
                    <td style="padding:7px 12px;"><span class="country-flag">${e.country_code || ''}</span> ${escapeHtml(e.country || 'Unknown')}</td>
                    <td style="padding:7px 12px;color:var(--text-muted);font-size:0.74rem;">${escapeHtml(e.http_version || e.protocol || 'HTTP/1.1')}</td>
                    <td style="padding:7px 12px;color:var(--text-muted);font-size:0.72rem;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(e.user_agent || '-')}</td>
                </tr>
            `).join('');
        }

        if (pagWrap) {
            let startPage = Math.max(1, currentPage - 2);
            let endPage = Math.min(totalPages, startPage + 4);
            if (endPage - startPage < 4) {
                startPage = Math.max(1, endPage - 4);
            }
            let pageBtnsHtml = '';
            for (let p = startPage; p <= endPage; p++) {
                const isActive = p === currentPage;
                pageBtnsHtml += `<button class="exp-page-btn" data-page="${p}" style="background:${isActive ? 'var(--accent-primary)' : 'var(--bg-secondary)'};border:1px solid ${isActive ? 'var(--accent-primary)' : 'var(--border-color)'};color:${isActive ? '#fff' : 'var(--text-secondary)'};padding:3px 8px;border-radius:4px;font-size:0.74rem;cursor:pointer;font-weight:${isActive ? '700' : '400'};">${p}</button>`;
            }

            pagWrap.innerHTML = `
                <span style="font-size:0.75rem;color:var(--text-muted);">Page ${currentPage} of ${totalPages} (${numberWithCommas(totalRows)} entries)</span>
                <div style="display:flex;gap:4px;align-items:center;">
                    <button id="exp-first-btn" style="background:var(--bg-secondary);border:1px solid var(--border-color);color:var(--text-secondary);padding:3px 8px;border-radius:4px;font-size:0.74rem;cursor:pointer;" ${currentPage <= 1 ? 'disabled' : ''}>« First</button>
                    <button id="exp-prev-btn" style="background:var(--bg-secondary);border:1px solid var(--border-color);color:var(--text-secondary);padding:3px 8px;border-radius:4px;font-size:0.74rem;cursor:pointer;" ${currentPage <= 1 ? 'disabled' : ''}>‹ Prev</button>
                    ${pageBtnsHtml}
                    <button id="exp-next-btn" style="background:var(--bg-secondary);border:1px solid var(--border-color);color:var(--text-secondary);padding:3px 8px;border-radius:4px;font-size:0.74rem;cursor:pointer;" ${currentPage >= totalPages ? 'disabled' : ''}>Next ›</button>
                    <button id="exp-last-btn" style="background:var(--bg-secondary);border:1px solid var(--border-color);color:var(--text-secondary);padding:3px 8px;border-radius:4px;font-size:0.74rem;cursor:pointer;" ${currentPage >= totalPages ? 'disabled' : ''}>Last »</button>
                </div>
            `;

            document.getElementById('exp-first-btn')?.addEventListener('click', () => {
                if (currentPage > 1) requestExplorerPage(1);
            });
            document.getElementById('exp-prev-btn')?.addEventListener('click', () => {
                if (currentPage > 1) requestExplorerPage(currentPage - 1);
            });
            document.getElementById('exp-next-btn')?.addEventListener('click', () => {
                if (currentPage < totalPages) requestExplorerPage(currentPage + 1);
            });
            document.getElementById('exp-last-btn')?.addEventListener('click', () => {
                if (currentPage < totalPages) requestExplorerPage(totalPages);
            });
            pagWrap.querySelectorAll('.exp-page-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    const targetPage = parseInt(btn.dataset.page, 10);
                    if (targetPage && targetPage !== currentPage) {
                        requestExplorerPage(targetPage);
                    }
                });
            });
        }
    }

    function requestExplorerPage(pageNumber) {
        explorerPage = pageNumber;
        if (activeWorker) {
            const workerFilters = Object.assign({}, activeFilters);
            if (sliderStartPct > 0 || sliderEndPct < 100) {
                const window = getSelectedTimeRange();
                if (window) {
                    workerFilters.startTimeSec = Math.floor(window.startMs / 1000);
                    workerFilters.endTimeSec = Math.floor(window.endMs / 1000);
                }
            } else if (activeTimeMinutes > 0 && maxLogTimestamp > 0) {
                workerFilters.startTimeSec = Math.floor((maxLogTimestamp - activeTimeMinutes * 60 * 1000) / 1000);
            }
            activeWorker.postMessage({
                action: 'get_page',
                pageNumber: explorerPage,
                pageSize: explorerPerPage,
                filters: workerFilters
            });
            return;
        }
        updateExplorerView();
    }

    function updateExplorerView() {
        if (activeWorker && latestPageResult) {
            if (latestPageResult.page === explorerPage && latestPageResult.pageSize === explorerPerPage) {
                renderExplorerRowsAndPagination(latestPageResult);
                return;
            }
            requestExplorerPage(explorerPage);
            return;
        }
        const startIdx = (explorerPage - 1) * explorerPerPage;
        const pageEntries = currentFilteredEntries.slice(startIdx, startIdx + explorerPerPage);
        const totalRows = currentFilteredEntries.length;
        const totalPages = Math.ceil(totalRows / explorerPerPage) || 1;
        renderExplorerRowsAndPagination({
            page: explorerPage,
            pageSize: explorerPerPage,
            totalPages,
            totalRows,
            rows: pageEntries
        });
    }

    function bindExplorerTableEvents() {
        document.getElementById('explorer-per-page')?.addEventListener('change', (e) => {
            explorerPerPage = parseInt(e.target.value, 10) || 25;
            explorerPage = 1;
            requestExplorerPage(1);
        });
    }

    function bindFilterEvents() {
        // Filters replace the dashboard DOM. Retire the old global drag
        // listeners before attaching handlers to the new handles.
        timelineDragEvents?.abort();
        timelineDragEvents = new AbortController();
        ['filter-method', 'filter-country', 'filter-asn', 'filter-bot', 'filter-path-select'].forEach(id => {
            document.getElementById(id)?.addEventListener('change', (e) => {
                const val = e.target.value;
                if (id === 'filter-method') activeFilters.method = val;
                else if (id === 'filter-country') activeFilters.country = val;
                else if (id === 'filter-asn') activeFilters.asn = val;
                else if (id === 'filter-bot') { activeFilters.bot = val; activeFilters.botGroup = ''; }
                else if (id === 'filter-path-select') {
                    activeFilters.pathSearch = (val === 'all') ? '' : val;
                    const pathInput = document.getElementById('filter-path');
                    if (pathInput) pathInput.value = activeFilters.pathSearch;
                }
                applyAndRenderFilters();
            });
        });

        // Search text inputs
        ['filter-ip', 'filter-path'].forEach(id => {
            const el = document.getElementById(id);
            if (el) {
                el.addEventListener('input', (e) => {
                    if (id === 'filter-ip') activeFilters.ipSearch = e.target.value;
                    if (id === 'filter-path') activeFilters.pathSearch = e.target.value;
                    if (_filterDebounceTimer) clearTimeout(_filterDebounceTimer);
                    _filterDebounceTimer = setTimeout(() => applyAndRenderFilters(), 150);
                });
            }
        });

        // Clear All Filters
        document.getElementById('filter-clear-btn')?.addEventListener('click', () => {
            activeFilters = {
                statusCategory: 'all',
                method: 'all',
                country: 'all',
                asn: 'all',
                bot: 'all',
                ipSearch: '',
                pathSearch: '',
                uaSearch: ''
            };
            activeTimeMinutes = 0;
            sliderStartPct = 0;
            sliderEndPct = 100;
            applyAndRenderFilters();
        });

        // Preset Time Buttons (30m, 1h, 2h)
        document.querySelectorAll('.shortcut-btn[data-mins]').forEach(btn => {
            btn.addEventListener('click', () => {
                activeTimeMinutes = parseInt(btn.dataset.mins, 10);
                const range = getGlobalTimeRange();
                if (range && range.totalSpan > 0) {
                    const totalMins = range.totalSpan / 60000;
                    const spanRatio = Math.min(1, activeTimeMinutes / totalMins);
                    sliderEndPct = 100;
                    sliderStartPct = Math.max(0, 100 - (spanRatio * 100));
                } else {
                    sliderStartPct = 0;
                    sliderEndPct = 100;
                }
                applyAndRenderFilters();
            });
        });

        // All Time Button
        document.getElementById('btn-all-time')?.addEventListener('click', () => {
            activeTimeMinutes = 0;
            sliderStartPct = 0;
            sliderEndPct = 100;
            applyAndRenderFilters();
        });

        // Custom Hours Stepper (- / +) with max hours boundary derived from log span
        const maxLogHours = Math.max(1, Math.ceil((originalParseResult?.logSpanMinutes || 120) / 60));

        document.getElementById('stepper-minus')?.addEventListener('click', () => {
            if (customHoursVal > 1) {
                customHoursVal--;
                const valEl = document.getElementById('stepper-val');
                if (valEl) valEl.value = String(customHoursVal);
                activeTimeMinutes = customHoursVal * 60;
                const range = getGlobalTimeRange();
                if (range && range.totalSpan > 0) {
                    const totalMins = range.totalSpan / 60000;
                    const spanRatio = Math.min(1, activeTimeMinutes / totalMins);
                    sliderEndPct = 100;
                    sliderStartPct = Math.max(0, 100 - (spanRatio * 100));
                }
                applyAndRenderFilters();
            }
        });

        document.getElementById('stepper-plus')?.addEventListener('click', () => {
            if (customHoursVal < maxLogHours) {
                customHoursVal++;
                const valEl = document.getElementById('stepper-val');
                if (valEl) valEl.value = String(customHoursVal);
                activeTimeMinutes = customHoursVal * 60;
                const range = getGlobalTimeRange();
                if (range && range.totalSpan > 0) {
                    const totalMins = range.totalSpan / 60000;
                    const spanRatio = Math.min(1, activeTimeMinutes / totalMins);
                    sliderEndPct = 100;
                    sliderStartPct = Math.max(0, 100 - (spanRatio * 100));
                }
                applyAndRenderFilters();
            }
        });

        // Direct typed input on stepper box with bounds clamping
        document.getElementById('stepper-val')?.addEventListener('change', (e) => {
            const raw = parseInt(e.target.value.replace(/[^0-9]/g, ''), 10);
            if (!isNaN(raw) && raw >= 1) {
                customHoursVal = Math.min(raw, maxLogHours);
            } else {
                customHoursVal = 1;
            }
            e.target.value = String(customHoursVal);
            activeTimeMinutes = customHoursVal * 60;
            const range = getGlobalTimeRange();
            if (range && range.totalSpan > 0) {
                const totalMins = range.totalSpan / 60000;
                const spanRatio = Math.min(1, activeTimeMinutes / totalMins);
                sliderEndPct = 100;
                sliderStartPct = Math.max(0, 100 - (spanRatio * 100));
            }
            applyAndRenderFilters();
        });

        // Timeline Slider Handles Dragging (Design 2: In-Chart Overlay)
        const scrubberTrack = document.getElementById('slider-scrubber-track');
        const handleStart = document.getElementById('handle-start');
        const handleEnd = document.getElementById('handle-end');
        const activeWindow = document.getElementById('slider-active-window');
        let isDragging = null;
        let dragWindowStartPct = 0;
        let dragWindowEndPct = 100;
        let dragMouseStartX = 0;
        let pointerId = null;
        let grabOffset = 0;
        const range = getGlobalTimeRange();
        const minimumGap = range?.totalSpan ? Math.min(100, 100000 / range.totalSpan) : 0;

        if (scrubberTrack && handleStart && handleEnd) {
            const listenerOptions = { signal: timelineDragEvents.signal };
            function updateSliderPos(e) {
                const rect = scrubberTrack.getBoundingClientRect();
                if (!rect.width) return;
                const clientX = e.clientX;
                const posPct = Math.max(0, Math.min(100, ((clientX - grabOffset - rect.left) / rect.width) * 100));

                if (isDragging === 'start') {
                    sliderStartPct = Math.max(0, Math.min(posPct, sliderEndPct - minimumGap));
                } else if (isDragging === 'end') {
                    sliderEndPct = Math.min(100, Math.max(posPct, sliderStartPct + minimumGap));
                } else if (isDragging === 'window') {
                    const deltaX = clientX - dragMouseStartX;
                    const deltaPct = (deltaX / rect.width) * 100;
                    const winWidth = dragWindowEndPct - dragWindowStartPct;

                    let newStart = dragWindowStartPct + deltaPct;
                    let newEnd = dragWindowEndPct + deltaPct;

                    if (newStart < 0) {
                        newStart = 0;
                        newEnd = winWidth;
                    }
                    if (newEnd > 100) {
                        newEnd = 100;
                        newStart = 100 - winWidth;
                    }
                    sliderStartPct = Math.max(0, newStart);
                    sliderEndPct = Math.min(100, newEnd);
                }

                updateTimelineSelection();
            }

            const beginDrag = (side, e) => {
                if (e.button !== 0 || pointerId !== null || !range?.totalSpan) return;
                e.preventDefault();
                e.stopPropagation();
                isDragging = side;
                pointerId = e.pointerId;
                activeTimeMinutes = 0;
                dragMouseStartX = e.clientX;
                dragWindowStartPct = sliderStartPct;
                dragWindowEndPct = sliderEndPct;
                const rect = scrubberTrack.getBoundingClientRect();
                grabOffset = side === 'window' ? 0 : e.clientX - rect.left - rect.width * (side === 'start' ? sliderStartPct : sliderEndPct) / 100;
                e.currentTarget.classList.add('dragging');
                e.currentTarget.setPointerCapture(e.pointerId);
            };

            handleStart.addEventListener('pointerdown', e => beginDrag('start', e), listenerOptions);
            handleEnd.addEventListener('pointerdown', e => beginDrag('end', e), listenerOptions);
            activeWindow?.addEventListener('pointerdown', e => beginDrag('window', e), listenerOptions);
            window.addEventListener('pointermove', e => {
                if (e.pointerId === pointerId) {
                    e.preventDefault();
                    updateSliderPos(e);
                }
            }, listenerOptions);

            const onUp = e => {
                if (e.pointerId === pointerId) {
                    if (e.type !== 'pointercancel') updateSliderPos(e);
                    handleStart.classList.remove('dragging');
                    handleEnd.classList.remove('dragging');
                    activeWindow?.classList.remove('dragging');
                    isDragging = null;
                    pointerId = null;
                    applyAndRenderFilters();
                }
            };

            window.addEventListener('pointerup', onUp, listenerOptions);
            window.addEventListener('pointercancel', onUp, listenerOptions);
            for (const side of ['start', 'end']) {
                const handle = side === 'start' ? handleStart : handleEnd;
                handle.addEventListener('keydown', e => {
                    if (!range?.totalSpan || !['ArrowLeft', 'ArrowRight', 'ArrowDown', 'ArrowUp', 'Home', 'End'].includes(e.key)) return;
                    e.preventDefault();
                    const step = (e.shiftKey ? 60000 : 1000) / range.totalSpan * 100;
                    const current = side === 'start' ? sliderStartPct : sliderEndPct;
                    const next = e.key === 'Home' ? 0 : e.key === 'End' ? 100 : current + (['ArrowLeft', 'ArrowDown'].includes(e.key) ? -step : step);
                    if (side === 'start') sliderStartPct = Math.max(0, Math.min(next, sliderEndPct - minimumGap));
                    else sliderEndPct = Math.min(100, Math.max(next, sliderStartPct + minimumGap));
                    activeTimeMinutes = 0;
                    applyAndRenderFilters();
                    document.getElementById(`handle-${side}`)?.focus();
                }, listenerOptions);
            }
        }
    }

    function sortExplorerEntries() {
        currentFilteredEntries.sort((a, b) => {
            let valA = a[explorerSortField];
            let valB = b[explorerSortField];
            if (explorerSortField === 'timestamp') {
                valA = valA instanceof Date ? valA.getTime() : new Date(valA).getTime() || 0;
                valB = valB instanceof Date ? valB.getTime() : new Date(valB).getTime() || 0;
            }
            if (valA < valB) return explorerSortDir === 'asc' ? -1 : 1;
            if (valA > valB) return explorerSortDir === 'asc' ? 1 : -1;
            return 0;
        });
    }

    function applyAndRenderFilters() {
        if (activeWorker) {
            explorerPage = 1;
            const workerFilters = Object.assign({}, activeFilters);
            if (sliderStartPct > 0 || sliderEndPct < 100) {
                const window = getSelectedTimeRange();
                if (window) {
                    workerFilters.startTimeSec = Math.floor(window.startMs / 1000);
                    workerFilters.endTimeSec = Math.floor(window.endMs / 1000);
                }
            } else if (activeTimeMinutes > 0 && maxLogTimestamp > 0) {
                workerFilters.startTimeSec = Math.floor((maxLogTimestamp - activeTimeMinutes * 60 * 1000) / 1000);
            }
            activeWorker.postMessage({
                action: 'filter',
                filters: workerFilters
            });
            return;
        }
        currentFilteredEntries = applyFilters(originalEnrichedEntries, activeFilters, activeTimeMinutes);
        sortExplorerEntries();
        explorerPage = 1;

        const newData = Analyzer.analyzeEnhancedLogs(currentFilteredEntries);
        render(newData, currentLogText, originalParseResult, { preserveFilters: true });
    }

    
    function getActiveFilterCount() {
        let count = 0;
        if (activeFilters.method && activeFilters.method !== 'all') count++;
        if (activeFilters.country && activeFilters.country !== 'all') count++;
        if (activeFilters.pathSearch) count++;
        if (activeFilters.asn && activeFilters.asn !== 'all') count++;
        if (activeFilters.bot && activeFilters.bot !== 'all') count++;
        if (activeFilters.ipSearch) count++;
        if (sliderStartPct > 0 || sliderEndPct < 100) count++;
        return count;
    }

    let scannedAbuseData = new Map(); // ip -> { abuse_score, total_reports, country_code }
    let isScanningAbuse = false;

    async function scanTop10AbuseIPs(topIps) {
        if (isScanningAbuse || !topIps || topIps.length === 0) return;
        isScanningAbuse = true;
        const btn = document.getElementById('btn-scan-abuseipdb');
        if (btn) btn.innerHTML = '<i class="bi bi-hourglass-split"></i> Scanning...';

        try {
            const targets = topIps.slice(0, 10).map(i => ({ ip: i.ip, hits: i.hits }));
            const resp = await fetch('/api/abuse', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ips: targets, max: 10 })
            });

            if (resp.ok) {
                const json = await resp.json();
                const allResults = [...(json.abusive || []), ...(json.non_abusive || [])];
                allResults.forEach(r => {
                    scannedAbuseData.set(r.ip, {
                        abuse_score: r.abuse_score || 0,
                        total_reports: r.total_reports || 0,
                        country_code: r.country_code || '--',
                        domain: r.domain || 'N/A'
                    });
                });
                renderAbuseTableBody(topIps);
            }
        } catch (err) {
            console.error('AbuseIPDB scan error:', err);
        } finally {
            isScanningAbuse = false;
            const btnAfter = document.getElementById('btn-scan-abuseipdb');
            if (btnAfter) btnAfter.innerHTML = '<i class="bi bi-check-all"></i> Scanned';
        }
    }

    function renderAbuseTableBody(topIps) {
        const body = document.getElementById('abuse-table-rows');
        if (!body) return;
        const ips = (topIps || []).slice(0, 10);
        if (ips.length === 0) {
            body.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-muted);padding:10px;">No attacking IPs</td></tr>';
            return;
        }

        body.innerHTML = ips.map(item => {
            const scan = scannedAbuseData.get(item.ip);
            let scoreBadge = '<span style="font-size:0.72rem;color:var(--text-muted);">Unchecked</span>';
            let domainText = '-';
            let countryTag = '-';

            if (scan) {
                const s = scan.abuse_score;
                if (s >= 80) scoreBadge = `<span style="background:rgba(244,63,94,0.15);color:#fb7185;padding:2px 8px;border-radius:4px;font-weight:700;">${s}% Bad</span>`;
                else if (s >= 25) scoreBadge = `<span style="background:rgba(245,158,11,0.15);color:#fbbf24;padding:2px 8px;border-radius:4px;font-weight:700;">${s}% Susp.</span>`;
                else scoreBadge = `<span style="background:rgba(16,185,129,0.15);color:#34d399;padding:2px 8px;border-radius:4px;font-weight:700;">${s}% Clean</span>`;
                domainText = escapeHtml(scan.domain || 'N/A');
                countryTag = scan.country_code;
            }

            return `
            <tr>
                <td><span class="ip-code">${escapeHtml(item.ip)}</span></td>
                <td>${scoreBadge}</td>
                <td style="font-size:0.72rem;color:var(--text-muted);">${domainText}</td>
                <td style="font-size:0.72rem;text-align:right;">${countryTag}</td>
            </tr>
            `;
        }).join('');
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
                        <span class="pill pill-amber" style="font-size:0.7rem;">${(data.http_metrics?.top_paths || []).length} Paths</span>
                    </div>
                    <div style="max-height:260px;overflow-y:auto;">
                        <table class="table-clean" style="width:100%;border-collapse:collapse;font-size:0.76rem;">
                            <thead>
                                <tr style="border-bottom:1px solid var(--border-color);">
                                    <th style="padding:6px 8px;text-align:left;color:var(--text-muted);">Endpoint Path</th>
                                    <th style="padding:6px 8px;text-align:right;color:var(--text-muted);">Hits</th>
                                    <th style="padding:6px 8px;text-align:right;color:var(--text-muted);">Share</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${(data.http_metrics?.top_paths || []).slice(0, 15).map(p => `
                                    <tr class="cross-filter-path-row" data-path="${escapeHtml(p.path)}" style="border-bottom:1px solid rgba(255,255,255,0.03);cursor:pointer;">
                                        <td style="padding:6px 8px;"><code style="font-size:0.74rem;color:var(--accent-cyan);">${escapeHtml(p.path)}</code></td>
                                        <td style="padding:6px 8px;text-align:right;font-weight:700;">${numberWithCommas(p.count)}</td>
                                        <td style="padding:6px 8px;text-align:right;color:var(--text-muted);">${p.percentage}%</td>
                                    </tr>
                                `).join('')}
                                ${(!data.http_metrics?.top_paths || data.http_metrics.top_paths.length === 0) ? '<tr><td colspan="3" style="text-align:center;color:var(--text-muted);padding:10px;">No path data</td></tr>' : ''}
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Card 2.2: Top Abusive IPs (AbuseIPDB Integration) -->
                <div class="card-table-wrap" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:16px;position:relative;">
                    <div class="table-header" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                        <span style="font-weight:700;font-size:0.86rem;"><i class="bi bi-radioactive" style="color:var(--accent-red);margin-right:6px;"></i>4. Abusive IPs (AbuseIPDB)</span>
                        <button id="btn-scan-abuseipdb" class="btn btn-rose" style="padding:2px 8px;font-size:0.7rem;display:none;">
                            <i class="bi bi-search"></i> Scan Top 10
                        </button>
                    </div>
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
                        <span class="pill pill-muted" style="font-size:0.7rem;">${(data.referrers || []).length} Sites</span>
                    </div>
                    <div style="max-height:260px;overflow-y:auto;">
                        <table class="table-clean" style="width:100%;border-collapse:collapse;font-size:0.76rem;">
                            <thead>
                                <tr style="border-bottom:1px solid var(--border-color);">
                                    <th style="padding:6px 8px;text-align:left;color:var(--text-muted);">Referrer URL</th>
                                    <th style="padding:6px 8px;text-align:right;color:var(--text-muted);">Hits</th>
                                    <th style="padding:6px 8px;text-align:right;color:var(--text-muted);">Share</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${(data.referrers || []).slice(0, 15).map(r => `
                                    <tr style="border-bottom:1px solid rgba(255,255,255,0.03);">
                                        <td style="padding:6px 8px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><code>${escapeHtml(r.referrer)}</code></td>
                                        <td style="padding:6px 8px;text-align:right;font-weight:700;">${numberWithCommas(r.hits)}</td>
                                        <td style="padding:6px 8px;text-align:right;color:var(--text-muted);">${r.pct}%</td>
                                    </tr>
                                `).join('')}
                                ${(!data.referrers || data.referrers.length === 0) ? '<tr><td colspan="3" style="text-align:center;color:var(--text-muted);padding:10px;">Direct traffic only</td></tr>' : ''}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
        `;
    }

    let logTableSubnetSearch = '';
    let logTablePathSearch = '';

    function renderLogExplorerCardHtml() {
        return `
            <div class="log-explorer-card" id="nginx-log-explorer" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;overflow:hidden;margin-bottom:20px;">
                <div class="log-explorer-header" style="padding:12px 18px;border-bottom:1px solid var(--border-color);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;background:rgba(0,0,0,0.2);">
                    <div style="display:flex;align-items:center;gap:8px;">
                        <h5 style="margin:0;font-size:0.88rem;font-weight:700;">
                            <i class="bi bi-table" style="color:var(--accent-primary);margin-right:6px;"></i> Log Explorer
                        </h5>
                        <span style="font-size:0.74rem;color:var(--text-muted);">(${numberWithCommas(currentFilteredEntries.length)} entries)</span>
                    </div>

                    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                        <input type="text" id="log-table-ip-subnet-search" placeholder="🔍 Filter IP / CIDR Subnet..." value="${escapeHtml(logTableSubnetSearch)}" style="background:rgba(0,0,0,0.3);border:1px solid var(--border-color);color:var(--text-primary);padding:5px 12px;border-radius:6px;font-size:0.75rem;min-width:210px;outline:none;" />
                        <input type="text" id="log-table-path-search" placeholder="🔍 Filter Path / URI Keyword..." value="${escapeHtml(logTablePathSearch)}" style="background:rgba(0,0,0,0.3);border:1px solid var(--border-color);color:var(--text-primary);padding:5px 12px;border-radius:6px;font-size:0.75rem;min-width:210px;outline:none;" />
                        
                        <div style="font-size:0.75rem;color:var(--text-muted);display:flex;align-items:center;gap:6px;">
                            Per page: 
                            <select id="explorer-per-page" style="background:var(--bg-secondary);border:1px solid var(--border-color);color:var(--text-primary);padding:3px 6px;border-radius:4px;font-size:0.75rem;">
                                <option value="10" ${explorerPerPage === 10 ? 'selected' : ''}>10</option>
                                <option value="25" ${explorerPerPage === 25 ? 'selected' : ''}>25</option>
                                <option value="50" ${explorerPerPage === 50 ? 'selected' : ''}>50</option>
                                <option value="100" ${explorerPerPage === 100 ? 'selected' : ''}>100</option>
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

    function renderUnifiedTelemetryCardHtml(requestRate) {
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
                        <button class="rps-res-btn ${activeRpsResolution === '1' ? 'active' : ''}" data-res="1" title="Group requests into 1-second intervals" style="background:${activeRpsResolution === '1' ? 'rgba(99,102,241,0.2)' : 'var(--bg-secondary)'};border:1px solid ${activeRpsResolution === '1' ? 'var(--accent-primary)' : 'var(--border-color)'};color:${activeRpsResolution === '1' ? '#fff' : 'var(--text-secondary)'};padding:2px 7px;border-radius:4px;font-size:0.7rem;font-weight:600;cursor:pointer;">1 sec</button>
                        <button class="rps-res-btn ${activeRpsResolution === '5' ? 'active' : ''}" data-res="5" title="Group requests into 5-second intervals" style="background:${activeRpsResolution === '5' ? 'rgba(99,102,241,0.2)' : 'var(--bg-secondary)'};border:1px solid ${activeRpsResolution === '5' ? 'var(--accent-primary)' : 'var(--border-color)'};color:${activeRpsResolution === '5' ? '#fff' : 'var(--text-secondary)'};padding:2px 7px;border-radius:4px;font-size:0.7rem;font-weight:600;cursor:pointer;">5 sec</button>
                        <button class="rps-res-btn ${activeRpsResolution === '60' ? 'active' : ''}" data-res="60" title="Group requests into 1-minute intervals" style="background:${activeRpsResolution === '60' ? 'rgba(99,102,241,0.2)' : 'var(--bg-secondary)'};border:1px solid ${activeRpsResolution === '60' ? 'var(--accent-primary)' : 'var(--border-color)'};color:${activeRpsResolution === '60' ? '#fff' : 'var(--text-secondary)'};padding:2px 7px;border-radius:4px;font-size:0.7rem;font-weight:600;cursor:pointer;">1 min</button>
                        <button class="rps-res-btn ${activeRpsResolution === '900' ? 'active' : ''}" data-res="900" title="Group requests into 15-minute intervals" style="background:${activeRpsResolution === '900' ? 'rgba(99,102,241,0.2)' : 'var(--bg-secondary)'};border:1px solid ${activeRpsResolution === '900' ? 'var(--accent-primary)' : 'var(--border-color)'};color:${activeRpsResolution === '900' ? '#fff' : 'var(--text-secondary)'};padding:2px 7px;border-radius:4px;font-size:0.7rem;font-weight:600;cursor:pointer;">15 min</button>
                        <span id="rps-resolution-note" aria-live="polite" style="font-size:0.68rem;color:var(--text-muted);"></span>
                    </div>

                    <!-- Shortcuts: 30m, 1h, 2h, Custom Stepper, All -->
                    <div class="shortcuts-cluster" role="group" aria-labelledby="time-range-label" style="display:flex;gap:4px;align-items:center;">
                        <span id="time-range-label" title="Filter backward from the latest log entry" style="font-size:0.68rem;color:var(--text-muted);margin-right:2px;white-space:nowrap;text-transform:uppercase;font-weight:600;">Time Range:</span>
                        <button class="shortcut-btn ${activeTimeMinutes === 30 ? 'active' : ''}" data-mins="30" title="Last 30 minutes of the loaded logs">Last 30m</button>
                        <button class="shortcut-btn ${activeTimeMinutes === 60 ? 'active' : ''}" data-mins="60" title="Last 1 hour of the loaded logs">1h</button>
                        <button class="shortcut-btn ${activeTimeMinutes === 120 ? 'active' : ''}" data-mins="120" title="Last 2 hours of the loaded logs">2h</button>
                        
                        <div class="stepper-box">
                            <button class="stepper-btn" id="stepper-minus" title="Decrease hours" aria-label="Decrease hours">-</button>
                            <input type="text" class="stepper-input" id="stepper-val" value="${customHoursVal}" title="Time range in hours" aria-label="Time range in hours" />
                            <button class="stepper-btn" id="stepper-plus" title="Increase hours" aria-label="Increase hours">+</button>
                        </div>

                        <button class="shortcut-btn ${activeTimeMinutes === 0 && sliderStartPct === 0 && sliderEndPct === 100 ? 'active' : ''}" id="btn-all-time" title="Use the full log period" style="font-weight:800;">All time</button>
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
                    <div class="slider-curtain-left" id="slider-curtain-left" style="width:${sliderStartPct}%;"></div>
                    <div class="slider-curtain-right" id="slider-curtain-right" style="width:${100 - sliderEndPct}%;"></div>

                    <!-- Active Window Highlight -->
                    <div class="slider-active-window" id="slider-active-window" style="left:${sliderStartPct}%;width:${sliderEndPct - sliderStartPct}%;"></div>

                    <!-- Tactile Zip Handles -->
                    <div class="slider-handle-in-chart slider-handle handle-start" id="handle-start" role="slider" tabindex="0" aria-label="Start time" aria-orientation="horizontal" style="left:calc(${sliderStartPct}% - 10px);"><time class="slider-handle-time"></time></div>
                    <div class="slider-handle-in-chart slider-handle handle-end" id="handle-end" role="slider" tabindex="0" aria-label="End time" aria-orientation="horizontal" style="left:calc(${sliderEndPct}% - 10px);"><time class="slider-handle-time"></time></div>

                    <!-- Floating Time Window Readout Capsule with Boundary Clamping -->
                    <div class="slider-floating-badge" id="time-window-readout" style="left:clamp(120px, ${(sliderStartPct + sliderEndPct) / 2}%, calc(100% - 120px));">
                        ${getTimeWindowHtml(sliderStartPct, sliderEndPct, activeTimeMinutes)}
                    </div>
                </div>
            </div>
        </div>
        `;
    }

    function renderFacetedFilterRibbonHtml(filterOptions) {
        const totalReqs = originalEnrichedEntries.length;
        const matchedReqs = currentFilteredEntries.length;

        return `
        <div class="master-filter-box" id="nginx-master-filter-box" style="margin-bottom:20px;padding:12px 16px;">
            <div class="faceted-filter-row" style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;">
                <div class="filter-selects-wrap" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                    <!-- 1. All HTTP Methods -->
                    <select class="filter-select" id="filter-method">
                        <option value="all" ${activeFilters.method === 'all' ? 'selected' : ''}>All HTTP Methods</option>
                        ${filterOptions.methods.map(m => `<option value="${escapeHtml(m)}" ${activeFilters.method === m ? 'selected' : ''}>${escapeHtml(m)}</option>`).join('')}
                    </select>

                    <!-- 2. All Countries -->
                    <select class="filter-select" id="filter-country">
                        <option value="all" ${activeFilters.country === 'all' ? 'selected' : ''}>All Countries</option>
                        ${filterOptions.countries.map(c => `<option value="${c.country}" ${activeFilters.country === c.country ? 'selected' : ''}>${c.country} (${numberWithCommas(c.count)})</option>`).join('')}
                    </select>

                    <!-- 3. All Paths -->
                    <select class="filter-select" id="filter-path-select">
                        <option value="all" ${!activeFilters.pathSearch ? 'selected' : ''}>All Paths</option>
                        ${(filterOptions.paths || []).map(p => `<option value="${p.path}" ${activeFilters.pathSearch === p.path ? 'selected' : ''}>${p.path} (${numberWithCommas(p.count)})</option>`).join('')}
                    </select>

                    <!-- 4. All ASNs -->
                    <select class="filter-select" id="filter-asn">
                        <option value="all" ${activeFilters.asn === 'all' ? 'selected' : ''}>All ASNs</option>
                        ${filterOptions.asns.map(a => `<option value="${a.asn}" ${activeFilters.asn === String(a.asn) ? 'selected' : ''}>${a.label} (${numberWithCommas(a.count)})</option>`).join('')}
                    </select>

                    <!-- 5. All Traffic -->
                    <select class="filter-select" id="filter-bot" style="${activeFilters.bot === 'spoofed' ? 'border-color:var(--accent-red);color:var(--accent-red);' : ''}">
                        <option value="all" ${activeFilters.bot === 'all' ? 'selected' : ''}>All Traffic</option>
                        <option value="human" ${activeFilters.bot === 'human' ? 'selected' : ''}>👤 Human Traffic Only</option>
                        <option value="all_bots" ${activeFilters.bot === 'all_bots' ? 'selected' : ''}>🤖 All Bots</option>
                        <option value="verified" ${activeFilters.bot === 'verified' ? 'selected' : ''}>🟢 Verified Bots${activeFilters.bot === 'verified' && activeFilters.botGroup ? ' · ' + escapeHtml(activeFilters.botGroup) : ''}</option>
                        <option value="spoofed" ${activeFilters.bot === 'spoofed' ? 'selected' : ''}>🔴 Fake / Spoofed Bots${activeFilters.bot === 'spoofed' && activeFilters.botGroup ? ' · ' + escapeHtml(activeFilters.botGroup) : ''}</option>
                        <option value="unverified" ${activeFilters.bot === 'unverified' ? 'selected' : ''}>⚪ Unverified Bots${activeFilters.bot === 'unverified' && activeFilters.botGroup ? ' · ' + escapeHtml(activeFilters.botGroup) : ''}</option>
                    </select>

                    <!-- Search Fields -->
                    <input type="text" class="search-field" id="filter-ip" placeholder="🔍 Search IP..." value="${escapeHtml(activeFilters.ipSearch)}" />
                    <input type="text" class="search-field" id="filter-path" placeholder="🔗 Search Path..." value="${escapeHtml(activeFilters.pathSearch)}" />
                </div>

                <!-- Match Counter -->
                <div style="display:flex;align-items:center;gap:8px;">
                    <div class="match-counter-pill" id="filter-matching-badge">
                        <i class="bi bi-funnel-fill" style="color:var(--accent-primary);"></i> Matching <strong>${numberWithCommas(matchedReqs)}</strong> / ${numberWithCommas(totalReqs)} requests
                    </div>
                    ${hasActiveFilters() ? `
                    <button class="clear-btn" id="filter-clear-btn" title="Reset All Filters">
                        <i class="bi bi-x-circle-fill"></i>
                    </button>
                    ` : ''}
                </div>
            </div>
        </div>
        `;
    }
    function dispose() {
        stopAdaptiveQueuePoller();
        dismissToastNotification(false);
        isMultiNodeSession = false;
        isModalOpen = false;
        dismissedChunkCount = 0;
        exclusionRevision++;
        timelineDragEvents?.abort();
        timelineDragEvents = null;
        themeObserver?.disconnect();
        themeObserver = null;
        clearTimeout(_filterDebounceTimer);
        if (queuePollTimer) clearInterval(queuePollTimer);
        queuePollTimer = null;
        if (heartbeatTimer) clearInterval(heartbeatTimer);
        heartbeatTimer = null;
        isModalPolling = false;
        queueItems = [];
        const modal = document.getElementById('add-logs-modal');
        if (modal && modal.parentNode) {
            modal.parentNode.removeChild(modal);
        }
        [countryChart, asnChart, rpsChart].forEach(chart => chart?.destroy());
        countryChart = asnChart = rpsChart = null;
        currentData = null;
        currentLogText = '';
        originalEnrichedEntries = [];
        currentFilteredEntries = [];
        originalParseResult = null;
        originalTimeRange = null;
    }

    if (typeof document !== 'undefined') {
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'visible' && isMultiNodeSession) {
                scheduleNextQueuePoll(0);
            }
        });
    }

return {
        render,
        dispose,
        switchStage,
        switchMitigateTab,
        updateMitigationFirewallPreview,
        showIPLogs
    };
})();

if (typeof window !== 'undefined') {
    window.Dashboard = Dashboard;
}
