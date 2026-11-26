/**
 * Share Modal — Frontend (Cloudflare R2 Object Storage)
 *
 * Flow:
 *   1. User clicks Share → Modal opens with input source info
 *   2. On submit, upload compressed log directly to R2 (/api/storage/upload or /api/storage/upload-external)
 *   3. Share record is created in MySQL with R2 object key
 *   4. Share link generated: /s/:code
 */

const ShareModal = (() => {
    let _parseResult = null;
    let _inputSource = null;  // 'url' | 'text' | 'file' | 'sample'
    let _logText = '';        // Original log content

    async function safeJson(resp) {
        const text = await resp.text();
        try {
            return JSON.parse(text);
        } catch {
            return { error: text || `HTTP ${resp.status}` };
        }
    }

    function mountModal() {
        if (document.getElementById('share-modal-backdrop')) return;

        const el = document.createElement('div');
        el.innerHTML = `
        <div id="share-modal-backdrop" style="display:none;position:fixed;inset:0;z-index:10000;background:rgba(7,8,15,0.75);backdrop-filter:blur(6px);align-items:center;justify-content:center;">
            <div id="share-modal" style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:18px;padding:32px 36px;max-width:480px;width:90%;box-shadow:0 24px 80px rgba(0,0,0,0.5);position:relative;">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;">
                    <h3 style="margin:0;font-size:20px;font-weight:600;color:var(--text-primary)">Share Analysis</h3>
                    <button id="share-close-btn" style="background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:24px;line-height:1">&times;</button>
                </div>
                <div id="share-form-section">
                    <div style="margin-bottom:20px;">
                        <label style="display:block;font-size:13px;font-weight:500;color:var(--text-muted);margin-bottom:8px;">Analysis Title</label>
                        <input id="share-title" type="text" placeholder="e.g. Unusual traffic from AS123" style="width:100%;padding:12px;background:var(--bg-input);border:1px solid var(--border-color);border-radius:8px;color:var(--text-primary);font-size:14px;">
                    </div>
                    <div style="grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px;display:grid;">
                        <div>
                            <label style="display:block;font-size:13px;font-weight:500;color:var(--text-muted);margin-bottom:8px;">Expiry</label>
                            <select id="share-expiry" style="width:100%;padding:12px;background:var(--bg-input);border:1px solid var(--border-color);border-radius:8px;color:var(--text-primary);font-size:14px;">
                                <option value="1h">1 Hour</option>
                                <option value="24h">24 Hours</option>
                                <option value="7d">7 Days</option>
                                <option value="never">Never</option>
                            </select>
                        </div>
                        <div>
                            <label style="display:block;font-size:13px;font-weight:500;color:var(--text-muted);margin-bottom:8px;">Password (Optional)</label>
                            <input id="share-password" type="password" placeholder="Enter password" style="width:100%;padding:12px;background:var(--bg-input);border:1px solid var(--border-color);border-radius:8px;color:var(--text-primary);font-size:14px;">
                        </div>
                    </div>
                    <button id="share-submit-btn" style="width:100%;padding:14px;background:var(--accent-primary);color:var(--signal-on-primary);border:1px solid var(--accent-primary);border-radius:8px;font-weight:600;cursor:pointer;transition:opacity 0.2s;">Create Share Link</button>
                </div>
                <div id="share-result-section" style="display:none;text-align:center;padding:16px 0;">
                    <div style="background:var(--bg-input);padding:16px;border-radius:12px;border:1px dashed var(--border-color);margin-bottom:20px;">
                        <div id="share-url-display" style="font-family:monospace;font-size:14px;color:var(--text-primary);word-break:break-all;margin-bottom:12px;"></div>
                        <button id="share-copy-btn" style="padding:8px 16px;background:var(--bg-card);border:1px solid var(--border-color);border-radius:6px;color:var(--text-primary);font-size:12px;cursor:pointer;">Copy Link</button>
                    </div>
                    <button id="share-done-btn" style="background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:14px;text-decoration:underline;">Close</button>
                </div>
                <div id="share-error" style="display:none;margin-top:20px;padding:12px;background:rgba(255,0,0,0.1);border:1px solid rgba(255,0,0,0.2);border-radius:8px;color:var(--accent-red,#f3898b);font-size:13px;text-align:center;"></div>
            </div>
        </div>
        `;
        const mount = document.querySelector('.signal-workspace') || document.body;
        mount.appendChild(el);

        document.getElementById('share-close-btn').onclick = close;
        document.getElementById('share-done-btn').onclick = close;
        document.getElementById('share-copy-btn').onclick = () => {
            const url = document.getElementById('share-url-display').innerText;
            let copied = false;
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(url).catch(() => {});
                copied = true;
            }
            if (!copied && typeof document !== 'undefined') {
                try {
                    const ta = document.createElement('textarea');
                    ta.value = url;
                    ta.style.position = 'fixed';
                    ta.style.left = '-9999px';
                    document.body.appendChild(ta);
                    ta.select();
                    document.execCommand('copy');
                    document.body.removeChild(ta);
                } catch (e) {}
            }
            const btn = document.getElementById('share-copy-btn');
            btn.innerText = 'Copied!';
            setTimeout(() => btn.innerText = 'Copy Link', 2000);
        };

        document.getElementById('share-submit-btn').onclick = handleSubmit;
    }

    async function handleSubmit() {
        const title = document.getElementById('share-title').value || 'Untitled Analysis';
        const password = document.getElementById('share-password').value;
        const expiry = document.getElementById('share-expiry').value;

        const submitBtn = document.getElementById('share-submit-btn');
        const errorEl = document.getElementById('share-error');

        submitBtn.disabled = true;
        submitBtn.innerText = 'Creating...';
        errorEl.style.display = 'none';

        // R2 Upload logic
        let r2Key = _parseResult?.r2_key;
        let shareCode = _parseResult?.shareCode;

        if (!r2Key) {
            try {
                const uploadResp = await safeJson(await fetch('/api/storage/upload', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        content: _logText,
                        title: title
                    })
                }));
                if (uploadResp.error) throw new Error(uploadResp.error);
                r2Key = uploadResp.r2Key;
                shareCode = uploadResp.shareCode;
            } catch (e) {
                errorEl.innerText = 'Upload failed: ' + e.message;
                errorEl.style.display = 'block';
                submitBtn.disabled = false;
                submitBtn.innerText = 'Create Share Link';
                return;
            }
        }

        // Create MySQL record
        try {
            const shareResp = await safeJson(await fetch('/api/share', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    title,
                    r2_key: r2Key,
                    shareCode: shareCode,
                    password: password || null,
                    expiry
                })
            }));
            if (shareResp.error) throw new Error(shareResp.error);

            document.getElementById('share-form-section').style.display = 'none';
            document.getElementById('share-result-section').style.display = 'block';
            document.getElementById('share-url-display').innerText = window.location.origin + '/s/' + shareResp.code;

        } catch (e) {
            errorEl.innerText = 'Share creation failed: ' + e.message;
            errorEl.style.display = 'block';
            submitBtn.disabled = false;
            submitBtn.innerText = 'Create Share Link';
        }
    }

    function close() {
        document.getElementById('share-modal-backdrop').style.display = 'none';
    }

    function open(data, parseResult, options = {}) {
        _parseResult = parseResult;
        _inputSource = options.inputSource || options.source || 'text';
        _logText = options.logText || '';

        if (_inputSource === 'terminal_ingest') {
            alert('Sharing is disabled for terminal-ingested logs to enforce our Zero-Data Retention policy. Use \'Download Report\' for self-contained offline reports.');
            return;
        }

        document.getElementById('share-form-section').style.display = 'block';
        document.getElementById('share-result-section').style.display = 'none';
        document.getElementById('share-error').style.display = 'none';
        document.getElementById('share-title').value = '';
        document.getElementById('share-password').value = '';
        document.getElementById('share-expiry').value = 'never';
        document.getElementById('share-modal-backdrop').style.display = 'flex';
    }

    mountModal();

    return { open, close };
})();
window.ShareModal = ShareModal;
