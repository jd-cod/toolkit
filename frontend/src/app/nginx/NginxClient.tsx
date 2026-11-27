'use client';

import { useEffect, useState, useRef } from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import { useClipboard } from '@/hooks/useClipboard';
import { useHydrated } from '@/hooks/useHydrated';
import { disposeNginxDashboard, loadNginxInput } from '@/lib/nginx-engine';

const samples = [
  { file: 'ecommerce-normal.log', icon: 'globe2', title: 'Normal Web Traffic', detail: 'A mix of visitors, requests, and everyday browsing.' },
  { file: 'attack-scanners.log', icon: 'shield-exclamation', title: 'Web Scanners & Exploits', detail: 'Explore common probes and attack patterns.' },
  { file: 'ddos-flood.log', icon: 'lightning-charge', title: 'Layer-7 Flood', detail: 'Inspect request bursts and high-volume clients.' },
  { file: 'bot-crawlers.log', icon: 'robot', title: 'Search & Bad Bots', detail: 'Compare crawler identities and verification.' },
  { file: 'heavy-traffic.log', icon: 'bar-chart-line', title: 'Heavy Web Traffic (100k)', detail: 'A larger example for exploring filters and timelines.' },
];

const inputSources = [
  { mode: 'upload', label: 'Upload file', detail: 'Local file', hint: 'Drop or choose', icon: 'upload' },
  { mode: 'server', label: 'cURL ingest', detail: 'From server', hint: 'Run a command', icon: 'terminal' },
  { mode: 'paste', label: 'Paste logs', detail: 'Clipboard', hint: 'Paste lines', icon: 'code-slash' },
  { mode: 'url', label: 'Remote URL', detail: 'Remote source', hint: 'Fetch a URL', icon: 'link-45deg' },
];

/** React owns the input skeleton; the classic engine owns its controls and results.
 * Keep IDs and sequential script loading compatible with shared snapshots.
 */
export default function NginxClient() {
  const hydrated = useHydrated();
  const origin = hydrated ? window.location.origin : '';
  const { copiedKey, copy: handleCopy } = useClipboard();
  const host = origin || 'https://domain.com';
  const serverCommands = [
    { key: 'curl-large', label: 'Recommended · Stream complete log (any size up to 5 GB)', command: `gzip -c /var/log/nginx/access.log | bash <(curl -fsSL ${host}/ingest)` },
    { key: 'curl-tail', label: 'Latest 50,000 requests (< 100 MB)', command: `tail -n 50000 /var/log/nginx/access.log | gzip -c | curl -sS -F "file=@-" ${host}/ingest` },
  ];
  const recommendedCommand = serverCommands[0];
  const fullCommand = serverCommands[1];

  const [inputMode, setInputMode] = useState<'upload' | 'server' | 'paste' | 'url'>('upload');
  const pendingSampleRef = useRef<string | null>(null);

  const handleSelectTab = (mode: 'upload' | 'server' | 'paste' | 'url') => {
    setInputMode(mode);
    const inputSection = document.getElementById('nginx-input-section');
    if (inputSection) {
      inputSection.dataset.inputMode = mode;
      const analyzeButton = document.getElementById('nginx-analyze-btn');
      const inputOptions = inputSection.querySelector('.signal-nginx-options') as HTMLElement | null;
      const isServer = mode === 'server';
      if (analyzeButton) analyzeButton.hidden = isServer;
      if (inputOptions) inputOptions.hidden = isServer;
    }
    ['upload', 'server', 'paste', 'url'].forEach(p => {
      const panel = document.getElementById(`nginx-panel-${p}`);
      if (panel) panel.hidden = p !== mode;
    });
    if (typeof window !== 'undefined' && (window as any).__selectInputMode) {
      (window as any).__selectInputMode(mode);
    }
  };

  const handleSampleClick = (sampleFile: string) => {
    const analyzeBtn = document.getElementById('nginx-analyze-btn');
    if (analyzeBtn?.dataset.engineReady === 'true') {
      return;
    }
    pendingSampleRef.current = sampleFile;
    const status = document.getElementById('nginx-input-status');
    if (status) status.textContent = 'Loading engine to analyze sample…';
  };

  useEffect(() => {
    let active = true;
    let cleanup: (() => void) | undefined;
    document.body.dataset.nginxPage = 'standalone';
    document.body.dataset.nginxView = 'input';
    loadNginxInput().then(() => {
      if (active) {
        cleanup = window.initNginxPage?.();
        if (pendingSampleRef.current) {
          const sample = pendingSampleRef.current;
          pendingSampleRef.current = null;
          const btn = document.querySelector<HTMLButtonElement>(`.btn-sample[data-sample="${sample}"]`);
          btn?.click();
        }
      }
    }).catch(() => {
      if (!active) return;
      const status = document.getElementById('nginx-input-status');
      if (status) status.textContent = 'The analysis engine could not load. Check your connection and reload this page.';
    });

    return () => {
      active = false;
      cleanup?.();
      disposeNginxDashboard();
      delete document.body.dataset.nginxPage;
      delete document.body.dataset.nginxView;
    };
  }, []);

  return (
    <>
      <Navbar />
      <main className="main-content signal-nginx-page">
        <header id="nginx-hero-section" className="signal-nginx-heading">
          <p className="signal-nginx-eyebrow">Observability &amp; Log Intelligence</p>
          <h1>Traffic Log Analyzer</h1>
          <p>Start with your logs. Find the signal: explore request patterns, status codes, bots, and the traffic that needs a closer look.</p>
          <ol className="signal-nginx-steps" aria-label="Analysis workflow">
            <li aria-current="step"><span>1</span> Add your logs</li>
            <li><span>2</span> Analyze locally</li>
            <li><span>3</span> Explore insights</li>
          </ol>
        </header>

        <div id="geoip-loader" className="signal-nginx-progress hidden" role="status">
          <i className="bi bi-globe2" aria-hidden="true"></i>
          <div>
            <strong>Loading GeoIP databases</strong>
            <div className="signal-nginx-progress-track"><div id="geoip-progress-bar" /></div>
            <span id="geoip-status">Initializing…</span>
          </div>
        </div>

        <div className="signal-nginx-import-layout">
          <section id="nginx-input-section" className="signal-nginx-panel" data-input-mode={inputMode} aria-label="Add logs">
            <div className="signal-nginx-input-heading">
              <div><p className="signal-nginx-eyebrow">Add logs</p><h2>Choose a source</h2></div>
              <span className="signal-nginx-source-count">4 ways to start</span>
            </div>
            <div className="signal-nginx-input-tabs signal-nginx-source-picker" role="tablist" aria-label="Log input source">
              {inputSources.map(({ mode, label, detail, hint, icon }) => {
                const isSelected = inputMode === mode;
                return (
                  <button key={mode} id={`nginx-tab-${mode}`} className="signal-nginx-source-option" type="button" role="tab"
                    data-input-tab={mode} aria-controls={`nginx-panel-${mode}`} aria-label={`${label} · ${detail}`}
                    aria-selected={isSelected} tabIndex={isSelected ? 0 : -1}
                    onClick={() => handleSelectTab(mode as any)}>
                    <span className="signal-nginx-source-icon"><i className={`bi bi-${icon}`} aria-hidden="true"></i></span>
                    <span className="signal-nginx-source-copy"><strong>{label}</strong><small>{detail}</small></span>
                    <span className="signal-nginx-source-hint">{hint}</span>
                  </button>
                );
              })}
            </div>
            <div className="signal-nginx-input-body">
              <div id="nginx-panel-upload" role="tabpanel" aria-labelledby="nginx-tab-upload" data-input-panel="upload" hidden={inputMode !== 'upload'}>
                <div id="nginx-dropzone" className="signal-nginx-dropzone">
                  <span className="signal-nginx-drop-symbol"><i className="bi bi-upload" aria-hidden="true"></i></span>
                  <div className="signal-nginx-drop-copy"><h2>Drop your access logs here</h2><p>One file or a whole rotation · .log, .txt, or .gz</p></div>
                  <label className="signal-nginx-button" htmlFor="nginx-logfile"><i className="bi bi-plus-lg" aria-hidden="true"></i> Choose files</label>
                  <input type="file" id="nginx-logfile" accept=".log,.txt,.gz" multiple aria-label="Choose log files" aria-describedby="nginx-dropzone-filename" />
                  <p id="nginx-dropzone-filename" aria-live="polite">Multi-gigabyte streaming support · Compressed or raw logs</p>
                </div>
              </div>
              <div id="nginx-panel-server" role="tabpanel" aria-labelledby="nginx-tab-server" data-input-panel="server" hidden={inputMode !== 'server'}>
                <div className="signal-nginx-panel-heading">
                  <span className="signal-nginx-server-symbol"><i className="bi bi-terminal" aria-hidden="true"></i></span>
                  <div>
                    <p className="signal-nginx-eyebrow">From a server</p>
                    <h2>Send logs with cURL</h2>
                    <p>Run one command over SSH. Your terminal will print a one-time dashboard link.</p>
                  </div>
                </div>
                <ol className="signal-nginx-server-steps" aria-label="cURL ingest steps">
                  <li><span>1</span> Copy</li><li><span>2</span> Run over SSH</li><li><span>3</span> Open link</li>
                </ol>
                <div className="signal-nginx-server-command">
                  <div className="signal-nginx-command-label"><strong>Complete access log (any size)</strong><span>Recommended</span></div>
                  <div className="cli-snippet"><code>{recommendedCommand.command}</code><button type="button" className="btn-cli-copy" onClick={() => void handleCopy(recommendedCommand.command, recommendedCommand.key)} data-copy={recommendedCommand.command} aria-label="Copy recommended cURL command">
                    <i className={`bi ${copiedKey === recommendedCommand.key ? 'bi-check2' : 'bi-clipboard'}`} aria-hidden="true"></i> <span aria-live="polite">{copiedKey === recommendedCommand.key ? 'Copied!' : 'Copy'}</span>
                  </button></div>
                </div>
                <details className="signal-nginx-server-more">
                  <summary><i className="bi bi-chevron-right" aria-hidden="true"></i> Or send latest 50,000 requests (&lt; 100 MB)</summary>
                  <div className="signal-nginx-server-command">
                    <div className="cli-snippet"><code>{fullCommand.command}</code><button type="button" className="btn-cli-copy" onClick={() => void handleCopy(fullCommand.command, fullCommand.key)} data-copy={fullCommand.command} aria-label="Copy complete cURL command">
                      <i className={`bi ${copiedKey === fullCommand.key ? 'bi-check2' : 'bi-clipboard'}`} aria-hidden="true"></i> <span aria-live="polite">{copiedKey === fullCommand.key ? 'Copied!' : 'Copy'}</span>
                    </button></div>
                  </div>
                </details>
                <div className="signal-nginx-server-note">
                  <i className="bi bi-shield-check" aria-hidden="true"></i>
                  <p><strong>One-time link · expires in 10 minutes.</strong> Temporary storage is deleted after download. Analysis runs in your browser.</p>
                </div>
              </div>
              <div id="nginx-panel-paste" role="tabpanel" aria-labelledby="nginx-tab-paste" data-input-panel="paste" hidden={inputMode !== 'paste'}>
                <div className="signal-nginx-panel-heading signal-nginx-panel-heading-compact"><span className="signal-nginx-server-symbol"><i className="bi bi-code-slash" aria-hidden="true"></i></span><div><h2>Paste logs</h2><p>Quick browser-only input</p></div></div>
                <label className="signal-nginx-field-label" htmlFor="nginx-logtext">Paste access logs</label>
                <textarea id="nginx-logtext" rows={6} spellCheck={false} placeholder={'Paste combined or common access log lines here…\n\nOne request per line.'} aria-describedby="nginx-paste-note" />
                <p id="nginx-paste-note" className="signal-nginx-help">Parsed locally in your browser. Use a file for large logs.</p>
              </div>
              <div id="nginx-panel-url" role="tabpanel" aria-labelledby="nginx-tab-url" data-input-panel="url" hidden={inputMode !== 'url'}>
                <div className="signal-nginx-panel-heading signal-nginx-panel-heading-compact"><span className="signal-nginx-server-symbol"><i className="bi bi-link-45deg" aria-hidden="true"></i></span><div><h2>Fetch from a URL</h2><p>Use a public or presigned log link</p></div></div>
                <label className="signal-nginx-field-label" htmlFor="nginx-gist-url">Remote log URL</label>
                <input id="nginx-gist-url" type="url" placeholder="https://example.com/access.log.gz" autoComplete="off" spellCheck={false} aria-describedby="nginx-url-note" />
                <p id="nginx-url-note" className="signal-nginx-help">Use a public HTTP(S), presigned S3, or raw Pastebin URL. The server fetches and stores a copy before analysis. Private network addresses are blocked.</p>
              </div>
              <fieldset className="signal-nginx-options">
                <legend>Analysis exclusions</legend>
                <div className="signal-exclusion-toggles">
                  <label htmlFor="nginx-skip-403"><input type="checkbox" id="nginx-skip-403" defaultChecked /> Ignore 403 responses</label>
                  <label htmlFor="nginx-skip-internal"><input type="checkbox" id="nginx-skip-internal" defaultChecked /> Ignore internal requests</label>
                  <label htmlFor="nginx-client-ip" title="Which address on a log line is the visitor. Automatic uses the forwarded address (X-Forwarded-For) when the connecting address is private, or when nearly every line carries one.">Client address
                    <select id="nginx-client-ip" className="filter-select" style={{ width: 'auto' }} defaultValue="auto">
                      <option value="auto">Automatic</option>
                      <option value="remote">Connecting address</option>
                      <option value="forwarded">X-Forwarded-For</option>
                    </select>
                  </label>
                </div>
                <details className="signal-nginx-option-help"><summary>What is excluded?</summary><p>Internal requests: private, loopback, link-local, CGNAT and IPv6 unique-local IPs (including mapped IPv4), plus exact paths /health, /healthz, /healthcheck, /health-check, /health_check, /readyz, /livez and /_health. Query strings and trailing slashes are ignored. This applies to every User-Agent and response status. Unknown ASN alone is not an exclusion.</p><p>403 filtering excludes ordinary blocked requests; recognized crawlers are retained for bot analysis. Uncheck either option to include those requests. You can also change these options above the results.</p></details>
              </fieldset>
              <div className="signal-nginx-input-action">
                <p id="nginx-input-status" role="status" aria-live="polite">Choose a file to start your analysis.</p>
                <button id="nginx-analyze-btn" type="button" className="signal-nginx-button signal-nginx-primary" disabled>
                  <i className="bi bi-arrow-right" aria-hidden="true"></i> Analyze Logs
                </button>
              </div>
            </div>
          </section>

          <aside id="nginx-sample-bar" className="signal-nginx-panel signal-nginx-samples" aria-label="Sample datasets">
            <p className="signal-nginx-eyebrow">No logs handy?</p>
            <h2>Take a sample for a spin.</h2>
            <p>Explore example datasets. No setup needed.</p>
            {samples.map(sample => (
              <button key={sample.file} type="button" className="btn-sample signal-nginx-sample" data-sample={sample.file} onClick={() => handleSampleClick(sample.file)}>
                <span className="signal-nginx-sample-icon"><i className={`bi bi-${sample.icon}`} aria-hidden="true"></i></span>
                <span><strong>{sample.title}</strong><small>{sample.detail}</small></span>
                <i className="bi bi-arrow-right" aria-hidden="true"></i>
              </button>
            ))}
            <p className="signal-nginx-help">Supports Nginx, Apache, Caddy, Cloudflare, and common formats. Skipped lines are counted in your analysis.</p>
          </aside>
        </div>

        <section id="nginx-tips-section" className="signal-nginx-local-note">
          <i className="bi bi-shield-check" aria-hidden="true"></i>
          <div><strong>Your local logs stay local.</strong><p>Local files and pasted logs are analyzed in your browser. Remote URLs, terminal sessions, sharing, and IP reputation lookups use server services. GeoIP databases are downloaded and cached locally.</p></div>
        </section>

        <div id="nginx-dashboard" style={{ display: 'none' }} />
      </main>
      <Footer />
    </>
  );
}
