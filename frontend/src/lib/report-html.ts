/**
 * One HTML shell for every tool's downloadable report.
 *
 * A tool describes its report as data (cards and sections) and gets back a
 * self-contained HTML document. Every value is escaped here, so callers pass
 * raw text and never build markup themselves.
 */

export type ReportValue = string | number | boolean | null | undefined;

export interface ReportCard {
  label: string;
  value: ReportValue;
  /** Small secondary line under the value. */
  meta?: string;
  mono?: boolean;
}

interface SectionBase {
  title: string;
  /** Small secondary text beside the title. */
  meta?: string;
}

export type ReportSection = SectionBase & (
  | { rows: [label: string, value: ReportValue][] }
  | { table: { columns: string[]; rows: ReportValue[][]; alignRight?: number[]; mono?: number[] }; empty?: string }
  | { list: string[]; empty?: string }
  | { pills: string[]; empty?: string }
  | { text: string }
  | { note: string }
);

export interface ReportDocument {
  /** Report name, e.g. "DNS Snapshot". */
  title: string;
  /** What the report is about, e.g. the domain or IP. */
  subject?: string;
  subtitle?: string;
  /** ISO timestamp of when the data was collected. */
  checkedAt?: string;
  cards?: ReportCard[];
  sections: ReportSection[];
}

export const REPORT_BRAND = 'SysAdmin Toolkit';

export function escapeHtml(value: unknown) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function display(value: ReportValue) {
  if (value === null || value === undefined || value === '') return '—';
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  return String(value);
}

/** Formats an ISO timestamp as "2026-11-26 10:00:00 UTC"; returns other text unchanged. */
export function formatReportTime(value?: string) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return `${date.toISOString().slice(0, 19).replace('T', ' ')} UTC`;
}

const REPORT_CSS = `
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0b1017;color:#eef3f7;padding:40px 20px;line-height:1.5}
.container{max-width:1100px;margin:0 auto}
.brand{font-size:.72rem;font-weight:700;letter-spacing:.13em;text-transform:uppercase;color:#65e2ba;margin-bottom:10px}
h1{font-size:1.8rem;font-weight:800;letter-spacing:-.02em;margin-bottom:6px;word-break:break-word}
.subtitle{color:#9baabc;font-size:.92rem;margin-bottom:4px;word-break:break-word}
.timestamp{color:#8293a7;font-size:.82rem;margin-bottom:26px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:20px}
.card{background:#111a24;border:1px solid #25303e;border-radius:12px;padding:18px;text-align:center}
.card-value{font-size:1.25rem;font-weight:800;line-height:1.25;word-break:break-word}
.card-label{font-size:.72rem;color:#8293a7;text-transform:uppercase;letter-spacing:.1em;margin-top:6px}
.card-meta{font-size:.76rem;color:#8293a7;margin-top:6px}
.section{background:#111a24;border:1px solid #25303e;border-radius:12px;margin-bottom:16px;overflow:hidden}
.section h2{padding:13px 18px;border-bottom:1px solid #25303e;font-size:.98rem;font-weight:700}
.section-meta{font-size:.78rem;color:#8293a7;margin-left:8px;font-weight:500}
.section-body{padding:16px 18px}
table{width:100%;border-collapse:collapse}
th{background:#0d151e;padding:10px 18px;text-align:left;font-size:.72rem;text-transform:uppercase;letter-spacing:.08em;color:#8293a7;border-bottom:1px solid #25303e}
td{padding:9px 18px;border-bottom:1px solid #1b2531;font-size:.87rem;vertical-align:top;word-break:break-word}
tr:last-child td{border-bottom:none}
td.key{color:#9baabc;width:36%}
.right{text-align:right}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.muted{color:#8293a7}
.pill{display:inline-block;padding:5px 11px;border-radius:999px;border:1px solid #25303e;margin:0 8px 8px 0;font-size:.82rem}
ul{padding-left:18px}
li{margin-bottom:4px;font-size:.88rem}
pre{white-space:pre-wrap;word-break:break-word;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.8rem;line-height:1.6}
.footer{text-align:center;color:#8293a7;font-size:.76rem;margin-top:30px;padding-top:16px;border-top:1px solid #25303e}
@media print{body{background:#fff;color:#111;padding:0}.card,.section{background:#fff;border-color:#ccc}th{background:#f3f4f6;color:#444}td{border-color:#e5e7eb}td.key,.muted,.subtitle,.timestamp,.card-label,.card-meta,.section-meta,.footer{color:#555}.brand{color:#087759}.section h2,.footer{border-color:#ccc}.pill{border-color:#ccc}}
`.trim();

function renderCards(cards: ReportCard[]) {
  if (cards.length === 0) return '';
  return `<div class="cards">${cards.map((card) => `
      <div class="card"><div class="card-value${card.mono ? ' mono' : ''}">${escapeHtml(display(card.value))}</div><div class="card-label">${escapeHtml(card.label)}</div>${card.meta ? `<div class="card-meta">${escapeHtml(card.meta)}</div>` : ''}</div>`).join('')}
    </div>`;
}

function renderEmpty(text: string) {
  return `<div class="section-body muted">${escapeHtml(text)}</div>`;
}

function renderSectionBody(section: ReportSection) {
  if ('rows' in section) {
    return `<table><tbody>${section.rows.map(([label, value]) =>
      `<tr><td class="key">${escapeHtml(label)}</td><td class="mono">${escapeHtml(display(value))}</td></tr>`).join('')}</tbody></table>`;
  }
  if ('table' in section) {
    const { columns, rows, alignRight = [], mono = [] } = section.table;
    if (rows.length === 0) return renderEmpty(section.empty || 'No data.');
    const cellClass = (index: number) => {
      const classes = [alignRight.includes(index) ? 'right' : '', mono.includes(index) ? 'mono' : ''].filter(Boolean).join(' ');
      return classes ? ` class="${classes}"` : '';
    };
    return `<table><thead><tr>${columns.map((column, index) => `<th${alignRight.includes(index) ? ' class="right"' : ''}>${escapeHtml(column)}</th>`).join('')}</tr></thead><tbody>${rows.map((row) =>
      `<tr>${row.map((value, index) => `<td${cellClass(index)}>${escapeHtml(display(value))}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
  }
  if ('list' in section) {
    if (section.list.length === 0) return renderEmpty(section.empty || 'None.');
    return `<div class="section-body"><ul>${section.list.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul></div>`;
  }
  if ('pills' in section) {
    if (section.pills.length === 0) return renderEmpty(section.empty || 'None.');
    return `<div class="section-body">${section.pills.map((item) => `<span class="pill">${escapeHtml(item)}</span>`).join('')}</div>`;
  }
  if ('text' in section) {
    return `<div class="section-body"><pre>${escapeHtml(section.text)}</pre></div>`;
  }
  return renderEmpty(section.note);
}

function renderSection(section: ReportSection) {
  return `
    <div class="section"><h2>${escapeHtml(section.title)}${section.meta ? `<span class="section-meta">${escapeHtml(section.meta)}</span>` : ''}</h2>${renderSectionBody(section)}</div>`;
}

export function buildReportHtml(doc: ReportDocument) {
  const checkedAt = formatReportTime(doc.checkedAt);
  const pageTitle = doc.subject ? `${doc.title} - ${doc.subject}` : doc.title;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(pageTitle)}</title>
  <style>${REPORT_CSS}</style>
</head>
<body>
  <div class="container">
    <div class="brand">${escapeHtml(REPORT_BRAND)}</div>
    <h1>${escapeHtml(doc.title)}</h1>
    ${doc.subject || doc.subtitle ? `<p class="subtitle">${escapeHtml([doc.subject, doc.subtitle].filter(Boolean).join(' · '))}</p>` : ''}
    ${checkedAt ? `<p class="timestamp">Checked at ${escapeHtml(checkedAt)}</p>` : '<p class="timestamp"></p>'}
    ${renderCards(doc.cards || [])}${doc.sections.map(renderSection).join('')}
    <div class="footer">Generated by ${escapeHtml(REPORT_BRAND)}${checkedAt ? ` · ${escapeHtml(checkedAt)}` : ''}</div>
  </div>
</body>
</html>`;
}
