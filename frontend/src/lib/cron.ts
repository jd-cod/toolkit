import { buildReportHtml } from './report-html';

export const DAY_NAMES = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
const MONTH_NAMES = ['','Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
const DAY_SHORT = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];

function parseField(field: string, min: number, max: number): number[] | null {
  const vals = new Set<number>();
  for (const part of field.split(',')) {
    if (part === '*') { for (let i = min; i <= max; i++) vals.add(i); }
    else if (part.includes('/')) {
      const [r, s] = part.split('/'); const step = parseInt(s, 10);
      if (isNaN(step) || step <= 0) return null;
      let a = min, b = max;
      if (r !== '*') { if (r.includes('-')) { [a, b] = r.split('-').map(Number); } else a = parseInt(r, 10); }
      for (let i = a; i <= b; i += step) vals.add(i);
    } else if (part.includes('-')) {
      const [a, b] = part.split('-').map(Number);
      for (let i = a; i <= b; i++) vals.add(i);
    } else { const n = parseInt(part, 10); if (isNaN(n)) return null; vals.add(n); }
  }
  for (const v of vals) if (v < min || v > max) return null;
  return [...vals].sort((a, b) => a - b);
}

export function parseCron(expr: string) {
  const p = expr.trim().split(/\s+/); if (p.length !== 5) return null;
  const m = parseField(p[0], 0, 59), h = parseField(p[1], 0, 23), d = parseField(p[2], 1, 31), mo = parseField(p[3], 1, 12), dw = parseField(p[4], 0, 7);
  if (!m || !h || !d || !mo || !dw) return null;
  return { raw: p, minute: m, hour: h, dom: d, month: mo, dow: [...new Set(dw.map(x => x === 7 ? 0 : x))].sort((a, b) => a - b) };
}

function fmtHour(h: number) { if (h === 0) return '12:00 AM'; if (h === 12) return '12:00 PM'; return h < 12 ? `${h}:00 AM` : `${h - 12}:00 PM`; }

export function describeCron(expr: string): string {
  const p = expr.trim().split(/\s+/); if (p.length !== 5) return '❌ Invalid: need 5 fields';
  const [mf, hf, df, mof, dwf] = p; const pcs: string[] = [];
  if (mf === '*') pcs.push('Every minute');
  else if (mf.startsWith('*/')) pcs.push(`Every ${mf.slice(2)} minutes`);
  else pcs.push(`At minute ${mf}`);
  if (hf === '*') { if (mf !== '*' && !mf.startsWith('*/')) pcs.push('of every hour'); }
  else if (hf.startsWith('*/')) pcs.push(`every ${hf.slice(2)} hours`);
  else if (hf.includes(',')) pcs.push(`at ${hf.split(',').map(x => fmtHour(+x)).join(' and ')}`);
  else { const h = +hf; if (mf === '0') { pcs.length = 0; pcs.push(`At ${fmtHour(h)}`); } else pcs.push(`past ${fmtHour(h)}`); }
  if (df !== '*') pcs.push(`on day ${df} of the month`);
  if (mof !== '*') pcs.push(`in ${mof.split(',').map(x => MONTH_NAMES[+x] || x).join(', ')}`);
  if (dwf !== '*') pcs.push(`on ${dwf.split(',').map(x => DAY_SHORT[+x % 7] || x).join(', ')}`);
  return pcs.join(' ');
}

export function getNextRuns(expr: string, count: number, from = new Date()): Date[] {
  const parsed = parseCron(expr); if (!parsed) return [];
  const runs: Date[] = [], cur = new Date(from);
  cur.setSeconds(0, 0); cur.setMinutes(cur.getMinutes() + 1);
  for (let i = 0; runs.length < count && i < 525600; i++) {
    if (parsed.minute.includes(cur.getMinutes()) && parsed.hour.includes(cur.getHours()) &&
      parsed.dom.includes(cur.getDate()) && parsed.month.includes(cur.getMonth() + 1) &&
      parsed.dow.includes(cur.getDay())) runs.push(new Date(cur));
    cur.setMinutes(cur.getMinutes() + 1);
  }
  return runs;
}

export function relTime(d: Date): string {
  const diff = d.getTime() - Date.now(), m = Math.floor(diff / 60000);
  if (m < 1) return 'now'; if (m < 60) return `in ${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `in ${h}h ${m % 60}m`; return `in ${Math.floor(h / 24)}d ${h % 24}h`;
}

export const CRON_FIELD_LABELS = ['Minute', 'Hour', 'Day(M)', 'Month', 'Day(W)'] as const;

/** A cron expression as it is shared; everything else is derived from it. */
export interface CronSnapshot {
  expression: string;
  checked_at_utc: string;
}

export function normalizeCronSnapshot(raw: unknown): CronSnapshot {
  const d = (raw ?? {}) as Partial<CronSnapshot>;
  return {
    expression: typeof d.expression === 'string' ? d.expression.trim().slice(0, 200) : '',
    checked_at_utc: typeof d.checked_at_utc === 'string' ? d.checked_at_utc : new Date().toISOString(),
  };
}

const runDate = (d: Date) => d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
const runTime = (d: Date) => d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: true });

/** Upcoming runs as CSV rows, in the browser's local time. */
export function cronCsvRows(expr: string, runs: Date[]) {
  const description = describeCron(expr);
  if (runs.length === 0) return [{ expression: expr.trim(), description, run: '', date: '', time: '', day: '' }];
  return runs.map((d, i) => ({ expression: expr.trim(), description, run: i + 1, date: runDate(d), time: runTime(d), day: DAY_NAMES[d.getDay()] }));
}

export function buildCronReportHtml(expr: string, runs: Date[], checkedAt?: string) {
  const parsed = parseCron(expr);
  return buildReportHtml({
    title: 'Cron Schedule Report',
    subject: expr.trim(),
    subtitle: describeCron(expr),
    checkedAt,
    timeLabel: 'Generated at',
    cards: parsed ? CRON_FIELD_LABELS.map((label, i) => ({ label, value: parsed.raw[i], mono: true })) : [],
    sections: [
      parsed
        ? {
            title: `Next ${runs.length} Executions`,
            meta: 'local time of the browser that created this report',
            empty: 'No upcoming executions found within a year.',
            table: {
              columns: ['#', 'Date', 'Time', 'Day'],
              mono: [1, 2],
              rows: runs.map((d, i) => [i + 1, runDate(d), runTime(d), DAY_NAMES[d.getDay()]]),
            },
          }
        : { title: 'Validation', note: 'This is not a valid five-field cron expression.' },
    ],
  });
}
