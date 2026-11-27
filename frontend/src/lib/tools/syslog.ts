/**
 * Shared helpers for the browser-side log analyzers (auth-log, mail-log):
 * line iteration, the syslog line header, IP validation and the timeline.
 * Plain TypeScript with no React or DOM use, so the unit tests import it
 * directly.
 *
 * Times are kept as written in the log. A timestamp is the wall-clock time of
 * the line stored as if it were UTC, so no time zone conversion ever happens
 * and the report shows the same hours as the log file. An ISO 8601 offset is
 * accepted and ignored for the same reason.
 */

export interface LogFinding {
  severity: 'critical' | 'warning' | 'info' | 'ok';
  title: string;
  detail?: string;
  /** An in-app page that helps with this finding. */
  link?: { href: string; label: string };
}

const SEVERITY_RANK: Record<LogFinding['severity'], number> = { critical: 0, warning: 1, info: 2, ok: 3 };

/** Most severe first. The sort is stable, so the order within a severity is kept. */
export function sortFindings(findings: LogFinding[]): LogFinding[] {
  return findings.slice().sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
}

/** Lines longer than this are cut before matching, which bounds the work any pattern can do. */
export const MAX_LINE_LENGTH = 4096;

/**
 * Calls `fn` for every non-empty line without building an array of all lines.
 * Handles LF and CRLF. Returns the number of lines passed to `fn`.
 */
export function forEachLine(text: string, fn: (line: string) => void): number {
  const length = text.length;
  let start = 0;
  let count = 0;
  while (start < length) {
    let end = text.indexOf('\n', start);
    if (end === -1) end = length;
    let stop = end;
    if (stop > start && text.charCodeAt(stop - 1) === 13) stop -= 1;
    if (stop > start) {
      count += 1;
      fn(stop - start > MAX_LINE_LENGTH ? text.slice(start, start + MAX_LINE_LENGTH) : text.slice(start, stop));
    }
    start = end + 1;
  }
  return count;
}

/* ---------- Syslog header ---------- */

export interface SyslogLine {
  /** Wall-clock time as written, in milliseconds. NaN when the line has no timestamp. */
  ts: number;
  host: string;
  /** The tag without the PID: `sshd`, `sudo`, `postfix/smtpd`. Empty when the line has no tag. */
  program: string;
  message: string;
}

export interface SyslogReader {
  parse(line: string): SyslogLine;
}

const MONTHS: Record<string, number> = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

// Traditional: "Nov 27 10:15:01 host " (the day is space padded, journalctl -o short-precise adds a fraction).
const TRADITIONAL = /^([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d{2}):(\d{2}):(\d{2})(?:\.\d+)? (\S+) /;
// ISO 8601: "2026-11-27T10:15:01.123456+00:00 host " (rsyslog) or "2026-11-27T10:15:01+0000 host " (journalctl -o short-iso).
const ISO = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})? (\S+) /;

const HOUR_MS = 3600000;
const DAY_MS = 86400000;

function isLeapYear(year: number): boolean {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
}

/**
 * Reads the `timestamp host tag[pid]: message` header of syslog lines.
 *
 * Traditional syslog timestamps carry no year. The current year is assumed,
 * and when that would put the line in the future (more than a day ahead of
 * `now`, to allow for a server in another time zone) the previous year is
 * used. February 29 falls back to the latest leap year.
 */
export function createSyslogReader(now: Date | number = Date.now()): SyslogReader {
  const nowDate = new Date(now);
  const valid = !Number.isNaN(nowDate.getTime());
  const reference = valid ? nowDate : new Date();
  const nowYear = reference.getFullYear();
  const nowWall = Date.UTC(nowYear, reference.getMonth(), reference.getDate(), reference.getHours(), reference.getMinutes(), reference.getSeconds());
  // Start of day per "month * 32 + day", so the year is worked out once per calendar day.
  const dayStarts = new Map<number, number>();

  function dayStart(month: number, day: number): number {
    const key = month * 32 + day;
    const cached = dayStarts.get(key);
    if (cached !== undefined) return cached;
    let year = nowYear;
    if (Date.UTC(year, month, day) > nowWall + DAY_MS) year -= 1;
    if (month === 1 && day === 29) {
      while (!isLeapYear(year)) year -= 1;
    }
    const start = Date.UTC(year, month, day);
    dayStarts.set(key, start);
    return start;
  }

  function parse(line: string): SyslogLine {
    const first = line.charCodeAt(0);
    let ts = NaN;
    let host = '';
    let rest = line;
    if (first >= 48 && first <= 57) {
      const match = ISO.exec(line);
      if (match) {
        const year = Number(match[1]);
        const month = Number(match[2]);
        const day = Number(match[3]);
        const hour = Number(match[4]);
        const minute = Number(match[5]);
        const second = Number(match[6]);
        if (year >= 1970 && year <= 2200 && month >= 1 && month <= 12 && day >= 1 && day <= 31 && hour <= 23 && minute <= 59 && second <= 60) {
          ts = Date.UTC(year, month - 1, day, hour, minute, second);
          host = match[7];
          rest = line.slice(match[0].length);
        }
      }
    } else if (first >= 65 && first <= 90) {
      const match = TRADITIONAL.exec(line);
      if (match) {
        const month = MONTHS[match[1]];
        const day = Number(match[2]);
        const hour = Number(match[3]);
        const minute = Number(match[4]);
        const second = Number(match[5]);
        if (month !== undefined && day >= 1 && day <= 31 && hour <= 23 && minute <= 59 && second <= 60) {
          ts = dayStart(month, day) + hour * HOUR_MS + minute * 60000 + second * 1000;
          host = match[6];
          rest = line.slice(match[0].length);
        }
      }
    }

    // "tag[pid]: message" or "tag: message". A tag never contains a space.
    let program = '';
    let message = rest;
    const colon = rest.indexOf(':');
    if (colon > 0) {
      const tag = rest.slice(0, colon);
      if (tag.indexOf(' ') === -1) {
        const bracket = tag.indexOf('[');
        program = bracket === -1 ? tag : tag.slice(0, bracket);
        message = rest.charCodeAt(colon + 1) === 32 ? rest.slice(colon + 2) : rest.slice(colon + 1);
      }
    }
    return { ts, host, program, message };
  }

  return { parse };
}

function pad2(value: number): string {
  return value < 10 ? `0${value}` : String(value);
}

/** `2026-11-27 10:15:01`, the time as written in the log. Empty for a missing time. */
export function formatLogTime(ts: number | null | undefined): string {
  if (ts === null || ts === undefined || Number.isNaN(ts)) return '';
  const date = new Date(ts);
  return `${date.getUTCFullYear()}-${pad2(date.getUTCMonth() + 1)}-${pad2(date.getUTCDate())} ${pad2(date.getUTCHours())}:${pad2(date.getUTCMinutes())}:${pad2(date.getUTCSeconds())}`;
}

/* ---------- IP addresses ---------- */

const IPV4 = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const IPV6_CHARS = /^[0-9A-Fa-f:.]+$/;
const HEX_GROUP = /^[0-9A-Fa-f]{1,4}$/;

function isIPv6(value: string): boolean {
  if (value.length < 2 || value.length > 45 || !IPV6_CHARS.test(value)) return false;
  const gap = value.indexOf('::');
  if (gap !== -1 && value.indexOf('::', gap + 1) !== -1) return false;
  let groups: string[];
  if (gap === -1) {
    groups = value.split(':');
  } else {
    const head = gap === 0 ? [] : value.slice(0, gap).split(':');
    const tail = gap + 2 === value.length ? [] : value.slice(gap + 2).split(':');
    groups = head.concat(tail);
  }
  let count = 0;
  for (let index = 0; index < groups.length; index += 1) {
    const group = groups[index];
    if (index === groups.length - 1 && group.indexOf('.') !== -1) {
      if (!IPV4.test(group)) return false;
      count += 2;
    } else {
      if (!HEX_GROUP.test(group)) return false;
      count += 1;
    }
  }
  return gap === -1 ? count === 8 : count <= 7;
}

/** 4 or 6 for a complete, valid address. 0 for anything else (hostnames, CIDR, partial addresses). */
export function ipVersion(value: string): 0 | 4 | 6 {
  if (typeof value !== 'string') return 0;
  if (IPV4.test(value)) return 4;
  if (value.indexOf(':') !== -1 && isIPv6(value)) return 6;
  return 0;
}

/**
 * The address in a canonical spelling (lower case, no `%zone` suffix), or an
 * empty string when the value is not a valid IPv4 or IPv6 address.
 */
export function cleanIp(value: string): string {
  if (typeof value !== 'string') return '';
  let candidate = value;
  const zone = candidate.indexOf('%');
  if (zone > 0) candidate = candidate.slice(0, zone);
  const version = ipVersion(candidate);
  if (version === 0) return '';
  return version === 6 ? candidate.toLowerCase() : candidate;
}

/** Loopback, private, link-local, CGNAT and unspecified addresses: never good candidates for a block list. */
export function isLocalAddress(ip: string): boolean {
  const version = ipVersion(ip);
  if (version === 4) {
    const parts = ip.split('.');
    const a = Number(parts[0]);
    const b = Number(parts[1]);
    return a === 0 || a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
  }
  if (version === 6) {
    const lower = ip.toLowerCase();
    if (lower === '::' || lower === '::1') return true;
    if (lower.startsWith('::ffff:')) {
      const mapped = lower.slice(7);
      return ipVersion(mapped) === 4 ? isLocalAddress(mapped) : false;
    }
    // fe80::/10 link-local and fc00::/7 unique local.
    return /^fe[89ab]/.test(lower) || /^f[cd]/.test(lower);
  }
  return false;
}

/* ---------- Timeline ---------- */

export interface TimelineBucket {
  /** Start of the hour or day, same clock as SyslogLine.ts. */
  start: number;
  /** `2026-11-27 10:00` for hours, `2026-11-27` for days. */
  label: string;
  /** One count per series, in the order the counter was created with. */
  counts: number[];
}

export interface Timeline {
  unit: 'hour' | 'day';
  buckets: TimelineBucket[];
  /** Largest sum of all series in one bucket. */
  max: number;
  /** True when the log covers more days than fit and only the latest are kept. */
  truncated: boolean;
}

export interface TimelineCounter {
  add(ts: number, series: number, amount?: number): void;
  build(maxHours?: number, maxDays?: number): Timeline;
}

/**
 * Counts events per hour. `build` returns hourly buckets with the gaps
 * filled, or daily buckets when the log covers more than `maxHours` hours.
 */
export function createTimelineCounter(seriesCount: number): TimelineCounter {
  const hours = new Map<number, number[]>();

  function add(ts: number, series: number, amount = 1): void {
    if (Number.isNaN(ts)) return;
    const hour = Math.floor(ts / HOUR_MS);
    let counts = hours.get(hour);
    if (!counts) {
      counts = new Array<number>(seriesCount).fill(0);
      hours.set(hour, counts);
    }
    counts[series] += amount;
  }

  function build(maxHours = 336, maxDays = 366): Timeline {
    if (hours.size === 0) return { unit: 'hour', buckets: [], max: 0, truncated: false };
    let first = Infinity;
    let last = -Infinity;
    for (const hour of hours.keys()) {
      if (hour < first) first = hour;
      if (hour > last) last = hour;
    }

    const hourly = last - first + 1 <= maxHours;
    const step = hourly ? 1 : 24;
    const size = hourly ? HOUR_MS : DAY_MS;
    const merged = new Map<number, number[]>();
    for (const [hour, counts] of hours) {
      const key = Math.floor(hour / step);
      const target = merged.get(key);
      if (!target) merged.set(key, counts.slice());
      else for (let index = 0; index < seriesCount; index += 1) target[index] += counts[index];
    }

    const end = Math.floor(last / step);
    let begin = Math.floor(first / step);
    let truncated = false;
    const limit = hourly ? maxHours : maxDays;
    if (end - begin + 1 > limit) {
      begin = end - limit + 1;
      truncated = true;
    }

    const buckets: TimelineBucket[] = [];
    let max = 0;
    for (let key = begin; key <= end; key += 1) {
      const counts = merged.get(key) || new Array<number>(seriesCount).fill(0);
      let sum = 0;
      for (let index = 0; index < seriesCount; index += 1) sum += counts[index];
      if (sum > max) max = sum;
      const start = key * size;
      const text = formatLogTime(start);
      buckets.push({ start, label: hourly ? text.slice(0, 16) : text.slice(0, 10), counts });
    }
    return { unit: hourly ? 'hour' : 'day', buckets, max, truncated };
  }

  return { add, build };
}
