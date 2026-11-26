import { downloadFile } from './download';

export function flattenObject(obj: unknown, prefix = ''): Record<string, unknown> {
  if (!obj || typeof obj !== 'object') return { [prefix || 'value']: obj };
  return Object.entries(obj).reduce<Record<string, unknown>>((acc, [k, value]) => {
    const pre = prefix.length ? prefix + ' ' : '';
    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      Object.assign(acc, flattenObject(value, pre + k));
    } else if (Array.isArray(value)) {
      acc[pre + k] = JSON.stringify(value);
    } else {
      acc[pre + k] = value;
    }
    return acc;
  }, {});
}

/** Serialise one object or an array of objects as CSV, one column per flattened key. */
export function toCSV(data: unknown) {
  const rows = Array.isArray(data) ? data : [data];
  const flattenedData = rows.map(row => flattenObject(row));

  // Get all unique headers across all rows
  const headers = Array.from(new Set(flattenedData.flatMap(row => Object.keys(row))));
  const cell = (value: unknown) => `"${(value === undefined || value === null ? '' : String(value)).replace(/"/g, '""')}"`;

  return [
    headers.map(cell).join(','),
    ...flattenedData.map(row => headers.map(h => cell(row[h])).join(',')),
  ].join('\n');
}

export function exportToCSV(data: unknown, filename: string) {
  downloadFile(toCSV(data), `${filename}.csv`, 'text/csv;charset=utf-8;');
}
