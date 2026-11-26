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

export function exportToCSV(data: unknown, filename: string) {
  const rows = Array.isArray(data) ? data : [data];
  const flattenedData = rows.map(row => flattenObject(row));
  
  // Get all unique headers across all rows
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
  URL.revokeObjectURL(url);
}
