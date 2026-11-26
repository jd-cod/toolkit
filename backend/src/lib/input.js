/**
 * Request bodies are untrusted JSON: a field expected to be a string can
 * arrive as a number, array or object, and calling string methods on those
 * throws. `str` returns the value only when it is a non-empty string.
 */
export function str(value, fallback = '') {
  return typeof value === 'string' && value ? value : fallback;
}

/** Returns the URL string when it is an absolute http(s) URL, otherwise ''. */
export function httpUrl(value) {
  const raw = str(value).trim();
  if (!raw) return '';
  try {
    const url = new URL(raw);
    return url.protocol === 'http:' || url.protocol === 'https:' ? raw : '';
  } catch {
    return '';
  }
}
