import { expect, type Download, type Page, type Request, type Route } from '@playwright/test';
import { readFile } from 'node:fs/promises';

/**
 * Helpers for what leaves a page: downloads, the clipboard and API calls.
 */

export interface CapturedDownload {
  filename: string;
  text: string;
  download: Download;
}

/** Runs `trigger`, waits for the browser download it starts, and reads the file. */
export async function captureDownload(page: Page, trigger: () => Promise<unknown>, timeout = 30_000): Promise<CapturedDownload> {
  const [download] = await Promise.all([page.waitForEvent('download', { timeout }), trigger()]);
  const path = await download.path();
  expect(path, 'the download should produce a file').toBeTruthy();
  return { filename: download.suggestedFilename(), text: await readFile(path as string, 'utf8'), download };
}

/** What a user would paste after pressing a "Copy" button. */
export async function readClipboard(page: Page): Promise<string> {
  return page.evaluate(() => navigator.clipboard.readText());
}

/** Empties the clipboard so a stale value cannot satisfy an assertion. */
export async function clearClipboard(page: Page): Promise<void> {
  await page.evaluate(() => navigator.clipboard.writeText(''));
}

export interface ApiCall {
  method: string;
  url: string;
  /** Parsed JSON request body, or the raw text when it is not JSON. */
  body: unknown;
}

export interface MockOptions {
  status?: number;
  method?: string;
  /** Milliseconds to hold the response, to observe loading states. */
  delayMs?: number;
  headers?: Record<string, string>;
}

function requestBody(request: Request): unknown {
  const raw = request.postData();
  if (raw == null) return null;
  try { return JSON.parse(raw); } catch { return raw; }
}

/**
 * Answers matching requests with `payload` and records what the page sent.
 *
 * `payload` may be a function of the recorded call, so a test can build the
 * response from the request (e.g. echo the domain the user typed).
 * Use for third-party-backed endpoints where a live answer cannot be predicted.
 */
export async function mockApi(
  page: Page,
  url: string | RegExp,
  payload: unknown | ((call: ApiCall) => unknown),
  options: MockOptions = {},
): Promise<ApiCall[]> {
  const calls: ApiCall[] = [];
  await page.route(url, async (route: Route) => {
    const request = route.request();
    if (options.method && request.method() !== options.method) return route.fallback();
    const call: ApiCall = { method: request.method(), url: request.url(), body: requestBody(request) };
    calls.push(call);
    if (options.delayMs) await new Promise(resolve => setTimeout(resolve, options.delayMs));
    const body = typeof payload === 'function' ? (payload as (c: ApiCall) => unknown)(call) : payload;
    await route.fulfill({
      status: options.status ?? 200,
      contentType: 'application/json',
      headers: options.headers,
      body: typeof body === 'string' ? body : JSON.stringify(body),
    });
  });
  return calls;
}

/** Makes matching requests fail at the network level (offline, DNS failure). */
export async function failApi(page: Page, url: string | RegExp): Promise<void> {
  await page.route(url, route => route.abort('failed'));
}

export interface LiveExchange<T = unknown> {
  status: number;
  request: unknown;
  response: T;
}

/**
 * Runs `trigger` and returns the real request/response pair for `urlPart`.
 * Use when the backend is the source of truth: the UI must show exactly what
 * the API returned.
 */
export async function captureApi<T = unknown>(
  page: Page,
  urlPart: string | RegExp,
  trigger: () => Promise<unknown>,
  timeout = 45_000,
): Promise<LiveExchange<T>> {
  const matches = (url: string) => (typeof urlPart === 'string' ? url.includes(urlPart) : urlPart.test(url));
  const [response] = await Promise.all([
    page.waitForResponse(res => matches(res.url()) && res.request().method() !== 'OPTIONS', { timeout }),
    trigger(),
  ]);
  let parsed: unknown = null;
  try { parsed = await response.json(); } catch { parsed = await response.text().catch(() => null); }
  return { status: response.status(), request: requestBody(response.request()), response: parsed as T };
}
