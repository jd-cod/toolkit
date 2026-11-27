import type { Page, Route } from '@playwright/test';
import type { ApiCall } from './io';

/**
 * Scripted API answers, one decision per request.
 *
 * `mockApi` (in _support/io) answers every request the same way after a fixed
 * delay. Three situations need more control than that:
 *  - holding a response open until the test has looked at the loading state
 *  - answering request A after request B (a stale response)
 *  - a different HTTP status for each request in one test
 *
 * `respond` is called for every matching request, in order, and may wait on a
 * `deferred()` the test resolves when it is ready.
 */

export interface ScriptedReply {
  status?: number;
  /** Sent as JSON unless it is a string. */
  body?: unknown;
  contentType?: string;
  /** Fail the request at the network level instead of answering. */
  abort?: boolean;
}

export interface ApiScript {
  /** Every request seen so far, in order. */
  calls: ApiCall[];
  /** Resolves once the reply to request number `index` (0-based) was handed to the browser. */
  delivered(index: number): Promise<void>;
}

export interface Deferred<T = void> {
  promise: Promise<T>;
  resolve(value: T): void;
}

export function deferred<T = void>(): Deferred<T> {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}

export async function scriptApi(
  page: Page,
  url: string | RegExp,
  respond: (call: ApiCall, index: number) => ScriptedReply | Promise<ScriptedReply>,
): Promise<ApiScript> {
  const calls: ApiCall[] = [];
  const delivery: Deferred[] = [];
  const slot = (index: number) => (delivery[index] ??= deferred());

  await page.route(url, async (route: Route) => {
    const request = route.request();
    const raw = request.postData();
    let body: unknown = raw;
    if (raw != null) { try { body = JSON.parse(raw); } catch { body = raw; } }
    const call: ApiCall = { method: request.method(), url: request.url(), body };
    const index = calls.push(call) - 1;
    const reply = await respond(call, index);
    try {
      if (reply.abort) await route.abort('failed');
      else {
        await route.fulfill({
          status: reply.status ?? 200,
          contentType: reply.contentType ?? 'application/json',
          body: typeof reply.body === 'string' ? reply.body : JSON.stringify(reply.body ?? {}),
        });
      }
    } catch {
      // The page was closed or navigated away while the reply was held.
    }
    slot(index).resolve();
  });

  return { calls, delivered: index => slot(index).promise };
}

/**
 * Lets the page finish reacting to something that just happened (a response
 * that arrived, a click): several animation frames, then one timer turn.
 * Use it before asserting that something did NOT change.
 */
export async function settle(page: Page): Promise<void> {
  await page.evaluate(() => new Promise<void>(resolve => {
    let frames = 0;
    const tick = () => { if (++frames >= 6) setTimeout(resolve, 0); else requestAnimationFrame(tick); };
    requestAnimationFrame(tick);
  }));
}
