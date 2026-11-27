import type { APIRequestContext, BrowserContext } from '@playwright/test';
import { randomBytes } from 'node:crypto';
import { botFeedFile } from './catalog';

/**
 * Stand-in for the object storage behind "Share Snapshot".
 *
 * Sharing a traffic analysis stores the log in Cloudflare R2 (a third-party
 * service) and the share record in our own database. Development and CI
 * stacks usually run without R2 credentials, so the storage endpoints answer
 * 503 and sharing cannot work at all.
 *
 * This class replaces ONLY the storage part, in the browser:
 *   POST /api/storage/upload          keeps the uploaded log in memory
 *   GET  /api/storage/download/:code  returns a link to that copy
 *   the link itself                   serves the stored log
 * and completes the two backend answers that need a storage link:
 *   GET  /api/share/:code             adds `download_url` for open shares
 *   POST /api/share/:code/verify      turns the backend's "cannot create a
 *                                     download link" (after it ACCEPTED the
 *                                     password) into a success with the link
 *
 * Everything else is the real backend: creating the share record, the
 * password check, expiry and "not found". When the stack has real storage,
 * `needed()` returns false and nothing is replaced.
 */
export class StorageStandIn {
  private static readonly ORIGIN = 'https://e2e-object-storage.invalid';
  /** share code → uploaded log text */
  readonly objects = new Map<string, string>();
  /** share codes whose stored log was actually fetched by a page */
  readonly downloads: string[] = [];

  /** True when the stack under test has no object storage configured. */
  static async needed(request: APIRequestContext): Promise<boolean> {
    if (process.env.E2E_STORAGE === 'real') return false;
    const probe = await request.get('/api/storage/download/e2eprobe0');
    return probe.status() === 503;
  }

  private link(code: string): string {
    return `${StorageStandIn.ORIGIN}/shares/${code}.log.gz`;
  }

  async install(context: BrowserContext): Promise<void> {
    await context.route('**/api/storage/upload', async route => {
      const body = route.request().postDataJSON() as { content?: string };
      const content = body?.content ?? '';
      if (!content) return route.fulfill({ status: 400, contentType: 'application/json', body: JSON.stringify({ error: 'No content provided.' }) });
      const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
      // An identifier, not test data: it only has to be unique among stored shares.
      const code = Array.from(randomBytes(8), byte => alphabet[byte % alphabet.length]).join('');
      this.objects.set(code, content);
      await route.fulfill({
        status: 200, contentType: 'application/json',
        body: JSON.stringify({ success: true, shareCode: code, r2Key: `shares/${code}.log.gz`, compressedSize: content.length, decompressedSize: content.length, lineCount: content.split('\n').length }),
      });
    });

    await context.route('**/api/storage/download/*', async route => {
      const code = new URL(route.request().url()).pathname.split('/').pop() as string;
      if (!this.objects.has(code)) return route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ error: 'Failed to generate download URL.' }) });
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ success: true, downloadUrl: this.link(code), expiresIn: 3600 }) });
    });

    await context.route(/\/api\/share\/[A-Za-z0-9]+$/, async route => {
      if (route.request().method() !== 'GET') return route.fallback();
      const code = new URL(route.request().url()).pathname.split('/').pop() as string;
      const response = await route.fetch();
      if (!response.ok() || !this.objects.has(code)) return route.fulfill({ response });
      const meta = await response.json();
      if (meta.share_type === 'nginx' && !meta.has_password && !meta.download_url) {
        meta.download_url = this.link(code);
        meta.r2_key = `shares/${code}.log.gz`;
      }
      await route.fulfill({ response, json: meta });
    });

    await context.route(/\/api\/share\/[A-Za-z0-9]+\/verify$/, async route => {
      const code = new URL(route.request().url()).pathname.split('/').slice(-2)[0];
      const response = await route.fetch();
      const text = await response.text();
      // The backend checks the password first; it reaches the storage step only when the password was right.
      if (response.status() === 500 && /download URL/i.test(text) && this.objects.has(code)) {
        const meta = await (await route.request().frame().page().request.get(`/api/share/${code}`)).json().catch(() => ({}));
        return route.fulfill({
          status: 200, contentType: 'application/json',
          body: JSON.stringify({ share_type: 'nginx', title: meta.title ?? '', download_url: this.link(code), r2_key: `shares/${code}.log.gz`, source_url: '' }),
        });
      }
      await route.fulfill({ response, body: text });
    });

    await context.route(`${StorageStandIn.ORIGIN}/**`, async route => {
      const code = (new URL(route.request().url()).pathname.split('/').pop() as string).replace(/\.log\.gz$/, '');
      const content = this.objects.get(code);
      if (content === undefined) return route.fulfill({ status: 404, body: 'not found' });
      this.downloads.push(code);
      await route.fulfill({ status: 200, contentType: 'text/plain; charset=utf-8', headers: { 'access-control-allow-origin': '*' }, body: content });
    });
  }
}

/** Pins the verified-bot address feed for every page of a browser context (see catalog.ts). */
export async function pinBotFeed(context: BrowserContext): Promise<void> {
  await context.route('**/data/verified-bots.json*', route =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(botFeedFile()) }));
}
