import { expect, type Page } from '@playwright/test';
import { expectedSsl, rgb, type CheckLine, type SslAnswer, type SslExpectation, type Tone } from './oracle';
import { markupWasExecuted, readView, type ShownCheck, type SslView } from './page';

/** Comparisons shared by the SSL specs. Every mismatch is reported (soft) with the field and the input named. */

function compareCheck(shown: ShownCheck | undefined, want: CheckLine, view: SslView, ctx: string, name: string) {
  expect.soft(shown?.text, `${ctx}: wording of the ${name} check`).toBe(want.text);
  expect.soft(shown?.ok, `${ctx}: ${name} check "${want.text}" is ${want.ok ? 'passed (tick)' : 'failed (cross)'}`).toBe(want.ok);
  expect.soft(shown?.color, `${ctx}: colour of the ${name} check (${want.ok ? 'green' : 'red'})`).toBe(rgb(want.ok ? view.tokens.good : view.tokens.bad));
}

export interface CompareOptions {
  /** Compare the Server / Intermediate / Root label of every chain row (default) or only of the first. */
  roles?: 'all' | 'first';
  /**
   * Also require that an untrusted certificate with a complete chain is not explained by
   * "Missing intermediate certificates". Off by default so that one dedicated test owns that rule.
   */
  trustReason?: boolean;
}

/** Compares a view read from the page with what the oracle expects for an answer. */
export function expectViewEquals(shown: SslView, want: SslExpectation, ctx: string, options: CompareOptions = {}) {
  const tone = (t: Tone) => rgb(shown.tokens[t]);
  expect.soft(new Set([shown.tokens.good, shown.tokens.warn, shown.tokens.bad]).size, `${ctx}: the theme's green, amber and red must be three different colours (${JSON.stringify(shown.tokens)})`).toBe(3);

  expect.soft(shown.actions, `${ctx}: action buttons above the result`).toEqual(['Export CSV', 'Copy Summary']);
  expect.soft(shown.checks.length, `${ctx}: number of validation checks`).toBe(6);
  compareCheck(shown.checks[0], want.dns, shown, ctx, 'DNS');
  compareCheck(shown.checks[1], want.server, shown, ctx, 'server');
  compareCheck(shown.checks[3], want.expiry, shown, ctx, 'expiry');
  compareCheck(shown.checks[4], want.host, shown, ctx, 'hostname');
  compareCheck(shown.checks[5], want.hsts, shown, ctx, 'HSTS');

  const trust = shown.checks[2];
  expect.soft(trust?.ok, `${ctx}: trust check is ${want.trustOk ? 'passed (tick)' : 'failed (cross)'}`).toBe(want.trustOk);
  expect.soft(trust?.color, `${ctx}: colour of the trust check`).toBe(tone(want.trustOk ? 'good' : 'bad'));
  if (want.trustText !== null) {
    expect.soft(trust?.text, `${ctx}: wording of the trust check`).toBe(want.trustText);
  } else if (options.trustReason) {
    // Untrusted although the chain has an intermediate and is not self-signed: the cause is expiry or the host name.
    expect.soft(['Missing intermediate certificates', 'Self-signed certificate', 'Certificate is trusted'],
      `${ctx}: the certificate is untrusted because it is expired or issued for another host; its chain is complete, so the trust check must not give this reason`)
      .not.toContain(trust?.text);
  }

  expect.soft(shown.cards.map(card => [card.label, card.value]), `${ctx}: summary cards [caption, value]`).toEqual(want.cards);
  const days = shown.cards.find(card => card.label === 'Days Until Expiry');
  const gradeCard = shown.cards.find(card => card.label === 'Security Grade');
  expect.soft(days?.color, `${ctx}: colour of "Days Until Expiry" ${want.cards[0][1]} (${want.daysTone})`).toBe(tone(want.daysTone));
  expect.soft(days?.edge, `${ctx}: top border of the "Days Until Expiry" card ${want.cards[0][1]} (${want.daysTone})`).toBe(tone(want.daysTone));
  expect.soft(gradeCard?.color, `${ctx}: colour of "Security Grade" ${want.cards[1][1]} (${want.gradeTone})`).toBe(tone(want.gradeTone));
  expect.soft(gradeCard?.edge, `${ctx}: top border of the "Security Grade" card ${want.cards[1][1]} (${want.gradeTone})`).toBe(tone(want.gradeTone));

  expect.soft(shown.responseTime, `${ctx}: response time next to "Certificate Details"`).toBe(want.responseTime);
  expect.soft(shown.details.map(([label]) => label), `${ctx}: rows of "Certificate Details", in order`).toEqual(want.details.map(([label]) => label));
  for (const [label, value] of want.details) {
    const rowShown = shown.details.find(([name]) => name === label);
    if (rowShown) expect.soft(rowShown[1], `${ctx}: "${label}" in Certificate Details`).toBe(value);
  }

  expect.soft(shown.sanTitle, `${ctx}: heading of the SAN list (with its count)`).toBe(want.sanTitle);
  expect.soft(shown.sans, `${ctx}: subject alternative names, in order`).toEqual(want.sans);

  expect.soft(shown.chainTitle, `${ctx}: heading of the certificate chain (with its count)`).toBe(want.chainTitle);
  expect.soft(shown.chain.length, `${ctx}: number of chain rows`).toBe(want.chain.length);
  for (const [i, cert] of want.chain.entries()) {
    const rowShown = shown.chain[i];
    if (!rowShown) continue;
    const where = `${ctx}: chain certificate #${i + 1} ("${cert.subject}")`;
    expect.soft(rowShown.subject, `${where}: subject`).toBe(cert.subject);
    if (options.roles !== 'first' || i === 0) {
      expect.soft(rowShown.badge, `${where}: role label next to the subject (issuer is "${cert.issuer}")`).toBe(cert.role);
      expect.soft(rowShown.side, `${where}: role label under the icon (issuer is "${cert.issuer}")`).toBe(cert.role);
    } else {
      expect.soft(rowShown.side, `${where}: both role labels agree`).toBe(rowShown.badge);
    }
    expect.soft(rowShown.org, `${where}: organisation line`).toBe(cert.org);
    expect.soft(rowShown.valid, `${where}: validity line`).toBe(cert.valid);
    expect.soft(rowShown.issuer, `${where}: issuer line`).toBe(cert.issuer);
    expect.soft(rowShown.key, `${where}: key line`).toBe(cert.key);
  }
}

/** Reads the page and compares everything in the result with `answer`. */
export async function expectPageShows(page: Page, answer: SslAnswer, ctx: string, options: CompareOptions = {}): Promise<SslView> {
  const shown = await readView(page);
  expectViewEquals(shown, expectedSsl(answer), ctx, options);
  return shown;
}

export async function expectNoMarkupExecuted(page: Page, ctx: string) {
  expect.soft(await markupWasExecuted(page), `${ctx}: markup inside values must be shown as text, never turned into elements or run`).toEqual([]);
}
