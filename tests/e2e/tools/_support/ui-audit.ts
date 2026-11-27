import { expect, type Page } from '@playwright/test';

/**
 * Generic "is this page visually broken?" checks, run inside the browser.
 *
 * It looks at what a person would trip over, not at pixels:
 *  - the page scrolls sideways
 *  - a control has no size, sits outside the viewport, or is covered by
 *    something else so a click would land on a different element
 *  - a control has no accessible name (nothing a user or screen reader can
 *    read to know what it does)
 *  - a button's label is cut off
 *  - leaked placeholders in visible text (`undefined`, `NaN`, `[object Object]`,
 *    `Invalid Date`)
 *  - broken images, duplicate element ids
 *
 * Every finding names the element, so the failure message says what to fix.
 */

export interface UiAuditOptions {
  /** CSS selector of the region to audit. Default: `main`, falling back to `body`. */
  scope?: string;
  /** CSS selectors of elements to leave out (and everything inside them). */
  ignore?: string[];
  /** Finding kinds to leave out, for a documented reason. */
  skipKinds?: UiFindingKind[];
  /** Extra regular expressions (source strings) that must not appear in visible text. */
  forbiddenText?: string[];
}

export type UiFindingKind =
  | 'horizontal-overflow'
  | 'zero-size'
  | 'outside-viewport'
  | 'covered'
  | 'no-accessible-name'
  | 'clipped-label'
  | 'placeholder-text'
  | 'broken-image'
  | 'duplicate-id';

export interface UiFinding {
  kind: UiFindingKind;
  element: string;
  detail: string;
}

export async function auditUi(page: Page, options: UiAuditOptions = {}): Promise<UiFinding[]> {
  const findings = await page.evaluate(async (opts) => {
    const out: { kind: string; element: string; detail: string }[] = [];
    const root = (opts.scope && document.querySelector(opts.scope)) || document.querySelector('main') || document.body;
    const ignored = (opts.ignore || []).flatMap(sel => Array.from(document.querySelectorAll(sel)));
    const isIgnored = (el: Element) => ignored.some(box => box === el || box.contains(el));

    const describe = (el: Element) => {
      const id = el.id ? `#${el.id}` : '';
      const cls = typeof el.className === 'string' && el.className.trim()
        ? '.' + el.className.trim().split(/\s+/).slice(0, 2).join('.') : '';
      const text = (el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 40);
      const extra = el.getAttribute('aria-label') || el.getAttribute('name') || el.getAttribute('placeholder') || text;
      return `<${el.tagName.toLowerCase()}${id}${cls}>${extra ? ` "${extra}"` : ''}`;
    };

    const isShown = (el: Element) => {
      const rect = el.getBoundingClientRect();
      if (rect.width === 0 && rect.height === 0) return false;
      // Content of a closed <details> keeps a box in Chrome but is not rendered.
      const details = el.closest('details:not([open])');
      if (details && !el.closest('summary')) return false;
      const check = (el as Element & { checkVisibility?: (o: object) => boolean }).checkVisibility;
      if (typeof check === 'function' && !check.call(el, { checkOpacity: true, checkVisibilityCSS: true, contentVisibilityAuto: true })) return false;
      for (let node: Element | null = el; node; node = node.parentElement) {
        const style = getComputedStyle(node);
        if (style.display === 'none' || style.visibility === 'hidden' || Number(style.opacity) === 0) return false;
        if ((node as HTMLElement).hidden) return false;
      }
      return true;
    };

    const insideScroller = (el: Element) => {
      for (let node = el.parentElement; node && node !== document.body; node = node.parentElement) {
        const style = getComputedStyle(node);
        if (/(auto|scroll)/.test(style.overflowX) && node.scrollWidth > node.clientWidth) return true;
      }
      return false;
    };

    const accessibleName = (el: Element): string => {
      const labelledBy = el.getAttribute('aria-labelledby');
      if (labelledBy) {
        const text = labelledBy.split(/\s+/).map(id => document.getElementById(id)?.textContent || '').join(' ').trim();
        if (text) return text;
      }
      const aria = el.getAttribute('aria-label');
      if (aria && aria.trim()) return aria.trim();
      if (el instanceof HTMLInputElement || el instanceof HTMLSelectElement || el instanceof HTMLTextAreaElement) {
        const labels = el.labels ? Array.from(el.labels).map(l => l.textContent || '').join(' ').trim() : '';
        if (labels) return labels;
        if (el instanceof HTMLInputElement && ['button', 'submit', 'reset'].includes(el.type) && el.value) return el.value;
        const placeholder = el.getAttribute('placeholder');
        if (placeholder && placeholder.trim()) return placeholder.trim();
      }
      const text = (el.textContent || '').replace(/\s+/g, ' ').trim();
      if (text) return text;
      const img = el.querySelector('img[alt]');
      if (img && img.getAttribute('alt')) return img.getAttribute('alt') as string;
      const title = el.getAttribute('title');
      return title ? title.trim() : '';
    };

    // 1. Sideways scrolling of the whole page.
    const doc = document.documentElement;
    if (doc.scrollWidth > doc.clientWidth + 1) {
      const widest = Array.from(root.querySelectorAll('*'))
        .filter(el => isShown(el) && !isIgnored(el) && !insideScroller(el) && el.getBoundingClientRect().right > doc.clientWidth + 1)
        .slice(0, 3).map(describe).join(', ');
      out.push({
        kind: 'horizontal-overflow', element: 'document',
        detail: `page is ${doc.scrollWidth}px wide in a ${doc.clientWidth}px viewport${widest ? `; pushed out by ${widest}` : ''}`,
      });
    }

    // 2. Interactive controls.
    const controls = Array.from(root.querySelectorAll(
      'button, a[href], input:not([type="hidden"]), select, textarea, summary, [role="button"], [role="tab"], [role="slider"], [role="checkbox"], [role="switch"], [role="link"], [tabindex]:not([tabindex="-1"])',
    )).filter(el => !isIgnored(el));

    for (const el of controls) {
      if (!isShown(el)) continue;
      const visuallyHiddenInput = el instanceof HTMLInputElement && el.type === 'file';
      const rect = el.getBoundingClientRect();
      if (!visuallyHiddenInput && (rect.width < 4 || rect.height < 4)) {
        out.push({ kind: 'zero-size', element: describe(el), detail: `rendered ${Math.round(rect.width)}x${Math.round(rect.height)}px` });
        continue;
      }
      if (!accessibleName(el)) {
        out.push({ kind: 'no-accessible-name', element: describe(el), detail: 'no text, label, aria-label, title or placeholder' });
      }
      if (visuallyHiddenInput) continue;

      if (!insideScroller(el) && (rect.left < -1 || rect.right > doc.clientWidth + 1)) {
        out.push({
          kind: 'outside-viewport', element: describe(el),
          detail: `spans x=${Math.round(rect.left)}..${Math.round(rect.right)} in a ${doc.clientWidth}px wide viewport`,
        });
        continue;
      }

      if (el instanceof HTMLButtonElement && el.scrollWidth > el.clientWidth + 2 && getComputedStyle(el).overflow !== 'visible') {
        // scrollWidth also counts decorative pseudo-elements (a hover shimmer that slides across the
        // button), so measure the real content before reporting.
        const range = document.createRange();
        range.selectNodeContents(el);
        const content = range.getBoundingClientRect();
        if (content.width > 0 && (content.right > rect.right + 2 || content.left < rect.left - 2)) {
          out.push({ kind: 'clipped-label', element: describe(el), detail: `label needs ${Math.round(content.width)}px, button shows ${el.clientWidth}px` });
        }
      }

      // Would a click at the centre reach this control?
      (el as HTMLElement).scrollIntoView({ block: 'center', inline: 'nearest' });
      const box = el.getBoundingClientRect();
      const x = Math.min(Math.max(box.left + box.width / 2, 0), doc.clientWidth - 1);
      const y = Math.min(Math.max(box.top + box.height / 2, 0), doc.clientHeight - 1);
      if (box.bottom < 0 || box.top > doc.clientHeight) continue;
      const hit = document.elementFromPoint(x, y);
      if (!hit) continue;
      const label = hit.closest('label');
      const reaches = hit === el || el.contains(hit) || hit.contains(el)
        || (label !== null && (label.contains(el) || (el.id !== '' && label.getAttribute('for') === el.id)));
      if (!reaches) {
        out.push({ kind: 'covered', element: describe(el), detail: `a click at its centre lands on ${describe(hit)}` });
      }
    }
    window.scrollTo(0, 0);

    // 3. Leaked placeholders in visible text.
    const patterns = [
      '\\bundefined\\b', '\\bNaN\\b', '\\[object Object\\]', 'Invalid Date',
      ...(opts.forbiddenText || []),
    ].map(source => new RegExp(source));
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const seen = new Set<string>();
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      const parent = node.parentElement;
      const text = (node.nodeValue || '').trim();
      if (!parent || !text) continue;
      if (['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEXTAREA', 'CODE', 'PRE'].includes(parent.tagName)) continue;
      const hit = patterns.find(re => re.test(text));
      if (!hit || isIgnored(parent) || !isShown(parent)) continue;
      const key = `${hit.source}|${text.slice(0, 60)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ kind: 'placeholder-text', element: describe(parent), detail: `visible text "${text.slice(0, 80)}" matches /${hit.source}/` });
    }

    // 4. Images that failed to load.
    for (const img of Array.from(root.querySelectorAll('img'))) {
      if (isIgnored(img) || !isShown(img)) continue;
      if (img.complete && img.naturalWidth === 0) out.push({ kind: 'broken-image', element: describe(img), detail: img.currentSrc || img.src });
    }

    // 5. Duplicate ids (break labels and selectors).
    const ids = new Map<string, number>();
    for (const el of Array.from(document.querySelectorAll('[id]'))) {
      if (el.id && !el.closest('svg')) ids.set(el.id, (ids.get(el.id) || 0) + 1);
    }
    for (const [id, count] of ids) {
      if (count > 1) out.push({ kind: 'duplicate-id', element: `#${id}`, detail: `used by ${count} elements` });
    }

    return out;
  }, { scope: options.scope, ignore: options.ignore, forbiddenText: options.forbiddenText });

  const skip = new Set<string>(options.skipKinds || []);
  return (findings as UiFinding[]).filter(f => !skip.has(f.kind));
}

export function formatFindings(findings: UiFinding[]): string {
  return findings.map(f => `  [${f.kind}] ${f.element}: ${f.detail}`).join('\n');
}

/** Soft assertion: the test continues, and every finding is reported. */
export async function expectNoUiGlitches(page: Page, label: string, options: UiAuditOptions = {}): Promise<void> {
  const findings = await auditUi(page, options);
  expect.soft(findings.length, `UI problems on ${label}:\n${formatFindings(findings)}\n`).toBe(0);
}

export const VIEWPORTS = {
  desktop: { width: 1440, height: 1080 },
  laptop: { width: 1024, height: 768 },
  mobile: { width: 390, height: 844 },
} as const;

/**
 * Checks that every listed control exists, is visible, is enabled and has a
 * readable name. Use it for the controls a tool cannot work without.
 */
export async function expectControlsUsable(page: Page, controls: Record<string, string>): Promise<void> {
  for (const [name, selector] of Object.entries(controls)) {
    const locator = page.locator(selector).first();
    await expect.soft(locator, `${name} (${selector}) should be visible`).toBeVisible();
    await expect.soft(locator, `${name} (${selector}) should be enabled`).toBeEnabled();
  }
}

/**
 * Layout audit of a page at rest.
 *
 * The buttons of the toolkit play a hover effect (a sheen that slides across
 * the button). and dialogs fade in. Mid-transition sizes and positions are not what a person
 * sees, so the audit is taken the way a screenshot would be:
 * pointer parked away from the controls, running transitions finished.
 * Endless animations (spinners) are left running.
 */
export async function expectNoUiGlitchesAtRest(page: Page, label: string, options: UiAuditOptions = {}): Promise<void> {
  await page.mouse.move(1, 1);
  await page.evaluate(async () => {
    const finite = document.getAnimations().filter(animation => {
      const end = animation.effect?.getComputedTiming().endTime;
      return typeof end === 'number' && Number.isFinite(end);
    });
    await Promise.all(finite.map(animation => animation.finished.catch(() => undefined)));
  });
  await expectNoUiGlitches(page, label, options);
}
