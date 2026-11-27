/**
 * Seeded random source for test data.
 *
 * Every suite generates fresh inputs on each run, so a failure must carry the
 * seed that produced it. The base seed comes from E2E_SEED (set by
 * playwright.config.ts when absent, and inherited by every worker); each test
 * derives its own seed from the base seed and its title, so one test can be
 * replayed alone with the same data:
 *
 *   E2E_SEED=123456 npx playwright test --project=tools -g "<test title>"
 */

export function hashString(text: string): number {
  let h = 2166136261;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

export function baseSeed(): number {
  const raw = Number(process.env.E2E_SEED);
  return Number.isFinite(raw) && raw > 0 ? Math.floor(raw) : 1;
}

export class Rng {
  private state: number;

  constructor(public readonly seed: number) {
    this.state = seed >>> 0 || 1;
  }

  /** Float in [0, 1). mulberry32. */
  next(): number {
    this.state = (this.state + 0x6d2b79f5) >>> 0;
    let t = this.state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }

  /** Integer in [min, max], both inclusive. */
  int(min: number, max: number): number {
    return min + Math.floor(this.next() * (max - min + 1));
  }

  bool(probability = 0.5): boolean {
    return this.next() < probability;
  }

  pick<T>(items: readonly T[]): T {
    if (items.length === 0) throw new Error('Rng.pick: empty list');
    return items[this.int(0, items.length - 1)];
  }

  /** Pick by weight; `weights[i]` belongs to `items[i]`. */
  weighted<T>(items: readonly T[], weights: readonly number[]): T {
    const total = weights.reduce((a, b) => a + b, 0);
    let roll = this.next() * total;
    for (let i = 0; i < items.length; i++) {
      roll -= weights[i];
      if (roll < 0) return items[i];
    }
    return items[items.length - 1];
  }

  shuffle<T>(items: readonly T[]): T[] {
    const out = items.slice();
    for (let i = out.length - 1; i > 0; i--) {
      const j = this.int(0, i);
      [out[i], out[j]] = [out[j], out[i]];
    }
    return out;
  }

  /** `count` distinct items (or all of them when there are fewer). */
  sample<T>(items: readonly T[], count: number): T[] {
    return this.shuffle(items).slice(0, Math.min(count, items.length));
  }

  string(length: number, alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789'): string {
    let out = '';
    for (let i = 0; i < length; i++) out += alphabet[this.int(0, alphabet.length - 1)];
    return out;
  }

  /** Independent generator for a named sub-stream, stable for this seed. */
  fork(label: string): Rng {
    return new Rng(hashString(`${this.seed}:${label}`));
  }
}
