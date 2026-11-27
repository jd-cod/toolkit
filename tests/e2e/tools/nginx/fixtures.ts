import { test as base, expect } from '../_support/fixtures';
import { loadGeoOracle, type GeoOracle } from './geo';
import { TrafficAnalyzer } from './page';
import { generateLog, type GeneratedLog, type GeneratorOptions } from './generator';

/**
 * Fixtures for the Traffic Analyzer specs.
 *
 *  - `geo`       country/network oracle read from the databases the site serves
 *  - `analyzer`  page object, already opened on /nginx with the engine loaded
 *  - `newLog`    generates a random log and saves it with the test's evidence
 */
export const test = base.extend<{
  geo: GeoOracle;
  analyzer: TrafficAnalyzer;
  newLog: (options?: GeneratorOptions, name?: string) => Promise<GeneratedLog>;
}>({
  geo: async ({ baseURL }, use) => {
    await use(await loadGeoOracle(baseURL as string));
  },

  analyzer: async ({ page }, use) => {
    const analyzer = new TrafficAnalyzer(page);
    await analyzer.open();
    await use(analyzer);
  },

  newLog: async ({ rng, geo, evidence }, use) => {
    let count = 0;
    await use(async (options = {}, name) => {
      const log = generateLog(rng.fork(`log-${count}`), geo, options);
      await evidence.save(name ?? `generated-access-${++count}.log`, log.text);
      return log;
    });
  },
});

export { expect };
