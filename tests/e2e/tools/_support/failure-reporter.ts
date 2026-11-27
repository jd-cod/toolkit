import type { FullConfig, FullResult, Reporter, Suite, TestCase, TestResult } from '@playwright/test/reporter';
import { mkdirSync, rmSync, writeFileSync, copyFileSync, existsSync } from 'node:fs';
import path from 'node:path';

/**
 * Failure-only reporter.
 *
 * A run prints one line per problem and a totals line; passing tests print
 * nothing. Everything needed to analyse a failure without re-running is
 * written to `test-results/tools-report/`:
 *
 *   failures.md    readable report: what was expected, what was shown, the
 *                  seed, the reproduce command, and the saved inputs
 *   failures.json  the same data for a program (or an AI agent) to read
 *   <n>-<test>/    the inputs the test generated, screenshots and traces
 *
 * The report is written on every run, including a clean one, so a stale
 * report can never be mistaken for the current state.
 */

interface FailureRecord {
  id: string;
  tool: string;
  title: string;
  file: string;
  line: number;
  outcome: 'failed' | 'flaky' | 'timedOut' | 'interrupted';
  seed: string;
  durationMs: number;
  errors: string[];
  failedSteps: string[];
  artifacts: string[];
  reproduce: string;
}

const ANSI = /\u001b\[[0-9;]*m/g;
const clean = (text: string) => text.replace(ANSI, '');

/** The index stays small enough to read in one go; nothing is dropped from the per-failure files. */
const INDEX_PROBLEMS = 4;
const INDEX_PROBLEM_CHARS = 1500;

class FailureReporter implements Reporter {
  private rootDir = process.cwd();
  private outDir = path.join(process.cwd(), 'test-results', 'tools-report');
  private records: FailureRecord[] = [];
  private counts = { passed: 0, failed: 0, flaky: 0, skipped: 0 };
  private total = 0;
  private startedAt = Date.now();

  onBegin(config: FullConfig, suite: Suite) {
    // config.rootDir is the test directory; reports belong next to the config file.
    this.rootDir = config.configFile ? path.dirname(config.configFile) : process.cwd();
    this.outDir = process.env.E2E_REPORT_DIR
      ? path.resolve(process.env.E2E_REPORT_DIR)
      : path.join(this.rootDir, 'test-results', 'tools-report');
    this.total = suite.allTests().length;
    this.startedAt = Date.now();
    rmSync(this.outDir, { recursive: true, force: true });
    mkdirSync(this.outDir, { recursive: true });
    console.log(`Running ${this.total} tests (seed E2E_SEED=${process.env.E2E_SEED ?? 'unset'}, base URL ${config.projects[0]?.use?.baseURL ?? 'default'})`);
  }

  onTestEnd(test: TestCase, result: TestResult) {
    // Wait for the last attempt; earlier attempts of a retried test are noise.
    const lastAttempt = result.retry >= test.retries || result.status === 'passed' || result.status === 'skipped';
    if (!lastAttempt) return;

    const outcome = test.outcome();
    if (outcome === 'skipped') { this.counts.skipped++; return; }
    if (outcome === 'expected') { this.counts.passed++; return; }
    if (outcome === 'flaky') this.counts.flaky++; else this.counts.failed++;

    // For a flaky test the interesting attempt is the one that failed.
    const failing = outcome === 'flaky' ? (test.results.find(r => r.status !== 'passed') ?? result) : result;
    const relFile = path.relative(this.rootDir, test.location.file);
    const tool = relFile.split(path.sep).slice(-2, -1)[0] || 'unknown';
    const index = this.records.length + 1;
    const slug = test.title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60);
    const id = `${String(index).padStart(3, '0')}-${tool}-${slug}`;
    const dir = path.join(this.outDir, id);
    try { mkdirSync(dir, { recursive: true }); } catch { /* reported without artifacts */ }

    const artifacts: string[] = [];
    failing.attachments.forEach((attachment, i) => {
      const name = attachment.name.replace(/[^a-zA-Z0-9._-]+/g, '_') || `attachment-${i}`;
      const target = path.join(dir, attachment.path ? `${i}-${path.basename(attachment.path)}` : name);
      try {
        if (attachment.body) writeFileSync(target, attachment.body);
        else if (attachment.path && existsSync(attachment.path)) copyFileSync(attachment.path, target);
        else return;
        artifacts.push(path.relative(this.rootDir, target));
      } catch { /* an unreadable artifact must not hide the failure itself */ }
    });

    const failedSteps: string[] = [];
    const walk = (steps: TestResult['steps'], trail: string[]) => {
      for (const step of steps) {
        const here = [...trail, step.title];
        if (step.error && step.category === 'test.step') failedSteps.push(here.join(' › '));
        walk(step.steps, step.category === 'test.step' ? here : trail);
      }
    };
    walk(failing.steps, []);

    const seed = test.annotations.find(a => a.type === 'seed')?.description
      ?? failing.annotations?.find(a => a.type === 'seed')?.description
      ?? `E2E_SEED=${process.env.E2E_SEED ?? 'unset'}`;
    const record: FailureRecord = {
      id,
      tool,
      title: test.titlePath().slice(3).join(' › '),
      file: relFile,
      line: test.location.line,
      outcome: outcome === 'flaky' ? 'flaky' : (failing.status === 'timedOut' || failing.status === 'interrupted' ? failing.status : 'failed'),
      seed,
      durationMs: failing.duration,
      errors: failing.errors.map(e => clean(e.message || e.value || String(e)).trim()),
      failedSteps,
      artifacts,
      reproduce: `E2E_SEED=${process.env.E2E_SEED ?? '1'} npx playwright test --project=tools ${relFile}:${test.location.line}`,
    };
    this.records.push(record);

    const first = (record.errors[0] || 'no error message').split('\n').slice(0, 6).join('\n    ');
    console.log(`\n✗ [${record.tool}] ${record.title}  (${record.outcome}${record.errors.length > 1 ? `, ${record.errors.length} problems` : ''})\n    ${first}`);
  }

  onEnd(result: FullResult) {
    const seconds = ((Date.now() - this.startedAt) / 1000).toFixed(1);
    const summary = {
      status: result.status,
      seed: process.env.E2E_SEED ?? null,
      finishedAt: new Date().toISOString(),
      durationSeconds: Number(seconds),
      totals: { ...this.counts, total: this.total },
      failures: this.records,
    };
    mkdirSync(this.outDir, { recursive: true });
    writeFileSync(path.join(this.outDir, 'failures.json'), JSON.stringify(summary, null, 2));
    writeFileSync(path.join(this.outDir, 'failures.md'), this.markdown(summary));

    const { passed, failed, flaky, skipped } = this.counts;
    console.log(`\n${failed === 0 && flaky === 0 ? 'OK' : 'PROBLEMS FOUND'}: ${passed} passed, ${failed} failed, ${flaky} flaky, ${skipped} skipped in ${seconds}s`);
    if (failed || flaky) console.log(`Details: ${path.relative(process.cwd(), path.join(this.outDir, 'failures.md'))}`);
  }

  printsToStdio() {
    return true;
  }

  private markdown(summary: { seed: string | null; finishedAt: string; durationSeconds: number; totals: Record<string, number>; failures: FailureRecord[] }): string {
    const t = summary.totals;
    const lines = [
      '# Tool test run — failure report',
      '',
      `- Finished: ${summary.finishedAt} (${summary.durationSeconds}s)`,
      `- Seed: \`E2E_SEED=${summary.seed}\` (re-run with this value to get the same generated inputs)`,
      `- Totals: ${t.passed} passed, ${t.failed} failed, ${t.flaky} flaky, ${t.skipped} skipped, ${t.total} total`,
      '',
    ];
    if (summary.failures.length === 0) {
      lines.push('No failures. Every checked value matched its expected value.');
      return lines.join('\n') + '\n';
    }
    const byTool = new Map<string, FailureRecord[]>();
    for (const f of summary.failures) byTool.set(f.tool, [...(byTool.get(f.tool) || []), f]);
    const tools = [...byTool.keys()].sort();
    lines.push(
      'This file is the index: every failure with its first problems. The complete list of problems for one',
      'failure is in `<id>/failure.md` next to its saved inputs, screenshot and trace.',
      '',
      '## Summary', '', '| Tool | Failures |', '| --- | --- |',
    );
    for (const tool of tools) lines.push(`| ${tool} | ${byTool.get(tool)!.length} |`);
    lines.push('');
    for (const tool of tools) {
      lines.push(`## Tool: ${tool}`, '');
      for (const f of byTool.get(tool)!) {
        const detail = path.join(this.outDir, f.id, 'failure.md');
        try { writeFileSync(detail, [...this.header(f, '#'), ...this.problems(f, '##', f.errors.length, Infinity), ''].join('\n')); } catch { /* the index still lists it */ }
        lines.push(...this.header(f, '###'), `- Full detail: \`${path.relative(this.rootDir, detail)}\``, ...this.problems(f, '####', INDEX_PROBLEMS, INDEX_PROBLEM_CHARS), '');
      }
    }
    return lines.join('\n') + '\n';
  }

  private header(f: FailureRecord, level: string): string[] {
    const lines = [
      `${level} ${f.id}`, '',
      `- Tool: ${f.tool}`,
      `- Test: ${f.title}`,
      `- Location: \`${f.file}:${f.line}\``,
      `- Outcome: ${f.outcome} after ${(f.durationMs / 1000).toFixed(1)}s`,
      `- Seed: ${f.seed}`,
      `- Reproduce: \`${f.reproduce}\``,
    ];
    if (f.failedSteps.length) lines.push(`- Failed steps: ${f.failedSteps.map(s => `\`${s}\``).join('; ')}`);
    if (f.artifacts.length) lines.push('- Saved inputs and artifacts:', ...f.artifacts.map(a => `  - \`${a}\``));
    return lines;
  }

  private problems(f: FailureRecord, level: string, maxProblems: number, maxChars: number): string[] {
    const lines: string[] = [];
    f.errors.slice(0, maxProblems).forEach((error, i) => {
      const text = error.length > maxChars ? `${error.slice(0, maxChars)}\n… (${error.length - maxChars} more characters in the full detail)` : error;
      lines.push('', `${level} Problem ${i + 1} of ${f.errors.length}`, '', '```', text, '```');
    });
    if (f.errors.length > maxProblems) lines.push('', `${f.errors.length - maxProblems} more problems in the full detail.`);
    return lines;
  }
}

export default FailureReporter;
