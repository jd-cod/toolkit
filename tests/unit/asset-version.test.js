import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const FRONTEND = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../frontend');

function files(dir) {
    return readdirSync(dir).flatMap(name => {
        const full = path.join(dir, name);
        return statSync(full).isDirectory() ? files(full) : [full];
    });
}

// The version of the scripts under public/js is made at build time
// (next.config.ts, src/lib/asset-version.ts). A number typed into a URL is not
// changed when the script is, and the script is cached for 30 days.
test('no script URL carries a hand-written version', () => {
    const found = [];
    for (const file of [...files(path.join(FRONTEND, 'src')), ...files(path.join(FRONTEND, 'public/js'))]) {
        if (!/\.(js|ts|tsx)$/.test(file)) continue;
        readFileSync(file, 'utf8').split('\n').forEach((text, at) => {
            if (/\/js\/[\w.-]+\.js\?v=[\w.]/.test(text)) found.push(`${path.relative(FRONTEND, file)}:${at + 1}`);
        });
    }
    assert.deepEqual(found, []);
});

test('the worker loads its scripts with the version it was started with', () => {
    const worker = readFileSync(path.join(FRONTEND, 'public/js/log-parser.worker.js'), 'utf8');
    const loads = worker.match(/importScripts\([^)]*\)/g) || [];
    assert.ok(loads.length >= 6);
    for (const load of loads) assert.match(load, /^importScripts\(`\/js\/[\w.-]+\.js\$\{v\}`\)$/);
});
