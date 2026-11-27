import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';
import { buildCsv, csvCell } from '../../frontend/src/lib/csv-utils.ts';

// report.js is a browser script; only its CSV builder is used here.
const sandbox = { window: {}, document: {} };
vm.runInNewContext(fs.readFileSync(fileURLToPath(new URL('../../frontend/public/js/report.js', import.meta.url)), 'utf8'), sandbox);
const reportCsv = sandbox.window.Report.toCsv;

const builders = { 'Traffic Analyzer report': reportCsv, 'tool pages': buildCsv };

for (const [name, toCsv] of Object.entries(builders)) {
    test(`${name}: text that a spreadsheet would run as a formula is neutralised`, () => {
        const rows = [
            { Item: '=HYPERLINK("http://evil.test","click")', Value: 3 },
            { Item: '+cmd|\' /C calc\'!A0', Value: 1 },
            { Item: '-2+3+cmd', Value: 1 },
            { Item: '@SUM(1+1)', Value: 1 },
            { Item: '\t=1+1', Value: 1 },
        ];
        const lines = toCsv(rows).split('\n');
        assert.equal(lines[0], '"Item","Value"');
        assert.equal(lines[1], '"\'=HYPERLINK(""http://evil.test"",""click"")","3"');
        for (const line of lines.slice(1)) assert.ok(line.startsWith('"\''), line);
    });

    test(`${name}: ordinary values are unchanged`, () => {
        const csv = toCsv([{ Item: '/products?id=1', Value: 12, Share: -4.5, Note: 'a "quoted", value', Ref: '-12', Empty: undefined, Zero: 0 }]);
        assert.equal(csv.split('\n')[1], '"/products?id=1","12","-4.5","a ""quoted"", value","-12","","0"');
    });

    test(`${name}: a lone dash stays, text that starts with one is marked`, () => {
        const cells = toCsv([{ A: '-', B: '-rf /' }]).split('\n')[1];
        assert.equal(cells, '"-","\'-rf /"');
    });
}

test('csvCell', () => {
    assert.equal(csvCell(null), '""');
    assert.equal(csvCell(-3), '"-3"');
    assert.equal(csvCell('=1'), '"\'=1"');
});
