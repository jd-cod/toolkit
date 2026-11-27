import test from 'node:test';
import assert from 'node:assert/strict';
import {
  eventCategories,
  eventCommands,
  eventLogs,
  KERBEROS_FAILURE_CODES,
  LOGON_FAILURE_CODES,
  LOGON_TYPES,
  parseEventId,
  referenceTablesFor,
  searchEvents,
  WINDOWS_EVENTS,
} from '../../frontend/src/lib/tools/windows-events.ts';

test('exact lookup by ID', () => {
  const result = searchEvents('4625');
  assert.equal(result.length, 1);
  assert.equal(result[0].id, 4625);
  assert.equal(result[0].source, 'Microsoft-Windows-Security-Auditing');
  assert.equal(result[0].log, 'Security');
  assert.equal(result[0].title, 'Failed logon');
  // The number may come with a label or spaces.
  assert.equal(searchEvents(' Event ID 4625 ')[0].id, 4625);
  assert.equal(searchEvents('id:7045')[0].source, 'Service Control Manager');
  assert.equal(parseEventId('#41'), 41);
  assert.equal(parseEventId('4625 failed'), null);
});

test('an ID used by several sources returns all of them', () => {
  const result = searchEvents('1001');
  assert.deepEqual(result.map(event => event.source).sort(), ['Microsoft-Windows-WER-SystemErrorReporting', 'Microsoft-Windows-Windows Defender', 'Windows Error Reporting']);
  assert.ok(result.every(event => event.id === 1001));
  assert.deepEqual(searchEvents('19').map(event => event.source).sort(), ['Microsoft-Windows-WHEA-Logger', 'Microsoft-Windows-WindowsUpdateClient']);
  assert.equal(searchEvents('129').length, 2);
  // 41 is exact: it does not drag in 4103 or 4104.
  assert.deepEqual(searchEvents('41').map(event => event.id), [41]);
});

test('a number that is not in the reference falls back to IDs that start with it', () => {
  const result = searchEvents('462');
  assert.deepEqual(result.map(event => event.id), [4624, 4625]);
  assert.deepEqual(searchEvents('99999'), []);
});

test('id and source are unique together', () => {
  const keys = WINDOWS_EVENTS.map(event => `${event.id}|${event.source}`);
  assert.equal(new Set(keys).size, keys.length);
});

test('every entry has all fields filled in', () => {
  for (const event of WINDOWS_EVENTS) {
    assert.ok(Number.isInteger(event.id) && event.id > 0 && event.id <= 65535, `id of ${event.id}`);
    for (const key of ['source', 'log', 'category', 'title', 'meaning', 'check']) {
      assert.equal(typeof event[key], 'string', `${event.id} ${key}`);
      assert.ok(event[key].trim().length > 0, `${event.id} ${key} is empty`);
      assert.equal(event[key], event[key].trim(), `${event.id} ${key} has stray whitespace`);
    }
    // The only exclamation mark allowed is the one in the WinDbg command !analyze.
    assert.ok(!/!/.test((event.title + event.meaning + event.check).replace('!analyze', '')), `${event.id} has an exclamation mark`);
  }
  assert.ok(WINDOWS_EVENTS.length >= 150);
});

test('keyword search covers title, meaning, category and source', () => {
  assert.ok(searchEvents('locked out').some(event => event.id === 4740));
  // Title matches rank before matches in the meaning only.
  assert.equal(searchEvents('scheduled task created')[0].id, 4698);
  // Source.
  assert.ok(searchEvents('kernel-power').every(event => event.source === 'Microsoft-Windows-Kernel-Power'));
  assert.ok(searchEvents('Service Control Manager').some(event => event.id === 7045));
  // Category.
  assert.ok(searchEvents('remote desktop').some(event => event.id === 21));
  // Meaning only.
  assert.ok(searchEvents('PSEXESVC').length === 0);
  assert.ok(searchEvents('blue screen').some(event => event.id === 1001 && event.log === 'System'));
  // An event that matches in the title, the source and the category ranks above a title match alone.
  assert.equal(searchEvents('service')[0].source, 'Service Control Manager');
  // Every word has to match.
  assert.deepEqual(searchEvents('logon zebra'), []);
  assert.equal(searchEvents('LOG CLEARED').length, 2);
});

test('filter by log and category', () => {
  const security = searchEvents('', { log: 'Security' });
  assert.ok(security.length > 50);
  assert.ok(security.every(event => event.log === 'Security'));
  assert.deepEqual(security.map(event => event.id), [...security.map(event => event.id)].sort((a, b) => a - b));

  const services = searchEvents('', { category: 'Services' });
  assert.ok(services.every(event => event.source === 'Service Control Manager'));
  assert.ok(services.some(event => event.id === 7036));

  // 1001 has three sources: the filter narrows it to one.
  assert.deepEqual(searchEvents('1001', { log: 'Application' }).map(event => event.source), ['Windows Error Reporting']);
  assert.deepEqual(searchEvents('4625', { category: 'Services' }), []);
  assert.ok(searchEvents('installed', { category: 'Services' }).every(event => event.category === 'Services'));
  assert.equal(searchEvents('').length, WINDOWS_EVENTS.length);
});

test('categories and logs', () => {
  const categories = eventCategories();
  assert.equal(categories.reduce((sum, item) => sum + item.count, 0), WINDOWS_EVENTS.length);
  assert.ok(categories.every(item => item.count > 0));
  assert.ok(categories.some(item => item.category === 'Logon and sessions'));
  const logs = eventLogs();
  assert.deepEqual(logs.slice(0, 3), ['Security', 'System', 'Application']);
  assert.equal(new Set(logs).size, logs.length);
});

test('generated commands use the log of the event, quoted where needed', () => {
  const failed = eventCommands(searchEvents('4625')[0]);
  assert.equal(failed.powershell, "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 50");
  assert.equal(failed.wevtutil, 'wevtutil qe Security "/q:*[System[(EventID=4625)]]" /c:10 /rd:true /f:text');

  const session = eventCommands(searchEvents('21')[0]);
  assert.equal(session.powershell, "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id=21} -MaxEvents 50");
  assert.equal(session.wevtutil, 'wevtutil qe Microsoft-Windows-TerminalServices-LocalSessionManager/Operational "/q:*[System[(EventID=21)]]" /c:10 /rd:true /f:text');

  // Log names with a space are quoted for cmd.
  const defender = eventCommands(searchEvents('1116')[0]);
  assert.ok(defender.powershell.includes("LogName='Microsoft-Windows-Windows Defender/Operational'"));
  assert.ok(defender.wevtutil.startsWith('wevtutil qe "Microsoft-Windows-Windows Defender/Operational" "/q:'));
  assert.ok(eventCommands(searchEvents('400')[0]).wevtutil.startsWith('wevtutil qe "Windows PowerShell" '));
  assert.equal(eventCommands({ id: 1, log: "it's" }).powershell, "Get-WinEvent -FilterHashtable @{LogName='it''s'; Id=1} -MaxEvents 50");
});

test('reference tables', () => {
  assert.deepEqual(LOGON_TYPES.map(row => row.code), ['2', '3', '4', '5', '7', '8', '9', '10', '11', '12', '13']);
  assert.equal(LOGON_TYPES.find(row => row.code === '10').name, 'RemoteInteractive');
  assert.equal(LOGON_FAILURE_CODES.find(row => row.code === '0xC000006A').name, 'STATUS_WRONG_PASSWORD');
  assert.equal(LOGON_FAILURE_CODES.find(row => row.code === '0xC0000234').name, 'STATUS_ACCOUNT_LOCKED_OUT');
  assert.equal(KERBEROS_FAILURE_CODES.find(row => row.code === '0x18').name, 'KDC_ERR_PREAUTH_FAILED');
  for (const table of [LOGON_TYPES, LOGON_FAILURE_CODES, KERBEROS_FAILURE_CODES]) {
    assert.equal(new Set(table.map(row => row.code)).size, table.length);
    assert.ok(table.every(row => row.code && row.name && row.meaning));
  }

  assert.deepEqual(referenceTablesFor(searchEvents('4625')), { logonTypes: true, logonFailureCodes: true, kerberosCodes: false });
  assert.deepEqual(referenceTablesFor(searchEvents('4624')), { logonTypes: true, logonFailureCodes: false, kerberosCodes: false });
  assert.deepEqual(referenceTablesFor(searchEvents('4771')), { logonTypes: false, logonFailureCodes: false, kerberosCodes: true });
  assert.deepEqual(referenceTablesFor(searchEvents('7045')), { logonTypes: false, logonFailureCodes: false, kerberosCodes: false });
});
