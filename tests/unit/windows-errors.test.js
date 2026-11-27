import test from 'node:test';
import assert from 'node:assert/strict';
import {
  BUG_CHECKS,
  decodeErrorCode,
  EXCEPTION_CODES,
  HRESULTS,
  HRESULT_FACILITIES,
  NTSTATUS_CODES,
  referenceCounts,
  searchErrors,
  toHex,
  WIN32_ERRORS,
} from '../../frontend/src/lib/tools/windows-errors.ts';

const field = (interpretation, start) => interpretation.fields.find(item => item.field.startsWith(start));

test('0x80070005 is an HRESULT in facility WIN32 that wraps ERROR_ACCESS_DENIED', () => {
  const result = decodeErrorCode('0x80070005');
  assert.equal(result.kind, 'code');
  assert.equal(result.interpretations.length, 1);
  const [hresult] = result.interpretations;
  assert.equal(hresult.kind, 'hresult');
  assert.equal(hresult.hex, '0x80070005');
  assert.equal(hresult.name, 'E_ACCESSDENIED');
  assert.equal(hresult.signed, '-2147024891');
  assert.equal(field(hresult, 'Severity').value, '1');
  assert.equal(field(hresult, 'Customer').value, '0');
  assert.equal(field(hresult, 'N ').value, '0');
  assert.equal(field(hresult, 'Facility').value, '7 (0x007)');
  assert.equal(field(hresult, 'Facility').meaning, 'FACILITY_WIN32.');
  assert.equal(field(hresult, 'Code').value, '5 (0x0005)');
  assert.deepEqual({ kind: hresult.wraps.kind, code: hresult.wraps.code, name: hresult.wraps.name }, { kind: 'win32', code: 5, name: 'ERROR_ACCESS_DENIED' });
  assert.deepEqual(hresult.commands.map(item => item.command), ['net helpmsg 5', 'certutil -error 0x80070005', '[ComponentModel.Win32Exception]::new(5).Message']);
});

test('the signed decimal form decodes to the same HRESULT', () => {
  const [hresult] = decodeErrorCode('-2147024891').interpretations;
  assert.equal(hresult.kind, 'hresult');
  assert.equal(hresult.hex, '0x80070005');
  assert.equal(hresult.readAs, 'decimal');
  assert.equal(hresult.wraps.name, 'ERROR_ACCESS_DENIED');
  // The unsigned decimal form too.
  assert.equal(decodeErrorCode('2147942405').interpretations[0].hex, '0x80070005');
});

test('an HRESULT without a name of its own takes it from the wrapped Win32 error', () => {
  const [hresult] = decodeErrorCode('0x800706BA').interpretations;
  assert.equal(hresult.name, 'HRESULT_FROM_WIN32(RPC_S_SERVER_UNAVAILABLE)');
  assert.equal(hresult.wraps.code, 1722);
  assert.ok(hresult.check.length > 0);
  assert.equal(decodeErrorCode('0x80072EE2').interpretations[0].wraps.name, 'ERROR_INTERNET_TIMEOUT');
  assert.equal(decodeErrorCode('0x80070643').interpretations[0].wraps.name, 'ERROR_INSTALL_FAILURE');
  assert.equal(decodeErrorCode('0x80073712').interpretations[0].wraps.name, 'ERROR_SXS_COMPONENT_STORE_CORRUPT');
});

test('a plain 5 is Win32 access denied', () => {
  const result = decodeErrorCode('5');
  assert.equal(result.interpretations.length, 1);
  const [win32] = result.interpretations;
  assert.equal(win32.kind, 'win32');
  assert.equal(win32.name, 'ERROR_ACCESS_DENIED');
  assert.equal(win32.display, '5');
  assert.equal(field(win32, 'As an HRESULT').value, '0x80070005');
  assert.deepEqual(win32.commands.map(item => item.command), ['net helpmsg 5', 'certutil -error 5', '[ComponentModel.Win32Exception]::new(5).Message']);
  assert.equal(decodeErrorCode('1603').interpretations[0].name, 'ERROR_INSTALL_FAILURE');
});

test('0xC0000005 is the NTSTATUS access violation', () => {
  const result = decodeErrorCode('0xC0000005');
  assert.equal(result.interpretations.length, 1);
  const [status] = result.interpretations;
  assert.equal(status.kind, 'ntstatus');
  assert.equal(status.name, 'STATUS_ACCESS_VIOLATION');
  assert.equal(field(status, 'Severity').value, '3');
  assert.equal(field(status, 'Severity').meaning, 'Error.');
  assert.equal(field(status, 'Facility').value, '0 (0x000)');
  assert.equal(field(status, 'Code').value, '5 (0x0005)');
  assert.deepEqual(status.commands.map(item => item.command), ['certutil -error 0xC0000005']);
  // As a process exit code it is often printed in decimal.
  assert.equal(decodeErrorCode('3221225477').interpretations[0].name, 'STATUS_ACCESS_VIOLATION');
  assert.equal(decodeErrorCode('-1073741819').interpretations[0].name, 'STATUS_ACCESS_VIOLATION');
  assert.equal(field(decodeErrorCode('0x80000005').interpretations[0], 'Severity').meaning, 'Warning.');
});

test('bare hex with letters is read as hex', () => {
  assert.equal(decodeErrorCode('c0000005').interpretations[0].name, 'STATUS_ACCESS_VIOLATION');
  assert.equal(decodeErrorCode('800f081f').interpretations[0].name, 'CBS_E_SOURCE_MISSING');
  assert.equal(decodeErrorCode(' 0X80004005. ').interpretations[0].name, 'E_FAIL');
  assert.equal(decodeErrorCode('7B').interpretations[0].name, 'INACCESSIBLE_BOOT_DEVICE');
  assert.equal(decodeErrorCode('ED').interpretations[0].name, 'UNMOUNTABLE_BOOT_VOLUME');
});

test('eight digits starting with 8 are offered as hex first, then decimal', () => {
  const result = decodeErrorCode('80070005');
  assert.match(result.message, /hex \(0x80070005\) or as a decimal/);
  assert.deepEqual(result.interpretations.map(item => [item.readAs, item.hex]), [['hex', '0x80070005'], ['decimal', '0x04C5C575']]);
  assert.equal(result.interpretations[0].name, 'E_ACCESSDENIED');
  assert.equal(result.interpretations[1].known, false);
  // Other digits-only input stays decimal.
  assert.deepEqual(decodeErrorCode('10054').interpretations.map(item => item.name), ['WSAECONNRESET']);
  assert.equal(decodeErrorCode('12345678').interpretations[0].readAs, 'decimal');
});

test('an unknown code keeps the structural breakdown', () => {
  const result = decodeErrorCode('0x8ABC1234');
  assert.equal(result.interpretations.length, 1);
  const [hresult] = result.interpretations;
  assert.equal(hresult.kind, 'hresult');
  assert.equal(hresult.known, false);
  assert.equal(hresult.name, '');
  assert.equal(field(hresult, 'Facility').value, '700 (0x2BC)');
  assert.equal(field(hresult, 'Facility').meaning, 'A facility that is not in the reference.');
  assert.equal(field(hresult, 'Code').value, '4660 (0x1234)');

  // An unknown 0xC... value could be an NTSTATUS or an HRESULT: both breakdowns are kept.
  assert.deepEqual(decodeErrorCode('0xC1900101').interpretations.map(item => [item.kind, item.known]), [['ntstatus', false], ['hresult', false]]);
  // An unknown Win32 number, and an unknown code inside a known facility.
  assert.deepEqual(decodeErrorCode('4242').interpretations.map(item => [item.kind, item.known]), [['win32', false]]);
  const update = decodeErrorCode('0x8024FFF0').interpretations[0];
  assert.equal(update.known, false);
  assert.equal(field(update, 'Facility').meaning, 'FACILITY_WINDOWSUPDATE.');
  assert.match(decodeErrorCode('0x80190194').interpretations[0].note, /HTTP 404/);
});

test('the N bit marks an HRESULT that wraps an NTSTATUS', () => {
  const [hresult] = decodeErrorCode('0xD0000005').interpretations;
  assert.equal(hresult.kind, 'hresult');
  assert.equal(field(hresult, 'N ').value, '1');
  assert.deepEqual({ kind: hresult.wraps.kind, display: hresult.wraps.display, name: hresult.wraps.name }, { kind: 'ntstatus', display: '0xC0000005', name: 'STATUS_ACCESS_VIOLATION' });
  assert.equal(hresult.name, 'HRESULT_FROM_NT(STATUS_ACCESS_VIOLATION)');
});

test('stop codes, exception codes and codes with several meanings', () => {
  // Written in hex, a small value is a stop code first and a Win32 error second.
  assert.deepEqual(decodeErrorCode('0x7B').interpretations.map(item => [item.kind, item.name]), [['bugcheck', 'INACCESSIBLE_BOOT_DEVICE'], ['win32', 'ERROR_INVALID_NAME']]);
  // Written in decimal, the Win32 error comes first. Plain digits are also tried as a hex stop code.
  assert.deepEqual(decodeErrorCode('50').interpretations.map(item => [item.kind, item.name, item.hex]), [['win32', 'ERROR_NOT_SUPPORTED', '0x00000032'], ['bugcheck', 'PAGE_FAULT_IN_NONPAGED_AREA', '0x00000050']]);
  assert.deepEqual(decodeErrorCode('0x1000007E').interpretations.map(item => item.kind), ['bugcheck']);
  assert.equal(decodeErrorCode('0x7B').interpretations[0].display, '0x7B');
  assert.equal(decodeErrorCode('0x1000007E').interpretations[0].display, '0x1000007E');
  assert.deepEqual(decodeErrorCode('0x7B').interpretations[0].commands, []);
  // Only codes that carry a Win32 error get the net helpmsg and PowerShell commands.
  assert.deepEqual(decodeErrorCode('0x80040154').interpretations[0].commands.map(item => item.command), ['certutil -error 0x80040154']);
  assert.deepEqual(decodeErrorCode('0xC000021A').interpretations.map(item => item.kind), ['ntstatus', 'bugcheck']);
  assert.deepEqual(decodeErrorCode('259').interpretations.map(item => item.name), ['ERROR_NO_MORE_ITEMS', 'STATUS_PENDING']);

  const [cpp] = decodeErrorCode('0xE06D7363').interpretations;
  assert.equal(cpp.kind, 'exception');
  assert.equal(cpp.label, 'Exception code');
  assert.equal(decodeErrorCode('0xE0434352').interpretations[0].kind, 'exception');
  // NTSTATUS_FROM_WIN32 values (0xC007xxxx) carry a Win32 error.
  assert.equal(decodeErrorCode('0xC0070005').interpretations[0].name, 'NTSTATUS_FROM_WIN32(ERROR_ACCESS_DENIED)');
  // Task Scheduler shows success HRESULTs such as 0x41301.
  const running = decodeErrorCode('0x41301').interpretations[0];
  assert.equal(running.name, 'SCHED_S_TASK_RUNNING');
  assert.equal(field(running, 'Severity').meaning, 'Success.');
});

test('text, empty and out of range input', () => {
  assert.equal(decodeErrorCode('').kind, 'empty');
  assert.equal(decodeErrorCode('   ').kind, 'empty');
  assert.equal(decodeErrorCode('sharing violation').kind, 'text');
  assert.equal(decodeErrorCode('ACCESS_DENIED').kind, 'text');
  // Words made of hex letters are text, not codes.
  assert.equal(decodeErrorCode('bad').kind, 'text');
  assert.equal(decodeErrorCode('dead').kind, 'text');
  assert.equal(decodeErrorCode('0xBAD').kind, 'code');
  assert.equal(decodeErrorCode('0x123456789').kind, 'invalid');
  assert.equal(decodeErrorCode('99999999999').kind, 'invalid');
  assert.equal(decodeErrorCode('-9999999999').kind, 'invalid');
  assert.equal(decodeErrorCode('0x0000000080070005').interpretations[0].name, 'E_ACCESSDENIED');
});

test('datasets have no duplicate codes or names and every entry is complete', () => {
  for (const [label, entries] of Object.entries({ WIN32_ERRORS, HRESULTS, NTSTATUS_CODES, EXCEPTION_CODES, BUG_CHECKS })) {
    const codes = entries.map(entry => entry.code);
    assert.equal(new Set(codes).size, codes.length, `${label} has a duplicate code`);
    const names = entries.map(entry => entry.name);
    assert.equal(new Set(names).size, names.length, `${label} has a duplicate name`);
    for (const entry of entries) {
      assert.ok(Number.isInteger(entry.code) && entry.code >= 0 && entry.code <= 0xffffffff, `${label} ${entry.name} code`);
      assert.ok(entry.name.trim() && entry.meaning.trim(), `${label} ${toHex(entry.code)} is incomplete`);
      assert.ok(!/!/.test(entry.meaning + (entry.check ?? '')), `${label} ${entry.name} has an exclamation mark`);
    }
  }
  assert.ok(WIN32_ERRORS.every(entry => entry.code <= 0xffff));
  // Named HRESULTs in facility WIN32 must agree with the Win32 table about the wrapped error.
  assert.equal(HRESULT_FACILITIES[7], 'WIN32');
  const counts = referenceCounts();
  assert.equal(counts.win32, WIN32_ERRORS.length);
  assert.equal(counts.bugcheck, BUG_CHECKS.length);
});

test('every known code decodes back to its own entry', () => {
  for (const entry of WIN32_ERRORS) {
    assert.ok(decodeErrorCode(String(entry.code)).interpretations.some(item => item.kind === 'win32' && item.name === entry.name), entry.name);
  }
  for (const [kind, entries] of [['hresult', HRESULTS], ['ntstatus', NTSTATUS_CODES], ['exception', EXCEPTION_CODES], ['bugcheck', BUG_CHECKS]]) {
    for (const entry of entries) {
      assert.ok(decodeErrorCode(toHex(entry.code)).interpretations.some(item => item.kind === kind && item.name === entry.name), `${kind} ${entry.name}`);
    }
  }
});

test('search by name or meaning', () => {
  const denied = searchErrors('ACCESS_DENIED');
  assert.equal(denied[0].name, 'ERROR_ACCESS_DENIED');
  for (const name of ['STATUS_ACCESS_DENIED', 'WBEM_E_ACCESS_DENIED', 'E_ACCESSDENIED']) assert.ok(denied.some(item => item.name === name), name);
  // The phrase in the name ranks before names that only contain the words.
  assert.ok(denied.findIndex(item => item.name === 'STATUS_ACCESS_DENIED') < denied.findIndex(item => item.name === 'E_ACCESSDENIED'));
  assert.equal(denied.find(item => item.name === 'ERROR_ACCESS_DENIED').display, '5');
  assert.equal(denied.find(item => item.name === 'STATUS_ACCESS_DENIED').display, '0xC0000022');

  const sharing = searchErrors('sharing violation');
  assert.deepEqual(sharing.map(item => item.name), ['ERROR_SHARING_VIOLATION', 'STATUS_SHARING_VIOLATION']);
  assert.equal(searchErrors('access denied')[0].name, denied[0].name);
  assert.ok(searchErrors('boot device').some(item => item.kind === 'bugcheck' && item.name === 'INACCESSIBLE_BOOT_DEVICE'));
  assert.deepEqual(searchErrors('no such thing anywhere'), []);
  assert.deepEqual(searchErrors('  '), []);
  // Results can be decoded again.
  for (const match of sharing) assert.ok(decodeErrorCode(match.display).interpretations.some(item => item.name === match.name));
});
