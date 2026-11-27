import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseEmailHeaders,
  splitHeaders,
  parseReceived,
  parseMailDate,
  parseAuthenticationResults,
  parseDkimSignature,
  decodeEncodedWords,
  organizationalDomain,
  addressDomain,
  formatDuration,
  EMAIL_HEADERS_SAMPLE,
  MAX_HEADERS,
} from '../../frontend/src/lib/tools/email-headers.ts';

const titles = analysis => analysis.findings.map(finding => finding.title);
const finding = (analysis, text) => analysis.findings.find(item => item.title.includes(text));

test('folded lines are joined to the header above, with CRLF or LF', () => {
  const raw = 'Subject: a long\r\n subject line\r\n\tin three parts\r\nTo: a@example.com\r\n';
  const { headers } = splitHeaders(raw);
  assert.deepEqual(headers, [
    { name: 'Subject', value: 'a long subject line in three parts' },
    { name: 'To', value: 'a@example.com' },
  ]);
  assert.deepEqual(splitHeaders(raw.replace(/\r\n/g, '\n')).headers, headers);
});

test('parsing stops at the first blank line so the body is ignored', () => {
  const analysis = parseEmailHeaders('\n\nFrom: a@example.com\nSubject: Hi\n\nReceived: this is body text\nX-Body: no\n');
  assert.deepEqual(analysis.headers.map(header => header.name), ['From', 'Subject']);
  assert.equal(analysis.hops.length, 0);
});

test('headers keep their order and duplicates', () => {
  const { headers } = splitHeaders('Received: one\nX-Test: a\nReceived: two\n');
  assert.deepEqual(headers.map(header => header.value), ['one', 'a', 'two']);
});

test('a Received header is split into its clauses and timestamp', () => {
  const hop = parseReceived('from mail.example.com (mail.example.com [192.0.2.10]) by mx.example.net (Postfix, from userid 0) with ESMTPS id 4F5A1 for <bob@example.net>; Mon, 2 Nov 2026 08:15:00 +0100 (CET)');
  assert.equal(hop.from, 'mail.example.com (mail.example.com [192.0.2.10])');
  assert.equal(hop.by, 'mx.example.net (Postfix, from userid 0)');
  assert.equal(hop.with, 'ESMTPS');
  assert.equal(hop.id, '4F5A1');
  assert.equal(hop.for, 'bob@example.net');
  assert.equal(hop.date, 'Mon, 2 Nov 2026 08:15:00 +0100 (CET)');
});

test('dates with offsets, zone names and comments are parsed, bad dates give null', () => {
  assert.equal(parseMailDate('Mon, 2 Nov 2026 08:15:00 +0100 (CET)'), Date.UTC(2026, 10, 2, 7, 15, 0));
  assert.equal(parseMailDate('2 Nov 2026 07:15:00 -0000'), Date.UTC(2026, 10, 2, 7, 15, 0));
  assert.equal(parseMailDate('Mon, 02 Nov 2026 02:15:00 EST'), Date.UTC(2026, 10, 2, 7, 15, 0));
  assert.equal(parseMailDate('Mon, 2 Nov 2026 07:15 GMT'), Date.UTC(2026, 10, 2, 7, 15, 0));
  assert.equal(parseMailDate('not a date'), null);
  assert.equal(parseMailDate(''), null);
});

test('hops are listed in travel order with delays and total transit time', () => {
  const analysis = parseEmailHeaders([
    'Received: from c.example by d.example with ESMTPS id 3; Mon, 2 Nov 2026 10:10:30 +0000',
    'Received: from b.example by c.example with ESMTP id 2;',
    ' Mon, 2 Nov 2026 11:00:20 +0100',
    'Received: from a.example by b.example with SMTP id 1; Mon, 2 Nov 2026 10:00:00 +0000',
    'From: a@a.example',
  ].join('\n'));
  assert.deepEqual(analysis.hops.map(hop => hop.by), ['b.example', 'c.example', 'd.example']);
  assert.deepEqual(analysis.hops.map(hop => hop.index), [1, 2, 3]);
  assert.deepEqual(analysis.hops.map(hop => hop.delaySeconds), [null, 20, 610]);
  assert.equal(analysis.totalTransitSeconds, 630);
  assert.ok(finding(analysis, 'Hop 3 took 10 min 10 s'));
  assert.equal(finding(analysis, 'Hop 3').severity, 'warning');
});

test('negative delays are clamped to zero and flagged as clock skew', () => {
  const analysis = parseEmailHeaders([
    'Received: from b by c; Mon, 2 Nov 2026 09:59:50 +0000',
    'Received: from a by b; Mon, 2 Nov 2026 10:00:00 +0000',
  ].join('\n'));
  assert.equal(analysis.hops[1].delaySeconds, 0);
  assert.equal(analysis.hops[1].clockSkew, true);
  assert.equal(analysis.hops[0].clockSkew, false);
  assert.equal(analysis.totalTransitSeconds, 0);
  assert.equal(finding(analysis, 'Clock difference').severity, 'info');
});

test('unreadable hop dates do not break delays for the other hops', () => {
  const analysis = parseEmailHeaders([
    'Received: from c by d; Mon, 2 Nov 2026 10:00:40 +0000',
    'Received: from b by c; sometime last week',
    'Received: from a by b',
    'Received: from x by a; Mon, 2 Nov 2026 10:00:00 +0000',
  ].join('\n'));
  assert.deepEqual(analysis.hops.map(hop => hop.timestamp === null), [false, true, true, false]);
  assert.deepEqual(analysis.hops.map(hop => hop.delaySeconds), [null, null, null, 40]);
  assert.equal(analysis.totalTransitSeconds, 40);
});

test('Authentication-Results gives spf, dkim and dmarc with their properties', () => {
  const results = parseAuthenticationResults(
    'mx.example.net; dkim=pass (2048-bit key; unprotected) header.d=example.com header.i=@example.com header.s=sel1 header.b=abc; ' +
    'dkim=fail reason="signature verification failed" header.d=list.example.org header.s=k2; ' +
    'spf=softfail (domain owner discourages use of this host) smtp.mailfrom=bounce@example.com; ' +
    'dmarc=pass (p=REJECT) header.from=example.com',
  );
  assert.deepEqual(results.map(result => `${result.method}=${result.result}`), ['dkim=pass', 'dkim=fail', 'spf=softfail', 'dmarc=pass']);
  assert.equal(results[0].authservId, 'mx.example.net');
  assert.equal(results[0].props['header.d'], 'example.com');
  assert.equal(results[0].props['header.i'], '@example.com');
  assert.equal(results[0].props['header.s'], 'sel1');
  assert.equal(results[0].comment, '2048-bit key; unprotected');
  assert.equal(results[1].props['header.d'], 'list.example.org');
  assert.equal(results[2].props['smtp.mailfrom'], 'bounce@example.com');
  assert.equal(results[3].props['header.from'], 'example.com');
});

test('several dkim results: one pass is an overall pass, and every signature is listed', () => {
  const analysis = parseEmailHeaders([
    'Authentication-Results: mx.example.net; dkim=fail header.d=list.example.org; dkim=pass header.d=example.com; spf=fail smtp.mailfrom=example.com; dmarc=fail header.from=example.com',
    'From: Alice <alice@example.com>',
  ].join('\n'));
  assert.equal(analysis.auth.dkim, 'pass');
  assert.equal(analysis.auth.spf, 'fail');
  assert.equal(analysis.auth.dmarc, 'fail');
  assert.equal(analysis.auth.results.filter(result => result.method === 'dkim').length, 2);
  assert.equal(finding(analysis, 'DKIM passed').severity, 'ok');
  assert.match(finding(analysis, 'DKIM passed').detail, /list\.example\.org \(fail\), example\.com \(pass\)/);
  assert.equal(finding(analysis, 'SPF failed').severity, 'critical');
  assert.equal(finding(analysis, 'DMARC failed').severity, 'critical');
  // Findings are sorted with the most severe first.
  assert.equal(analysis.findings[0].severity, 'critical');
});

test('the top Authentication-Results header decides the overall result', () => {
  const analysis = parseEmailHeaders([
    'Authentication-Results: mx.final.example; spf=fail smtp.mailfrom=a.example',
    'Authentication-Results: mx.earlier.example; spf=pass smtp.mailfrom=a.example; dkim=none',
  ].join('\n'));
  assert.equal(analysis.auth.spf, 'fail');
  assert.equal(analysis.auth.dkim, 'none');
  assert.equal(analysis.auth.dmarc, null);
});

test('ARC results, Received-SPF and DKIM-Signature tags are parsed', () => {
  const analysis = parseEmailHeaders([
    'ARC-Authentication-Results: i=1; mx.example.net; dkim=pass header.d=example.com; spf=pass smtp.mailfrom=example.com',
    'Received-SPF: Pass (mx.example.net: domain of a@example.com designates 192.0.2.1 as permitted sender) client-ip=192.0.2.1; envelope-from="a@example.com"; helo=mail.example.com;',
    'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=Example.com; s=sel1;',
    '\th=from:to:subject; bh=abc=; b=def',
    ' ghi=',
  ].join('\n'));
  assert.deepEqual(analysis.auth.arcResults.map(result => `${result.method}=${result.result}`), ['dkim=pass', 'spf=pass']);
  assert.equal(analysis.auth.arcResults[0].authservId, 'mx.example.net');
  assert.equal(analysis.auth.receivedSpf[0].result, 'pass');
  assert.equal(analysis.auth.receivedSpf[0].props['client-ip'], '192.0.2.1');
  assert.equal(analysis.auth.receivedSpf[0].props['envelope-from'], 'a@example.com');
  assert.deepEqual(analysis.auth.dkimSignatures, [{ d: 'example.com', s: 'sel1', a: 'rsa-sha256' }]);
  assert.deepEqual(parseDkimSignature('garbage'), { d: '', s: '', a: '' });
  // No Authentication-Results header: SPF falls back to Received-SPF and the gap is reported.
  assert.equal(analysis.auth.hasAuthenticationResults, false);
  assert.equal(analysis.auth.spf, 'pass');
  assert.equal(finding(analysis, 'No Authentication-Results header').severity, 'warning');
});

test('a DKIM signature from another domain is reported as not aligned', () => {
  const analysis = parseEmailHeaders([
    'Authentication-Results: mx.example.net; dkim=pass header.d=mailer-service.net header.s=s1; spf=pass smtp.mailfrom=bounce.mailer-service.net',
    'Return-Path: <b-123@bounce.mailer-service.net>',
    'From: "Billing" <billing@shop.example.com>',
    'Reply-To: help@other-desk.org',
  ].join('\n'));
  const alignment = finding(analysis, 'DKIM signing domain is not aligned');
  assert.equal(alignment.severity, 'warning');
  assert.match(alignment.detail, /mailer-service\.net/);
  assert.match(alignment.detail, /approximate/);
  assert.equal(finding(analysis, 'From domain differs from Return-Path domain').severity, 'warning');
  assert.equal(finding(analysis, 'Reply-To domain differs from From domain').severity, 'warning');
});

test('a subdomain of the From domain counts as aligned', () => {
  const analysis = parseEmailHeaders([
    'Authentication-Results: mx.example.net; dkim=pass header.i=@mail.example.com; dmarc=pass header.from=example.com',
    'Return-Path: <bounce@bounces.example.com>',
    'Reply-To: support@example.com',
    'From: news@example.com',
  ].join('\n'));
  assert.equal(finding(analysis, 'DKIM signing domain is aligned').severity, 'ok');
  assert.ok(!titles(analysis).some(title => title.includes('differs')));
});

test('organizational domain and address helpers', () => {
  assert.equal(organizationalDomain('a.b.example.com'), 'example.com');
  assert.equal(organizationalDomain('example.com'), 'example.com');
  assert.equal(organizationalDomain('mail.example.co.uk'), 'example.co.uk');
  assert.equal(addressDomain('"fake@paypal.com" <real@Evil.Example>'), 'evil.example');
  assert.equal(addressDomain('plain@example.com'), 'example.com');
  assert.equal(addressDomain('<>'), '');
  assert.equal(addressDomain('no address here'), '');
});

test('encoded words in Subject and From are decoded', () => {
  assert.equal(decodeEncodedWords('=?UTF-8?B?SGVsbG8gV8O2cmxk?='), 'Hello Wörld');
  assert.equal(decodeEncodedWords('=?utf-8?Q?Caf=C3=A9_au_lait?= today'), 'Café au lait today');
  assert.equal(decodeEncodedWords('=?ISO-8859-1?Q?Andr=E9?= <andre@example.com>'), 'André <andre@example.com>');
  // Whitespace between two encoded words is dropped, and a character split across words survives.
  assert.equal(decodeEncodedWords('=?UTF-8?B?w6TDtg==?= =?UTF-8?B?w7w=?='), 'äöü');
  assert.equal(decodeEncodedWords('=?UTF-8?B?4oI=?= =?UTF-8?B?rA==?='), '€');
  assert.equal(decodeEncodedWords('plain text = no ?= change'), 'plain text = no ?= change');
  assert.equal(decodeEncodedWords('=?UTF-8?B?!!!?= rest'), '=?UTF-8?B?!!!?= rest');
  assert.equal(decodeEncodedWords('=?x-unknown-charset?Q?abc?='), 'abc');

  const analysis = parseEmailHeaders('Subject: =?UTF-8?Q?Rechnung_f=C3=BCr?=\n =?UTF-8?Q?_M=C3=A4rz?=\nFrom: =?UTF-8?B?SsO8cmdlbg==?= <j@example.com>\n');
  assert.equal(analysis.summary.subject, 'Rechnung für März');
  assert.equal(analysis.summary.from, 'Jürgen <j@example.com>');
});

test('summary fields, spam headers and X-Originating-IP', () => {
  const analysis = parseEmailHeaders([
    'Return-Path: <a@example.com>',
    'From: a@example.com',
    'To: b@example.net',
    'Cc: c@example.net',
    'Subject: Test',
    'Date: Mon, 2 Nov 2026 10:00:00 +0000',
    'Message-ID: <1@example.com>',
    'User-Agent: Mutt/2.2',
    'X-Spam-Flag: YES',
    'X-Spam-Score: 7.1',
    'X-Originating-IP: [203.0.113.9]',
  ].join('\n'));
  assert.deepEqual(analysis.summary, {
    from: 'a@example.com', to: 'b@example.net', cc: 'c@example.net', subject: 'Test', date: 'Mon, 2 Nov 2026 10:00:00 +0000',
    messageId: '<1@example.com>', returnPath: '<a@example.com>', replyTo: '', mailer: 'Mutt/2.2',
  });
  assert.equal(finding(analysis, 'marked this message as spam').severity, 'warning');
  assert.match(finding(analysis, 'X-Originating-IP').detail, /203\.0\.113\.9/);
});

test('the sample has five hops, passing authentication and one slow hop', () => {
  const analysis = parseEmailHeaders(EMAIL_HEADERS_SAMPLE);
  assert.equal(analysis.hops.length, 5);
  assert.equal(analysis.hops[0].from.startsWith('app-02.northwind-billing.com'), true);
  assert.deepEqual(analysis.hops.map(hop => hop.delaySeconds), [null, 2, 409, 2, 1]);
  assert.equal(analysis.totalTransitSeconds, 414);
  assert.deepEqual([analysis.auth.spf, analysis.auth.dkim, analysis.auth.dmarc], ['pass', 'pass', 'pass']);
  assert.equal(analysis.summary.subject, 'Invoice INV-20418 for November – due 8 December');
  assert.equal(analysis.summary.from, 'Northwind Billing – Invoices <invoices@northwind-billing.com>');
  assert.ok(finding(analysis, 'Hop 3 took 6 min 49 s'));
  assert.ok(!analysis.headers.some(header => header.value.includes('message body')));
});

test('garbage, empty and non-string input give an empty result without throwing', () => {
  for (const input of ['', '   \n\n  ', 'just some words\nwith no header in sight', '\u0000\u0001\u0002 ((( ;;; ===', ':::\n: value\n', null, undefined, 42]) {
    const analysis = parseEmailHeaders(input);
    assert.deepEqual(analysis.headers, []);
    assert.deepEqual(analysis.hops, []);
    assert.deepEqual(analysis.findings, []);
    assert.equal(analysis.totalTransitSeconds, null);
    assert.equal(analysis.auth.spf, null);
    assert.equal(analysis.summary.subject, '');
  }
});

test('malformed header values do not throw', () => {
  const analysis = parseEmailHeaders([
    'Received: ((((( unbalanced; ;;; from by with id for',
    'Received:',
    'Authentication-Results: ;;;===; spf=; dkim; =pass; "unterminated',
    'Received-SPF:',
    'DKIM-Signature: ;;=;d',
    'From: <<<>>>@@@',
    'Subject: =?UTF-8?B?????= =?=?=?Q??=',
  ].join('\n'));
  assert.equal(analysis.headers.length, 7);
  assert.equal(analysis.hops.length, 2);
});

test('very large input is handled quickly and capped', () => {
  const started = Date.now();
  const garbage = parseEmailHeaders('no header on this line ((( =?x?b?\n'.repeat(150000));
  assert.equal(garbage.headers.length, 0);
  const many = parseEmailHeaders('Received: from a by b with ESMTP id 1; Mon, 2 Nov 2026 10:00:00 +0000\n'.repeat(150000));
  assert.equal(many.headers.length, MAX_HEADERS);
  assert.equal(many.truncated, true);
  const folded = parseEmailHeaders(`X-Long: start\n${' continuation line\n'.repeat(150000)}`);
  assert.equal(folded.headers.length, 1);
  assert.ok(Date.now() - started < 5000);
});

test('durations are formatted in short units', () => {
  assert.equal(formatDuration(0), '0 s');
  assert.equal(formatDuration(59), '59 s');
  assert.equal(formatDuration(120), '2 min');
  assert.equal(formatDuration(409), '6 min 49 s');
  assert.equal(formatDuration(7500), '2 h 5 min');
  assert.equal(formatDuration(90000), '1 d 1 h');
});
