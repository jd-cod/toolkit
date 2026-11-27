import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeMailLog, isReputationReason, normalizeReason, rejectCategory } from '../../frontend/src/lib/tools/mail-log.ts';
import { buildMailLogSample } from '../../frontend/src/lib/tools/mail-log-sample.ts';
import { formatLogTime } from '../../frontend/src/lib/tools/syslog.ts';

// Local noon on 27 November 2026. Syslog lines without a year are dated against this.
const NOW = new Date(2026, 10, 27, 12, 0, 0);
const pf = (program, message, time = '10:15:01') => `Nov 27 ${time} mx1 postfix/${program}[1234]: ${message}`;
const analyze = (lines, options = {}) => analyzeMailLog(Array.isArray(lines) ? lines.join('\n') : lines, { now: NOW, ...options });
const sent = (id, to, extra = 'relay=mx.example.net[203.0.113.20]:25, delay=1.4, delays=0.05/0.01/0.6/0.74, dsn=2.0.0') => pf('smtp', `${id}: to=<${to}>, ${extra}, status=sent (250 2.0.0 Ok: queued as 7C1A52E0F3)`);
const queued = (id, from, size = 1000) => pf('qmgr', `${id}: from=<${from}>, size=${size}, nrcpt=1 (queue active)`);

test('smtpd connect and disconnect lines are recognized', () => {
  const result = analyze([
    pf('smtpd', 'connect from mail.example.org[198.51.100.10]'),
    pf('smtpd', 'connect from unknown[2001:db8::7]'),
    pf('smtpd', 'disconnect from mail.example.org[198.51.100.10] ehlo=1 mail=1 rcpt=1 data=1 quit=1 commands=5'),
    pf('smtpd', '4F9D21A0C2: client=mail.example.org[198.51.100.10]'),
    pf('cleanup', '4F9D21A0C2: message-id=<20261127101501.4F9D21A0C2@mx1.example.com>'),
    pf('pickup', '5A0B31A0D7: uid=0 from=<root>'),
  ]);
  assert.equal(result.totals.lines, 6);
  assert.equal(result.totals.recognized, 6);
  assert.equal(result.totals.connections, 2);
  assert.equal(result.totals.queued, 0);
});

test('qmgr lines count queued messages and bytes once per message', () => {
  const result = analyze([
    queued('4F9D21A0C2', 'Alice@Example.org', 4821),
    queued('4F9D21A0C2', 'Alice@Example.org', 4821),
    queued('5A0B31A0D7', 'alice@example.org', 1000),
    queued('6B1C42B1E8', '', 3000),
    pf('qmgr', '4F9D21A0C2: removed'),
    queued('4F9D21A0C2', 'bob@example.com', 500),
  ]);
  assert.equal(result.totals.recognized, 6);
  assert.equal(result.totals.queued, 4, 'a retry of an open message is not a new message, a reused ID after removal is');
  assert.equal(result.totals.bytesQueued, 4821 + 1000 + 3000 + 500);
  assert.deepEqual(result.topSenders.map(row => [row.sender, row.messages, row.bytes]), [
    ['alice@example.org', 2, 5821],
    ['<>', 1, 3000],
    ['bob@example.com', 1, 500],
  ]);
  assert.equal(result.senderTotal, 3);
});

test('delivery lines from every delivery agent are counted by status', () => {
  const result = analyze([
    queued('4F9D21A0C2', 'alice@example.org'),
    sent('4F9D21A0C2', 'carol@example.net'),
    pf('lmtp', '4F9D21A0C2: to=<bob@example.com>, orig_to=<sales@example.com>, relay=mx1.example.com[private/dovecot-lmtp], delay=0.2, delays=0.1/0.01/0.01/0.08, dsn=2.0.0, status=sent (250 2.0.0 <bob@example.com> kHXrL3 Saved)'),
    pf('local', '4F9D21A0C2: to=<root@mx1.example.com>, relay=local, delay=0.12, delays=0.08/0.01/0/0.03, dsn=2.0.0, status=sent (delivered to mailbox)'),
    pf('virtual', '4F9D21A0C2: to=<dave@example.com>, relay=virtual, delay=0.3, delays=0.2/0.01/0/0.09, dsn=2.0.0, status=sent (delivered to maildir)'),
    pf('pipe', '4F9D21A0C2: to=<erin@example.com>, relay=dovecot, delay=0.1, delays=0.05/0/0/0.05, dsn=2.0.0, status=sent (delivered via dovecot service)'),
    pf('error', '4F9D21A0C2: to=<gina@slow.example>, relay=none, delay=3600, delays=3599/0.01/0/0.02, dsn=4.4.1, status=deferred (delivery temporarily suspended: connect to mx.slow.example[203.0.113.60]:25: Connection timed out)'),
    pf('smtp', '4F9D21A0C2: to=<nobody@example.net>, relay=mx.example.net[203.0.113.20]:25, delay=0.6, delays=0.03/0.01/0.4/0.16, dsn=5.1.1, status=bounced (host mx.example.net[203.0.113.20] said: 550 5.1.1 <nobody@example.net>: Recipient address rejected: User unknown in virtual mailbox table (in reply to RCPT TO command))'),
    pf('smtp', '4F9D21A0C2: to=<old@example.net>, relay=none, delay=432000, delays=432000/0/0/0, dsn=4.4.1, status=expired (connect to mx.example.net[203.0.113.20]:25: Connection timed out)'),
    pf('qmgr', '5A0B31A0D7: from=<alice@example.org>, status=expired, returned to sender'),
    pf('smtp', '4F9D21A0C2: to=<probe@example.net>, relay=mx.example.net[203.0.113.20]:25, delay=0.2, delays=0/0/0.1/0.1, dsn=2.1.5, status=deliverable (250 2.1.5 Ok)'),
  ]);
  assert.equal(result.totals.delivered, 5);
  assert.equal(result.totals.deferred, 1);
  assert.equal(result.totals.bounced, 1);
  assert.equal(result.totals.expired, 2);
  assert.equal(result.totals.recognized, 10, 'an address probe is not a delivery');
  assert.deepEqual(result.topSenders[0], { sender: 'alice@example.org', messages: 1, bytes: 1000, sent: 5, deferred: 1, bounced: 1 });
  assert.equal(result.recipientTotal, 7);
  assert.deepEqual(result.topDomains[0], { name: 'example.com', sent: 3, deferred: 0, bounced: 0, total: 3 });
  assert.deepEqual(result.topDomains.find(row => row.name === 'example.net'), { name: 'example.net', sent: 1, deferred: 0, bounced: 1, total: 2 });
  assert.deepEqual(result.topRecipients.find(row => row.name === 'gina@slow.example'), { name: 'gina@slow.example', sent: 0, deferred: 1, bounced: 0, total: 1 });
  assert.equal(result.deferredReasons[0].example, 'delivery temporarily suspended: connect to mx.slow.example[203.0.113.60]:25: Connection timed out');
  assert.equal(result.bouncedReasons[0].example.endsWith('(in reply to RCPT TO command)'), true, 'nested parentheses stay in the reason');
});

test('delay average and maximum come from sent mail only', () => {
  const line = (delay, status) => pf('smtp', `4F9D21A0C2: to=<carol@example.net>, relay=mx.example.net[203.0.113.20]:25, delay=${delay}, delays=0/0/0/0, dsn=2.0.0, status=${status} (text with delay=999 inside)`);
  const result = analyze([line('1.5', 'sent'), line('0.5', 'sent'), line('10', 'sent'), line('5000', 'deferred'), line('7000', 'bounced')]);
  assert.equal(result.delay.count, 3);
  assert.equal(result.delay.average, 4);
  assert.equal(result.delay.max, 10);
  assert.deepEqual(analyze([]).delay, { count: 0, average: 0, max: 0 });
});

test('rejects are grouped by code and category, with the client address', () => {
  const result = analyze([
    pf('smtpd', 'NOQUEUE: reject: RCPT from unknown[203.0.113.150]: 554 5.7.1 <victim@elsewhere.example>: Relay access denied; from=<promo@spam.example> to=<victim@elsewhere.example> proto=ESMTP helo=<203.0.113.150>'),
    pf('smtpd', 'NOQUEUE: reject: RCPT from unknown[203.0.113.150]: 554 5.7.1 <other@elsewhere.example>: Relay access denied; from=<promo@spam.example> to=<other@elsewhere.example> proto=ESMTP helo=<203.0.113.150>'),
    pf('smtpd', 'NOQUEUE: reject: RCPT from mail.example.org[198.51.100.10]: 550 5.1.1 <jim@example.com>: Recipient address rejected: User unknown in local recipient table; from=<alice@example.org> to=<jim@example.com> proto=ESMTP helo=<mail.example.org>'),
    pf('smtpd', 'NOQUEUE: reject: RCPT from unknown[203.0.113.151]: 554 5.7.1 Service unavailable; Client host [203.0.113.151] blocked using zen.spamhaus.org; https://www.spamhaus.org/query/ip/203.0.113.151; from=<offer@bulk.example> to=<bob@example.com> proto=ESMTP helo=<bulk.example>'),
    pf('smtpd', 'NOQUEUE: reject: RCPT from unknown[203.0.113.152]: 450 4.7.25 Client host rejected: cannot find your hostname, [203.0.113.152]; from=<news@nohost.example> to=<support@example.com> proto=ESMTP helo=<nohost.example>'),
    pf('smtpd', 'NOQUEUE: reject: RCPT from unknown[2001:db8:91::7]: 504 5.5.2 <WIN-4K2JD81>: Helo command rejected: need fully-qualified hostname; from=<a@b.example> to=<bob@example.com> proto=ESMTP helo=<WIN-4K2JD81>'),
    pf('smtpd', 'NOQUEUE: reject: MAIL from mail.fake.example[203.0.113.153]: 450 4.1.8 <bounce@no-such-domain.example>: Sender address rejected: Domain not found; from=<bounce@no-such-domain.example> proto=ESMTP helo=<mail.fake.example>'),
    pf('smtpd', 'NOQUEUE: reject: CONNECT from unknown[203.0.113.154]: 554 5.7.1 <unknown[203.0.113.154]>: Client host rejected: Access denied; proto=SMTP'),
    pf('smtpd', 'NOQUEUE: reject: RCPT from unknown[203.0.113.155]: 450 4.2.0 <bob@example.com>: Recipient address rejected: Greylisted, see http://postgrey.schweikert.ch/help/example.com.html; from=<x@y.example> to=<bob@example.com> proto=ESMTP helo=<y.example>'),
    pf('smtpd', 'NOQUEUE: reject: RCPT from unknown[203.0.113.156]: 452 4.3.1 Insufficient system storage; from=<x@y.example> to=<bob@example.com> proto=ESMTP helo=<y.example>'),
    pf('postscreen', 'NOQUEUE: reject: RCPT from [203.0.113.157]:54321: 550 5.7.1 Service unavailable; client [203.0.113.157] blocked using bl.spamcop.net; from=<x@y.example>, to=<bob@example.com>, proto=ESMTP, helo=<y.example>'),
    pf('smtpd', 'NOQUEUE: milter-reject: RCPT from unknown[203.0.113.158]: 451 4.7.1 Service unavailable - try again later; from=<x@y.example> to=<bob@example.com> proto=ESMTP helo=<y.example>'),
    pf('cleanup', '4F9D21A0C2: milter-reject: END-OF-MESSAGE from mail.example.org[198.51.100.10]: 5.7.1 Message rejected as spam; from=<alice@example.org> to=<bob@example.com> proto=ESMTP helo=<mail.example.org>'),
    pf('smtpd', 'NOQUEUE: reject_warning: RCPT from unknown[203.0.113.159]: 554 5.7.1 Service unavailable; from=<x@y.example> to=<bob@example.com> proto=ESMTP helo=<y.example>'),
  ]);
  assert.equal(result.totals.rejected, 13, 'reject_warning only warns and is not a reject');
  assert.equal(result.totals.recognized, 13);
  const groups = Object.fromEntries(result.rejectReasons.map(row => [`${row.code} ${row.category}`, row.count]));
  assert.deepEqual(groups, {
    '554 Relay access denied': 2,
    '550 Recipient address rejected: User unknown': 1,
    '554 Blocked using zen.spamhaus.org': 1,
    '450 Client host rejected': 1,
    '504 Helo command rejected': 1,
    '450 Sender address rejected': 1,
    '554 Client host rejected': 1,
    '450 Greylisted': 1,
    '452 Other': 1,
    '550 Blocked using bl.spamcop.net': 1,
    '451 Other': 1,
    '5.7.1 Other': 1,
  });
  assert.equal(result.rejectReasons[0].category, 'Relay access denied');
  assert.equal(result.rejectReasons[0].example, '<victim@elsewhere.example>: Relay access denied', 'the from= and to= fields are cut off');
  assert.equal(result.rejectReasonTotal, 12);
  assert.deepEqual(result.topRejectedClients.slice(0, 2), [
    { ip: '198.51.100.10', host: 'mail.example.org', count: 2 },
    { ip: '203.0.113.150', host: 'unknown', count: 2 },
  ]);
  assert.ok(result.topRejectedClients.some(row => row.ip === '2001:db8:91::7'));
  assert.ok(result.topRejectedClients.some(row => row.ip === '203.0.113.157' && row.host === 'unknown'), 'postscreen writes no host name');
  assert.equal(result.rejectedClientTotal, 11);
  assert.equal(result.timeline.buckets[0].counts[3], 13);
});

test('reject categories', () => {
  assert.equal(rejectCategory('<a@b>: Relay access denied'), 'Relay access denied');
  assert.equal(rejectCategory('<a@b>: Recipient address rejected: User unknown in virtual mailbox table'), 'Recipient address rejected: User unknown');
  assert.equal(rejectCategory('<a@b>: Recipient address rejected: Access denied'), 'Recipient address rejected');
  assert.equal(rejectCategory('<a@b>: Recipient address rejected: Greylisted for 300 seconds'), 'Greylisted');
  assert.equal(rejectCategory('Service unavailable; Client host [192.0.2.1] blocked using ZEN.spamhaus.org.; listed'), 'Blocked using zen.spamhaus.org');
  assert.equal(rejectCategory('Client host rejected: cannot find your reverse hostname'), 'Client host rejected');
  assert.equal(rejectCategory('<x@y>: Sender address rejected: Domain not found'), 'Sender address rejected');
  assert.equal(rejectCategory('<x>: Helo command rejected: Host not found'), 'Helo command rejected');
  assert.equal(rejectCategory('Error: too many recipients'), 'Other');
  assert.equal(rejectCategory(undefined), 'Other');
});

test('SASL failures and connections dropped during AUTH are counted per address', () => {
  const result = analyze([
    pf('smtpd', 'warning: unknown[203.0.113.200]: SASL LOGIN authentication failed: UGFzc3dvcmQ6'),
    pf('smtpd', 'warning: unknown[203.0.113.200]: SASL LOGIN authentication failed: UGFzc3dvcmQ6'),
    pf('smtpd', 'warning: unknown[203.0.113.200]: SASL PLAIN authentication failed: (reason unavailable), sasl_username=info@example.com'),
    pf('smtpd', 'warning: host.example.net[2001:DB8:77::9]: SASL PLAIN authentication failed: authentication failure'),
    pf('submission/smtpd', 'warning: unknown[203.0.113.201]: SASL CRAM-MD5 authentication failed: Invalid authentication mechanism'),
    pf('smtpd', 'lost connection after AUTH from unknown[203.0.113.200]'),
    pf('smtpd', 'too many errors after AUTH from unknown[203.0.113.200]'),
    pf('smtpd', 'lost connection after DATA (0 bytes) from unknown[203.0.113.202]'),
    pf('smtpd', 'timeout after RCPT from unknown[203.0.113.203]'),
    pf('smtpd', 'warning: hostname mail.fake.example does not resolve to address 203.0.113.153'),
  ]);
  assert.equal(result.totals.saslFailures, 5);
  assert.equal(result.totals.recognized, 9, 'other warnings are not recognized');
  assert.deepEqual(result.saslClients, [
    { ip: '203.0.113.200', host: 'unknown', failures: 3, aborted: 2 },
    { ip: '2001:db8:77::9', host: 'host.example.net', failures: 1, aborted: 0 },
    { ip: '203.0.113.201', host: 'unknown', failures: 1, aborted: 0 },
  ]);
  assert.equal(result.saslClientTotal, 3);
});

test('postscreen and bounce service lines', () => {
  const result = analyze([
    pf('postscreen', 'CONNECT from [203.0.113.154]:41876 to [192.0.2.25]:25'),
    pf('postscreen', 'PREGREET 11 after 0.07 from [203.0.113.154]:41876: EHLO User\\r\\n'),
    pf('postscreen', 'DNSBL rank 6 for [203.0.113.154]:41876'),
    pf('postscreen', 'DNSBL rank 3 for [2001:db8::99]:41877'),
    pf('bounce', '4F9D21A0C2: sender non-delivery notification: 5A0B31A0D7'),
    pf('bounce', '4F9D21A0C2: sender delivery status notification: 6B1C42B1E8'),
  ]);
  assert.equal(result.totals.postscreenPregreet, 1);
  assert.equal(result.totals.postscreenDnsbl, 2);
  assert.equal(result.totals.bounceNotifications, 1);
  assert.equal(result.totals.recognized, 5);
  assert.equal(result.totals.rejected, 0);
});

test('other instance names, service names and long queue IDs are accepted', () => {
  const result = analyze([
    'Nov 27 10:15:01 mx1 postfix-out/qmgr[77]: 3Pt2mN2VXxznjll: from=<alice@example.org>, size=2000, nrcpt=1 (queue active)',
    'Nov 27 10:15:02 mx1 postfix-out/smtp[78]: 3Pt2mN2VXxznjll: to=<carol@example.net>, relay=mx.example.net[203.0.113.20]:25, delay=1, delays=0/0/0.5/0.5, dsn=2.0.0, status=sent (250 2.0.0 Ok)',
    'Nov 27 10:15:02 mx1 postfix-out/qmgr[77]: 3Pt2mN2VXxznjll: removed',
    'Nov 27 10:15:03 mx1 postfix/submission/smtpd[79]: connect from unknown[198.51.100.99]',
    'Nov 27 10:15:03 mx1 postfix/smtps/smtpd[80]: NOQUEUE: reject: RCPT from unknown[198.51.100.99]: 554 5.7.1 <x@y.example>: Relay access denied; from=<a@b.example> to=<x@y.example> proto=ESMTP helo=<h>',
    'Nov 27 10:15:04 mx1 postfix/smtp[81]: 4bXkQ51zYJz9sS4: to=<dave@example.net>, relay=none, delay=30, delays=0/0/30/0, dsn=4.4.1, status=deferred (connect to mx.example.net[203.0.113.20]:25: Connection refused)',
  ]);
  assert.equal(result.totals.recognized, 6);
  assert.equal(result.totals.queued, 1);
  assert.equal(result.totals.delivered, 1);
  assert.equal(result.totals.deferred, 1);
  assert.equal(result.totals.rejected, 1);
  assert.equal(result.totals.connections, 1);
  assert.equal(result.topSenders[0].sent, 1);
});

test('lines from other programs are ignored', () => {
  const result = analyze([
    'Nov 27 10:15:01 mx1 dovecot[900]: imap-login: Login: user=<bob@example.com>, method=PLAIN, rip=198.51.100.5, lip=192.0.2.25, mpid=901, TLS',
    'Nov 27 10:15:01 mx1 dovecot[900]: lmtp(bob@example.com): msgid=<x@y>: saved mail to INBOX, status=sent (ok)',
    'Nov 27 10:15:01 mx1 exim[901]: 1tGh2a-0001Xy-2B <= alice@example.org H=mail.example.org [198.51.100.10] P=esmtps S=4821',
    'Nov 27 10:15:01 mx1 sendmail[902]: 4ARAF1x9000902: to=<carol@example.net>, delay=00:00:01, mailer=esmtp, stat=Sent',
    'Nov 27 10:15:01 mx1 opendkim[903]: 4F9D21A0C2: DKIM-Signature field added (s=mail, d=example.com)',
    'Nov 27 10:15:01 mx1 postfix[904]: Postfix is running with backwards-compatible default settings',
    pf('anvil', 'statistics: max connection rate 3/60s for (smtp:203.0.113.200) at Nov 27 10:12:11'),
    pf('smtpd', 'warning: TLS library problem: error:0A000126:SSL routines::unexpected eof while reading'),
    pf('qmgr', 'NOQUEUE: from=<x@y>, size=1, nrcpt=1 (queue active)'),
  ]);
  assert.equal(result.totals.lines, 9);
  assert.equal(result.totals.recognized, 0);
  assert.equal(result.totals.queued, 0);
  assert.equal(result.totals.delivered, 0);
  assert.equal(result.findings[0].title, 'No Postfix lines were recognized');
});

test('reasons are normalized so similar ones group', () => {
  assert.equal(normalizeReason('connect to mx.slow.example[203.0.113.60]:25: Connection timed out'), 'connect to <host>: Connection timed out');
  assert.equal(normalizeReason('connect to mail.other.example[2001:db8::25]:25: Connection timed out'), 'connect to <host>: Connection timed out');
  assert.equal(
    normalizeReason('host mx.example.net[203.0.113.20] said: 550 5.1.1 <nobody@example.net>: Recipient address rejected: User unknown in virtual mailbox table (in reply to RCPT TO command)'),
    'host <host> said: 550 5.1.1 <address>: Recipient address rejected: User unknown in virtual mailbox table (in reply to RCPT TO command)',
  );
  assert.equal(normalizeReason('Host or domain name not found. Name service error for name=typo.example type=MX: Host not found, try again'), 'Host or domain name not found. Name service error for name=<name> type=MX: Host not found, try again');
  assert.equal(normalizeReason('host mx.a.example[192.0.2.9] said: 554 5.7.1 Client host [192.0.2.25] blocked, see 198.51.100.7'), 'host <host> said: 554 5.7.1 Client host [<ip>] blocked, see <ip>');
  assert.equal(normalizeReason('host a[192.0.2.9] said: 451 4.3.0 queue id 7C1A52E0F3 ref 3Pt2mN2VXxznjll ticket 1234567 try later'), 'host <host> said: 451 4.3.0 queue id <id> ref <id> ticket <n> try later');
  assert.equal(normalizeReason('unknown user: "bob"'), 'unknown user: "..."');
  assert.equal(normalizeReason('user bob@example.com   over   quota'), 'user <address> over quota');
  assert.equal(normalizeReason(undefined), '');
  assert.ok(normalizeReason('x'.repeat(5000)).length <= 200);

  const deferred = (to, reason) => pf('smtp', `4F9D21A0C2: to=<${to}>, relay=none, delay=30, delays=0/0/30/0, dsn=4.4.1, status=deferred (${reason})`);
  const bounced = (to, reason) => pf('smtp', `4F9D21A0C2: to=<${to}>, relay=none, delay=1, delays=0/0/1/0, dsn=5.1.1, status=bounced (${reason})`);
  const result = analyze([
    deferred('a@one.example', 'connect to mx.one.example[203.0.113.60]:25: Connection timed out'),
    deferred('b@two.example', 'connect to mx.two.example[203.0.113.61]:25: Connection timed out'),
    deferred('c@three.example', 'connect to mail.three.example[2001:db8::25]:25: Connection timed out'),
    deferred('d@four.example', 'connect to mx.four.example[203.0.113.62]:25: Connection refused'),
    bounced('e@five.example', 'host mx.five.example[203.0.113.63] said: 550 5.1.1 <e@five.example>: Recipient address rejected: User unknown in virtual mailbox table (in reply to RCPT TO command)'),
    bounced('f@six.example', 'host mx.six.example[203.0.113.64] said: 550 5.1.1 <f@six.example>: Recipient address rejected: User unknown in virtual mailbox table (in reply to RCPT TO command)'),
    bounced('g@seven.example', 'unknown user: "g"'),
  ]);
  assert.deepEqual(result.deferredReasons, [
    { reason: 'connect to <host>: Connection timed out', count: 3, example: 'connect to mx.one.example[203.0.113.60]:25: Connection timed out' },
    { reason: 'connect to <host>: Connection refused', count: 1, example: 'connect to mx.four.example[203.0.113.62]:25: Connection refused' },
  ]);
  assert.equal(result.deferredReasonTotal, 2);
  assert.equal(result.bouncedReasons.length, 2);
  assert.equal(result.bouncedReasons[0].count, 2);
  assert.equal(result.bouncedReasons[0].example.includes('e@five.example'), true, 'the first raw reason is kept as the example');
});

test('reputation wording from remote servers is detected', () => {
  assert.ok(isReputationReason('host mx.big.example[203.0.113.80] said: 554 5.7.1 Service unavailable; Client host [192.0.2.25] blocked using zen.spamhaus.org (in reply to RCPT TO command)'));
  assert.ok(isReputationReason('host mx.big.example[203.0.113.80] refused to talk to me: 554 5.7.1 Your IP 192.0.2.25 is blacklisted'));
  assert.ok(isReputationReason('host mx.big.example[203.0.113.80] said: 550 5.7.1 Our system has detected that this message is suspicious due to the very low reputation of the sending IP address (in reply to end of DATA command)'));
  assert.ok(isReputationReason('host mx.big.example[203.0.113.80] said: 550 5.7.606 Access denied, banned sending IP [192.0.2.25] (in reply to RCPT TO command)'));
  assert.ok(isReputationReason('host mx.big.example[203.0.113.80] said: 550 5.7.1 Unfortunately, messages from [192.0.2.25] weren\'t sent. Please contact your Internet service provider since part of their network is on our block list (S3150).'));
  assert.ok(!isReputationReason('host mx.example.net[203.0.113.20] said: 550 5.1.1 <nobody@example.net>: Recipient address rejected: User unknown (in reply to RCPT TO command)'));
  assert.ok(!isReputationReason('host mx.example.net[203.0.113.20] said: 552 5.2.2 Mailbox full (in reply to RCPT TO command)'));
  assert.ok(!isReputationReason('connect to mx.slow.example[203.0.113.60]:25: Connection timed out'));
  assert.ok(!isReputationReason('blocked using zen.spamhaus.org'), 'only answers from a remote server count');
  assert.ok(!isReputationReason(null));
});

test('a bounce for a block list reason is critical and links to the blacklist tool', () => {
  const bounce = pf('smtp', '4F9D21A0C2: to=<info@bigmail.example>, relay=mx.bigmail.example[203.0.113.80]:25, delay=0.7, delays=0.03/0.01/0.5/0.16, dsn=5.7.1, status=bounced (host mx.bigmail.example[203.0.113.80] said: 554 5.7.1 Service unavailable; Client host [192.0.2.25] blocked using zen.spamhaus.org; https://www.spamhaus.org/query/ip/192.0.2.25 (in reply to RCPT TO command))');
  const result = analyze([bounce, sent('5A0B31A0D7', 'a@example.net'), sent('5A0B31A0D7', 'b@example.net'), sent('5A0B31A0D7', 'c@example.net')]);
  assert.equal(result.findings[0].severity, 'critical');
  assert.ok(result.findings[0].title.startsWith('1 bounce says your server is blocked'));
  assert.ok(result.findings[0].detail.includes('/blacklist'));
  assert.ok(result.findings[0].detail.includes('zen.spamhaus.org'));
  assert.deepEqual(result.findings[0].link, { href: '/blacklist', label: 'Open the blacklist check' });

  const deferredOnly = analyze([
    pf('smtp', '4F9D21A0C2: to=<info@bigmail.example>, relay=mx.bigmail.example[203.0.113.80]:25, delay=0.7, delays=0.03/0.01/0.5/0.16, dsn=4.7.0, status=deferred (host mx.bigmail.example[203.0.113.80] said: 421 4.7.0 Temporarily rate limited due to IP reputation (in reply to MAIL FROM command))'),
    ...Array.from({ length: 20 }, (_, index) => sent('5A0B31A0D7', `u${index}@example.net`)),
  ]);
  assert.equal(deferredOnly.findings.length, 1);
  assert.equal(deferredOnly.findings[0].severity, 'warning');
  assert.equal(deferredOnly.findings[0].link.href, '/blacklist');
});

test('many SASL failures from one address are a warning that names it', () => {
  const lines = [];
  for (let index = 0; index < 12; index += 1) lines.push(pf('smtpd', 'warning: unknown[203.0.113.200]: SASL LOGIN authentication failed: UGFzc3dvcmQ6'));
  for (let index = 0; index < 3; index += 1) lines.push(pf('smtpd', 'warning: unknown[203.0.113.201]: SASL LOGIN authentication failed: UGFzc3dvcmQ6'));
  const result = analyze(lines);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].severity, 'warning');
  assert.equal(result.findings[0].title, '12 failed SMTP logins from 203.0.113.200');
  assert.ok(result.findings[0].detail.includes('15 SASL logins failed in total, from 2 addresses'));
  assert.deepEqual(analyze(lines.slice(3)).findings, [{ severity: 'ok', title: 'Nothing stands out in this log' }]);
});

test('one sender with most of the mail and many bounces is a warning', () => {
  const lines = [];
  let serial = 0;
  const message = (from, to, bounce) => {
    serial += 1;
    const id = (0x4f9d21a0c2 + serial).toString(16).toUpperCase();
    lines.push(queued(id, from));
    lines.push(bounce
      ? pf('smtp', `${id}: to=<${to}>, relay=mx.old.example[203.0.113.90]:25, delay=0.6, delays=0/0/0.4/0.2, dsn=5.1.1, status=bounced (host mx.old.example[203.0.113.90] said: 550 5.1.1 <${to}>: Recipient address rejected: User unknown (in reply to RCPT TO command))`)
      : sent(id, to));
    lines.push(pf('qmgr', `${id}: removed`));
  };
  for (let index = 0; index < 30; index += 1) message('webform@example.com', `user${index}@old.example`, index < 12);
  for (let index = 0; index < 20; index += 1) message(`staff${index % 4}@example.com`, 'carol@example.net', false);
  const result = analyze(lines);
  const finding = result.findings.find(item => item.title.startsWith('webform@example.com'));
  assert.equal(finding.severity, 'warning');
  assert.equal(finding.title, 'webform@example.com sent 60% of all queued mail, with 12 bounces');
  assert.ok(finding.detail.includes('30 of 50 messages'));
  assert.ok(finding.detail.includes('40% of its deliveries bounced'));
  assert.ok(finding.detail.includes('compromised account'));
  assert.deepEqual(result.topSenders[0], { sender: 'webform@example.com', messages: 30, bytes: 30000, sent: 18, deferred: 0, bounced: 12 });

  const healthy = lines.filter(line => !line.includes('status=bounced'));
  assert.ok(!analyze(healthy).findings.some(item => item.title.startsWith('webform@example.com')));
});

test('a deferred share above ten percent is a warning with the top reason', () => {
  const deferred = index => pf('smtp', `4F9D21A0C2: to=<u${index}@slow.example>, relay=none, delay=30, delays=0/0/30/0, dsn=4.4.1, status=deferred (connect to mx.slow.example[203.0.113.60]:25: Connection timed out)`);
  const lines = [];
  for (let index = 0; index < 17; index += 1) lines.push(sent('5A0B31A0D7', `u${index}@example.net`));
  for (let index = 0; index < 3; index += 1) lines.push(deferred(index));
  const result = analyze(lines);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].severity, 'warning');
  assert.equal(result.findings[0].title, '15% of delivery attempts were deferred');
  assert.ok(result.findings[0].detail.includes('3 of 20 attempts'));
  assert.ok(result.findings[0].detail.includes('Connection timed out'));

  // 2 of 20 is exactly ten percent, which is not above it.
  assert.deepEqual(analyze([...lines.slice(0, 19), sent('5A0B31A0D7', 'last@example.net')]).findings, [{ severity: 'ok', title: 'Nothing stands out in this log' }]);
});

test('relay access denied is information, not a problem', () => {
  const result = analyze([
    pf('smtpd', 'NOQUEUE: reject: RCPT from unknown[203.0.113.150]: 554 5.7.1 <victim@elsewhere.example>: Relay access denied; from=<promo@spam.example> to=<victim@elsewhere.example> proto=ESMTP helo=<203.0.113.150>'),
  ]);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].severity, 'info');
  assert.equal(result.findings[0].title, '1 relay attempt was refused');
  assert.ok(result.findings[0].detail.includes('correctly'));
});

test('both timestamp formats are read and feed the hourly timeline', () => {
  const oneDay = [
    'Nov 27 09:59:59 mx1 postfix/smtp[1]: 4F9D21A0C2: to=<a@example.net>, relay=mx.example.net[203.0.113.20]:25, delay=1, delays=0/0/0.5/0.5, dsn=2.0.0, status=sent (250 Ok)',
    '2026-11-27T10:15:01.123456+00:00 mx1 postfix/smtp[1]: 4F9D21A0C2: to=<b@example.net>, relay=none, delay=30, delays=0/0/30/0, dsn=4.4.1, status=deferred (connect to mx.example.net[203.0.113.20]:25: Connection timed out)',
    '2026-11-27T10:20:00+0000 mx1 postfix/smtp[1]: 4F9D21A0C2: to=<c@example.net>, relay=none, delay=1, delays=0/0/1/0, dsn=5.1.1, status=bounced (unknown user)',
    '2026-11-27T12:00:00Z mx1 postfix/smtpd[2]: NOQUEUE: reject: RCPT from unknown[203.0.113.150]: 554 5.7.1 <x@y.example>: Relay access denied; from=<a@b.example> to=<x@y.example> proto=ESMTP helo=<h>',
  ];
  const day = analyze(oneDay);
  assert.equal(day.totals.recognized, 4);
  assert.equal(formatLogTime(day.firstSeen), '2026-11-27 09:59:59');
  assert.equal(formatLogTime(day.lastSeen), '2026-11-27 12:00:00');
  assert.equal(day.timeline.unit, 'hour');
  assert.deepEqual(day.timeline.buckets.map(bucket => [bucket.label, bucket.counts]), [
    ['2026-11-27 09:00', [1, 0, 0, 0]],
    ['2026-11-27 10:00', [0, 1, 1, 0]],
    ['2026-11-27 11:00', [0, 0, 0, 0]],
    ['2026-11-27 12:00', [0, 0, 0, 1]],
  ]);
  assert.equal(day.timeline.max, 2);

  const year = analyze([
    'Dec 31 23:00:00 mx1 postfix/smtp[1]: 4F9D21A0C2: to=<d@example.net>, relay=mx.example.net[203.0.113.20]:25, delay=1, delays=0/0/0.5/0.5, dsn=2.0.0, status=sent (250 Ok)',
    ...oneDay,
  ]);
  assert.equal(formatLogTime(year.firstSeen), '2025-12-31 23:00:00', 'a date that would be in the future belongs to last year');
  assert.equal(year.timeline.unit, 'day', 'eleven months do not fit in hourly bars');
});

test('lists are capped at 25 and keep their totals', () => {
  const lines = [];
  for (let index = 0; index < 60; index += 1) {
    const id = (0x4f9d21a0c2 + index).toString(16).toUpperCase();
    lines.push(queued(id, `sender${index}@example.com`));
    lines.push(sent(id, `rcpt${index}@domain${index}.example`));
    lines.push(pf('smtpd', `NOQUEUE: reject: RCPT from unknown[203.0.113.${index}]: 554 5.7.1 <x@y.example>: Relay access denied; from=<a@b.example> to=<x@y.example> proto=ESMTP helo=<h>`));
    lines.push(pf('smtpd', `warning: unknown[198.51.100.${index}]: SASL LOGIN authentication failed: UGFzc3dvcmQ6`));
  }
  const result = analyze(lines);
  assert.deepEqual([result.topSenders.length, result.senderTotal], [25, 60]);
  assert.deepEqual([result.topRecipients.length, result.recipientTotal], [25, 60]);
  assert.deepEqual([result.topDomains.length, result.domainTotal], [25, 60]);
  assert.deepEqual([result.topRejectedClients.length, result.rejectedClientTotal], [25, 60]);
  assert.deepEqual([result.saslClients.length, result.saslClientTotal], [25, 60]);
  assert.equal(analyze(lines, { limit: 5 }).topSenders.length, 5);
});

test('garbage and empty input do not throw', () => {
  for (const input of ['', '\n\n\r\n', '   ', undefined, null, 42, {}, '\u0000\u0001', 'Nov 27 10:15:01 mx1 postfix/smtp[1]:', 'Nov 27 10:15:01 mx1 postfix/smtp[1]: ', pf('smtp', '4F9D21A0C2: to=<'), pf('smtp', '4F9D21A0C2: to=<>, status='), pf('smtp', '4F9D21A0C2: to=<a@b>, status=sent ('), pf('qmgr', '4F9D21A0C2: from=<>, size=, nrcpt='), pf('smtpd', 'NOQUEUE: reject: RCPT from [: 554'), pf('smtpd', 'NOQUEUE: reject: '), pf('smtpd', 'warning: [: SASL'), 'postfix/smtpd', 'postfix/', '🙂'.repeat(5000), pf('smtp', `4F9D21A0C2: to=<a@b>, ${'status='.repeat(500)}`), pf('smtp', `4F9D21A0C2: to=<a@b>, relay=none, delay=1, status=deferred (${'a[1.2.3.4]'.repeat(2000)}`), `${pf('smtp', '4F9D21A0C2: to=<a@b>, relay=none, delay=1, status=bounced (')}${'x@'.repeat(3000)})`]) {
    const result = analyzeMailLog(input, { now: NOW });
    assert.ok(result.totals.lines >= 0);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Number.isFinite(result.delay.average));
  }
  const empty = analyzeMailLog('');
  assert.equal(empty.totals.lines, 0);
  assert.deepEqual(empty.findings, []);
  assert.deepEqual(empty.timeline.buckets, []);
  assert.equal(empty.firstSeen, null);
});

test('the sample log shows every kind of finding', () => {
  const sample = buildMailLogSample();
  assert.equal(sample, buildMailLogSample(), 'the sample is the same every time');
  const result = analyze(sample);
  assert.equal(result.totals.recognized, result.totals.lines, 'every sample line is a Postfix line the analyzer knows');
  assert.ok(result.totals.delivered > 0 && result.totals.deferred > 0 && result.totals.bounced > 0 && result.totals.rejected > 0 && result.totals.saslFailures > 0);
  assert.deepEqual(result.findings.map(item => item.severity), ['critical', 'warning', 'warning', 'warning', 'info']);
  assert.ok(result.findings[1].title.includes('203.0.113.200'));
  assert.ok(result.findings[2].title.startsWith('webform@example.com'));
  assert.ok(result.rejectReasons.some(row => row.category === 'Blocked using zen.spamhaus.org'));
  assert.equal(result.topSenders[0].sender, 'webform@example.com');
  assert.equal(result.timeline.unit, 'hour');
});

test('200,000 lines are analyzed in a few seconds', () => {
  const lines = [];
  const expected = { queued: 0, sent: 0, deferred: 0, bounced: 0, rejected: 0, sasl: 0 };
  let serial = 0;
  while (lines.length < 200000) {
    serial += 1;
    const index = serial;
    const hour = String(Math.floor(index / 1700) % 24).padStart(2, '0');
    const minute = String(Math.floor(index / 29) % 60).padStart(2, '0');
    const second = String(index % 60).padStart(2, '0');
    const head = program => `Nov 26 ${hour}:${minute}:${second} mx1 postfix/${program}[${1000 + (index % 30000)}]: `;
    const id = (0x4f9d21a0c2 + index * 7).toString(16).toUpperCase();
    const client = `host${index % 3000}.example.net[203.${index % 200}.${(index >> 3) % 250}.${(index * 7) % 250}]`;
    lines.push(`${head('smtpd')}connect from ${client}`);
    switch (index % 5) {
      case 0:
        lines.push(`${head('smtpd')}NOQUEUE: reject: RCPT from ${client}: 554 5.7.1 <victim${index}@elsewhere.example>: Relay access denied; from=<promo${index % 50}@spam.example> to=<victim${index}@elsewhere.example> proto=ESMTP helo=<h${index}>`);
        expected.rejected += 1;
        break;
      case 1:
        lines.push(`${head('smtpd')}warning: ${client}: SASL LOGIN authentication failed: UGFzc3dvcmQ6`);
        lines.push(`${head('smtpd')}lost connection after AUTH from ${client}`);
        expected.sasl += 1;
        break;
      default: {
        lines.push(`${head('smtpd')}${id}: client=${client}`);
        lines.push(`${head('cleanup')}${id}: message-id=<${index}.${id}@mx1.example.com>`);
        lines.push(`${head('qmgr')}${id}: from=<user${index % 400}@example.com>, size=${1000 + (index % 9000)}, nrcpt=1 (queue active)`);
        expected.queued += 1;
        const to = `rcpt${index % 20000}@domain${index % 700}.example`;
        if (index % 20 === 2) {
          lines.push(`${head('smtp')}${id}: to=<${to}>, relay=none, delay=${30 + (index % 900)}, delays=0.1/0.01/30/0, dsn=4.4.1, status=deferred (connect to mx${index % 300}.domain${index % 700}.example[198.51.${index % 250}.${index % 199}]:25: Connection timed out)`);
          expected.deferred += 1;
        } else if (index % 20 === 3) {
          lines.push(`${head('smtp')}${id}: to=<${to}>, relay=mx.domain${index % 700}.example[198.51.100.${index % 250}]:25, delay=0.6, delays=0.03/0.01/0.4/0.16, dsn=5.1.1, status=bounced (host mx.domain${index % 700}.example[198.51.100.${index % 250}] said: 550 5.1.1 <${to}>: Recipient address rejected: User unknown in virtual mailbox table (in reply to RCPT TO command))`);
          lines.push(`${head('bounce')}${id}: sender non-delivery notification: ${(0x5a0b31a0d7 + index).toString(16).toUpperCase()}`);
          expected.bounced += 1;
        } else {
          lines.push(`${head('smtp')}${id}: to=<${to}>, relay=mx.domain${index % 700}.example[198.51.100.${index % 250}]:25, delay=${(index % 50) / 10}, delays=0.05/0.01/0.6/0.74, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as ${(0x7c1a52e0f3 + index).toString(16).toUpperCase()})`);
          expected.sent += 1;
        }
        lines.push(`${head('qmgr')}${id}: removed`);
      }
    }
    lines.push(`${head('smtpd')}disconnect from ${client} ehlo=1 mail=1 rcpt=1 data=1 quit=1 commands=5`);
    if (index % 9 === 0) lines.push(`Nov 26 ${hour}:${minute}:${second} mx1 dovecot[700]: imap-login: Login: user=<bob@example.com>, method=PLAIN, rip=198.51.100.5, lip=192.0.2.25, mpid=${index}, TLS`);
  }
  const text = lines.join('\n');
  const started = performance.now();
  const result = analyzeMailLog(text, { now: NOW });
  const elapsed = performance.now() - started;

  assert.equal(result.totals.lines, lines.length);
  assert.ok(result.totals.lines >= 200000);
  assert.equal(result.totals.queued, expected.queued);
  assert.equal(result.totals.delivered, expected.sent);
  assert.equal(result.totals.deferred, expected.deferred);
  assert.equal(result.totals.bounced, expected.bounced);
  assert.equal(result.totals.rejected, expected.rejected);
  assert.equal(result.totals.saslFailures, expected.sasl);
  assert.equal(result.deferredReasons.length, 1, 'every timeout groups into one reason');
  assert.equal(result.deferredReasons[0].count, expected.deferred);
  assert.equal(result.bouncedReasons.length, 1);
  assert.equal(result.topRecipients.length, 25);
  assert.equal(result.senderTotal, 240);
  assert.ok(elapsed < 5000, `took ${Math.round(elapsed)} ms`);
});
