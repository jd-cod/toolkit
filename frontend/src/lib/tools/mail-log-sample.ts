/**
 * Builds the sample log for the Mail Log Analyzer: a Postfix server
 * (mx1.example.com, 192.0.2.25) on one morning. The addresses are from the
 * documentation ranges (RFC 5737, RFC 3849). The same text every time.
 */

interface SampleLine {
  at: number;
  text: string;
}

function pad2(value: number): string {
  return value < 10 ? `0${value}` : String(value);
}

/** Seconds since midnight as `HH:MM:SS`, or `HHMMSS` with an empty separator. */
function clock(at: number, separator = ''): string {
  const second = Math.floor(at);
  return [pad2(Math.floor(second / 3600)), pad2(Math.floor((second % 3600) / 60)), pad2(second % 60)].join(separator);
}

export function buildMailLogSample(): string {
  const out: SampleLine[] = [];
  let order = 0;
  let serial = 0;
  // `at` is seconds since midnight. A tiny step keeps lines of one message in the order they were added.
  const add = (at: number, program: string, pid: number, message: string) => {
    order += 1;
    out.push({ at: at + order / 100000, text: `postfix/${program}[${pid}]: ${message}` });
  };
  const queueId = () => {
    serial += 1;
    return (0x4f9d21a0c2 + serial * 0x1f3b7).toString(16).toUpperCase();
  };

  /** One message from qmgr to its removal, with one delivery line. */
  const message = (at: number, sender: string, size: number, recipient: string, agent: string, fields: string, status: string, client?: { name: string; pid: number }) => {
    const id = queueId();
    if (client) add(at, 'smtpd', client.pid, `${id}: client=${client.name}`);
    add(at, 'cleanup', 2210, `${id}: message-id=<20261126${clock(at)}.${id}@mx1.example.com>`);
    add(at, 'qmgr', 1182, `${id}: from=<${sender}>, size=${size}, nrcpt=1 (queue active)`);
    add(at + 1, agent, agent === 'smtp' ? 2304 : 2251, `${id}: to=<${recipient}>, ${fields}, status=${status}`);
    if (status.startsWith('bounced')) add(at + 1, 'bounce', 2260, `${id}: sender non-delivery notification: ${queueId()}`);
    add(at + 1, 'qmgr', 1182, `${id}: removed`);
  };

  const sentRemote = (relay: string, delay: string) => `relay=${relay}, delay=${delay}, delays=0.05/0.01/0.3/${(Number(delay) - 0.36).toFixed(2)}, dsn=2.0.0`;

  // Incoming mail delivered to local mailboxes.
  const inbound: Array<[string, string, string]> = [
    ['alice@example.org', 'bob@example.com', 'mail.example.org[198.51.100.10]'],
    ['billing@shop.example', 'accounts@example.com', 'out.shop.example[198.51.100.31]'],
    ['carol@example.net', 'bob@example.com', 'mx.example.net[203.0.113.20]'],
    ['noreply@forum.example', 'dave@example.com', 'smtp.forum.example[198.51.100.44]'],
    ['alice@example.org', 'dave@example.com', 'mail.example.org[198.51.100.10]'],
    ['hr@partner.example', 'accounts@example.com', 'mail.partner.example[198.51.100.52]'],
    ['carol@example.net', 'support@example.com', 'mx.example.net[203.0.113.20]'],
    ['monitor@status.example', 'bob@example.com', 'out.status.example[198.51.100.61]'],
  ];
  inbound.forEach(([sender, recipient, client], index) => {
    const at = 6 * 3600 + 300 + index * 1490;
    add(at - 1, 'smtpd', 2190 + index, `connect from ${client}`);
    message(at, sender, 3800 + index * 913, recipient, 'local', `relay=local, delay=0.${12 + index}, delays=0.08/0.01/0/0.0${3 + (index % 5)}, dsn=2.0.0`, 'sent (delivered to mailbox)', { name: client, pid: 2190 + index });
    add(at + 2, 'smtpd', 2190 + index, `disconnect from ${client} ehlo=1 starttls=1 mail=1 rcpt=1 data=1 quit=1 commands=6`);
  });

  // Outgoing mail from staff.
  const outbound: Array<[string, string, string, string]> = [
    ['bob@example.com', 'carol@example.net', 'mx.example.net[203.0.113.20]:25', '1.4'],
    ['dave@example.com', 'alice@example.org', 'mail.example.org[198.51.100.10]:25', '0.9'],
    ['bob@example.com', 'sales@shop.example', 'in.shop.example[198.51.100.30]:25', '2.2'],
    ['support@example.com', 'erin@customer.example', 'mx.customer.example[2001:db8:40::25]:25', '1.1'],
    ['dave@example.com', 'carol@example.net', 'mx.example.net[203.0.113.20]:25', '1.7'],
    ['bob@example.com', 'frank@partner.example', 'mail.partner.example[198.51.100.52]:25', '3.6'],
    ['support@example.com', 'alice@example.org', 'mail.example.org[198.51.100.10]:25', '0.8'],
    ['accounts@example.com', 'billing@shop.example', 'in.shop.example[198.51.100.30]:25', '2.9'],
  ];
  outbound.forEach(([sender, recipient, relay, delay], index) => {
    message(7 * 3600 + 95 + index * 1270, sender, 5200 + index * 1377, recipient, 'smtp', sentRemote(relay, delay), `sent (250 2.0.0 Ok: queued as ${queueId()})`);
  });

  // A web form script that mails a stale list: many bounces, some refused because of a block list.
  for (let index = 0; index < 24; index += 1) {
    const at = 8 * 3600 + 40 + index * 151;
    const sender = 'webform@example.com';
    if (index % 12 === 5) {
      message(at, sender, 2140, `info${index}@bigmail.example`, 'smtp', 'relay=mx.bigmail.example[203.0.113.80]:25, delay=0.7, delays=0.03/0.01/0.5/0.16, dsn=5.7.1',
        'bounced (host mx.bigmail.example[203.0.113.80] said: 554 5.7.1 Service unavailable; Client host [192.0.2.25] blocked using zen.spamhaus.org; https://www.spamhaus.org/query/ip/192.0.2.25 (in reply to RCPT TO command))');
    } else if (index % 2 === 1) {
      message(at, sender, 2140, `user${index}@oldlist.example`, 'smtp', 'relay=mx.oldlist.example[203.0.113.90]:25, delay=0.6, delays=0.03/0.01/0.4/0.16, dsn=5.1.1',
        `bounced (host mx.oldlist.example[203.0.113.90] said: 550 5.1.1 <user${index}@oldlist.example>: Recipient address rejected: User unknown in virtual mailbox table (in reply to RCPT TO command))`);
    } else {
      message(at, sender, 2140, `reader${index}@example.net`, 'smtp', sentRemote('mx.example.net[203.0.113.20]:25', '1.3'), `sent (250 2.0.0 Ok: queued as ${queueId()})`);
    }
  }

  // Mail that cannot be delivered yet and is retried.
  const slow = queueId();
  add(7 * 3600 + 2000, 'cleanup', 2210, `${slow}: message-id=<20261126${clock(7 * 3600 + 2000)}.${slow}@mx1.example.com>`);
  [7 * 3600 + 2000, 8 * 3600 + 500, 9 * 3600 + 800, 10 * 3600 + 2600].forEach((at, index) => {
    add(at, 'qmgr', 1182, `${slow}: from=<bob@example.com>, size=18230, nrcpt=1 (queue active)`);
    add(at + 30, 'smtp', 2304, `${slow}: to=<gina@slow.example>, relay=none, delay=${30 + index * 2500}, delays=${index * 2500}/0.02/30/0, dsn=4.4.1, status=deferred (connect to mx.slow.example[203.0.113.60]:25: Connection timed out)`);
  });
  const greylisted = queueId();
  add(9 * 3600 + 1400, 'qmgr', 1182, `${greylisted}: from=<dave@example.com>, size=6120, nrcpt=1 (queue active)`);
  add(9 * 3600 + 1401, 'smtp', 2304, `${greylisted}: to=<henry@grey.example>, relay=mx.grey.example[203.0.113.70]:25, delay=1.2, delays=0.04/0.01/0.9/0.25, dsn=4.7.1, status=deferred (host mx.grey.example[203.0.113.70] said: 451 4.7.1 Greylisting in action, please come back later (in reply to RCPT TO command))`);
  add(9 * 3600 + 1750, 'qmgr', 1182, `${greylisted}: from=<dave@example.com>, size=6120, nrcpt=1 (queue active)`);
  add(9 * 3600 + 1751, 'smtp', 2304, `${greylisted}: to=<henry@grey.example>, relay=mx.grey.example[203.0.113.70]:25, delay=351, delays=350/0.02/0.8/0.2, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as ${queueId()})`);
  add(9 * 3600 + 1751, 'qmgr', 1182, `${greylisted}: removed`);
  const noDns = queueId();
  add(10 * 3600 + 300, 'qmgr', 1182, `${noDns}: from=<support@example.com>, size=4410, nrcpt=1 (queue active)`);
  add(10 * 3600 + 300, 'smtp', 2304, `${noDns}: to=<ivan@typo-domain.example>, relay=none, delay=0.3, delays=0.05/0.01/0.24/0, dsn=4.4.3, status=deferred (Host or domain name not found. Name service error for name=typo-domain.example type=MX: Host not found, try again)`);

  // Mail refused before it was queued.
  const rejects: Array<[number, string, string]> = [
    [6 * 3600 + 1011, 'unknown[203.0.113.150]', '554 5.7.1 <victim@elsewhere.example>: Relay access denied; from=<promo@spam.example> to=<victim@elsewhere.example> proto=ESMTP helo=<203.0.113.150>'],
    [6 * 3600 + 1013, 'unknown[203.0.113.150]', '554 5.7.1 <other@elsewhere.example>: Relay access denied; from=<promo@spam.example> to=<other@elsewhere.example> proto=ESMTP helo=<203.0.113.150>'],
    [7 * 3600 + 640, 'unknown[203.0.113.150]', '554 5.7.1 <third@elsewhere.example>: Relay access denied; from=<promo@spam.example> to=<third@elsewhere.example> proto=ESMTP helo=<203.0.113.150>'],
    [7 * 3600 + 3105, 'mail.example.org[198.51.100.10]', '550 5.1.1 <jim@example.com>: Recipient address rejected: User unknown in local recipient table; from=<alice@example.org> to=<jim@example.com> proto=ESMTP helo=<mail.example.org>'],
    [8 * 3600 + 1502, 'unknown[203.0.113.151]', '554 5.7.1 Service unavailable; Client host [203.0.113.151] blocked using zen.spamhaus.org; https://www.spamhaus.org/query/ip/203.0.113.151; from=<offer@bulk.example> to=<bob@example.com> proto=ESMTP helo=<bulk.example>'],
    [8 * 3600 + 1560, 'unknown[203.0.113.151]', '554 5.7.1 Service unavailable; Client host [203.0.113.151] blocked using zen.spamhaus.org; https://www.spamhaus.org/query/ip/203.0.113.151; from=<offer@bulk.example> to=<dave@example.com> proto=ESMTP helo=<bulk.example>'],
    [9 * 3600 + 222, 'unknown[203.0.113.152]', '450 4.7.25 Client host rejected: cannot find your hostname, [203.0.113.152]; from=<news@nohost.example> to=<support@example.com> proto=ESMTP helo=<nohost.example>'],
    [9 * 3600 + 2750, 'unknown[2001:db8:91::7]', '504 5.5.2 <WIN-4K2JD81>: Helo command rejected: need fully-qualified hostname; from=<a@b.example> to=<bob@example.com> proto=ESMTP helo=<WIN-4K2JD81>'],
    [10 * 3600 + 1310, 'mail.fake.example[203.0.113.153]', '450 4.1.8 <bounce@no-such-domain.example>: Sender address rejected: Domain not found; from=<bounce@no-such-domain.example> to=<accounts@example.com> proto=ESMTP helo=<mail.fake.example>'],
    [10 * 3600 + 2222, 'unknown[203.0.113.150]', '554 5.7.1 <fourth@elsewhere.example>: Relay access denied; from=<promo@spam.example> to=<fourth@elsewhere.example> proto=ESMTP helo=<203.0.113.150>'],
  ];
  rejects.forEach(([at, client, text], index) => {
    add(at - 1, 'smtpd', 2400 + index, `connect from ${client}`);
    add(at, 'smtpd', 2400 + index, `NOQUEUE: reject: RCPT from ${client}: ${text}`);
    add(at + 1, 'smtpd', 2400 + index, `disconnect from ${client} ehlo=1 mail=1 rcpt=0/1 quit=1 commands=3/4`);
  });
  add(8 * 3600 + 1499, 'postscreen', 2380, 'PREGREET 11 after 0.07 from [203.0.113.154]:41876: EHLO User\\r\\n');
  add(8 * 3600 + 1500, 'postscreen', 2380, 'DNSBL rank 6 for [203.0.113.154]:41876');

  // Password guessing against SMTP AUTH.
  for (let index = 0; index < 14; index += 1) {
    const at = 9 * 3600 + 3000 + index * 23;
    add(at, 'smtpd', 2500 + index, 'connect from unknown[203.0.113.200]');
    add(at + 2, 'smtpd', 2500 + index, 'warning: unknown[203.0.113.200]: SASL LOGIN authentication failed: UGFzc3dvcmQ6');
    add(at + 3, 'smtpd', 2500 + index, 'lost connection after AUTH from unknown[203.0.113.200]');
    add(at + 3, 'smtpd', 2500 + index, 'disconnect from unknown[203.0.113.200] ehlo=1 auth=0/1 commands=1/2');
  }
  for (let index = 0; index < 3; index += 1) {
    const at = 10 * 3600 + 3100 + index * 41;
    add(at, 'smtpd', 2540 + index, 'warning: unknown[2001:db8:77::9]: SASL PLAIN authentication failed: authentication failure');
  }

  return out
    .sort((a, b) => a.at - b.at)
    .map(line => `Nov 26 ${clock(line.at, ':')} mx1 ${line.text}`)
    .join('\n');
}
