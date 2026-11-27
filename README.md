# SysAdmin Toolkit

A self-hosted, open-source web application providing essential sysadmin and network utilities in a single modern dashboard.

## Included Utilities
- **Traffic Log Analyzer**: Multi-gigabyte client-side log processing engine for Nginx and Apache logs.
- **DNS Lookup & Propagation**: Real-time multi-resolver DNS record inspection (A, AAAA, MX, TXT, CNAME, NS, SOA).
- **SSL Certificate Checker**: Expiry inspection, chain verification, and SAN parsing.
- **WHOIS & RDAP Lookup**: Registrar, domain dates, and status inspection.
- **ASN & Network Prefix Finder**: IPv4 & IPv6 network allocation lookup.
- **IP Reputation & Abuse Lookup**: Abuse scoring and report inspection.
- **What Is My IP**: Public IPv4 and IPv6 detection with geolocation and headers.
- **Subnet & CIDR Calculator**: Subnet ranges, masks, and address calculations.
- **Chmod Calculator**: Linux octal and symbolic permission builder.
- **Crontab Builder**: Visual schedule builder with human-readable preview.
- **Password & Passphrase Generator**: Cryptographically secure credential generation.

Added in the 2026-11 tools pack (see `docs/TOOLS_ROADMAP.md`):
- **Email**: SPF, DKIM & DMARC checker, blacklist (DNSBL) check, email header analyzer, SMTP server test.
- **Web and certificates**: HTTP headers and redirect checker, open port checker, certificate and CSR decoder.
- **Linux**: SSH config auditor, systemd timer generator, firewall rule generator, rsync command builder, SSH auth log analyzer, Postfix mail log analyzer.
- **Windows**: event ID lookup, error code lookup, robocopy command builder.
- **Also**: IPv6 in the subnet calculator, IIS (W3C) logs in the Traffic Log Analyzer.
- **Monitoring** (in `/admin`): certificate and domain expiry, blacklist listing, DNS record changes, HTTP and TCP uptime and cron job heartbeats, with webhook, Slack-style and email alerts.

---

## Quick Start (Docker)

To run the full application and database:

```bash
docker compose up -d --build
```

Access in browser:
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:4000/api

Default Admin Credentials:
- **Username**: `admin`
- **Password**: `adminpassword123`

---

## Local Development (Without Docker App Container)

1. Start MySQL:
   ```bash
   docker compose up -d mysql
   ```

2. Backend:
   ```bash
   cd backend
   npm install
   npm run migrate
   npm run dev
   ```

3. Frontend:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

---

## License
MIT
