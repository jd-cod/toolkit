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
   `npm run dev` and `npm run build` first write the Traffic Analyzer's sample logs into
   `frontend/public/samples` (`npm run samples`). They are generated, the same on every run, and
   are not kept in the repository. The two large ones need `python3`.

## Tests

```bash
npm run test:unit       # browser scripts and frontend modules, in Node 24 or newer; needs no packages
npm run test:backend    # after `npm ci` in backend/
npm install && E2E_BASE_URL=http://127.0.0.1:3000 npx playwright test   # against a running instance
```

The same unit, backend, lint, type and build checks run on every pull request (`.github/workflows/ci.yml`).

---

## License
MIT
