# SysAdmin Toolkit Developer Guide

## Architecture
- **Frontend**: Next.js 16 (App Router), React 19, TypeScript, CSS Tokens.
- **Backend**: Node.js Fastify API server with MySQL (`mysql2`), S3/R2 storage integration.
- **Database**: MySQL 8.4 with automated migrations (`backend/src/migrate.js`).

## Running the App
- Docker full stack: `docker compose up -d --build`
- Docker MySQL only: `docker compose up -d mysql`
- Backend direct: `cd backend && npm run dev` (Port 4000)
- Frontend direct: `cd frontend && npm run dev` (Port 3000)

## Tools
- Before adding or changing a tool, read `docs/TOOLS_ROADMAP.md`: what exists, why, how a tool is wired, and what is deferred.

## Code Standards
- Keep changes minimal, clean, and well-tested.
- Validate inputs at trust boundaries.
