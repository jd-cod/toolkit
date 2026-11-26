# ──────────────────────────────────────────────────────────
# SysAdmin Toolkit — Multi-Stage Production Dockerfile
# ──────────────────────────────────────────────────────────
# Stages:
#   1. deps-backend  — install backend production dependencies
#   2. deps-frontend — install frontend dependencies
#   3. build-frontend — build Next.js production bundle
#   4. production    — slim runtime with both services
#
# Build:   docker build -t systoolkit .
# Run:     docker run -p 3000:3000 -p 4000:4000 --env-file backend/.env systoolkit
# ──────────────────────────────────────────────────────────

# ═══════════════════════════════════════════════════════════
# Stage 1: Backend Dependencies
# ═══════════════════════════════════════════════════════════
FROM node:22-alpine AS deps-backend

# bcrypt requires native compilation
RUN apk add --no-cache python3 make g++ libc6-compat

WORKDIR /app/backend
COPY backend/package.json backend/package-lock.json ./
RUN npm ci --production --ignore-scripts=false && \
    npm cache clean --force

# ═══════════════════════════════════════════════════════════
# Stage 2: Frontend Dependencies
# ═══════════════════════════════════════════════════════════
FROM node:22-alpine AS deps-frontend

WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci && npm cache clean --force

# ═══════════════════════════════════════════════════════════
# Stage 3: Build Frontend (Next.js)
# ═══════════════════════════════════════════════════════════
FROM node:22-alpine AS build-frontend

WORKDIR /app/frontend

# Copy dependencies from stage 2
COPY --from=deps-frontend /app/frontend/node_modules ./node_modules

# Copy frontend source
COPY frontend/ ./

# Build arguments for API URL at build time
ARG NEXT_PUBLIC_API_URL=/api
ARG BACKEND_API_URL=http://127.0.0.1:4000/api
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}
ENV BACKEND_API_URL=${BACKEND_API_URL}

# Build Next.js production bundle
RUN npm run build

# ═══════════════════════════════════════════════════════════
# Stage 4: Production Runtime
# ═══════════════════════════════════════════════════════════
FROM node:22-alpine AS production

# Label metadata
LABEL maintainer="SysAdmin Toolkit"
LABEL description="SysAdmin Toolkit — Self-Hosted Network Tools"
LABEL version="1.0.0"

# Runtime dependencies for bcrypt native module
RUN apk add --no-cache libc6-compat tini

# Create non-root user
RUN addgroup -S app && adduser -S app -G app

WORKDIR /app

# ── Backend ──
COPY --from=deps-backend /app/backend/node_modules ./backend/node_modules
COPY backend/package.json ./backend/
COPY backend/src/ ./backend/src/
COPY backend/migrations/ ./backend/migrations/

# ── Frontend ──
# Copy only the production build artifacts (standalone not used — using standard next start)
COPY --from=build-frontend /app/frontend/.next ./frontend/.next
COPY --from=build-frontend /app/frontend/public ./frontend/public
COPY --from=build-frontend /app/frontend/package.json ./frontend/
COPY --from=build-frontend /app/frontend/next.config.ts ./frontend/
COPY --from=build-frontend /app/frontend/server.js ./frontend/
COPY --from=deps-frontend /app/frontend/node_modules ./frontend/node_modules

# ── PM2 / Process Config ──
COPY ecosystem.config.cjs ./

# ── Data directories for GeoIP / IP2Location downloads & public data ──
RUN mkdir -p /app/backend/data /app/logs /app/frontend/public/data && \
    chown -R app:app /app

# Install PM2 globally
RUN npm install -g pm2 && npm cache clean --force

# Switch to non-root user
USER app

# ── Environment defaults ──
ENV NODE_ENV=production
ENV HOST=0.0.0.0

# Expose ports
EXPOSE 3000 4000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD wget -qO- http://127.0.0.1:4000/api/health || exit 1

# Use tini as init system for proper signal handling
ENTRYPOINT ["/sbin/tini", "--"]

# Apply pending SQL migrations before serving. The migrations directory is baked
# into the image at build time, NOT bind-mounted, and the per-file mounts in
# docker-compose land in MySQL's initdb.d — which only runs on an empty data
# volume. So on a container restart against an existing database nothing applied
# new migrations. Replay them here; the runner is idempotent and logs per-file.
#
# `|| true` is deliberate: a migration that fails against a partially-upgraded
# database must not stop the API from coming up. migrate.js stops at the failing
# file, logs it and exits non-zero; /api/health then answers "degraded" with the
# number of pending migrations until a later start applies them.
CMD ["sh", "-c", "(cd /app/backend && node src/migrate.js) || true; cd /app; exec pm2-runtime start ecosystem.config.cjs"]
