#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────
# SysAdmin Toolkit — Local Dev Startup Script
# ─────────────────────────────────────────────

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"
ENV_FILE="$BACKEND_DIR/.env"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

print_step()  { echo -e "\n${CYAN}${BOLD}▸ $1${NC}"; }
print_ok()    { echo -e "  ${GREEN}✔ $1${NC}"; }
print_warn()  { echo -e "  ${YELLOW}⚠ $1${NC}"; }
print_fail()  { echo -e "  ${RED}✖ $1${NC}"; }

# ── 1. Load DB credentials from backend/.env ───────────────
print_step "Loading database credentials from backend/.env"

if [[ ! -f "$ENV_FILE" ]]; then
  print_fail "backend/.env not found at $ENV_FILE"
  exit 1
fi

load_env_var() {
  grep -E "^$1=" "$ENV_FILE" | head -1 | cut -d '=' -f2-
}

DB_HOST=$(load_env_var DB_HOST)
DB_PORT=$(load_env_var DB_PORT)
DB_USER=$(load_env_var DB_USER)
DB_PASSWORD=$(load_env_var DB_PASSWORD)
DB_NAME=$(load_env_var DB_NAME)
BACKEND_PORT=$(load_env_var PORT)

print_ok "Host=$DB_HOST  Port=$DB_PORT  User=$DB_USER  DB=$DB_NAME"

# ── 2. Check MySQL connectivity ────────────────────────────
print_step "Checking MySQL connectivity"

if ! command -v mysql &>/dev/null; then
  print_warn "mysql CLI not found — trying mysqladmin..."
  if ! command -v mysqladmin &>/dev/null; then
    print_warn "No MySQL client found. Skipping DB check (backend will verify on boot)."
    MYSQL_OK="skip"
  else
    if mysqladmin ping -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASSWORD" --silent 2>/dev/null; then
      MYSQL_OK="yes"
    else
      MYSQL_OK="no"
    fi
  fi
else
  if mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASSWORD" -e "SELECT 1" "$DB_NAME" &>/dev/null; then
    MYSQL_OK="yes"
  else
    MYSQL_OK="no"
  fi
fi

if [[ "$MYSQL_OK" == "yes" ]]; then
  print_ok "MySQL is reachable and credentials are valid"
elif [[ "$MYSQL_OK" == "no" ]]; then
  print_fail "Cannot connect to MySQL at $DB_HOST:$DB_PORT with user '$DB_USER'"
  echo ""
  echo -e "  ${YELLOW}Possible fixes:${NC}"
  echo "    1. Check if MySQL is running:  brew services list | grep mysql"
  echo "    2. Verify credentials in backend/.env"
  echo ""
  read -rp "  Continue anyway? (y/N) " answer
  if [[ ! "$answer" =~ ^[Yy]$ ]]; then
    echo -e "${RED}Aborted.${NC}"
    exit 1
  fi
fi

# ── 3. Install dependencies if needed ──────────────────────
install_if_needed() {
  local dir="$1" name="$2" bin="${3:-}"
  if [[ ! -d "$dir/node_modules" || ( -n "$bin" && ! -x "$dir/node_modules/.bin/$bin" ) ]]; then
    print_step "Installing $name dependencies"
    (cd "$dir" && npm install)
    print_ok "$name dependencies installed"
  else
    print_ok "$name dependencies already installed"
  fi
}

print_step "Checking dependencies"
install_if_needed "$BACKEND_DIR" "Backend" "nodemon"
install_if_needed "$FRONTEND_DIR" "Frontend" "next"

# ── 4. Kill any existing processes on ports ─────────────────
kill_port() {
  local port="$1"
  local pid
  pid=$(lsof -ti :"$port" 2>/dev/null || true)
  if [[ -n "$pid" ]]; then
    print_warn "Port $port in use (PID $pid) — killing..."
    kill -9 $pid 2>/dev/null || true
    sleep 1
  fi
}

print_step "Freeing ports"
kill_port "${BACKEND_PORT:-4000}"
kill_port 3000
print_ok "Ports ${BACKEND_PORT:-4000} and 3000 are free"

# ── 5. Start Backend ───────────────────────────────────────
print_step "Starting Backend (Fastify) on port ${BACKEND_PORT:-4000}"
(cd "$BACKEND_DIR" && npm run dev) &
BACKEND_PID=$!

# Wait for backend to be ready
echo -n "  Waiting for backend"
for i in {1..20}; do
  if curl -s "http://127.0.0.1:${BACKEND_PORT:-4000}/api/health" &>/dev/null; then
    echo ""
    print_ok "Backend is ready (PID $BACKEND_PID)"
    break
  fi
  echo -n "."
  sleep 1
  if [[ $i -eq 20 ]]; then
    echo ""
    print_warn "Backend did not respond in 20s — check logs above"
  fi
done

# ── 6. Start Frontend ──────────────────────────────────────
print_step "Starting Frontend (Next.js) on port 3000"
(cd "$FRONTEND_DIR" && npm run dev) &
FRONTEND_PID=$!

# Wait for frontend to be ready
echo -n "  Waiting for frontend"
for i in {1..30}; do
  if curl -s "http://localhost:3000" &>/dev/null; then
    echo ""
    print_ok "Frontend is ready (PID $FRONTEND_PID)"
    break
  fi
  echo -n "."
  sleep 1
  if [[ $i -eq 30 ]]; then
    echo ""
    print_warn "Frontend did not respond in 30s — check logs above"
  fi
done

# ── 7. Summary ──────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}  🚀 SysAdmin Toolkit — Dev Servers Running${NC}"
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${CYAN}Frontend${NC}  →  http://localhost:3000"
echo -e "  ${CYAN}Backend${NC}   →  http://localhost:${BACKEND_PORT:-4000}"
echo -e "  ${CYAN}API Health${NC}→  http://localhost:${BACKEND_PORT:-4000}/api/health"
echo ""
echo -e "  ${YELLOW}Press Ctrl+C to stop both servers${NC}"
echo ""

# ── 8. Trap Ctrl+C to clean shutdown ───────────────────────
cleanup() {
  echo ""
  print_step "Shutting down servers..."
  kill $BACKEND_PID 2>/dev/null || true
  kill $FRONTEND_PID 2>/dev/null || true
  # Also kill any child processes (nodemon, next dev)
  pkill -P $BACKEND_PID 2>/dev/null || true
  pkill -P $FRONTEND_PID 2>/dev/null || true
  print_ok "All servers stopped. Goodbye!"
  exit 0
}

trap cleanup SIGINT SIGTERM

# Keep script alive — wait for both background processes
wait
