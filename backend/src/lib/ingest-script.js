/**
 * Ingest Bash Runner Script Generator
 *
 * Produces a portable, standalone POSIX/Bash runner script that streams logs directly
 * to Cloudflare R2 object storage via presigned S3 PUT URLs, bypassing Cloudflare's
 * 100 MB proxy upload ceiling.
 */

// Both values are written into a script that the user pipes into bash, so
// anything outside these character sets would be executed on their server.
const SAFE_SESSION_ID = /^[A-Za-z0-9_-]{1,64}$/;
const SAFE_BASE_URL = /^https?:\/\/(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(?::\d{1,5})?(?:\/[A-Za-z0-9._~\/-]*)?$/;

export function sanitizeSessionId(value) {
  return typeof value === 'string' && SAFE_SESSION_ID.test(value) ? value : '';
}

export function isSafeBaseUrl(value) {
  return typeof value === 'string' && SAFE_BASE_URL.test(value);
}

export function generateIngestScript(baseUrl, targetSessionId = '') {
  if (!isSafeBaseUrl(baseUrl)) {
    throw new Error('Refusing to generate an ingest script for an unsafe base URL.');
  }
  targetSessionId = sanitizeSessionId(targetSessionId);
  const cleanBase = baseUrl.replace(/\/+$/, '');

  return `#!/usr/bin/env bash
# ==============================================================================
# SysAdmin Toolkit Log Ingestion Runner
# Streams nginx access logs directly to storage, bypassing proxy upload limits.
#
# Usage:
#   gzip -c /var/log/nginx/access.log | bash <(curl -fsSL ${cleanBase}/ingest)
#   curl -fsSL ${cleanBase}/ingest | bash -s /var/log/nginx/access.log
# ==============================================================================

set -eo pipefail

BASE_URL="${cleanBase}"
TARGET_SESSION_ID="${targetSessionId}"

# Helper: Extract JSON field without requiring jq
extract_json() {
  local key="$1"
  local json="$2"
  if command -v jq >/dev/null 2>&1; then
    echo "$json" | jq -r ".$key // empty"
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c "import sys, json; data=json.loads(sys.argv[1]); print(data.get('$key', ''))" "$json" 2>/dev/null
  else
    echo "$json" | sed -n 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p'
  fi
}

# Determine input source: file argument or piped stdin
INPUT_FILE=""
IS_PIPED=0

if [ -n "\${1:-}" ]; then
  if [ ! -f "$1" ]; then
    echo "❌ Error: File not found: $1" >&2
    exit 1
  fi
  INPUT_FILE="$1"
elif [ ! -t 0 ]; then
  IS_PIPED=1
else
  echo "" >&2
  echo "🚀 SysAdmin Toolkit Nginx Log Ingest" >&2
  echo "--------------------------------" >&2
  echo "Usage:" >&2
  echo "  gzip -c /var/log/nginx/access.log | bash <(curl -fsSL \${BASE_URL}/ingest)" >&2
  echo "  curl -fsSL \${BASE_URL}/ingest | bash -s /var/log/nginx/access.log" >&2
  echo "" >&2
  exit 1
fi

echo "🚀 Initializing secure log upload session..." >&2

# Step 1: Request presigned upload session from backend
INIT_URL="\${BASE_URL}/api/ingest/init"
if [ -n "\${TARGET_SESSION_ID}" ]; then
  INIT_URL="\${INIT_URL}?sessionId=\${TARGET_SESSION_ID}"
fi
INIT_RESP=$(curl -fsSL -X POST "\${INIT_URL}" 2>&1) || {
  echo "❌ Error: Failed to connect to SysAdmin Toolkit: $INIT_RESP" >&2
  exit 1
}

SESSION_ID=$(extract_json "sessionId" "$INIT_RESP")
CHUNK_ID=$(extract_json "chunkId" "$INIT_RESP")
UPLOAD_URL=$(extract_json "uploadUrl" "$INIT_RESP")
VIEW_URL=$(extract_json "viewUrl" "$INIT_RESP")

if [ -z "$UPLOAD_URL" ] || [ -z "$SESSION_ID" ]; then
  echo "❌ Error: Failed to obtain upload authorization." >&2
  echo "$INIT_RESP" >&2
  exit 1
fi

echo "📦 Preparing log payload..." >&2

# Step 2: Prepare gzipped payload and stream directly to R2
TMP_FILE=""
TARGET_FILE=""

cleanup() {
  if [ -n "$TMP_FILE" ] && [ -f "$TMP_FILE" ]; then
    rm -f "$TMP_FILE"
  fi
}
trap cleanup EXIT INT TERM

if [ -n "$INPUT_FILE" ]; then
  # Check if file is already gzipped
  if file "$INPUT_FILE" 2>/dev/null | grep -qi 'gzip'; then
    TARGET_FILE="$INPUT_FILE"
  else
    TMP_FILE=$(mktemp /tmp/systoolkit-XXXXXX.log.gz)
    gzip -c "$INPUT_FILE" > "$TMP_FILE"
    TARGET_FILE="$TMP_FILE"
  fi
else
  # Reading from piped stdin — buffer to temp file so curl sends mandatory Content-Length to S3/R2
  TMP_FILE=$(mktemp /tmp/systoolkit-XXXXXX.log.gz)
  MAGIC=$(dd bs=2 count=1 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \\n')

  if [ "$MAGIC" = "1f8b" ]; then
    (printf '\\x1f\\x8b'; cat) > "$TMP_FILE"
  else
    (printf "%b" "\\x\${MAGIC:0:2}\\x\${MAGIC:2:2}" 2>/dev/null; cat) | gzip -c > "$TMP_FILE"
  fi
  TARGET_FILE="$TMP_FILE"
fi

UPLOAD_SIZE=$(wc -c < "$TARGET_FILE" 2>/dev/null | tr -d ' ')
echo "🚀 Uploading log ($UPLOAD_SIZE bytes) directly to storage (bypassing proxy limits)..." >&2

curl -# -X PUT -H "Content-Type: application/gzip" --data-binary @"$TARGET_FILE" "$UPLOAD_URL"

# Step 3: Finalize session on backend
FINALIZE_URL="\${BASE_URL}/api/ingest/\${SESSION_ID}/finalize"
if [ -n "$CHUNK_ID" ]; then
  FINALIZE_URL="\${FINALIZE_URL}?chunkId=\${CHUNK_ID}"
fi
FINALIZE_RESP=$(curl -fsSL -H "Accept: application/json" -H "User-Agent: SysAdmin Toolkit-CLI/1.0" -X POST "$FINALIZE_URL" 2>&1) || {
  echo "❌ Error: Upload succeeded but session finalization failed: $FINALIZE_RESP" >&2
  exit 1
}

FINAL_URL=$(extract_json "url" "$FINALIZE_RESP")
if [ -z "$FINAL_URL" ]; then
  FINAL_URL="$VIEW_URL"
fi

if [ -n "$TARGET_SESSION_ID" ] || [ "$CHUNK_ID" != "chunk-1" ]; then
  echo ""
  echo "✅ Uploaded to active session! Switch to your browser to view merged metrics."
  echo ""
  echo "👉 Dashboard: $FINAL_URL"
  echo ""
else
  echo ""
  echo "🚀 Nginx Log Analysis Ready!"
  echo ""
  echo "👉 View Dashboard: $FINAL_URL"
  echo ""
  echo "ℹ️  Note: This link is valid for 15 minutes and is automatically deleted upon first viewing."
  echo ""
fi
`;
}
