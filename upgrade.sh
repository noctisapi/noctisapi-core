#!/usr/bin/env bash
# upgrade.sh — Upgrade NoctisAPI Core → Pro
#
# Usage:
#   bash upgrade.sh --license-key sk_live_XXXX [options]
#
# Options:
#   --license-key KEY     PRO license key (required)
#   --license-file PATH   Offline license.json to install for runtime validation (optional)
#   --server URL          Licensing server URL (default: $LICENSING_SERVER env var)
#   --dir PATH            Installation directory (default: current directory)
#   --yes                 Skip confirmation prompts
#
# What it does:
#   1. Validates the license key and fetches a presigned download URL from R2
#   2. Downloads the PRO Docker image tar and loads it
#   3. Updates .env with PRO image reference and licensing vars
#   4. Installs license.json into the data volume (if --license-file provided)
#   5. Restarts services with the new image (preserving all data)
set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
LICENSING_SERVER="${LICENSING_SERVER:-}"
LICENSE_KEY=""
LICENSE_FILE=""
INSTALL_DIR="$(pwd)"
IMAGE_NAME="noctisapi/noctisapi-pro"
AUTO_YES=0

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
BOLD="\033[1m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"; RED="\033[0;31m"; CYAN="\033[0;36m"; RESET="\033[0m"
info()    { echo -e "${GREEN}==>${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✗]${RESET} $*"; exit 1; }
step()    { echo -e "\n${CYAN}${BOLD}[$1]${RESET} $2"; }
prompt()  { echo -e "${BOLD}$*${RESET}"; }

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --license-key)  LICENSE_KEY="$2";       shift 2 ;;
    --license-file) LICENSE_FILE="$2";      shift 2 ;;
    --server)       LICENSING_SERVER="$2";  shift 2 ;;
    --dir)          INSTALL_DIR="$2";       shift 2 ;;
    --yes)          AUTO_YES=1;             shift   ;;
    *) error "Unknown option: $1" ;;
  esac
done

[[ -z "$LICENSE_KEY" ]]       && error "--license-key is required."
[[ -z "$LICENSING_SERVER" ]]  && error "--server (or \$LICENSING_SERVER env var) is required."
[[ ! -d "$INSTALL_DIR" ]]     && error "Install directory not found: $INSTALL_DIR"

ENV_FILE="${INSTALL_DIR}/.env"
COMPOSE_FILE="${INSTALL_DIR}/docker-compose.yml"

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
step "0/5" "Checking dependencies"
for cmd in curl docker jq; do
  command -v "$cmd" &>/dev/null || error "'$cmd' is required but not installed."
done
docker compose version &>/dev/null || error "docker compose (v2) is required."
info "All dependencies OK"

# ---------------------------------------------------------------------------
# Detect existing installation
# ---------------------------------------------------------------------------
if [[ ! -f "$ENV_FILE" ]]; then
  warn "No .env found in ${INSTALL_DIR}. This looks like a fresh setup, not an upgrade."
  warn "If you want a fresh install, use install.sh instead."
  [[ "$AUTO_YES" -eq 0 ]] && { prompt "Continue anyway? [y/N]"; read -r yn; [[ "$yn" =~ ^[Yy]$ ]] || exit 0; }
fi

# ---------------------------------------------------------------------------
# Step 1 — Validate license and get download URL
# ---------------------------------------------------------------------------
step "1/5" "Validating license key"

HTTP_CODE=$(curl --silent --output /tmp/_noctis_resp.json --write-out "%{http_code}" \
  -X POST "${LICENSING_SERVER}/v1/distribution/download" \
  -H "X-License-Key: ${LICENSE_KEY}")

if [[ "$HTTP_CODE" != "200" ]]; then
  DETAIL=$(jq -r '.detail // "unknown error"' /tmp/_noctis_resp.json 2>/dev/null || echo "unknown")
  case "$HTTP_CODE" in
    401) error "Invalid or expired license key." ;;
    403) error "License rejected: ${DETAIL}" ;;
    404) error "PRO image not available yet. Contact support." ;;
    501) error "Distribution not configured on server. Contact support." ;;
    *)   error "Unexpected error (HTTP ${HTTP_CODE}): ${DETAIL}" ;;
  esac
fi

DOWNLOAD_URL=$(jq -r '.download_url'   /tmp/_noctis_resp.json)
FILENAME=$(jq -r '.filename'           /tmp/_noctis_resp.json)
VERSION=$(jq -r '.image_version'       /tmp/_noctis_resp.json)
rm -f /tmp/_noctis_resp.json

info "License valid — PRO image version: ${BOLD}${VERSION}${RESET}"

# ---------------------------------------------------------------------------
# Confirm upgrade
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}──────────────────────────────────────────────${RESET}"
echo -e "${BOLD}  NoctisAPI Core → Pro Upgrade${RESET}"
echo -e "${BOLD}──────────────────────────────────────────────${RESET}"
echo -e "  Install dir : ${INSTALL_DIR}"
echo -e "  PRO version : ${VERSION}"
echo -e "  Image       : ${IMAGE_NAME}:${VERSION}"
echo -e "${BOLD}──────────────────────────────────────────────${RESET}"
echo ""
if [[ "$AUTO_YES" -eq 0 ]]; then
  prompt "Proceed with upgrade? [y/N]"
  read -r yn
  [[ "$yn" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }
fi

# ---------------------------------------------------------------------------
# Step 2 — Download and load PRO image
# ---------------------------------------------------------------------------
step "2/5" "Downloading PRO image"

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

info "Downloading ${FILENAME}..."
curl --progress-bar --location -o "${TMP_DIR}/${FILENAME}" "$DOWNLOAD_URL"

info "Loading Docker image..."
docker load -i "${TMP_DIR}/${FILENAME}"
info "Image loaded: ${IMAGE_NAME}:${VERSION}"

# ---------------------------------------------------------------------------
# Step 3 — Update .env
# ---------------------------------------------------------------------------
step "3/5" "Updating .env"

_env_set() {
  local key="$1" val="$2"
  if grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
    sed -i "s|^${key}=.*|${key}=${val}|" "$ENV_FILE"
    info "  Updated ${key}"
  else
    echo "${key}=${val}" >> "$ENV_FILE"
    info "  Added   ${key}"
  fi
}

# Create .env if it doesn't exist
touch "$ENV_FILE"

_env_set "HP_IMAGE"       "${IMAGE_NAME}"
_env_set "APP_VERSION"    "${VERSION}"

# PRO licensing vars (only add if not already present)
_env_set "HP_LICENSE_MODE"                      "offline"
_env_set "HP_ENFORCE_LICENSE"                   "1"
_env_set "HP_LICENSE_STATUS_REFRESH_SECONDS"    "30"
_env_set "HP_LICENSE_STATUS_MAX_REFRESH_SECONDS" "300"
_env_set "INSTANCE_ID_PATH"                     "/var/lib/myapp/instance_id"
_env_set "HP_OFFLINE_LICENSE_PATH"              "/var/lib/myapp/license.json"
_env_set "HP_OFFLINE_LICENSE_STATE_PATH"        "/var/lib/myapp/license_state.json"
_env_set "HP_OFFLINE_PUBLIC_KEYS_BUNDLE_PATH"   "/app/app/offline_public_keys.json"

info ".env updated"

# ---------------------------------------------------------------------------
# Step 4 — Install license.json into volume (if provided)
# ---------------------------------------------------------------------------
step "4/5" "Installing license.json"

if [[ -n "$LICENSE_FILE" ]]; then
  if [[ ! -f "$LICENSE_FILE" ]]; then
    error "License file not found: ${LICENSE_FILE}"
  fi
  if ! jq empty "$LICENSE_FILE" 2>/dev/null; then
    error "Invalid JSON in license file: ${LICENSE_FILE}"
  fi

  VOLUME_NAME=$(cd "$INSTALL_DIR" && docker compose config --format json 2>/dev/null \
    | jq -r '.volumes | to_entries[] | select(.value.name? // .key | test("myapp")) | .value.name // .key' \
    | head -1)

  if [[ -z "$VOLUME_NAME" ]]; then
    # Fallback: derive volume name from compose project
    PROJECT=$(basename "$INSTALL_DIR")
    VOLUME_NAME="${PROJECT}_hp_prod_myapp"
  fi

  info "Installing license.json into volume ${VOLUME_NAME}..."
  cp "$LICENSE_FILE" "${TMP_DIR}/license.json"
  docker run --rm \
    -v "${VOLUME_NAME}:/var/lib/myapp" \
    -v "${TMP_DIR}/license.json:/tmp/license.json:ro" \
    busybox sh -c "cp /tmp/license.json /var/lib/myapp/license.json && chown 10001:0 /var/lib/myapp/license.json && chmod 600 /var/lib/myapp/license.json"
  info "license.json installed"
else
  warn "No --license-file provided. Skipping license.json installation."
  warn "You can install it later with:"
  warn "  docker run --rm -v <volume>:/var/lib/myapp -v /path/to/license.json:/tmp/license.json:ro \\"
  warn "    busybox sh -c 'cp /tmp/license.json /var/lib/myapp/license.json'"
fi

# ---------------------------------------------------------------------------
# Step 5 — Restart services
# ---------------------------------------------------------------------------
step "5/5" "Restarting services"

cd "$INSTALL_DIR"
info "Pulling image reference and restarting..."
docker compose up -d --remove-orphans

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}${BOLD}✔ Upgrade to NoctisAPI Pro ${VERSION} complete!${RESET}"
echo ""
echo -e "  Logs:   ${CYAN}docker compose logs -f app${RESET}"
echo -e "  Stop:   ${CYAN}cd ${INSTALL_DIR} && docker compose down${RESET}"
echo ""
