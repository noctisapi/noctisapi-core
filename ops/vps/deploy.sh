#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-${ROOT_DIR}/compose/docker-compose.prod.yml}"
ENV_FILE="${ENV_FILE:-${ROOT_DIR}/.env.prod}"
PROJECT_NAME="${COMPOSE_PROJECT_NAME:-shadowapi-core}"

if [ ! -f "${ENV_FILE}" ]; then
  echo "ERROR: ${ENV_FILE} not found. Create it before deploying." >&2
  exit 1
fi

required_vars=(
  HP_IMAGE
  APP_VERSION
  HP_PUBLIC_HOST
  ACME_EMAIL
)

missing=()
for v in "${required_vars[@]}"; do
  if ! grep -qE "^${v}=" "${ENV_FILE}"; then
    missing+=("${v}")
  fi
done
if [ "${#missing[@]}" -gt 0 ]; then
  echo "ERROR: Missing required vars in ${ENV_FILE}: ${missing[*]}" >&2
  exit 1
fi

echo "Deploying from:"
echo "  PROJECT_NAME=${PROJECT_NAME}"
echo "  COMPOSE_FILE=${COMPOSE_FILE}"
echo "  ENV_FILE=${ENV_FILE}"

cd "${ROOT_DIR}"

echo "Pulling images..."
docker compose -p "${PROJECT_NAME}" --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" pull

echo "Starting services..."
docker compose -p "${PROJECT_NAME}" --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" up -d --remove-orphans

echo "Pruning unused images..."
docker image prune -f >/dev/null 2>&1 || true

echo "Done."
