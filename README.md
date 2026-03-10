# NoctisAPI Core

NoctisAPI Core is a compact deception platform that exposes a realistic public API surface and an internal admin panel for observing, scoring, and grouping attacker behavior. Designed for safe, non-executing interaction while providing rich telemetry for analysis.

## What is included

- Public honeypot API with staged behavior and consistent synthetic data
- Internal/admin decoys
- GeoIP country flags (MaxMind GeoLite2)
- API availability monitoring from the admin panel
- Admin panel: actors, sessions, API health, environment settings, diagnostics
- Basic scoring and stages
- Bulk actor management
- Retention pruning and backup script
- Docker + Traefik deploy with automatic TLS (ACME)
- Trusted proxy IP resolution, structured logging, request timeout middleware

## Repository layout

```
app/               Core services (public API, admin panel, monitor, health)
templates/         Jinja2 HTML templates
static/            CSS and JS assets
migrations/        Alembic database schema
compose/           Docker Compose files (dev + prod)
ops/               Deployment scripts, crons, systemd unit
documentation/     Detailed docs and runbooks
scripts/           Utility scripts
```

## Quick start — development

```bash
# 1. Clone
git clone https://github.com/0x-unkwn0wn/shadowapi-core
cd shadowapi-core

# 2. (Optional) Add GeoLite2 for country flags — place GeoLite2-Country.mmdb in data/

# 3. Start
docker compose -f compose/docker-compose.dev.yml up --build
```

Open:
- Public API: `http://127.0.0.1:8000/docs`
- Admin panel: `http://127.0.0.1:9001`

The dev stack runs a one-shot migrator before starting services. The SQLite database is created automatically on first run in the `hp_dev_data` Docker volume.

## Quick start — production (VPS)

See [`documentation/ops/vps/DEPLOY.md`](documentation/ops/vps/DEPLOY.md) for the full step-by-step guide.

Short version:

```bash
git clone https://github.com/0x-unkwn0wn/shadowapi-core /opt/noctisapi-core
cd /opt/noctisapi-core

cp .env.prod.example .env.prod
# Edit .env.prod:
#   Change: HP_PUBLIC_HOST, HP_PUBLIC_BASE_URL, HONEYPOT_PUBLIC_BASE_URL, ACME_EMAIL, HP_SEED
#   Leave:  all variables marked ✔ FIXED — they are pre-configured for the Docker network

docker build -t ghcr.io/0x-unkwn0wn/shadowapi-core:latest .
docker compose --env-file .env.prod -f compose/docker-compose.prod.yml up -d
```

Access the admin panel via SSH tunnel (it is not exposed publicly):

```bash
# On your local machine:
ssh -L 9001:127.0.0.1:9001 user@your-server-ip
# Then open http://localhost:9001
```

## Environment variables

See `.env.prod.example` for the full annotated reference.

- Variables marked **`✔ FIXED`** are pre-configured for the Docker Compose network. Do not change them.
- Variables marked **`← YOU MUST CHANGE THIS`** must be set to your own values.

## Notes

- Do not commit `.env.prod` or `GeoLite2-Country.mmdb` to git (both are in `.gitignore`).
- `HP_SEED` must be a long, stable random secret. Changing it breaks existing actor IDs.
- `HONEYPOT_MONITOR_BASE_URL=http://app:8000` is already hardcoded in `compose/docker-compose.prod.yml` under the `admin` service. You do not need to set it in `.env.prod`.

## License

Apache-2.0
