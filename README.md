# NoctisAPI Core

> A lightweight, open-source deception platform that exposes a realistic public API surface to attract and profile attackers — while keeping your infrastructure safe.

NoctisAPI Core is a self-hosted honeypot API built with FastAPI. It records, scores, and stages attacker behavior in real time, giving security teams actionable telemetry without executing any attacker-supplied logic.

---

## Key Features

- **Realistic API surface** — synthetic public API with staged responses and consistent fake data designed to fool automated scanners and persistent attackers
- **Actor profiling** — every interacting IP is tracked, scored, and progressed through behavioral stages
- **Session tracking** — multi-step interaction sequences are grouped into sessions with stage progression
- **API Modular** — configure per-endpoint behavior (enabled, response mode, richness level, fixed status) from the admin panel
- **Endpoint analytics** — hit patterns, interest scoring, and actor fingerprinting over configurable time windows
- **API availability monitoring** — continuous health checks of the honeypot public API from the admin panel
- **GeoIP enrichment** — country flags and ISO codes via MaxMind GeoLite2 (optional)
- **Structured logging** — every request is logged with actor ID, path, method, IP, UA, and status
- **Trusted proxy resolution** — correct client IP extraction behind Cloudflare, Traefik, or any reverse proxy
- **Bulk actor management** — archive, soft-delete, restore, or purge actors in bulk
- **Docker + Traefik** — production-ready compose stack with automatic TLS via ACME

---

## Architecture

NoctisAPI Core runs as two services sharing a single SQLite database via a Docker volume:

```
┌─────────────────────────────────────────────────────┐
│                   Docker Network                    │
│                                                     │
│  ┌─────────────────────┐   ┌───────────────────┐   │
│  │   Public API (app)  │   │  Admin Panel      │   │
│  │   FastAPI · :8000   │   │  FastAPI · :9001  │   │
│  │   Internet-facing   │   │  Internal only    │   │
│  └────────┬────────────┘   └────────┬──────────┘   │
│           │                         │               │
│           └──────────┬──────────────┘               │
│                      │                              │
│              ┌───────▼────────┐                     │
│              │  SQLite (WAL)  │                     │
│              │  /data/*.db    │                     │
│              └────────────────┘                     │
└─────────────────────────────────────────────────────┘
         ▲
  Traefik (TLS termination, port 443)
```

- **Public API** (`app/honeypot_public.py`) — serves attacker-facing endpoints on port 8000
- **Admin Panel** (`app/panel_mvp.py`) — internal dashboard on port 9001, protected by SSH tunnel
- **SQLite WAL** — `busy_timeout=5000` + retry logic for concurrent access safety

---

## Repository Structure

```
app/               Core services (public API, admin panel, monitor, health)
templates/         Jinja2 HTML templates for the admin panel
static/            CSS and JS assets
migrations/        Alembic database schema migrations
compose/           Docker Compose files (dev + prod)
ops/               Deployment scripts, crons, systemd unit
documentation/     Detailed docs and runbooks
scripts/           Utility and maintenance scripts
```

---

## Quick Start — Development

```bash
# 1. Clone
git clone https://github.com/0x-unkwn0wn/noctisapi-core
cd noctisapi-core

# 2. (Optional) Add GeoIP — place GeoLite2-Country.mmdb in data/

# 3. Start dev stack
docker compose -f compose/docker-compose.dev.yml up --build
```

| Service | URL |
|---|---|
| Public API (Swagger) | `http://127.0.0.1:8000/docs` |
| Admin Panel | `http://127.0.0.1:9001` |

The dev stack runs a one-shot database migrator before starting services. The SQLite database is created automatically in the `hp_dev_data` Docker volume on first run.

---

## Production Deployment

For the full step-by-step guide see [`documentation/ops/vps/DEPLOY.md`](documentation/ops/vps/DEPLOY.md).

```bash
# 1. Clone to server
git clone https://github.com/0x-unkwn0wn/noctisapi-core /opt/noctisapi-core
cd /opt/noctisapi-core

# 2. Configure environment
cp .env.prod.example .env.prod
# Edit .env.prod — see Environment Variables below

# 3. Build and start
docker build -t ghcr.io/0x-unkwn0wn/noctisapi-core:latest .
docker compose --env-file .env.prod -f compose/docker-compose.prod.yml up -d
```

---

## Accessing the Admin Panel

The admin panel is **not publicly exposed**. Access it via SSH tunnel:

```bash
# On your local machine:
ssh -L 9001:127.0.0.1:9001 user@your-server-ip

# Then open:
http://localhost:9001
```

---

## Environment Variables

See `.env.prod.example` for the full annotated reference.

| Marker | Meaning |
|---|---|
| `✔ FIXED` | Pre-configured for the Docker Compose network — do not change |
| `← YOU MUST CHANGE THIS` | Must be set to your own values before deploying |

**Key variables to set:**

| Variable | Description |
|---|---|
| `HP_PUBLIC_HOST` | Your public domain (e.g. `api.example.com`) |
| `HP_PUBLIC_BASE_URL` | Full public URL of the honeypot API |
| `ACME_EMAIL` | Email used for Let's Encrypt TLS certificate |
| `HP_SEED` | Long, stable random secret — used to derive actor IDs |

> **Important:** `HP_SEED` must never change after first run. Changing it invalidates all existing actor IDs. `HONEYPOT_MONITOR_BASE_URL` is already hardcoded in the prod compose file — do not set it in `.env.prod`.

---

## Screenshots

| Dashboard | Actors |
|---|---|
| ![Dashboard](screenshots/dashboard.png) | ![Actors](screenshots/actors.png) |

| API Modular | API Health |
|---|---|
| ![API Modular](screenshots/api_modular.png) | ![API Health](screenshots/api_health.png) |

---

## Use Cases

- **Threat intelligence** — profile automated scanners, credential stuffers, and targeted attackers
- **Deception in depth** — deploy alongside real services to detect lateral movement and recon
- **Research** — study attacker tooling, timing, and TTPs in a safe, isolated environment
- **Incident response** — identify attacker IPs, user agents, and behavioral patterns from captured sessions

---

## Notes

- Do not commit `.env.prod` or `GeoLite2-Country.mmdb` — both are in `.gitignore`
- The SQLite database file is stored in a Docker volume and persists across container restarts
- For high-traffic deployments, consider periodic retention pruning via the included scripts

---

## License

[Apache-2.0](LICENSE)
