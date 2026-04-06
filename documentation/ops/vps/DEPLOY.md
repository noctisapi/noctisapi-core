# NoctisAPI Core — VPS Deployment (Ubuntu 22.04+)

Concrete, repeatable deployment flow for a single VPS with Docker + Traefik (ACME TLS).

---

## 1. System prep

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg lsb-release ufw git
```

Install Docker + Compose plugin:

```bash
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER   # reconnect SSH after this
```

Firewall (open SSH + web only, keep admin port local):

```bash
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable
# Port 9001 (admin panel) stays 127.0.0.1-only — access via SSH tunnel only
```

---

## 2. Clone the repo

```bash
sudo mkdir -p /opt/noctisapi-core
sudo chown -R $USER:$USER /opt/noctisapi-core
git clone https://github.com/0x-unkwn0wn/shadowapi-core /opt/noctisapi-core
cd /opt/noctisapi-core
```

---

## 3. Configure `.env.prod`

```bash
cp .env.prod.example .env.prod
nano .env.prod   # or vim
```

**Values you MUST change** (marked `← YOU MUST CHANGE THIS` in the example):

| Variable | Description |
|---|---|
| `HP_PUBLIC_HOST` | Your public API domain (e.g. `api.example.com`) |
| `HP_PUBLIC_BASE_URL` | Full public URL (e.g. `https://api.example.com`) |
| `HONEYPOT_PUBLIC_BASE_URL` | Same as above |
| `ACME_EMAIL` | Your email for Let's Encrypt |
| `HP_SEED` | Long random secret — generate with `python3 -c "import secrets; print(secrets.token_hex(32))"` |

**Values that are pre-configured and MUST NOT be changed** (marked `✔ FIXED`):

| Variable | Value | Why fixed |
|---|---|---|
| `HONEYPOT_MONITOR_BASE_URL` | `http://app:8000` | Internal Docker network — admin talks to app container directly |
| `HONEYPOT_MONITOR_UA` | `HealthCheck/1.0,curl/` | Monitor user-agent list |
| `HP_DB_PATH` | `/data/honeypot.db` | Container volume path |
| `DATABASE_URL` | `sqlite+pysqlite:////data/honeypot.db` | Container volume path |
| `HP_ASN_RESOLVER_URL` | `https://ipwho.is/{ip}` | Optional geo resolver |

> Note: `HONEYPOT_MONITOR_BASE_URL` is also hardcoded in `compose/docker-compose.prod.yml`
> under the `admin` service environment, which takes precedence over `.env.prod`.
> You do not need to set it in `.env.prod` for standard deployments.

---

## 4. Geo resolver (for country flags)

Core uses `HP_ASN_RESOLVER_URL=https://ipwho.is/{ip}` by default. No local
database or bind mount is required. To use a different resolver, set
`HP_ASN_RESOLVER_URL` to an HTTP endpoint that returns country code/name JSON and
keeps the `{ip}` placeholder.

---

## 5. Build the Docker image

The image is built from the local repo on the server. This ensures the running code matches exactly what is in the repository:

```bash
cd /opt/noctisapi-core
docker build -t ghcr.io/0x-unkwn0wn/shadowapi-core:latest .
```

> If you forked the repo, change the image tag to match `HP_IMAGE` in your `.env.prod`.

---

## 6. First deploy

```bash
cd /opt/noctisapi-core
docker compose --env-file .env.prod -f compose/docker-compose.prod.yml up -d
```

Verify the public API is up:

```bash
curl -sS https://<your-api-host>/health
```

---

## 7. Access the admin panel

The admin panel runs on port 9001 **bound to localhost only** (`127.0.0.1:9001`).
It is **not exposed via Traefik** — access it via SSH tunnel from your local machine:

```bash
# On your local machine:
ssh -L 9001:127.0.0.1:9001 user@your-server-ip
```

Then open your browser at `http://localhost:9001`.

---

## 8. Update (new image version)

```bash
cd /opt/noctisapi-core
git pull
docker build -t ghcr.io/0x-unkwn0wn/shadowapi-core:latest .
docker compose --env-file .env.prod -f compose/docker-compose.prod.yml up -d --force-recreate
```

---

## 9. Data retention (optional)

```bash
sudo cp ops/cron/noctisapi-core-retention /etc/cron.d/noctisapi-core-retention
```

The cron runs daily at 03:15 UTC. Override retention periods in `/etc/cron.d/noctisapi-core-retention`:

```
HP_RETENTION_EVENTS_DAYS=30
HP_RETENTION_SESSIONS_DAYS=30
HP_RETENTION_CHECKS_DAYS=14
```

---

## 10. systemd auto-start (optional)

```bash
sudo cp ops/vps/noctisapi-core.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now noctisapi-core.service
```

---

## Troubleshooting

**Migration fails on first start:**
The `migrate` service runs `alembic upgrade head` before `app` and `admin` start.
If it fails (e.g. after switching from a different image version), fix the DB version:

```bash
docker compose --env-file .env.prod -f compose/docker-compose.prod.yml down
docker run --rm -v compose_hp_prod_data:/data python:3.11-alpine \
  python -c "
import sqlite3
c = sqlite3.connect('/data/honeypot.db')
c.execute(\"UPDATE alembic_version SET version_num='20260208_01_core_schema'\")
c.commit()
print('Fixed:', c.execute('SELECT * FROM alembic_version').fetchall())
"
docker compose --env-file .env.prod -f compose/docker-compose.prod.yml up -d
```

**Port 9001 already allocated:**
An old container is still running. Run `docker compose ... down` first, then `up -d`.

**Admin panel shows old UI after update:**
The old image is still cached. Rebuild and force-recreate:
```bash
docker build -t ghcr.io/0x-unkwn0wn/shadowapi-core:latest .
docker compose --env-file .env.prod -f compose/docker-compose.prod.yml up -d --force-recreate
```
