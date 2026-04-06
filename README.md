# NoctisAPI Core

`shadowapi-core` is the open-source Core edition of NoctisAPI.
It contains the public honeypot API, the internal admin panel, and the current
Core implementation of the Modular API layer.

## Important DNS Requirement Before Deploying

Before you deploy, create a DNS `A` record for the public domain you will use
and point it to the public IP address of the machine where the honeypot will
run.

Example:

- `api.example.com -> 203.0.113.10`

This is required so `HP_PUBLIC_HOST`, Traefik routing, and the Let's Encrypt
HTTP challenge can resolve correctly. If the domain does not already resolve to
the server, the production deployment will not come up cleanly over HTTPS.

## What This Repo Contains

- The public honeypot API in `app/honeypot_public.py`
- The internal admin panel in `app/panel_mvp.py`
- The Core Modular API engine in `app/api_modular.py`
- The production Docker stack in `compose/docker-compose.prod.yml`
- The interactive setup script in `setup.sh`

## How the Current Modular API Works in Core

The Core repo uses the classic Modular API implementation based on per-endpoint
configuration stored in SQLite.

### 1. Real endpoint catalog

The admin panel reads the public OpenAPI document and builds a route catalog of
real honeypot endpoints. This prevents saving modular config for paths that do
not exist in the API surface.

### 2. Per-endpoint config storage

Endpoint overrides are stored in the `api_endpoint_configs` table.
Each row controls:

- `enabled`
- `response_mode`
- `fixed_status`
- `richness_level`

### 3. Matching precedence

Incoming requests are resolved against saved config using this precedence:

1. exact path + exact method
2. exact path + any method
3. pattern path + exact method
4. pattern path + any method
5. fallback default config

Path matching supports:

- exact paths
- path parameters such as `/users/{id}`
- shell-style wildcards such as `*` and `?`

### 4. Built-in templates

Core ships four quick templates that can be applied from the panel:

- `balanced`
- `minimal`
- `error_trap`
- `disabled`

These are shortcuts for common per-endpoint response profiles.

### 5. Analytics

The Core Modular API also exposes analytics derived from recent events:

- endpoint metrics
- interest scoring
- fingerprinting by IP / path / method / user-agent spread

These are available through the admin panel endpoints under
`/dashboard/api-modular`.

### 6. What Core does not do

`shadowapi-core` includes the Modular API foundation, but not the full PRO
policy engine:

- mutation settings are OSS stubs
- rule evaluation and advanced response mutation are not active in Core
- the PRO build extends this foundation with the richer modular controls

## Production Deployment

### Fast path

Use the interactive setup script:

```bash
bash setup.sh --domain api.example.com --email ops@example.com --yes
```

### Manual path

```bash
cp .env.prod.example .env.prod
```

Set at least:

- `HP_PUBLIC_HOST`
- `ACME_EMAIL`
- `HP_SEED`
- `DATABASE_URL`

Then start the production stack:

```bash
docker compose --env-file .env.prod -f compose/docker-compose.prod.yml up -d
```

### What the stack runs

The production compose file starts:

- `migrate`
- `app`
- `admin`
- `traefik`

The public API is routed through Traefik on `80/443`.
The admin panel stays private and should only be exposed on:

- `127.0.0.1:9001`

## Accessing the Admin Panel

Use an SSH tunnel from your workstation:

```bash
ssh -L 9001:127.0.0.1:9001 user@your-server
```

Then open:

```text
http://localhost:9001
```

## Local Development

```bash
docker compose -f compose/docker-compose.dev.yml up --build
```

Development URLs:

- Public API: `http://127.0.0.1:8000`
- Admin panel: `http://127.0.0.1:9001`

Useful commands:

```bash
make db-upgrade
docker compose -f compose/docker-compose.dev.yml logs -f
docker compose -f compose/docker-compose.dev.yml down
```

## Operational Notes

- Keep `HP_SEED` stable after first deployment.
- The admin panel is meant to remain internal.
- The public API is intentionally deceptive and should be fronted by the public
  domain configured in `HP_PUBLIC_HOST`.

## License

Core is open source. The PRO edition adds advanced investigation workflows and
the full modular policy engine on top of this base.
