# Self-Hosting HiveMind

Run HiveMind on your own VM with Docker Compose. Use the same artifacts as the
SaaS: the official `ghcr.io/wandb/hivemind-server` image (API + dashboard;
the worker runs the identical image), ClickHouse, Redis, and Caddy for TLS.
Architecture and rationale: [self-hosting-design.md](https://hivemind.wandb.tools/docs).

## Requirements

- A Linux VM reachable from the internet (the collaborative features are the
  point — your team's daemons and browsers need to reach it). **4 GB RAM /
  2 vCPU minimum**; ClickHouse is the resource floor.
- Docker with the compose plugin.
- A DNS record pointing at the VM (Caddy provisions Let's Encrypt TLS
  automatically). `localhost` works for kicking the tires.

## Quick start

```bash
git clone https://github.com/wandb/agentstream
cd agentstream/selfhost
hivemind serve up
```

`hivemind serve up`:

1. on first run, configures the instance (`hivemind serve setup`): generates
   `~/.hivemind/serve/default/.env` with a random `JWT_SECRET`, and asks for
   your domain, how TLS is handled (Caddy terminates it, or an upstream proxy
   does), which host ports to bind Caddy to (default 80/443), which
   [ClickHouse](#database-clickhouse) to use (bundled container or an
   external/managed one), object storage, the [LLM provider](#llm-provider),
   and an optional [license](#license),
2. pulls the published images and starts the stack,
3. prints the one-time **setup URL** like
   `https://your-domain/setup?token=ab12…`.

Open that URL to create the first admin account. The setup UI also lets you
create a GitHub App for team features, or skip it for a single-player
instance.

Other commands: `hivemind serve down` (stop), `hivemind serve restart [svc]`,
`hivemind serve logs [svc]`, `hivemind serve status`, `hivemind serve --help`.
Use `hivemind serve --name smoke up` to run an isolated test instance; its
state lives under `~/.hivemind/serve/smoke`.

## Single-player mode (no GitHub App)

For a personal instance, open the setup URL and choose **Skip GitHub App**.
Login (dashboard and `hivemind login`) then runs on GitHub's **device flow**,
which needs only a public client id — the instance rides on the same baked-in
client id the CLI ships with, so there is nothing to register and no secret to
manage.

The **first GitHub user to log in claims the instance**; every other
identity is rejected from then on (the claim persists in
`~/.hivemind/serve/<name>/data/instance-owner.json`). To pin the owner up
front instead, set `SINGLE_USER_GITHUB_LOGIN=your-github-username`.

What you give up when you skip the GitHub App: org-membership verification,
PR walkthrough comments, membership/PR webhooks, and silent token refresh
(re-login when the session expires). Upgrading later is non-destructive:
configure a GitHub App and keep the same user and data. User ids are derived
deterministically from your GitHub id.

### Admin mode (escalation) on self-host

Super-admin powers (instance-wide operational pages like Insights Ops) are
not granted by your base session — you opt into them via **admin mode**, the
same downscoping model SaaS uses so a stolen session token can't wield them.
SaaS gates this behind phishing-resistant OIDC step-up, which self-host
doesn't have, so self-host instead requires a **fresh sign-in**: enabling
admin mode within ~5 minutes of logging in succeeds immediately; otherwise
the dashboard sends you to sign in again first. Tune the window with
`ESCALATION_REAUTH_MAX_AGE_SECONDS`. Cross-tenant SaaS features
(impersonation, the org directory) are disabled on self-host — a single-org
deployment has no other tenants to act on.

## The GitHub App (one app for everything)

HiveMind uses a single GitHub App for all GitHub integration:

| Capability | How it's used |
|---|---|
| Dashboard login | OAuth authorization-code flow with the App's client id/secret |
| Daemon login | Browser/loopback flow (server-brokered) and device flow for headless machines |
| Org membership verification | App installation tokens — attributes sessions to your org, including private memberships |
| PR walkthrough comments | Installation token, `pull_requests: write` |
| Membership/PR webhooks | Keeps org membership and PR state fresh |

The `/setup` wizard creates this app for you via GitHub's
[app-manifest flow](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest):
you pick a name and (optionally) the GitHub org that should own the app,
confirm on github.com, and land back on your instance with the credentials
already installed — app id, private key, client id/secret, and webhook
secret are written to `~/.hivemind/serve/<name>/data/github-app.env` and
picked up on every boot. The API also hot-applies them, so login works
immediately.

Three steps remain (the first two aren't settable via manifest):

1. **Install the app** on your GitHub organization (the wizard links you
   there). Creating an app only registers it; installing it on the org is
   what grants the membership/PR access.
2. In the app's settings, tick **“Enable Device Flow”** — needed for
   `hivemind login` on SSH-only machines.
3. Back on the server, **`hivemind serve restart worker`** — the worker
   only reads credentials at startup; until restarted, membership checks
   and PR comments silently no-op. (The API itself hot-applies them, so
   logins work immediately.)

To restrict who can log in to your instance, set
`ALLOWED_GITHUB_ORGS=my-org` in `~/.hivemind/serve/<name>/.env`
(unset = any GitHub user).

### Creating the app manually (no wizard)

If you prefer, create the app yourself at
**GitHub → Settings → Developer settings → GitHub Apps → New GitHub App**
(under your org), then fill the `GITHUB_APP_*` values into
`~/.hivemind/serve/<name>/.env`:

| Setting | Value |
|---|---|
| Homepage URL | `https://YOUR_DOMAIN` |
| Callback URL | `https://YOUR_DOMAIN/v1/auth/callback` |
| ✅ Expiring user tokens | enabled (default) |
| ✅ Enable Device Flow | enabled |
| Webhook URL | `https://YOUR_DOMAIN/v1/webhooks/github` |
| Webhook secret | random string → `GITHUB_APP_WEBHOOK_SECRET` |
| Org permissions | **Members: Read-only** |
| Repo permissions | **Metadata: Read-only**, **Pull requests: Read & write** |
| Subscribe to events | **Pull request**, **Membership** |
| Where can it be installed | Only on this account |

Credentials → env vars: App ID → `GITHUB_APP_ID`, app slug (from the app's
URL) → `GITHUB_APP_SLUG`, client ID → `GITHUB_APP_CLIENT_ID`, a generated
client secret → `GITHUB_APP_CLIENT_SECRET`, a generated private key (the
`.pem` contents) → `GITHUB_APP_PRIVATE_KEY`. Then
`hivemind serve up` again.

## Connecting daemons

On each developer machine:

```bash
curl -fsSL https://YOUR_DOMAIN/install | sh     # installs the CLI, pointed at YOUR_DOMAIN
hivemind login
hivemind start
```

Because the script is served from your instance, it runs
`hivemind config set server.endpoint https://YOUR_DOMAIN` for you — no manual
endpoint step. Re-running `curl … | sh` repoints an already-installed daemon at
the server and reports the change, so it doubles as the "switch servers"
command. (Override the baked-in endpoint with `HIVEMIND_SERVER_ENDPOINT=…` before
the pipe, or set it later with `hivemind config set server.endpoint …`.)

Daemons discover your GitHub App's client id from the server
(`GET /v1/auth/github/config`), so no client-side GitHub configuration is
needed.

## Operations

```bash
cd agentstream/selfhost
hivemind serve status                  # service status
hivemind serve logs app                # API logs
hivemind serve logs worker             # normalization/enrichment logs
hivemind serve up                      # start the stack (safe to re-run)
hivemind serve upgrade                 # upgrade to the newest release (see "Upgrades")
hivemind serve upgrade --check         # report whether a newer release is available
hivemind serve down                    # stop (volumes persist)
hivemind serve down --volumes          # stop and remove Docker named volumes
hivemind serve reset                   # guarded stop + volume removal
hivemind serve reset --all             # also remove .env and local data
hivemind serve --name smoke up         # isolated Compose project + state dir
hivemind serve tailscale enable        # expose on your tailnet (see below)
hivemind serve install-service         # start the stack on boot via systemd
```

These wrap `docker compose` with the right project name, compose file, env
file, and data directory. Prefer `hivemind serve` for routine operations so
named test instances use the matching volumes and local state.

To run from a source checkout instead of the published image (development,
unreleased changes), set `HIVEMIND_BUILD=1` — `hivemind serve` layers in the build
override (`docker-compose.build.yml`):

```bash
HIVEMIND_BUILD=1 hivemind serve up
```

For the default instance, mutable state lives in `~/.hivemind/serve/default`.
Named Docker volumes hold ClickHouse, Redis, and Caddy state using the Compose
project prefix (`default_clickhouse_data`, `default_redis_data`, and so on).
Local setup data, GitHub App credentials, screenshots, and exports live in
`~/.hivemind/serve/default/data/`. Back up the named volumes and that data
directory.

## Upgrades

The worker phones home to the W&B SaaS once a day (the anonymized license
check-in; opt out with `HIVEMIND_TELEMETRY=false` or `DO_NOT_TRACK=1`), and
the response includes the newest released server version. When your instance
is behind, the dashboard shows an update banner with the command to run:

```bash
hivemind serve upgrade
```

It pulls the new images *while the current stack keeps serving* — the only
downtime is the container swap — then recreates just the services whose image
or configuration changed (`up -d --remove-orphans`), waits for the app to come
back healthy, and reports the old → new version. Database migrations run
automatically when the new app container boots. If the stack isn't running,
`upgrade` starts it. `hivemind serve upgrade --check` only reports status.

Version selection:

- By default the stack tracks the `:latest` image tag, so `upgrade` moves you
  to the newest stable release.
- If you pinned `HIVEMIND_VERSION` in `.env`, `upgrade` bumps the pin to the
  newest release (or to `--version X.Y.Z`) before pulling, leaving the rest of
  the file untouched.
- Airgapped from the check-in endpoint? The newest version is read from the
  public release manifest instead; if that's unreachable too, pass
  `--version` explicitly.

The compose files themselves (services, wiring) are re-materialized into the
instance directory from the CLI on every `serve up`/`upgrade`, so stack-layout
changes ship with CLI releases: services added in a new layout are created,
and services removed from it are cleaned up (`--remove-orphans`). Because of
this, `upgrade` warns when your CLI is older than the target server release —
upgrade the CLI first (`brew upgrade hivemind` or
`uv tool upgrade wandb-hivemind`) so image and layout move together.

## Configuration reference

`~/.hivemind/serve/<name>/.env` (see `selfhost/.env.example`):

| Variable | Required | Purpose |
|---|---|---|
| `DOMAIN` | yes | Public hostname; Caddy provisions TLS for it |
| `EXTERNAL_URL` | yes | Public base URL (scheme + domain); also pins the `/setup` wizard's manifest URLs so they can't be influenced by request Host headers |
| `JWT_SECRET` | yes | Session-token signing secret (`hivemind serve setup` generates this) |
| `HIVEMIND_SECRET_KEY` | no | Master key (Fernet) encrypting instance-wide secrets — the GitHub App credentials, and any future shared key — in ClickHouse so they ride the backup. `hivemind serve setup` generates it. **Back it up**: losing it makes those secrets unrecoverable (session data is unaffected). Unset = keep secrets in `.env`/compose instead |
| `HIVEMIND_VERSION` | no | Server image tag (default `latest`); pin a release like `0.7.6`, or `edge` for main builds |
| `SITE_ADDRESS` | no | Caddy site address override; defaults to `EXTERNAL_URL`. Set `http://` when TLS terminates upstream (see below) |
| `CADDY_HTTP_PORT` | no | Host port Caddy binds for HTTP (default `80`) |
| `CADDY_HTTPS_PORT` | no | Host port Caddy binds for HTTPS (default `443`) |
| `HIVEMIND_SERVE_DATA_DIR` | no | Local data bind mount; `hivemind serve setup` sets this to `~/.hivemind/serve/<name>/data` |
| `CLICKHOUSE_HOST` | no | Point at an [external/managed ClickHouse](#database-clickhouse); any value other than `clickhouse` disables the bundled container |
| `CLICKHOUSE_PORT` | no | ClickHouse HTTP(S) port (bundled `8123`; managed CH is usually `8443`) |
| `CLICKHOUSE_SECURE` | no | Force TLS. Port `8443`/`443` already auto-enables it, so managed CH usually needs nothing here; set `true` only for TLS on a non-standard port |
| `CLICKHOUSE_DB` / `CLICKHOUSE_USER` / `CLICKHOUSE_PASSWORD` | no | Database name (default `agentstream`), username (default `default`), and password for an external ClickHouse |
| `HIVEMIND_LICENSE` | no | Signed [license](#license) token (verified offline); unset runs unlicensed with a banner |
| `LICENSE_ENFORCEMENT_MODE` | no | `off` \| `warn` (default) \| `enforce`; `warn` shows banners but never disables anything |
| `GITHUB_APP_*` | via wizard | GitHub App credentials; the wizard stores them encrypted in ClickHouse (`instance_secrets`). Set here only to override the wizard or bring your own app |
| `SINGLE_USER_GITHUB_LOGIN` | no | Pin the app-less single-player owner by GitHub username |
| `ALLOWED_GITHUB_ORGS` | no | Comma-separated login allowlist |
| `WORKER_MAX_IN_FLIGHT` | no | Concurrent jobs per worker container; unset auto-sizes from the host CPU count (see [Scaling the worker](#scaling-the-worker)) |
| `WORKER_REPLICAS` | no | Number of worker containers (default `1`); they share one Redis Streams consumer group |
| `ANTHROPIC_API_KEY` | no | Default LLM (Claude) for insights, PR walkthroughs, personas, summaries |
| `OPENAI_API_KEY` | no | Default provider for embeddings (insight clustering + semantic search) |
| `LLM_PROVIDER` | no | Point AI features at another provider: `wandb` (W&B Inference), `openai`, `anthropic`, `bedrock`, or any OpenAI-compatible alias (see [LLM provider](#llm-provider)) |
| `LLM_API_KEY` / `LLM_BASE_URL` / `LLM_MODEL` | with `LLM_PROVIDER` | Credentials, endpoint, and default model for the chosen provider |
| `LLM_EXTRA_HEADERS` | no | JSON of extra request headers (W&B Inference uses `{"OpenAI-Project": "entity/project"}`) |
| `LLM_BEDROCK_REGION` | with `bedrock` | AWS region for Amazon Bedrock |
| `TITLE_EXTRACTION_MODEL` / `WEEKLY_SUMMARY_MODEL` | no | Smaller per-feature model overrides; each falls back to `LLM_MODEL` |
| `EMBEDDINGS_BASE_URL` / `EMBEDDINGS_API_KEY` / `EMBEDDINGS_MODEL` | no | Override the embeddings endpoint (must emit 1536-dim vectors); falls back to `OPENAI_API_KEY` |
| `STORAGE_PROVIDER` | no | `local` (default), `s3`, or `gcs` — backend for screenshots/exports (see [Object storage](#object-storage)) |
| `S3_BUCKET_NAME` | with `s3` | Bucket for screenshots and data exports |
| `S3_ENDPOINT_URL` | no | S3 endpoint for non-AWS stores (R2, GCS-interop, MinIO) |
| `AWS_REGION` / `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | with `s3` | Region + credentials (HMAC keys for R2/GCS); `auto` region for R2/GCS |
| `GCS_BUCKET_NAME` / `GOOGLE_APPLICATION_CREDENTIALS` | with `gcs` | Native GCS bucket + service-account JSON path |
| `CLICKHOUSE_STORAGE_CONFIG` | no | Set to `./clickhouse-storage.xml` to back ClickHouse with object storage (experimental) |
| `CLICKHOUSE_S3_ENDPOINT` | with CH backing | Bucket + key prefix for ClickHouse parts, e.g. `https://bucket.s3.us-east-1.amazonaws.com/clickhouse/` |
| `CLICKHOUSE_S3_CACHE_SIZE` | no | Local hot-data cache size for the ClickHouse S3 disk (default `10Gi`) |
| `COMPOSE_PROFILES` | no | Set to `backup` to run the nightly ClickHouse backup sidecar (see [Backups](#backups)) |
| `CLICKHOUSE_BACKUP_S3_ENDPOINT` | with backups | Backup destination (`clickhouse-backups/` prefix in your bucket) |
| `CLICKHOUSE_BACKUP_RETENTION_DAYS` | no | Days of nightly backups to keep (default `3`) |
| `CLICKHOUSE_BACKUP_HOUR` | no | UTC hour (0–23) the backup runs (default `3`) |
| `TAILSCALE_MODE` | no | Set by `hivemind serve tailscale enable` (`host` or `sidecar`); `sidecar` makes `hivemind serve up` layer in the Tailscale sidecar overlay (see [Remote access with Tailscale](#remote-access-with-tailscale)) |
| `TAILSCALE_AUTHKEY` | no | Auth key / OAuth client secret for the sidecar (sidecar mode) |
| `TAILSCALE_HOSTNAME` | no | Node name on your tailnet (`<name>.<tailnet>.ts.net`) |
| `TAILSCALE_FUNNEL` | no | `true` exposes the instance on the public internet via Tailscale Funnel |

To run the AI features against your own provider — Ollama, the W&B / CoreWeave
inference service, a self-hosted vLLM, or Amazon Bedrock — see the dedicated
guide: [`docs/llm-providers.md`](llm-providers.md). No external router (LiteLLM)
is involved; the backend talks to your endpoint through the OpenAI or Anthropic
SDK directly.

### Scaling the worker

The `worker` container does the heavy lifting: it normalizes uploaded sessions
into AG-UI events and runs the AI features (insights, PR walkthroughs, personas,
enrichment). The `app` container just serves the API and dashboard. If uploads
pile up — `hivemind serve logs worker` shows a growing backlog, or new sessions
take a while to appear enriched — the worker is the thing to scale. Two
independent knobs, usable together:

**Vertical — more concurrency per container (`WORKER_MAX_IN_FLIGHT`).** A single
worker processes jobs concurrently on one async event loop with a matching-size
thread pool. Unset, it auto-sizes from the host CPU count (`4 × cores`, floor 10,
cap 32); jobs are mostly I/O-bound (ClickHouse, LLM and GitHub calls), so the
default oversubscribes cores. Raise it on a big box with ClickHouse and RAM
headroom; lower it if a small box is CPU-starved. Each slot holds a ClickHouse
connection and a thread, so this also scales load on ClickHouse.

```bash
# ~/.hivemind/serve/default/.env
WORKER_MAX_IN_FLIGHT=24
```

**Horizontal — more worker containers (`WORKER_REPLICAS`).** Run several workers
that share the work. They join one Redis Streams consumer group, so jobs are
split across them and a container that dies has its in-flight jobs reclaimed by a
sibling. Only one replica runs the periodic "leader" tasks (PR enrichment sweeps,
daily intelligence) — a Redis claim guards them, so replicas never duplicate them
or double your GitHub/LLM spend. Prefer this over a very large
`WORKER_MAX_IN_FLIGHT` once one container is CPU-bound, or to survive a worker
crash without pausing processing.

```bash
# ~/.hivemind/serve/default/.env
WORKER_REPLICAS=3
```

Apply either change with `hivemind serve up` (or `docker compose up -d`). All
containers share the one Redis and ClickHouse, so scale those hosts too if the
worker fleet grows — ClickHouse is the resource floor. Priority handling needs no
configuration: the queue already drains separate normal / low / long priority
streams concurrently within every worker, so background work can't starve session
normalization.

### Behind a TLS-terminating proxy

VM platforms with a built-in HTTPS proxy (exe.dev, Cloudflare Tunnel, a cloud
load balancer) terminate TLS before traffic reaches the VM, so Caddy must not
try to provision certificates itself — the platform owns port 443 and ACME
would fail. Choose **"an upstream proxy/load balancer terminates TLS"** when
`hivemind serve setup` asks, which writes the split below to
`~/.hivemind/serve/<name>/.env`:

```bash
EXTERNAL_URL=https://your-vm.exe.dev   # the public URL users and daemons see
SITE_ADDRESS=http://                   # Caddy serves plain HTTP, any host
```

`EXTERNAL_URL` keeps powering setup-wizard manifests, printed links, and
OAuth callbacks (absolute URLs are rewritten to https for non-localhost
hosts); `SITE_ADDRESS` makes Caddy a plain reverse proxy on port 80, which
the platform proxy forwards to.

Self-host defaults baked into the compose file: `QUEUE_PROVIDER=redis`,
`USAGE_QUOTA_MODE=off`, `RETENTION_SWEEP_MODE=off`, `AUTO_MIGRATE=true`,
`TERMS_ACCEPTANCE_ENABLED=false` (self-hosters cover users under their own
agreement, so the per-user terms prompt is skipped).

### Remote access with Tailscale

If you run HiveMind on a home server or a VM with no public DNS, put it on your
[tailnet](https://tailscale.com) instead of opening ports. Tailscale terminates
TLS and gives the instance a stable `https://<name>.<tailnet>.ts.net` URL with
an automatic certificate. Both modes reuse the upstream-TLS split above
(`SITE_ADDRESS=http://`, `EXTERNAL_URL=https://…ts.net`); `hivemind serve
tailscale enable` writes it for you.

```bash
hivemind serve tailscale enable     # detects how you're set up and guides you
hivemind serve tailscale status     # show the mode, URL, and live serve config
hivemind serve tailscale disable    # stop exposing the instance
```

`enable` picks a mode automatically, or force one with `--mode`:

- **Host mode** — used when Tailscale is already running on this machine. It
  runs `tailscale serve` (or `tailscale funnel` with `--funnel`) to publish the
  stack's HTTP port under this node's MagicDNS name. Nothing is added to the
  compose stack; the `tailscale serve` config persists across reboots.

- **Sidecar mode** — used when you pass `--authkey` (or Tailscale isn't on the
  host). It runs a `tailscale/tailscale` container
  (`docker-compose.tailscale.yml`) that joins your tailnet with its **own** node
  identity. Create a key at
  <https://login.tailscale.com/admin/settings/keys>:

  ```bash
  hivemind serve tailscale enable --authkey tskey-auth-xxxx --hostname hivemind
  hivemind serve up                # (re)start so the sidecar joins the tailnet
  ```

  The sidecar shares Caddy's network namespace so Tailscale Serve can proxy to
  Caddy on `localhost` — Serve [only proxies to
  localhost](https://github.com/tailscale/tailscale/issues/8751). It needs
  `/dev/net/tun` plus the `net_admin`/`sys_module` capabilities (already in the
  overlay). On a host without the tun device, run `sudo modprobe tun`, or set
  `TAILSCALE_USERSPACE=true` and remove the `devices:` entry from the overlay.

Pass `--funnel` in either mode to expose the instance on the **public
internet** (off by default — tailnet-only). Funnel must first be allowed in
your [tailnet ACLs](https://tailscale.com/kb/1223/funnel).

### Start on boot (systemd)

Every service in the compose file uses `restart: unless-stopped`, so the stack
comes back on its own after a Docker daemon restart — as long as Docker itself
starts on boot (`sudo systemctl enable --now docker`). To manage the stack as a
first-class systemd service (ordered after Docker, clean start/stop), generate a
unit:

```bash
hivemind serve install-service          # writes the unit + prints install steps
hivemind serve install-service --install # also copies + enables it (needs sudo)
```

The unit is a `Type=oneshot`/`RemainAfterExit=yes` service that runs `hivemind
serve up` at boot (after `docker.service`) and `hivemind serve down` on stop; the
per-container restart policy keeps things running in between. On macOS/Windows,
enable "Start Docker Desktop when you log in" instead — the restart policy then
handles the rest.

## LLM provider

The advanced AI features — session summaries, insights, PR walkthroughs,
personas, weekly summaries — call an LLM. They're bring-your-own-key and
quietly no-op until one is configured. `hivemind serve setup` asks which
provider to use; you can also set the env directly.

The default is Anthropic — set `ANTHROPIC_API_KEY` and you're done. To point
every feature at another provider, set the generic `LLM_*` vars; the backend
maps the provider, and `wandb` / `coreweave` / `ollama` / `vllm` all use the
OpenAI-compatible path:

| Provider | Env |
|---|---|
| Anthropic (default) | `ANTHROPIC_API_KEY` |
| W&B Inference / CoreWeave | `LLM_PROVIDER=wandb`, `LLM_BASE_URL=https://api.inference.wandb.ai/v1`, `LLM_API_KEY`, `LLM_MODEL` |
| OpenAI | `LLM_PROVIDER=openai`, `LLM_API_KEY`, `LLM_MODEL` |
| Ollama / vLLM / gateway | `LLM_PROVIDER=openai`, `LLM_BASE_URL`, `LLM_MODEL` (key optional) |

W&B Inference attributes usage to a project via a header — set
`LLM_EXTRA_HEADERS={"OpenAI-Project": "entity/project"}` (the wizard prompts
for this). Titles and weekly summaries are short prompts, so they default to a
smaller, cheaper model: the wizard sets `TITLE_EXTRACTION_MODEL` and
`WEEKLY_SUMMARY_MODEL` (each falls back to `LLM_MODEL` when unset). The worker
runs the same features, so it reads the identical config.

## Database (ClickHouse)

All session data lives in ClickHouse. By default the stack runs a **bundled
ClickHouse container** on the same host — the simplest option, and fine for
small teams. `hivemind serve setup` also offers an **external / managed
ClickHouse**, recommended for production because the provider handles backups,
upgrades, and scaling for you ([ClickHouse Cloud](https://clickhouse.cloud) is
the managed option the wizard points at, but any reachable ClickHouse works).

Choosing external ClickHouse writes the connection env below and makes
`hivemind serve` **leave the bundled container out entirely** (no local
container, no `clickhouse_data` volume, no nightly-backup sidecar — the managed
instance owns its own backups):

```bash
CLICKHOUSE_HOST=abc123.us-east-1.aws.clickhouse.cloud
CLICKHOUSE_PORT=8443        # managed CH speaks HTTPS on 8443; bundled uses 8123
# CLICKHOUSE_SECURE is unnecessary here — port 8443/443 auto-enables TLS. Set
# CLICKHOUSE_SECURE=true only to force TLS on a non-standard port.
CLICKHOUSE_DB=agentstream
CLICKHOUSE_USER=default
CLICKHOUSE_PASSWORD=…
```

The `agentstream` database is created automatically on first boot
(`AUTO_MIGRATE=true`), so the credentials only need `CREATE DATABASE` plus table
DDL. To switch an existing instance, set these in `.env` and
`hivemind serve up` — but note the two stores are separate: data in the bundled
container does **not** migrate to the external one automatically. Point at
external ClickHouse before ingesting real data, or migrate it yourself (e.g. a
native `BACKUP`/`RESTORE` between the two).

## Object storage

Session screenshots and data exports default to the local `./data` volume
(`STORAGE_PROVIDER=local`). For a durable, backed-up, multi-host-friendly
store, choose **object storage** when `hivemind serve setup` asks — it writes
the env below. You can also fill it in by hand.

The backend's `s3` provider speaks plain S3, so one set of credentials covers
several providers:

| Provider | `S3_ENDPOINT_URL` | `AWS_REGION` | Credentials |
|---|---|---|---|
| AWS S3 | *(unset)* | real region (`us-east-1`) | IAM access key / secret |
| Cloudflare R2 | `https://<account-id>.r2.cloudflarestorage.com` | `auto` | R2 API token (HMAC) |
| Google Cloud Storage | `https://storage.googleapis.com` | `auto` | HMAC key (Cloud Console → Settings → Interoperability) |
| MinIO / Ceph / other | `https://minio.example.com` | `us-east-1` | access key / secret |

The wizard reaches GCS through its S3-interop endpoint so the same HMAC keys
serve the app, the nightly backups, and the optional ClickHouse disk. Native
GCS (`STORAGE_PROVIDER=gcs` with `GCS_BUCKET_NAME` and a service-account JSON at
`GOOGLE_APPLICATION_CREDENTIALS`) also works and is the right choice when
running on GCP with workload identity.

## Backups

Once object storage is configured, `hivemind serve setup` offers to run
**nightly ClickHouse backups to the same bucket**, keeping the last few days
and pruning older ones. This is the recommended way to make your data
recoverable — and it's the only thing that makes the local `clickhouse_data`
volume truly disposable.

Saying yes writes these to `.env` and starts a small `clickhouse-backup`
sidecar (the `rclone/rclone` image) under the `backup` compose profile:

| Var | Default | Meaning |
|---|---|---|
| `COMPOSE_PROFILES` | — | Set to `backup` to include the sidecar in the stack |
| `CLICKHOUSE_BACKUP_S3_ENDPOINT` | — | Backup destination, the `clickhouse-backups/` prefix in your bucket |
| `CLICKHOUSE_BACKUP_RETENTION_DAYS` | `3` | Backups older than this are pruned after each run |
| `CLICKHOUSE_BACKUP_HOUR` | `3` | UTC hour (0–23) the nightly backup runs |
| `CLICKHOUSE_BACKUP_RCLONE_PROVIDER` | `AWS` | `AWS` for S3; `Other` for R2 / GCS / MinIO |

How it works: the sidecar runs ClickHouse's native
[`BACKUP DATABASE agentstream TO S3(...)`](https://clickhouse.com/docs/en/operations/backup)
each night — a consistent, self-contained snapshot of schema **and** data that
works whether tables live on the local disk or the S3 storage policy. Each run
writes a timestamped folder under `clickhouse-backups/`, then prunes folders
older than the retention window with `rclone delete --min-age`. Backups are
**full, not incremental**, so any one folder restores on its own and retention
is a simple age cutoff.

Notes:

- **Put backups in a different bucket (or enable bucket versioning) if you
  can.** Sharing one bucket with the app's data and the optional ClickHouse
  disk is fine for convenience, but a lost bucket then takes the backups too.
- **Redis is not backed up** — it only holds the job queue, which the worker's
  leader loop reconstructs.
- **Secrets ride the backups automatically.** The GitHub App credentials are
  stored encrypted in ClickHouse (so they're in the nightly snapshot), and the
  `.env` is encrypted under `HIVEMIND_SECRET_KEY` and pushed to
  `config-backups/env.enc` on every boot — see "Secrets & config" below.
- **Run one on demand / read full errors:**
  `docker compose exec clickhouse-backup /bin/sh /usr/local/bin/clickhouse-backup.sh`

### Secrets & config

Two secret stores back up automatically once `HIVEMIND_SECRET_KEY` is set
(`hivemind serve setup` generates it):

- **Instance secrets** — the GitHub App credentials live encrypted (Fernet,
  under the master key) in ClickHouse's `instance_secrets` table, so they're
  captured by the nightly snapshot above and re-applied to the environment on
  boot.
- **`config-backups/env.enc`** — on every boot the app encrypts your `.env`
  (which holds the bootstrap values it needs *before* it can reach ClickHouse:
  the master key, bucket + ClickHouse coordinates, `JWT_SECRET`) and uploads it
  to the bucket. Editing `.env` by hand is fine — the next boot re-snapshots it.

Back up the **recovery kit** out-of-band — it's the master key plus the bucket
credentials, the one thing not recoverable from the bucket itself:

```bash
hivemind serve recovery-kit          # QR + fields to scan into a password manager
hivemind serve recovery-kit --file kit.json   # or a 0600 file (delete after import)
```

> Losing the master key makes the encrypted secrets unrecoverable (you'd
> re-create the GitHub App and re-issue tokens) — but your **session data**
> stays plaintext in the ClickHouse backup, so it is never lost.

### Restoring

On a fresh host, rebuild `.env` from the snapshot using the recovery kit, then
restore the data:

```bash
hivemind serve restore --kit-file kit.json   # pulls + decrypts env.enc → writes .env
hivemind serve up
```

Then point `clickhouse-client` at the instance and restore a chosen backup
folder (start with `AUTO_MIGRATE=false` — the backup carries the schema):

```sql
RESTORE DATABASE agentstream
FROM S3('https://<bucket>.s3.<region>.amazonaws.com/clickhouse-backups/<TIMESTAMP>',
        '<ACCESS_KEY>', '<SECRET_KEY>');
```

Once the data is back, the app re-applies the GitHub App credentials from
`instance_secrets` on its next boot — no manual re-entry.

### ClickHouse on object storage (experimental, manual)

You can also **back ClickHouse's table data with the same bucket**, keeping a
local cache of hot data — the model [ClickHouse Cloud](https://clickhouse.com/docs/en/guides/separation-storage-compute)
uses. This is advanced and not offered by the setup wizard; enable it by hand
after reading the trade-offs below, and only on a **fresh install**.

To enable, set in `.env` and restart (`hivemind serve restart`):

```bash
CLICKHOUSE_STORAGE_CONFIG=./clickhouse-storage.xml
CLICKHOUSE_S3_ENDPOINT=https://<bucket>.s3.<region>.amazonaws.com/clickhouse/
CLICKHOUSE_S3_CACHE_SIZE=10Gi   # local hot-data cache
```

This points `CLICKHOUSE_STORAGE_CONFIG` at the bundled
`clickhouse-storage.xml`, which defines an [S3 disk](https://clickhouse.com/docs/en/operations/storage-policies)
wrapped in a [filesystem cache](https://clickhouse.com/docs/en/operations/storage-policies#dynamic-cache)
and makes that the **default storage policy**. New `MergeTree` tables — which
is all of them, since the migrations don't pin a policy — are then created with
their parts in the bucket and hot data cached locally under
`/var/lib/clickhouse/disks/s3_cache/` (size = `CLICKHOUSE_S3_CACHE_SIZE`,
default `10Gi`). Credentials are reused from `AWS_ACCESS_KEY_ID` /
`AWS_SECRET_ACCESS_KEY`, read by the config via `from_env`.

Trade-offs to understand before enabling:

- **The local volume holds the metadata.** The S3 disk keeps its *metadata*
  (the map from parts to object keys) on the local `clickhouse_data` volume.
  Losing the volume orphans the bucket data — object keys are not
  reconstructable from the parts alone. Object storage backing does **not** by
  itself make the volume disposable; the [nightly backups](#backups) above are
  what do, since a native `RESTORE` rebuilds both metadata and data. (ClickHouse
  Cloud avoids this with a separate metadata service; a single-node self-host
  does not.)
- **Latency.** Cold reads hit S3. The cache absorbs repeat reads, but queries
  that miss it are slower than local NVMe. Size the cache to your hot set.
- **System tables go to S3 too.** The default policy applies to ClickHouse's
  own log tables (`query_log`, …). The cache covers them, but they add small
  writes to the bucket. To keep them local, add per-table
  `<query_log><storage_policy>default</storage_policy></query_log>` overrides
  to `clickhouse-storage.xml`.
- **Switching an existing install is not automatic.** Tables created before
  enabling stay on the local `default` policy; only new tables land on S3. To
  migrate existing data, either start fresh, or `ALTER TABLE … MODIFY SETTING
  storage_policy='s3_cached'` and move parts (`ALTER TABLE … MOVE PARTITION …
  TO DISK 's3_cache'`) per table.

To disable later, remove `CLICKHOUSE_STORAGE_CONFIG` from `.env` (the no-op
`clickhouse-storage.disabled.xml` is mounted by default) and restart — but note
any data already written to S3 stays on the S3 policy for those tables.

## License

HiveMind self-host runs **unlicensed** out of the box — everything keeps
working and the dashboard shows a "get a license" banner (`warn` mode). A
license unlocks the premium tier and clears the banner; it's a signed token
verified **offline** (Ed25519), so it works airgapped and never phones home to
validate.

`hivemind serve setup` handles it three ways:

- **Fetch a trial automatically.** If you're logged in (`hivemind login`),
  setup offers to fetch a free 30-day trial license for you — one keypress,
  no copy/paste. The trial endpoint is idempotent: one active trial per user,
  and re-running setup (even weeks later, or on another machine) returns the
  same license instead of failing.
- **Paste one at setup.** The wizard links you to the public license page
  ([hivemind.wandb.tools/license](https://hivemind.wandb.tools/license)) where
  you can get a free trial or a full license, then prompts you to paste the
  token. Leave it blank to stay unlicensed.
- **Forward from the environment.** If `HIVEMIND_LICENSE` is already set when
  `hivemind serve setup` runs, it's written straight to `.env` without
  prompting — handy for scripted/automated installs:

  ```bash
  HIVEMIND_LICENSE="$(cat acme.lic)" hivemind serve setup
  ```

You can also drop the token into `~/.hivemind/serve/<name>/.env` by hand
(`HIVEMIND_LICENSE=…`) and `hivemind serve restart`. Enforcement is governed by
`LICENSE_ENFORCEMENT_MODE` (`off` | `warn` (default) | `enforce`); `warn` only
ever shows banners. See [self-hosted-licensing-design.md](https://hivemind.wandb.tools/docs)
for the full model.

### Trial auto-renewal & license renewals

**Trial licenses renew themselves.** When a trial gets within a week of expiry,
the daily anonymized check-in returns a fresh 30-day trial and the instance
applies it automatically — an actively-evaluating install never hits the expiry
cliff. (Requires the check-in to reach the SaaS; airgapped instances request a
new trial from the license page instead. Revoking a trial stops its renewal
chain.)

**Renewals apply without a restart.** A pushed renewal (trial or a renewed
production license) is stored encrypted in `instance_secrets` — so it rides the
nightly ClickHouse backup — and every container picks it up within about a
minute via its license read paths. The freshest *verifiable* token always wins:
a stale `HIVEMIND_LICENSE` left in `.env` can't mask a newer stored renewal
(and a forged or older token can never displace a configured one). If
`HIVEMIND_LICENSE_FILE` is configured, the renewal is also written there.

## Current limitations

- **OIDC SSO / SCIM** are enterprise paths and work, but require your own
  IdP configuration (`docs/Auth_RBAC.md`).

Live session streaming runs on Redis pub/sub and works out of the box.
