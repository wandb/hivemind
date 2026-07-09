# AgentStream self-host stack

```bash
hivemind serve up
```

configures the default instance on first run (writes
`~/.hivemind/serve/default/.env` interactively — domain, TLS handling, Caddy
host ports), starts the stack (API+dashboard, worker, ClickHouse, Redis,
Caddy), and prints the one-time `/setup` URL. The setup UI lets you create a
GitHub App or skip it for a single-player instance.

```bash
hivemind serve setup     # (re)configure .env
hivemind serve up        # start
hivemind serve down      # stop (data persists)
hivemind serve down -v   # stop and remove Docker volumes
hivemind serve --name smoke up  # isolated test instance
hivemind serve --help    # all commands
```

`hivemind serve` is the recommended path — it generates `.env`, materializes
these Compose files into an instance dir, layers the right overlays (bundled vs.
external ClickHouse, Tailscale), and wraps `docker compose` with the matching
project name and data dir.

## Running Compose directly

The files in this directory are the whole stack, so you can also skip the CLI
and drive `docker compose` yourself — useful for reading the stack or wiring it
into your own orchestration:

```bash
cp .env.example .env       # then set DOMAIN, EXTERNAL_URL, JWT_SECRET, …
docker compose -f docker-compose.yml -f docker-compose.clickhouse.yml up -d
```

Drop `docker-compose.clickhouse.yml` when pointing at an external/managed
ClickHouse, and add `docker-compose.tailscale.yml` for the Tailscale sidecar.
You then own the pieces `hivemind serve` handles for you (secret generation,
`.env` prompts, upgrades).

Full guide: [docs/self-hosting.md](../docs/self-hosting.md).
