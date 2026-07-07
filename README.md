# W&B HiveMind

W&B HiveMind is a shared dashboard for AI coding sessions. A lightweight daemon runs on each developer's machine, watches for coding agent activity, and sends session transcripts to [hivemind.wandb.tools](https://hivemind.wandb.tools).

Coding agents like Claude Code, Codex, Cursor, Gemini CLI, OpenCode, GitHub Copilot CLI, and Pi all write transcripts to the local filesystem as they work. The HiveMind daemon wakes up every 30 seconds, checks for new activity, and uploads anything it finds. There's nothing to configure per agent. If the agent writes transcripts, HiveMind picks them up.

This repository hosts release binaries for the HiveMind daemon and is the public issue tracker. Found a bug or have a feature request? [Open an issue](https://github.com/wandb/hivemind/issues). The dashboard and docs live at [hivemind.wandb.tools](https://hivemind.wandb.tools).

## Getting started

Install the client and start the daemon. `hivemind start` registers a background service (launchd on macOS, systemd on Linux) so the daemon keeps running and starts on login, prompting you to authenticate through GitHub or your organization's SSO if you haven't already.

### Install (macOS or Linux)

```bash
curl -fsSL https://hivemind.wandb.tools/install | sh
hivemind start
```

The one-line installer is the recommended path. On an Apple Silicon Mac with Homebrew it installs the `wandb-hivemind` cask, so you get a clean `brew uninstall` later; everywhere else it downloads the signed binary to `~/.local/bin` — no Homebrew, Python, or `sudo` required. Either way the daemon detects and applies upgrades automatically.

To skip the cask and always install the raw signed binary — even on a Homebrew Mac — pass `--binary`:

```bash
curl -fsSL https://hivemind.wandb.tools/install | sh -s -- --binary
```

On macOS the binary requires Apple Silicon; on an Intel Mac, use `uv` (below). For fleet rollouts through an MDM, see [Deploying with MDM](https://hivemind.wandb.tools/docs/mdm).

### macOS (Homebrew cask)

Prefer to drive the install through Homebrew yourself? Install the cask directly:

```bash
brew install wandb/taps/wandb-hivemind
hivemind start
```

Homebrew 6 requires third-party taps to be trusted before their code runs. Installing by fully-qualified name records that trust automatically (you'll see `Trusted cask wandb/taps/wandb-hivemind` on first install); review or revoke it later with `brew trust` / `brew untrust`.

The cask installs the same self-updating binary, so there's nothing to upgrade by hand — `brew upgrade` is a no-op for it unless you pass `--greedy`. The cask is Apple Silicon-only; on an Intel Mac, use `uv` below.

### Any platform (uv)

```bash
uv tool install wandb-hivemind
hivemind start
```

`uv` installs the cross-platform Python package — the path for Intel Macs and Windows, where the one-line installer and cask don't apply. Upgrade with:

```bash
uv tool upgrade wandb-hivemind
```

### Uninstalling

How you remove HiveMind depends on how it was installed. Since the one-line installer uses the cask on an Apple Silicon Mac with Homebrew, check whether brew owns it:

```bash
brew list wandb/taps/wandb-hivemind
```

If that succeeds, uninstall through brew with `--zap` — this stops and unregisters the launchd service, removes the binary, and clears the leftover LaunchAgent plist and logs (it deliberately leaves `~/.hivemind` alone — see below):

```bash
brew uninstall --zap wandb/taps/wandb-hivemind
```

Installed with `uv`? Use `uv tool uninstall wandb-hivemind`. Otherwise it's a binary install — stop and unregister the daemon, then remove the binary:

```bash
hivemind stop --disable
rm ~/.local/bin/hivemind
```

Either way, your data in `~/.hivemind/` is left in place. It holds the daemon's sync state — which sessions have already been uploaded — so removing it and reinstalling later triggers a re-sync. Delete it only if you don't intend to use HiveMind again:

```bash
rm -rf ~/.hivemind
```

### Docker (sidecar)

For containerized agents, run the daemon as a sidecar that watches the agent's transcript directory. Images are published for `linux/amd64` and `linux/arm64`:

```bash
docker run -d \
  -v claude-sessions:/watch/.claude:ro \
  -e HIVEMIND_TOKEN=<your-token> \
  -e HIVEMIND_WATCH_PATHS=/watch/.claude \
  ghcr.io/wandb/hivemind:latest
```

Mount the directory your agent writes transcripts to (read-only is fine) and point `HIVEMIND_WATCH_PATHS` at it. The HiveMind server image is also available as [`ghcr.io/wandb/hivemind-server`](https://github.com/wandb/hivemind/pkgs/container/hivemind-server).

## How it works

Once the daemon is running, open any supported coding agent and start working. Within 30 seconds your session appears on the [dashboard](https://hivemind.wandb.tools). You can watch sessions in real-time, review past conversations, and dig into individual tool calls.

### Supported agents

| Agent              | Transcript source                      |
| ------------------ | -------------------------------------- |
| Claude Code        | `~/.claude/projects/` JSONL files      |
| Codex              | `~/.codex/` session logs               |
| Cursor             | SQLite databases in Cursor's app data  |
| Gemini CLI         | `~/.gemini/` session history           |
| OpenCode           | `~/.opencode/` session files           |
| GitHub Copilot CLI | `~/.copilot/session-state/` event logs |
| Pi                 | `~/.pi/agent/sessions/` JSONL files    |

### The HiveMind agent

HiveMind also installs an `@hivemind` agent definition when the daemon starts (Claude Code, Codex, and Cursor). Type `@hivemind` in a supported agent to ask questions about past coding sessions: what you worked on last week, how a bug was fixed, where a particular change was made. It searches across your team's session history and pulls the answer into your current conversation.

## Self-hosting

Run HiveMind on your own infrastructure instead of [hivemind.wandb.tools](https://hivemind.wandb.tools). The self-hosted stack uses the same artifacts as the SaaS — the `ghcr.io/wandb/hivemind-server` image (API + dashboard + worker), ClickHouse, Redis, and Caddy for TLS.

The recommended path is the `hivemind serve` command, which configures the instance, materializes the Compose files, and wraps `docker compose` for you:

```bash
curl -fsSL https://hivemind.wandb.tools/install | sh
hivemind serve up
```

`hivemind serve up` generates an `.env` (domain, TLS handling, LLM provider, optional license), pulls the published images, starts the stack, and prints a one-time setup URL for creating the first admin account.

Prefer to drive Docker Compose yourself? The raw stack lives in [`selfhost/`](selfhost/) — the same files `hivemind serve` runs — so you can read it or wire it into your own orchestration:

```bash
cd selfhost
cp .env.example .env       # then set DOMAIN, EXTERNAL_URL, JWT_SECRET, …
docker compose -f docker-compose.yml -f docker-compose.clickhouse.yml up -d
```

See the [self-hosting guide](docs/self-hosting.md) for the full walkthrough — GitHub App setup, single-player mode, external/managed ClickHouse, object storage, backups, Tailscale, upgrades, and the [LLM provider](docs/llm-providers.md) options.

## How HiveMind compares

HiveMind gives you one view across every coding agent your team uses, instead of a separate dashboard per vendor. Native dashboards from individual agent vendors only show their own usage. HiveMind brings Claude Code, Codex, Cursor, Gemini, Copilot, and more together with session-level detail, spend, and outcomes in one place.

### HiveMind and Weave

If you already use W&B Weave, it works together with HiveMind. They cover different stages and answer different questions.

- Weave observes what your AI application does in _production_, tracking LLM and agent traces, evaluations, and quality.
- HiveMind observes how your team _builds software_ with AI coding agents, tracking details like sessions, spend, and productivity.

## Next steps

- [hivemind.wandb.tools](https://hivemind.wandb.tools): Sign in and see your team's sessions on the live dashboard
- [Documentation](https://hivemind.wandb.tools/docs): Full docs, including configuration and MDM deployment
