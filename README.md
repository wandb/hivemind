# W&B HiveMind

W&B HiveMind is a shared dashboard for AI coding sessions. A lightweight daemon runs on each developer's machine, watches for coding agent activity, and sends session transcripts to [hivemind.wandb.tools](https://hivemind.wandb.tools).

Coding agents like Claude Code, Codex, Cursor, Gemini CLI, OpenCode, GitHub Copilot CLI, and Pi all write transcripts to the local filesystem as they work. The HiveMind daemon wakes up every 30 seconds, checks for new activity, and uploads anything it finds. There's nothing to configure per agent. If the agent writes transcripts, HiveMind picks them up.

This repository hosts release binaries for the HiveMind daemon and is the public issue tracker. Found a bug or have a feature request? [Open an issue](https://github.com/wandb/hivemind/issues). The dashboard and docs live at [hivemind.wandb.tools](https://hivemind.wandb.tools).

## Getting started

Install the client and start the daemon. `hivemind start` registers a background service (launchd on macOS, systemd on Linux) so the daemon keeps running and starts on login, prompting you to authenticate through GitHub or your organization's SSO if you haven't already. Choose the method that fits your platform.

### macOS (Homebrew)

```bash
brew install --cask wandb/taps/wandb-hivemind
hivemind start
```

Homebrew 6 requires third-party taps to be trusted before their code runs; installing the fully-qualified cask above will prompt you to trust it. To trust it ahead of time instead (e.g. for non-interactive installs):

```bash
brew trust --cask wandb/taps/wandb-hivemind
```

Always use the fully-qualified `wandb/taps/...` names — homebrew-core has an unrelated package also named `hivemind`.

The cask installs a self-updating binary, so there's nothing to upgrade by hand — `brew upgrade` is a no-op for it unless you pass `--greedy`. On an Intel Mac, install the Python formula instead: `brew install wandb/taps/hivemind`.

### macOS or Linux (uv)

```bash
uv tool install wandb-hivemind
hivemind start
```

`uv` automatically selects the correct binary for your operating system. Upgrade with:

```bash
uv tool upgrade wandb-hivemind
```

### Standalone installer (macOS or Linux)

If you'd rather not depend on Homebrew, Python, or `uv`, the standalone installer downloads a signed binary to `~/.local/bin`. It doesn't require `sudo`:

```bash
curl -fsSL https://hivemind.wandb.tools/install | sh
hivemind start
```

Once started, the standalone binary detects and applies upgrades automatically.

On macOS, the standalone binary requires Apple Silicon; on an Intel Mac, use Homebrew instead. For fleet rollouts through an MDM, see [Deploying with MDM](https://hivemind.wandb.tools/docs/mdm).

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

## How HiveMind compares

HiveMind gives you one view across every coding agent your team uses, instead of a separate dashboard per vendor. Native dashboards from individual agent vendors only show their own usage. HiveMind brings Claude Code, Codex, Cursor, Gemini, Copilot, and more together with session-level detail, spend, and outcomes in one place.

### HiveMind and Weave

If you already use W&B Weave, it works together with HiveMind. They cover different stages and answer different questions.

- Weave observes what your AI application does in _production_, tracking LLM and agent traces, evaluations, and quality.
- HiveMind observes how your team _builds software_ with AI coding agents, tracking details like sessions, spend, and productivity.

## Next steps

- [hivemind.wandb.tools](https://hivemind.wandb.tools): Sign in and see your team's sessions on the live dashboard
- [Documentation](https://hivemind.wandb.tools/docs): Full docs, including configuration and MDM deployment
