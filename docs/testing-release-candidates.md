# Testing a self-hosted release candidate

Use a disposable Linux Docker host with Docker Compose available. Test the
published CLI and server together: this public repository contains deployment
artifacts, while the server package and dashboard are in the published image.
Keep test data and credentials separate from a production instance.

## Pin the CLI and server

From this checkout, use Python 3.9+ to install the CLI in an isolated prefix
and create the persistent `~/.local/bin/hivemind-rc` executable:

```bash
python3 scripts/install-candidate.py
export PATH="$HOME/.local/bin:$PATH"
rc_prefix=$(readlink -f "$HOME/.local/share/hivemind-releases/current")
rc_version=$(basename "$rc_prefix")
rc_name=candidate
hivemind-rc --version
sha256sum "$rc_prefix/bin/hivemind"
docker version
docker compose version
docker image ls --digests
```

The helper reads the live stable and prerelease manifests used by `install.sh`.
It selects the RC when it is newer than stable, otherwise stable. A missing
prerelease manifest (HTTP 404) also selects stable; network errors and malformed
manifests fail visibly. Versions are compared numerically, so `rc10` follows
`rc9`, and `1.1.1` supersedes `1.1.1rc4` even if the RC manifest still exists.
The selected version stays fixed until you rerun the helper; sessions and CLI
invocations do not silently upgrade. The command keeps its `hivemind-rc` name
when the selected version is stable.

To reproduce a specific release, run
`python3 scripts/install-candidate.py 1.1.1rc4` (`1.1.1-rc4` is accepted too).
To print the current selection without installing, use
`python3 scripts/install-candidate.py --resolve-only`.
After changing versions, refresh `rc_prefix` and `rc_version` using the commands
above and render the server configuration below again.

The installer verifies the binary checksum against the versioned manifest.
Record it with the checkout SHA (`git rev-parse HEAD`) and the selected
`manifests/hivemind-<version>.json`. Inspect cached images before starting;
`serve up` may need network access when images are missing.

Scoping `XDG_CONFIG_HOME` also isolates the install marker and Linux user-service
discovery; `--prefix` alone still writes the shared `hivemind/install-method`
marker. The installer and wrapper both scope it to the selected version's
config directory. Use `serve` for this test, without starting or replacing a developer's managed session-sync daemon.

Choose an unused instance name and host port. Named instances separate Compose
projects, volumes, and `~/.hivemind/serve/<name>` state; they still share host
ports. This configuration pins the **server** separately from the CLI and turns
off telemetry, with no model provider configured:

```bash
python3 - "$rc_prefix/selfhost.json" "$rc_version" <<'PY'
import json, sys
from pathlib import Path
config = {
    "version": 1,
    "network": {
        "domain": "localhost", "tls": "none",
        "http_port": 8080, "https_port": 0,
    },
    "extra_env": {
        "HIVEMIND_VERSION": sys.argv[2],
        "HIVEMIND_TELEMETRY": "false",
        "DO_NOT_TRACK": "1",
    },
}
Path(sys.argv[1]).write_text(json.dumps(config, indent=2) + "\n")
PY
hivemind-rc serve --name "$rc_name" setup --config "$rc_prefix/selfhost.json"
umask 077
hivemind-rc serve --name "$rc_name" up > "$rc_prefix/serve-up.private.log" 2>&1
hivemind-rc serve --name "$rc_name" status
```

The server version comes from the same selection as the CLI. Setup can be
rendered again with `--force --config "$rc_prefix/selfhost.json"`; it preserves
existing instance keys by default.
Startup output includes a one-time setup URL: keep the log private and exclude
setup tokens, cookies, and credentials from shared evidence.

## Verify the running artifact and lifecycle

```bash
app_id=$(docker ps -q --filter "label=com.docker.compose.project=$rc_name" \
  --filter label=com.docker.compose.service=app)
docker inspect "$app_id" --format '{{.Image}} {{json .Mounts}}'
docker image inspect "ghcr.io/wandb/hivemind-server:$rc_version" \
  --format '{{json .RepoDigests}}'
curl -fsS http://localhost:8080/health > "$rc_prefix/health.json"
python3 - "$rc_prefix/health.json" "$rc_version" <<'PY'
import json, sys
h = json.load(open(sys.argv[1]))
assert h['version'] == sys.argv[2], h
assert h['status'] == 'ok' and h['clickhouse'] == 'ok', h
assert h['cache']['type'] == 'redis', h
print('PASS', h)
PY
curl -fsS http://localhost:8080/ > "$rc_prefix/dashboard.html"
```

Record the image digest and build SHA from health, and check the worker uses
the same image. Inspect mounts before reusing containers: a source bind mount
can invalidate a published-image test. Confirm the dashboard actually renders
in a browser; an HTTP 200 alone can be the SPA fallback for an unknown route.
Check worker health and restart count after it has had time to run.

Run `hivemind-rc serve --name "$rc_name" down`, confirm the endpoint stops, then
run the redirected `up` command again and repeat the health and worker checks.
Data should persist. `down --volumes` removes this project's named volumes;
setup and bind-mounted data remain under its instance directory.

## Audit managed-agent exclusion

Here **Agents/Forager** means hosted managed-agent execution and its settings.
Supported ingestion and search of coding-agent sessions remain separate features.
For each candidate, record the expected policy and the actual results:

- Inspect `/v1/instance/config`, authenticated `/v1/forager/access`, dashboard
  navigation, personal settings, organization settings, and admin-mode Members.
  Use a disposable local account or a synthetic local database fixture, with no
  production account or service credentials. Document how authentication was
  established; a fixture does not validate GitHub login.
- Visit `/agents`, `/settings/agents`, `/org/agents`, and `/admin/agents`
  directly. Hidden navigation does not establish that a route is excluded.
  If the policy requires no managed-agent UI, a rendered disabled Agents page
  or a Forager preview toggle fails that policy.
- Test actual registered API routes with authenticated requests: sessions,
  environments, templates, models, sandbox-provider secrets, personal and org
  integrations, routines, and MCP. For a disabled feature, expect a deliberate
  denial and inspect the response body/content type. An anonymous 401 proves
  authentication only; HTML 200 may be a fallback, not a working API.
- In the isolated fixture, check whether an escalated admin can mutate
  `/v1/forager/admin/users/{user_id}/access`; restore the setting afterward.
  Record internal callback/broker denials separately from user API denials.
  Avoid sending notifications or invoking an external control plane.
- Inspect the image's actual `agentstream_api` package (locate it with
  `docker exec "$app_id" python -c 'import agentstream_api; print(agentstream_api.__file__)'`)
  for route registration, Forager access dependencies, and selfhost gates.
  Distinguish an explicit selfhost exclusion from missing Forager configuration.
  Bundled frontend strings alone prove neither runtime access nor exclusion.
- Check `hivemind-rc --help`, `hivemind-rc forager-mcp --help`, and `hivemind-rc notify --help`
  separately. Advertising a client bridge is different evidence from exposing
  managed-agent server settings.

Report each tested surface, role, status, and evidence. State any untested
routes, authentication limitations, and whether only the default configuration
was checked. Do not conclude “no Agent/Forager logic exposed” from hidden links
or an unconfigured backend. Preserve failures for release review rather than
patching private application code in this deployment repository.
