# Testing a self-hosted release candidate

Use a disposable Linux Docker host with Docker Compose available. Test the
published CLI and server together: this public repository contains deployment
artifacts, while the server package and dashboard are in the published image.
Keep test data and credentials separate from a production instance.

## Pin the CLI and server

From this checkout, install the candidate under its own prefix. Release tags
use `1.1.1rc4`, even when the candidate is described as `1.1.1-rc4`.

```bash
rc_version=1.1.1rc4
rc_name=rc4
rc_prefix="$HOME/.local/share/hivemind-releases/$rc_version"
mkdir -p "$rc_prefix/config"
chmod 700 "$rc_prefix" "$rc_prefix/config"
XDG_CONFIG_HOME="$rc_prefix/config" sh install.sh \
  --binary --version "$rc_version" --prefix "$rc_prefix"

hmrc() {
  XDG_CONFIG_HOME="$rc_prefix/config" "$rc_prefix/bin/hivemind" "$@"
}
hmrc --version
sha256sum "$rc_prefix/bin/hivemind"
docker version
docker compose version
docker image ls --digests
```

The installer verifies the binary checksum against the versioned manifest.
Record it with the checkout SHA (`git rev-parse HEAD`) and compare it with
`manifests/hivemind-1.1.1rc4.json` for this example. Use `--dry-run` on the
installer to check resolution without installing. Inspect cached images before
starting; `serve up` may need network access when images are missing.

Scoping `XDG_CONFIG_HOME` also isolates the install marker and Linux user-service
discovery; `--prefix` alone still writes the shared `hivemind/install-method`
marker. Invoke the candidate by path or the function above. Use `serve` for this
test, without starting or replacing a developer's managed session-sync daemon.

Choose an unused instance name and host port. Named instances separate Compose
projects, volumes, and `~/.hivemind/serve/<name>` state; they still share host
ports. This configuration pins the **server** separately from the CLI and turns
off telemetry, with no model provider configured:

```bash
cat > "$rc_prefix/selfhost.json" <<'JSON'
{
  "version": 1,
  "network": {
    "domain": "localhost", "tls": "none",
    "http_port": 8080, "https_port": 0
  },
  "extra_env": {
    "HIVEMIND_VERSION": "1.1.1rc4",
    "HIVEMIND_TELEMETRY": "false",
    "DO_NOT_TRACK": "1"
  }
}
JSON
hmrc serve --name "$rc_name" setup --config "$rc_prefix/selfhost.json"
umask 077
hmrc serve --name "$rc_name" up > "$rc_prefix/serve-up.private.log" 2>&1
hmrc serve --name "$rc_name" status
```

Change both version pins when testing another candidate. Setup can be rendered
again with `--force --config`; it preserves existing instance keys by default.
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

Run `hmrc serve --name "$rc_name" down`, confirm the endpoint stops, then run
the redirected `up` command again and repeat the health and worker checks.
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
- Check `hmrc --help`, `hmrc forager-mcp --help`, and `hmrc notify --help`
  separately. Advertising a client bridge is different evidence from exposing
  managed-agent server settings.

Report each tested surface, role, status, and evidence. State any untested
routes, authentication limitations, and whether only the default configuration
was checked. Do not conclude “no Agent/Forager logic exposed” from hidden links
or an unconfigured backend. Preserve failures for release review rather than
patching private application code in this deployment repository.
