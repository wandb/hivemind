# Hivemind Helm chart

Run the self-hosted Hivemind stack on Kubernetes. This is the
Kubernetes-native counterpart to [`selfhost/docker-compose.yml`](../../../selfhost/docker-compose.yml):
the **same `ghcr.io/wandb/hivemind-server` image** as the SaaS, differing only
in configuration (see [`docs/self-hosting.md`](../../../docs/self-hosting.md)
and [`docs/self-hosting-design.md`](../../../docs/self-hosting-design.md)).

```
                         ┌──────────────── Ingress (TLS) ───────────────┐
                         │                                              │
                         ▼                                              │
   ┌──────────────────────────┐         ┌──────────────────────────┐   │
   │ api  (Deployment, HPA)   │         │ worker (Deployment, KEDA) │   │
   │ FastAPI + dashboard :8080│         │ python -m ...worker       │   │
   └───────────┬──────────────┘         └───────────┬──────────────┘   │
               │   same image, different command     │                  │
       ┌───────┴───────────────┬─────────────────────┴───────┐          │
       ▼                       ▼                             ▼          │
 ┌───────────┐          ┌───────────┐                 ┌────────────┐    │
 │ ClickHouse│          │   Redis   │  Redis Streams  │ ClickStack │◀───┘
 │ StatefulSet│         │ StatefulSet│  (the queue)   │ (HyperDX)  │  (optional)
 └───────────┘          └───────────┘                 └────────────┘
```

## What you get

| Component | Kind | Notes |
|-----------|------|-------|
| `api` | Deployment + Service + HPA | FastAPI + the built dashboard, `/health`, autoscaled on CPU |
| `worker` | Deployment + KEDA ScaledObject | Same image, `python -m agentstream_api.worker`; autoscaled on **Redis-Streams queue lag** |
| `clickhouse` | StatefulSet + Service | Bundled single node (toggle to external/managed) |
| `redis` | StatefulSet + Service | Bundled, AOF-persistent — backs the job queue and live pub/sub |
| migration | Job | `python -m agentstream_api.migrations migrate`, run per revision |
| `clickstack` | Deployment + Service + Ingress | Optional HyperDX (OpenTelemetry + ClickHouse) observability |
| `otel-collector` | Deployment + Service + ConfigMap | Optional standalone OTLP→ClickHouse collector feeding ClickStack's traces |
| routing | Gateway API `HTTPRoute` *or* `Ingress` | Replaces Caddy; Gateway API recommended (see [Routing](#routing)) |

## Prerequisites

- Kubernetes 1.23+ and Helm 3.8+
- Ingress: a controller, plus cert-manager or a pre-created TLS Secret.
  **Gateway API (recommended):** the Gateway API CRDs, a controller that
  implements them (Envoy Gateway, Istio, Cilium, NGINX Gateway Fabric, the
  cloud gateways…), and a `Gateway` to attach to. See [Routing](#routing).
- A default StorageClass (or set `*.persistence.storageClass`)
- For queue-depth worker autoscaling: the [KEDA](https://keda.sh) operator
  (Redis ≥ 7 for consumer-group lag). Otherwise set `worker.autoscaling.mode: hpa`.

## Quick start

```bash
helm install hivemind deploy/helm/hivemind \
  --namespace hivemind --create-namespace \
  --set externalURL=https://hivemind.example.com \
  --set ingress.host=hivemind.example.com
```

Point the host's DNS at your ingress controller, then open
`https://hivemind.example.com/setup` to create the instance's GitHub App
(or run single-player). A `JWT_SECRET` is generated automatically and preserved
across upgrades (the chart reads back the existing Secret via `lookup`).

> **GitOps:** `lookup` only works during an in-cluster `helm install/upgrade`.
> If you render with `helm template | kubectl apply` (Argo CD, Flux), there is
> no cluster read-back, so a blank `secrets.jwtSecret` is regenerated on every
> sync and **invalidates all sessions**. Pin `secrets.jwtSecret` (or point
> `secrets.existingSecret` at a Secret you manage) for GitOps flows.

On first install the `api` pods stay **NotReady** until the migration Job
applies the schema — this is expected and self-heals (the pods carry
`AUTO_MIGRATE=false` and wait for ClickHouse). Watch it:

```bash
kubectl -n hivemind logs job -l app.kubernetes.io/component=migrate -f
```

## Routing

External access (which replaces Caddy from the Compose stack) is exposed via
**Gateway API** (recommended) or **Ingress** — enable exactly one. The Ingress
API is feature-frozen and the upstream Ingress-NGINX controller is retired as
of March 2026, so Gateway API is the path forward on new clusters.

**Gateway API** (`gateway.networking.k8s.io/v1 HTTPRoute`). The chart creates
an `HTTPRoute` that attaches to a `Gateway` you already run (the platform team
owns the Gateway and its TLS listener — that role split is the point of Gateway
API):

```yaml
ingress:
  enabled: false
gateway:
  enabled: true
  parentRefs:
    - name: external          # your Gateway
      namespace: infra        # its namespace
  hostnames: [hivemind.example.com]   # defaults to the externalURL host
```

**Ingress** (`networking.k8s.io/v1`, the default) — TLS via cert-manager or a
pre-created Secret:

```yaml
ingress:
  enabled: true
  className: nginx
  host: hivemind.example.com
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  tls:
    enabled: true
```

Enabling both is rejected at render time.

## Autoscaling

**API** scales on CPU via a standard HPA (`api.autoscaling`).

**Worker** defaults to **KEDA** (`worker.autoscaling.mode: keda`), scaling on the
consumer-group **lag** of the latency-sensitive Redis streams
(`queue:jobs:normal` and `queue:jobs:long`, group `workers`). One trigger per
stream; KEDA scales to satisfy the most-backed-up one. Tune per-replica targets
in `worker.autoscaling.keda.triggers[*].lagCount`.

- Keep `worker.autoscaling.minReplicas >= 1`: periodic **leader-loop sweeps**
  (the queue's durability backstop) run on exactly one elected worker.
- No KEDA? Set `worker.autoscaling.mode: hpa` (CPU) or `none` (fixed).

Workers are safe to run at any replica count — the Redis consumer group
distributes jobs and `XAUTOCLAIM` reclaims work from crashed pods.

## External / managed datastores

Disable a bundled datastore and point at a managed one:

```yaml
clickhouse:
  enabled: false
externalClickHouse:
  host: xxx.clickhouse.cloud
  httpPort: 8443            # 8443/443 auto-negotiates TLS (set `secure: true` to force it on another port)
  database: agentstream
  user: default
  existingSecret: clickhouse-credentials   # key: CLICKHOUSE_PASSWORD

redis:
  enabled: false
externalRedis:
  host: my-redis.example.com
  port: 6379
  existingSecret: redis-credentials         # key: REDIS_PASSWORD
```

## Storage

Session screenshots and data exports go to a `StorageProvider`:

| `storage.provider` | Use |
|--------------------|-----|
| `local` (default) | A PVC at `storage.local.mountPath`. **Must be `ReadWriteMany`** when the api runs more than one replica (exports are streamed back through the API). |
| `s3` | Any S3-compatible store (AWS, MinIO, R2). Recommended for HA — no shared volume needed. Set `storage.s3.endpointURL` for non-AWS. |
| `gcs` | Google Cloud Storage; mount a SA key via `storage.gcs.existingSecret`. |

## AI features — LLM provider & embeddings

Insights, PR walkthroughs, personas, session enrichment and fork-context all
reach an LLM through a provider abstraction. It's **bring-your-own-provider** and
every feature quietly no-ops until one is configured. Non-secret settings live
under `config.llm` / `config.embeddings`; API keys under `secrets.llm`. Full
matrix (Ollama, vLLM, W&B/CoreWeave, Bedrock): [`docs/llm-providers.md`](../../../docs/llm-providers.md).

**Anthropic (default)** — just a key:

```yaml
secrets:
  llm:
    anthropicApiKey: sk-ant-...
```

**Any OpenAI-compatible endpoint** (Ollama, vLLM, W&B/CoreWeave). The `openai`
provider is auto-selected once `config.llm.baseURL` is set:

```yaml
config:
  llm:
    baseURL: https://api.inference.wandb.ai/v1
    model: meta-llama/Llama-3.3-70B-Instruct
    # smallModel: <cheaper model for titles / weekly summaries>
    # extraHeaders: '{"OpenAI-Project": "my-team/my-project"}'
secrets:
  llm:
    apiKey: <your-endpoint-key>
```

**Amazon Bedrock** (Anthropic models via the AWS credential chain / IRSA):

```yaml
config:
  llm:
    provider: bedrock
    bedrockRegion: us-east-1
    model: us.anthropic.claude-sonnet-4-20250514-v1:0
```

**Embeddings** (insight clustering + semantic search) are OpenAI-compatible and
fall back to `secrets.llm.openaiApiKey`. A replacement model MUST emit
1536-dimensional vectors. Disable them with `config.embeddings.provider: none`.
Per-feature model overrides live under `config.llm.models.*` (each falls back to
`config.llm.model`).

## Licensing

Self-host instances run unlicensed (a "get a license" banner shows; nothing is
disabled). To license the instance, paste the signed blob from the Hivemind
admin console — it is verified offline (Ed25519), so it works airgapped:

```yaml
secrets:
  license: <signed-license-blob>       # or provide it via secrets.existingSecret as HIVEMIND_LICENSE
```

The enforcement level is carried by the license itself, not a chart setting. A
daily anonymized check-in (install id, version, license state — never session
data) is on by default; opt out with `config.telemetry: false`, or repoint it
for a private endpoint with `config.license.telemetryEndpoint`.

If you rely on the first-boot `/setup` wizard (instead of supplying
`secrets.githubApp.*` directly), set `secrets.hivemindSecretKey` — the master key
that encrypts the wizard-created GitHub App credentials at rest in ClickHouse.
**Back it up:** losing it makes those secrets unrecoverable.

## Observability — tracing

The api/worker emit OpenTelemetry **traces** (no Prometheus endpoint). Turn them
on with `observability.tracing.enabled=true` and point them somewhere. There are
two shapes, and **the right production choice is usually "bring your own"**:

| | `observability.clickstack` (bundled all-in-one) | `observability.tracing.otlpEndpoint` (bring your own) |
|---|---|---|
| What it is | HyperDX's `all-in-one` image (Collector + ClickHouse + Mongo + UI in one pod) | Your OTLP collector / vendor |
| Good for | Kicking the tires, demos, small single-node self-host | **Production / anything that needs to scale** |
| Caveats | Single pod, single PVC, not HA; the chart wires up several Kubernetes workarounds for an image built for `docker run` (see below) | You operate the backend; chart just exports OTLP |

### Production: bring your own ClickStack / collector (recommended at scale)

Leave `clickstack.enabled=false` and export OTLP to an endpoint you operate.
None of the bundled-path machinery (collector, dashboards sidecar, init
container, host aliases) is rendered — the chart only sets the api/worker OTLP
env. Works with any of:

- **ClickHouse Cloud's managed ClickStack / HyperDX** — create a ClickStack
  service, copy its OTLP ingest endpoint + API key.
- **A self-hosted scalable HyperDX** — the official component Helm charts
  (separate Collector / ClickHouse / app, horizontally scalable), or your
  existing ClickHouse.
- **Any OTLP backend** — Grafana Tempo, Honeycomb, Datadog, Jaeger, etc.

```yaml
observability:
  tracing:
    enabled: true
    sampleRate: "0.3"
    otlpEndpoint: https://otlp.us.clickstack.example:4317   # your collector / managed ingest
    otlpHeaders: "authorization=<your-ingestion-key>"        # if the backend wants auth
  clickstack:
    enabled: false
```

Dashboards/alerts then live in *your* HyperDX/Grafana, not this chart — the
`dashboards/*.json` here are HyperDX-format and can be imported there as a
starting point.

### Bundled ClickStack all-in-one (quickstart / small self-host)

`observability.clickstack.enabled=true` deploys HyperDX's all-in-one and ships
api/worker traces to it for search, dashboards, and alerting:

```yaml
observability:
  tracing:
    enabled: true
    sampleRate: "0.3"
  clickstack:
    enabled: true
    ingress:
      enabled: true
      host: hyperdx.example.com
```

It is self-contained (does not touch the application ClickHouse). Because the
all-in-one is built for `docker run`, not Kubernetes, the chart adds a few
workarounds to make it behave under k8s — all gated on this path: a standalone
collector (the bundled OpAMP one won't wire OTLP), `hostAliases` for
`ch-server`/`db`, an init container that clears stale CH/Mongo lock files on
restart, and a dashboards sidecar (below). They are contained and tested, but
they're the reason this path is "small self-host," not "scale" — for the latter,
use *bring your own* above.

The HyperDX UI's post-login / auth redirects are anchored on `FRONTEND_URL`,
derived automatically from the `clickstack.gateway` hostname (HTTPS) or
`clickstack.ingress` host — override with `observability.clickstack.frontendURL`.
Without it the all-in-one falls back to `http://localhost:8080` and bounces you
off the real host after login.

**Standalone collector.** The all-in-one's bundled collector is OpAMP-managed
and only wires its OTLP receivers into a pipeline after manual HyperDX UI
onboarding — so out of the box nothing listens on 4317/4318. To make traces flow
on first install, `observability.collector.enabled=true` (the default when
ClickStack is on) deploys a small standalone `otel/opentelemetry-collector-contrib`
with a static `otlp → clickhouse` pipeline that writes the standard `otel_traces`
schema into ClickStack's own ClickHouse — exactly the table the autoProvisioned
HyperDX "Traces" source reads. The api/worker OTLP endpoint is auto-routed to it.
It authenticates over native TCP (9000) as the image's network-reachable `api`
user (`observability.collector.clickhouse.*`), because the bundled `default` user
is pinned to localhost. Setting `observability.tracing.otlpEndpoint` (external
collector) disables it. Viewing the traces still requires creating a HyperDX
account once via its **Setup Account** page.

### Dashboards & alerts

With `observability.clickstack.dashboards.enabled=true` (the default) the chart
ships three starter dashboards — **API health** (request rate, 5xx, p50/p95
latency, slowest endpoints, ClickHouse dependency latency) and **Worker health**
(jobs processed, errors, job duration, slowest operations, ClickHouse query
latency), both built on the api/worker traces and mirroring the signals in the
GCP `monitoring` Terraform module; plus **Redis health** (memory used/rss/peak,
connected/blocked clients, ops/sec, keyspace hit/miss rate, network I/O,
keys total/expired/evicted, fragmentation ratio), built on Redis metrics. The
JSON lives in the chart's `dashboards/` dir — drop another `*.json` there and the
sidecar picks it up automatically (reference the `Traces`/`Logs`/`Metrics`
sources via the `__TRACES_SOURCE_ID__`/`__LOGS_SOURCE_ID__`/`__METRICS_SOURCE_ID__`
placeholders).

Unlike the trace dashboards, **Redis health needs a metrics source.** Redis
emits no telemetry on its own, so the standalone OTel collector runs a `redis`
receiver (`observability.collector.redisMetrics.enabled=true`, the default) that
scrapes Redis INFO stats into ClickStack's `otel_metrics_*` tables — the same
tables HyperDX's `Metrics` source reads. It lives in *that* collector (not the
`kubernetesMetrics` one, which is off by default and absent in production) so it
runs whenever the bundled ClickStack does, independent of k8s infra telemetry.
It is a no-op unless a Redis is configured (`redis.enabled` or
`externalRedis.host`), and authenticates with the Redis password when one is set.

HyperDX's provisioner reads static JSON but does not remap the per-install
Source ObjectIds the tiles reference, and the all-in-one only runs its
`check-alerts` task on its own cron. So a small **sidecar** in the ClickStack pod
resolves the Traces/Logs/Metrics source ids by name, substitutes them into the
templates, and runs HyperDX's `provision-dashboards` task on a loop
(`dashboards.intervalSeconds`). It is idempotent and self-heals: the dashboards
appear (tagged `provisioned`) on the next cycle **after** you finish HyperDX
account setup — which is when the team they attach to first exists.

> **Alerts are a manual step.** HyperDX alerts are not file-provisionable — they
> live in Mongo keyed to a team and saved-search/tile. Add them in the UI off the
> provisioned dashboard tiles (tile → ⋯ → *Create alert*) or a saved search;
> good first ones, matching the GCP module: **API 5xx** (the *5xx responses* tile
> > 0) and **API p95 latency** (the latency tile over your SLO). The all-in-one
> already runs HyperDX's `check-alerts` task, so alerts fire once created.

### Monitoring the application ClickHouse

HyperDX ships a built-in **ClickHouse** preset dashboard (left nav → *ClickHouse*:
query latency heatmap, slowest queries, inserts/merges, parts, CPU/memory). It
reads `system.query_log`, `system.metric_log`, and `system.asynchronous_metric_log`
**directly over a connection** — it is *not* fed by OTel metrics — and has a
connection picker at the top. Out of the box that only lists "Local ClickHouse"
(the bundled telemetry store), so the dashboard would profile HyperDX's own
ClickHouse rather than the application's.

With `observability.clickstack.appClickHouseConnection.enabled=true` (the default)
the provisioner sidecar registers the chart's ClickHouse (the same instance the
api/worker use — `clickhouse.*` or `externalClickHouse.*`) as a second HyperDX
connection named `Application ClickHouse`. Pick it in the ClickHouse dashboard's
connection selector to monitor the app database. No extra collector, no ClickHouse
Prometheus endpoint, no `otel_metrics` — just a connection, which is why it also
works on an already-provisioned install (`DEFAULT_CONNECTIONS` only seeds on a
clean, empty-Mongo first boot, but the sidecar upserts on every loop). The upsert
is insert-only: it never overwrites a connection of that name, so edits you make
in the UI stick.

## Migrations & upgrades

Migrations run as a per-revision `Job` (not a Helm hook — hooks would deadlock
on first install before the bundled ClickHouse/ConfigMap/Secret exist). On
upgrade:

```bash
helm upgrade hivemind deploy/helm/hivemind -f my-values.yaml
```

a fresh migration Job runs and the workloads roll once config/secret checksums
change. Pin `image.tag` to a released `hivemind-server` version for
reproducible upgrades.

## Local testing

A one-command, laptop-sized dev stack (single replica, no KEDA) fronted by a
real Envoy Gateway, ClickStack on with traces wired out of the box. Driven from
the repo root via [`hivemindctl`](../../../hivemindctl), sharing the same chart +
smoke test (reachability + a full ingest→normalize→events round-trip) as a real
deployment, on **OrbStack** (simplest on macOS).

### OrbStack (recommended on macOS)

Uses OrbStack's built-in Kubernetes, which exposes the gateway at
`*.k8s.orb.local` with automatic, trusted HTTPS — no host ports, no mkcert, no
`/etc/hosts`. Enable Kubernetes in **OrbStack → Settings → Kubernetes**, then:

```bash
hivemindctl orb up         # Envoy Gateway + helm install on the orbstack context
hivemindctl orb smoke      # assert it works (reachability + ingest round-trip)
hivemindctl orb status
hivemindctl orb logs worker -f
hivemindctl orb down       # uninstall release + namespace (keeps the cluster)
```

Reach it at **`https://hivemind.k8s.orb.local`** (dashboard) and
**`https://clickstack.k8s.orb.local`** (HyperDX); plain HTTP on those hosts also
serves with no redirect. Uses [`values-orbstack.yaml`](./values-orbstack.yaml)
and the gateway manifests in [`../../orb/gateway/`](../../orb/gateway/).

> **Tracing out of the box:** the dev overlay ships a standalone OTel collector
> (`observability.collector.enabled`) with a static `otlp → clickhouse` pipeline
> that writes spans straight into ClickStack's ClickHouse `otel_traces` table, so
> api/worker traces flow on first boot with no HyperDX UI onboarding — the bundled
> OpAMP-managed collector never wires OTLP on its own. Confirm spans landed with
> `hivemindctl orb smoke` then query the count:
> `kubectl -n hivemind exec deploy/hivemind-clickstack -- clickhouse-client --query
> "SELECT ServiceName, count() FROM default.otel_traces GROUP BY ServiceName"`.
> To browse them in the HyperDX UI, complete its one-time **Setup Account** page.

## Production profile

See [`values-production.yaml`](./values-production.yaml) for an HA example
(KEDA, cert-manager TLS, S3 storage, sized datastores, ClickStack).

> **ClickHouse open-files limit.** ClickHouse wants a high `nofile` ulimit
> (its docs recommend 262144) and raises its own soft limit to the hard limit
> on startup. The chart can't set this: Kubernetes has no pod-spec ulimit
> ([#18108](https://github.com/kubernetes/kubernetes/issues/18108)), and the
> pod drops all capabilities + runs as non-root, so it can't raise the hard
> limit itself. The hard limit comes from the node's container runtime
> (containerd `LimitNOFILE`, commonly 1048576 — already ample). If
> `system.metrics`/server logs show ClickHouse capped below 262144 under load,
> raise `LimitNOFILE` in containerd on the worker nodes — it is a node-level
> setting, not a chart value.

## Key values

| Key | Default | Description |
|-----|---------|-------------|
| `externalURL` | `http://localhost` | Public base URL (EXTERNAL_URL + DASHBOARD_URL) |
| `image.tag` | chart `appVersion` | `ghcr.io/wandb/hivemind-server` tag |
| `config.allowedGithubOrgs` | `none` | Restrict login to GitHub orgs |
| `secrets.jwtSecret` | _(auto)_ | Session signing secret; generated + preserved if blank |
| `config.llm.*` / `secrets.llm.*` | _(unset)_ | LLM provider (anthropic \| openai \| bedrock) for AI features |
| `config.embeddings.provider` | _(auto)_ | `none` to disable insight clustering / semantic search |
| `secrets.license` | _(unset)_ | Signed self-host license (HIVEMIND_LICENSE); unlicensed = warn banner |
| `secrets.hivemindSecretKey` | _(unset)_ | Master key for `/setup`-wizard GitHub App creds (back it up) |
| `config.telemetry` | `true` | Daily anonymized license check-in; `false` to opt out |
| `externalClickHouse.secure` | `false` | Force CLICKHOUSE_SECURE (auto on 8443/443) |
| `api.autoscaling.*` | 2–10, 70% CPU | API HPA |
| `worker.autoscaling.mode` | `keda` | `keda` \| `hpa` \| `none` |
| `worker.autoscaling.keda.triggers` | normal/long | Redis-Streams lag triggers |
| `clickhouse.enabled` / `redis.enabled` | `true` | Bundle datastores or use external |
| `storage.provider` | `local` | `local` \| `s3` \| `gcs` |
| `observability.clickstack.enabled` | `false` | Deploy HyperDX |
| `observability.collector.enabled` | `true` | Standalone OTel collector → ClickStack `otel_traces` (out-of-the-box tracing) |
| `observability.clickstack.dashboards.enabled` | `true` | Auto-provision starter HyperDX dashboards (API + Worker health) |
| `observability.clickstack.appClickHouseConnection.enabled` | `true` | Register the app ClickHouse as a HyperDX connection for the built-in ClickHouse dashboard |
| `observability.clickstack.kubernetesMetrics.enabled` | `false` | Ship k8s infra telemetry → ClickStack for HyperDX's Kubernetes dashboards |
| `gateway.enabled` / `gateway.parentRefs` | `false` | Gateway API HTTPRoute (recommended) |
| `ingress.enabled` / `ingress.host` | `true` / from URL | Ingress routing (legacy) |

Full reference: [`values.yaml`](./values.yaml).
