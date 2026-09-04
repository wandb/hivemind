# HiveMind self-host Terraform modules

Stand up a self-hosted HiveMind instance as infrastructure-as-code, with no
interactive setup step.

| Module | What it is |
|--------|------------|
| [`hivemind-config`](modules/hivemind-config) | Pure logic, no provider. Renders the `hivemind serve setup --config` document and the map of secrets it references. Reusable on any cloud, or none. |
| [`hivemind-gcp`](modules/hivemind-gcp) | A complete GCP deployment: VM, networking, GCS bucket over S3-interop, Secret Manager, and keyless Vertex AI. |

```hcl
module "hivemind" {
  # Always pin with ?ref=. Without it Terraform tracks the default branch, so
  # the module under your deployment changes whenever we push.
  source = "github.com/wandb/hivemind//terraform/modules/hivemind-gcp?ref=v1.0.8"

  project_id       = "acme-prod"
  hivemind_version = "v1.0.8"

  domain            = "hivemind.acme.com"
  static_ip         = true
  web_source_ranges = ["0.0.0.0/0"]

  bucket_name         = "acme-hivemind"
  allowed_github_orgs = "acme"

  llm = { provider = "vertex" } # keyless via the VM's service account
}
```

| Example | Topology |
|---------|----------|
| [`minimal`](examples/minimal) | One VM, bundled ClickHouse, no public port — reached over an IAP tunnel. |
| [`production`](examples/production) | Public domain, TLS from Caddy/Let's Encrypt on the VM, ClickHouse Cloud, GCS. |
| [`load-balancer`](examples/load-balancer) | The same, fronted by a Google load balancer with a managed certificate and Cloud Armor. |
| [`clickhouse-cloud`](examples/clickhouse-cloud) | `production`, but the ClickHouse Cloud service is provisioned in the same apply and allowlists the instance itself. |

Each example ships a `terraform.tfvars.example`. Copy it to `terraform.tfvars`
(auto-loaded) and fill it in; keep tokens and passwords in `TF_VAR_*` environment
variables rather than the file.

## Networking: bring your own VPC, or let the module make one

Leave `network` and `subnetwork` empty and the module creates a dedicated VPC, a
regional subnet (`subnet_cidr`, default `10.90.0.0/24`) with Private Google
Access on, and the firewall rules. Nothing is placed in your default network.

Set both to attach to an existing VPC instead — a name or a self-link:

```hcl
network    = "corp-shared"
subnetwork = "corp-shared-us-central1"
```

Both are required together; `subnetwork` alone has nothing to attach to, and
`network` alone leaves no subnet to infer, which the module refuses at plan time
rather than several minutes into an apply.

The module still creates its firewall rules in `project_id`, targeting the
instance's own network tag, so it does not widen anything else on the VPC. That
also means **Shared VPC is not supported yet**: there the firewall rules belong
in the host project, and this module has no `network_project` input. Attaching
to a Shared VPC subnet will fail on the firewall rules.

## Choosing how TLS is terminated

Caddy on the VM is the default and needs nothing from this module: it gets a
Let's Encrypt certificate itself as soon as `domain` resolves to the instance.

`load_balancer = true` moves termination to a global external Application Load
Balancer instead. Worth it for a Google-managed certificate you never renew, for
Cloud Armor, or for an anycast address that outlives the VM — at roughly
$18/month for the forwarding rules. It pins `tls = "upstream"`, so Caddy serves
plain HTTP on `:80` and the balancer owns the public `https://` URL.

Two consequences are easy to miss:

- **`web_source_ranges` stops being access control.** Requests reach the VM from
  Google's proxy range, never from the client's address, so the firewall can no
  longer distinguish them. Filter with `lb_security_policy` (Cloud Armor) and
  leave `web_source_ranges` empty — otherwise clients can hit the VM directly
  and bypass the policy entirely.
- **A Google-managed certificate needs DNS first.** It stays `PROVISIONING`
  until `domain` resolves to `load_balancer_ip`, so the apply finishes well
  before the site does — usually 15–30 minutes. Set `dns_managed_zone` and the
  module publishes the record itself, which is what lets a single apply
  converge.

## Requirements

**`hivemind_version` must be a release that supports `hivemind serve setup
--config`.** These modules configure the instance by rendering a JSON config
that the CLI turns into `.env` at boot. Older CLIs fail the startup script with
`Error: No such option: --config`, and the stack never starts. Check
`hivemind serve setup --help` if you are unsure.

## How configuration reaches the instance

1. `hivemind-config` renders a `config.json` describing *intent* — storage
   provider, LLM provider, ClickHouse target. It contains **no secret values**:
   every secret is an `{"env": "NAME"}` reference.
2. `config.json` goes into instance metadata (safe — it's secret-free). The
   secret *values* go to Secret Manager, and the VM's service account is granted
   `secretAccessor` on exactly those.
3. At boot the startup script fetches the secrets, exports them, and runs
   `hivemind serve setup --config`, which turns intent into `.env` and starts
   the stack.

Endpoint derivation (S3 addressing style, the rclone provider for the backup
sidecar, URL assembly) lives in the CLI, not in HCL — so there is exactly one
implementation of it, and Terraform never has to track its quirks.

### Settings with no input of their own

`extra_env` and `extra_env_secrets` pass environment straight through to the
app and worker, for anything these modules don't model:

```hcl
extra_env         = { WORKER_MAX_IN_FLIGHT = "8" }
extra_env_secrets = { SOME_TOKEN = var.some_token }   # -> Secret Manager
```

The split is about where the value ends up: `extra_env` values are part of the
rendered config document and therefore sit in instance metadata, which anyone
holding `roles/viewer` can read. `extra_env_secrets` gets one Secret Manager
secret per entry, read at boot like the license and API keys — use it for
anything you wouldn't paste in a ticket.

Setup **refuses** a name that something else already sets, rather than letting
two sources race for the same `.env` line. That covers a name an input of yours
configures (`LLM_API_KEY` when you set `llm_api_key`) and one the compose stack
pins deliberately (`USAGE_QUOTA_MODE`, `RETENTION_SWEEP_MODE`, `ENVIRONMENT`,
…). Both fail the apply's first boot with the name and its owner, so an
override never silently does nothing.

> **Never render secrets into a startup script.** Instance metadata is readable
> by anyone with `roles/viewer` on the project and by every process on the VM.
> That's why this module routes them through Secret Manager instead.

## Re-applying

Changing configuration updates instance metadata and the Secret Manager
versions; the instance picks them up on its next boot (`gcloud compute
instances reset`, or stop/start). The startup script re-runs
`setup --config --force` on every boot, and the CLI **preserves the instance's
`JWT_SECRET` and `HIVEMIND_SECRET_KEY` across re-runs** — rotating those would
invalidate every issued token and make the encrypted GitHub App credentials
unreadable. Use `--rotate-keys` only when you mean it.

## What Terraform can't do for you

- **The first admin.** Setup stays open until a `super_admin` exists; visit
  `<external_url>/setup?token=…` (get it with `hivemind serve setup --url`) and
  sign in once to claim the instance.
- **Creating a GitHub App**, unless you already have one — the manifest flow
  needs a browser. Existing App credentials can be set in `.env` directly.
- **Fetching a license.** The wizard can pull a 30-day trial because it runs as
  a logged-in operator; a provisioned VM has no such identity, and giving it one
  would mean putting a personal token on a server. Leave `license` unset and the
  instance runs unlicensed with a banner. To license it, get a token from
  <https://hivemind.wandb.tools/license> — or, if you're already logged in,
  `hivemind api -X POST /licenses/trial` (idempotent; it returns the same trial
  on every call) — and pass it as `license`, sourced from `TF_VAR_license` so it
  stays out of version control.
- **DNS**, unless the zone is in this project — then set `dns_managed_zone`.
  Otherwise point an A record at the `dns_target` output *before* first boot:
  neither Let's Encrypt nor a Google-managed certificate can validate a name
  that doesn't resolve yet.

## Notes

- **`static_ip = true` for anything real.** An ephemeral IP changes across a
  stop/start, which breaks both a DNS record and a ClickHouse Cloud IP
  allowlist. A load balancer covers the first of those — the balancer's address
  is stable — but not the second: outbound traffic still leaves from the
  instance's own IP.
- **Sizing.** The bundled ClickHouse makes 16 GB (`e2-standard-4`) the
  practical floor. Point `clickhouse` at a managed service to shed that.
- **The bundled ClickHouse is not backed up off-host** unless `bucket_name` is
  set; `backup_retention_days` then drives a nightly dump to the bucket. With
  an external ClickHouse the backups are that service's job, and this module
  leaves the sidecar off.
- **`cursor_api_key` enriches Cursor sessions** with the usage and cost Cursor
  reports, so Cursor spend lands next to every other agent's. The key is scoped
  to one Cursor team; leave `cursor_api_org_ids` empty unless the instance
  serves users outside the team it belongs to, since empty means "try every
  Cursor session".
- After the first apply, save the recovery kit (`hivemind serve recovery-kit`)
  — it is the only way to rebuild an instance's config on a new host.
