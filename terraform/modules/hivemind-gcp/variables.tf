variable "project_id" {
  description = "GCP project to deploy into"
  type        = string
}

variable "region" {
  description = "Region for the subnet, bucket and static IP"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "Zone for the VM"
  type        = string
  default     = "us-central1-a"
}

variable "name" {
  description = "Name prefix for every resource, and the VM's hostname"
  type        = string
  default     = "hivemind"
}

variable "hivemind_version" {
  description = <<-EOT
    wandb/hivemind release to install, as the PEP 440 canonical tag (v1.0.6, v1.0.6rc1).
    Also pinned as HIVEMIND_VERSION so the server image matches the CLI — leaving it
    unset would run `:latest`, which tracks the last stable release and can predate
    the CLI you installed.
  EOT
  type        = string
}

variable "hivemind_sha256" {
  description = <<-EOT
    Expected sha256 of the `hivemind-linux-x86_64` release binary. Empty verifies
    against the SHA256SUMS asset published with the release, which is enough to
    catch a corrupt or truncated download but is served from the same place as
    the binary. Pin the digest here — from a channel you trust independently —
    if your threat model includes the release itself being replaced.
  EOT
  type        = string
  default     = ""

  validation {
    condition     = var.hivemind_sha256 == "" || can(regex("^[0-9a-f]{64}$", var.hivemind_sha256))
    error_message = "hivemind_sha256 must be a 64-character lowercase hex sha256 digest, or empty."
  }
}

# --- Sizing -----------------------------------------------------------------

variable "machine_type" {
  description = "VM size. The stack runs ClickHouse, Redis, API, worker, dashboard and Caddy; 16 GB is the practical floor with the bundled ClickHouse."
  type        = string
  default     = "e2-standard-4"
}

variable "boot_disk_gb" {
  description = "Boot disk size in GB. Session data lives here unless an external ClickHouse is configured."
  type        = number
  default     = 200
}

variable "boot_disk_type" {
  description = "Boot disk type. pd-ssd is worth it for the bundled ClickHouse under load."
  type        = string
  default     = "pd-balanced"
}

variable "deletion_protection" {
  description = "Block accidental `terraform destroy` / console deletion of the VM."
  type        = bool
  default     = false
}

# --- Networking -------------------------------------------------------------

variable "network" {
  description = "Existing VPC self-link or name to attach to. Empty creates a dedicated VPC."
  type        = string
  default     = ""
}

variable "subnetwork" {
  description = "Existing subnetwork self-link or name. Required when `network` is set."
  type        = string
  default     = ""
}

variable "subnet_cidr" {
  description = "CIDR for the created subnet (ignored when using an existing network)."
  type        = string
  default     = "10.90.0.0/24"
}

variable "static_ip" {
  description = "Reserve a static external IP. Required in practice for a DNS record and for ClickHouse Cloud IP allowlisting, which an ephemeral IP breaks on every restart."
  type        = bool
  default     = false
}

variable "ssh_source_ranges" {
  description = "CIDRs allowed to reach TCP 22. Defaults to the IAP TCP-forwarding range, so SSH is never exposed to the internet."
  type        = list(string)
  default     = ["35.235.240.0/20"]
}

variable "web_source_ranges" {
  description = "CIDRs allowed to reach the VM directly on TCP 80/443. Empty exposes no web port (reach it over an IAP tunnel); use [\"0.0.0.0/0\"] for a public instance. Leave empty when `load_balancer` is set — the balancer gets its own rule, and this would let clients bypass it."
  type        = list(string)
  default     = []
}

# --- Load balancer ----------------------------------------------------------

variable "load_balancer" {
  description = <<-EOT
    Front the instance with a global external Application Load Balancer, terminating
    TLS on a Google-managed certificate for `domain`. Off by default: Caddy already
    gets a Let's Encrypt certificate on the VM for free. Turn it on for Cloud Armor,
    an anycast address that outlives the VM, or a certificate you don't renew yourself.
    Forces tls = "upstream" and adds roughly $18/month of forwarding-rule cost.
  EOT
  type        = bool
  default     = false
}

variable "lb_extra_domains" {
  description = "Additional hostnames on the Google-managed certificate. `domain` is always included. Every one of them must resolve to `load_balancer_ip` before the certificate can issue."
  type        = list(string)
  default     = []
}

variable "lb_ssl_certificates" {
  description = "Self-links of existing SSL certificates to serve instead of a Google-managed one. Use for a certificate from your own CA, or one you rotate outside Terraform."
  type        = list(string)
  default     = []
}

variable "lb_security_policy" {
  description = "Cloud Armor security policy self-link to attach to the backend. Empty leaves the balancer open to the internet — with a balancer in front, this is the only place client IPs can be filtered."
  type        = string
  default     = ""
}

variable "lb_timeout_sec" {
  description = "Backend response timeout. Must stay well above the longest SSE stream the dashboard holds open; the 30s GCP default cuts them off mid-session."
  type        = number
  default     = 3600
}

variable "lb_logging" {
  description = "Sample every request into Cloud Logging. Useful while bringing an instance up, and a real cost at steady state."
  type        = bool
  default     = false
}

# --- DNS --------------------------------------------------------------------

variable "dns_managed_zone" {
  description = "Name of an existing Cloud DNS managed zone in this project to publish `domain` into, pointed at the balancer (or the VM when there is none). Empty means you create the record yourself — do it before the first apply finishes, or certificate issuance stalls."
  type        = string
  default     = ""
}

variable "dns_ttl" {
  description = "TTL for the created A record."
  type        = number
  default     = 300
}

# --- Instance configuration (forwarded to hivemind-config) ------------------

variable "domain" {
  description = "Public hostname. 'localhost' keeps the instance reachable only through an SSH/IAP tunnel."
  type        = string
  default     = "localhost"
}

variable "tls" {
  description = "TLS mode: caddy | upstream | none. Null derives it from the domain."
  type        = string
  default     = null
}

variable "allowed_github_orgs" {
  description = "Comma-separated GitHub orgs whose members may sign in. \"*\" accepts any GitHub account. Empty is refused on a publicly reachable instance unless `github_host` is set, since it would let anyone register."
  type        = string
  default     = ""
}

variable "github_host" {
  description = "GitHub Enterprise hostname. Empty uses github.com."
  type        = string
  default     = ""
}

variable "license" {
  description = "HiveMind license token. Empty runs unlicensed."
  type        = string
  default     = ""
  sensitive   = true
}

variable "clickhouse" {
  description = "External/managed ClickHouse (e.g. ClickHouse Cloud). Null runs the bundled container."
  type = object({
    host     = string
    port     = optional(string)
    secure   = optional(bool, true)
    database = optional(string)
    username = optional(string)
  })
  default = null
}

variable "clickhouse_password" {
  description = "Password for the external ClickHouse."
  type        = string
  default     = ""
  sensitive   = true
}

# --- Object storage ---------------------------------------------------------

variable "bucket_name" {
  description = "Create a GCS bucket with this name and wire it up over the S3-interop endpoint. Empty keeps data on the instance disk."
  type        = string
  default     = ""
}

variable "bucket_location" {
  description = "Bucket location. Null uses `region`."
  type        = string
  default     = null
}

variable "bucket_force_destroy" {
  description = "Let `terraform destroy` delete a non-empty bucket. Leave false for anything holding real data."
  type        = bool
  default     = false
}

variable "bucket_versioning" {
  description = "Keep noncurrent object versions, so a bad delete is recoverable."
  type        = bool
  default     = true
}

variable "bucket_object_ttl_days" {
  description = "Delete objects older than this many days. Null keeps them forever."
  type        = number
  default     = null
}

variable "backup_retention_days" {
  description = "Nightly ClickHouse backups to the bucket, keeping this many days. Null disables them. Only applies with the bundled ClickHouse."
  type        = number
  default     = 3
}

# --- LLM --------------------------------------------------------------------

variable "llm" {
  description = <<-EOT
    LLM provider for AI features. Null leaves them unconfigured (a safe no-op).
    provider = "vertex" with no api_key/credentials is keyless: this module grants
    the VM's service account roles/aiplatform.user and the cloud-platform scope, and
    the backend picks it up from the metadata server. Leave `project` null to use
    this project.
  EOT
  type = object({
    provider      = string
    model         = optional(string)
    small_model   = optional(string)
    base_url      = optional(string)
    project       = optional(string)
    location      = optional(string)
    wandb_project = optional(string)
  })
  default = null
}

variable "llm_api_key" {
  description = "API key for the LLM provider. Empty for keyless setups (Vertex on GCP, local Ollama)."
  type        = string
  default     = ""
  sensitive   = true
}

variable "llm_credentials" {
  description = "Vertex service-account JSON, for running off GCP. Empty uses the VM's attached service account, which is the recommended path."
  type        = string
  default     = ""
  sensitive   = true
}

# --- Cursor -----------------------------------------------------------------

variable "cursor_api_key" {
  description = <<-EOT
    Cursor Admin API key (Cursor: Dashboard -> Settings -> Cursor Admin API),
    which enriches Cursor sessions with the usage and cost Cursor reports, so
    Cursor spend sits alongside every other agent's. Stored in Secret Manager
    like the other credentials. Empty leaves Cursor sessions unenriched.
  EOT
  type        = string
  default     = ""
  sensitive   = true
}

variable "cursor_api_org_ids" {
  description = "Comma-separated HiveMind org ids to attempt Cursor enrichment for. Empty attempts every Cursor session — right when the key's Cursor team is this instance. The key is team-scoped, so narrow this only when users span teams it cannot resolve."
  type        = string
  default     = ""
}

# --- Escape hatch -----------------------------------------------------------

variable "extra_env" {
  description = <<-EOT
    Environment passed to the app and worker verbatim, for settings this module
    has no input for. These ride in the VM's metadata (the rendered config
    document), which anyone holding roles/viewer on the project can read — put
    anything secret in `extra_env_secrets`. A name an existing input already
    configures is refused at setup rather than silently merged.
  EOT
  type        = map(string)
  default     = {}
}

variable "extra_env_secrets" {
  description = "Same as `extra_env`, for values that must not sit in instance metadata. Each becomes its own Secret Manager secret, read at boot like the license and API keys."
  type        = map(string)
  default     = {}
  sensitive   = true
}

variable "labels" {
  description = "Labels applied to the VM and bucket"
  type        = map(string)
  default     = {}
}
