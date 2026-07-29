# Secret values are separate, explicitly-sensitive scalars rather than fields
# inside the structural objects. Terraform propagates sensitivity to anything
# derived from a sensitive value, and a sensitive value can't drive count /
# for_each — so mixing "which provider is this" with "what is the password"
# makes the shape of the deployment unusable for resource decisions.

variable "domain" {
  description = "Public hostname the instance is reachable at. 'localhost' keeps it host-only."
  type        = string
  default     = "localhost"
}

variable "tls" {
  description = "TLS mode: caddy (Let's Encrypt), upstream (a proxy/LB terminates TLS), or none. Null derives it from the domain."
  type        = string
  default     = null

  validation {
    condition     = var.tls == null || contains(["caddy", "upstream", "none"], coalesce(var.tls, "caddy"))
    error_message = "tls must be one of: caddy, upstream, none."
  }
}

variable "http_port" {
  description = "Host port bound for HTTP. Null picks 80 (or 4483 for localhost)."
  type        = string
  default     = null
}

variable "https_port" {
  description = "Host port bound for HTTPS. Null picks 443 when Caddy terminates TLS, else 0 (ephemeral)."
  type        = string
  default     = null
}

variable "allowed_github_orgs" {
  description = "Comma-separated GitHub orgs allowed to sign in. Empty leaves login open to any GitHub user."
  type        = string
  default     = ""
}

variable "github_host" {
  description = "GitHub Enterprise hostname. Empty uses github.com."
  type        = string
  default     = ""
}

variable "github_ca_bundle" {
  description = "Path (on the instance) to a PEM CA bundle for a GHES appliance behind a private CA."
  type        = string
  default     = ""
}

# --- ClickHouse -------------------------------------------------------------

variable "clickhouse" {
  description = "External/managed ClickHouse. Null runs the bundled container instead."
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
  description = "Password for the external ClickHouse. Empty when it needs none."
  type        = string
  default     = ""
  sensitive   = true
}

# --- Object storage ---------------------------------------------------------

variable "storage" {
  description = "Object storage for screenshots/exports. Null keeps data on the instance's disk."
  type = object({
    provider              = string # aws | r2 | gcs | custom
    bucket                = string
    region                = optional(string)
    account_id            = optional(string) # r2
    endpoint              = optional(string) # custom
    access_key_id         = string
    backup_retention_days = optional(number) # null disables nightly ClickHouse backups
  })
  default = null

  validation {
    condition = var.storage == null || contains(
      ["aws", "r2", "gcs", "custom"], coalesce(try(var.storage.provider, null), "aws")
    )
    error_message = "storage.provider must be one of: aws, r2, gcs, custom."
  }
}

variable "storage_secret_access_key" {
  description = "Secret access key (or GCS HMAC secret) for the object store."
  type        = string
  default     = ""
  sensitive   = true
}

# --- LLM --------------------------------------------------------------------

variable "llm" {
  description = "LLM provider powering AI features. Null leaves them unconfigured (a safe no-op)."
  type = object({
    provider      = string # wandb | anthropic | openai | vertex | custom
    model         = optional(string)
    small_model   = optional(string)
    base_url      = optional(string) # custom
    project       = optional(string) # vertex
    location      = optional(string) # vertex
    wandb_project = optional(string)
  })
  default = null

  validation {
    condition = var.llm == null || contains(
      ["wandb", "anthropic", "openai", "vertex", "custom"],
      coalesce(try(var.llm.provider, null), "vertex")
    )
    error_message = "llm.provider must be one of: wandb, anthropic, openai, vertex, custom."
  }
}

variable "llm_api_key" {
  description = "API key for the LLM provider. Empty for keyless setups (Vertex on GCP, local Ollama)."
  type        = string
  default     = ""
  sensitive   = true
}

variable "llm_credentials" {
  description = "Google service-account JSON for Vertex when running off GCP. Empty uses the metadata server."
  type        = string
  default     = ""
  sensitive   = true
}

variable "license" {
  description = "HiveMind license token. Empty runs unlicensed (works, with a banner)."
  type        = string
  default     = ""
  sensitive   = true
}

variable "cursor_api_key" {
  description = "Cursor Admin API key, which enriches Cursor sessions with the usage and cost Cursor reports. Empty leaves Cursor sessions unenriched."
  type        = string
  default     = ""
  sensitive   = true
}

variable "cursor_api_org_ids" {
  description = "Comma-separated HiveMind org ids to attempt Cursor enrichment for. Empty attempts every Cursor session, which is right when the key's Cursor team is the instance; narrow it only when users span teams the key cannot resolve."
  type        = string
  default     = ""
}

variable "extra_env" {
  description = <<-EOT
    Environment passed to the app and worker verbatim, for settings this module
    has no input for. Values are visible in the rendered config document (and so
    in instance metadata on GCP) — put anything secret in `extra_env_secrets`.
    A name a configured section already produces is refused by setup rather than
    merged, since both would render into the same .env line.
  EOT
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for name in keys(var.extra_env) : can(regex("^[A-Z][A-Z0-9_]*$", name))])
    error_message = "extra_env keys must be environment variable names: A-Z, 0-9 and _, starting with a letter."
  }
}

variable "extra_env_secrets" {
  description = "Same as `extra_env`, for values that must not appear in the rendered config. Each becomes a secret reference the instance resolves at boot; the caller stores the value (Secret Manager, Vault)."
  type        = map(string)
  default     = {}
  sensitive   = true

  # nonsensitive() unwraps the check, not the values: a name is not a secret,
  # and a condition derived from a sensitive variable can't be evaluated.
  validation {
    condition     = nonsensitive(alltrue([for name in keys(var.extra_env_secrets) : can(regex("^[A-Z][A-Z0-9_]*$", name))]))
    error_message = "extra_env_secrets keys must be environment variable names: A-Z, 0-9 and _, starting with a letter."
  }
}
