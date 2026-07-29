terraform {
  required_version = ">= 1.3" # optional() object attributes
}

# Renders the `hivemind serve setup --config` document. Deliberately has no
# provider and creates nothing: it is the single place that knows the config
# schema, so a GCP module, an AWS module, or a hand-rolled Ansible role all
# emit the same thing. Derivation of the *env* file (S3 endpoint addressing,
# rclone provider quirks, URL assembly) stays in the CLI — this module only
# states intent.

locals {
  is_local = var.domain == "localhost"
  tls      = coalesce(var.tls, local.is_local ? "none" : "caddy")

  http_port  = coalesce(var.http_port, local.is_local ? "4483" : "80")
  https_port = coalesce(var.https_port, local.tls == "caddy" ? "443" : "0")

  # Which secrets exist is decided from the *structure*, not from the secret
  # values, so `secret_env_names` stays non-sensitive and can drive for_each.
  # A configured storage block always carries a key; ClickHouse/LLM/license
  # are opt-in.
  # nonsensitive() unwraps the *presence* check only. Whether a password was
  # supplied is not itself a secret, but Terraform marks any value derived from
  # a sensitive variable, and a marked value cannot drive count/for_each.
  wants_clickhouse_password = var.clickhouse != null && nonsensitive(var.clickhouse_password != "")
  wants_storage_secret      = var.storage != null
  wants_llm_api_key         = var.llm != null && nonsensitive(var.llm_api_key != "")
  wants_llm_credentials     = var.llm != null && nonsensitive(var.llm_credentials != "")
  wants_license             = nonsensitive(var.license != "")
  wants_cursor_api_key      = nonsensitive(var.cursor_api_key != "")

  # One env var per entry, named after it so the instance's Secret Manager
  # entries stay recognizable. Only the *keys* are unwrapped — the values keep
  # their sensitive marks all the way into secret_env.
  extra_secret_names = nonsensitive(keys(var.extra_env_secrets))
  extra_secret_env   = { for name in local.extra_secret_names : "HM_CFG_EXTRA_${name}" => var.extra_env_secrets[name] }

  secret_env = merge(
    local.wants_clickhouse_password ? { HM_CFG_CLICKHOUSE_PASSWORD = var.clickhouse_password } : {},
    local.wants_storage_secret ? { HM_CFG_STORAGE_SECRET_ACCESS_KEY = var.storage_secret_access_key } : {},
    local.wants_llm_api_key ? { HM_CFG_LLM_API_KEY = var.llm_api_key } : {},
    local.wants_llm_credentials ? { HM_CFG_LLM_CREDENTIALS = var.llm_credentials } : {},
    local.wants_license ? { HM_CFG_LICENSE = var.license } : {},
    local.wants_cursor_api_key ? { HM_CFG_CURSOR_API_KEY = var.cursor_api_key } : {},
    local.extra_secret_env,
  )

  secret_env_names = concat(
    compact([
      local.wants_clickhouse_password ? "HM_CFG_CLICKHOUSE_PASSWORD" : "",
      local.wants_storage_secret ? "HM_CFG_STORAGE_SECRET_ACCESS_KEY" : "",
      local.wants_llm_api_key ? "HM_CFG_LLM_API_KEY" : "",
      local.wants_llm_credentials ? "HM_CFG_LLM_CREDENTIALS" : "",
      local.wants_license ? "HM_CFG_LICENSE" : "",
      local.wants_cursor_api_key ? "HM_CFG_CURSOR_API_KEY" : "",
    ]),
    [for name in local.extra_secret_names : "HM_CFG_EXTRA_${name}"],
  )

  # Null attributes are dropped rather than emitted as JSON null: setup
  # validates section shapes strictly, and an absent key is what "use the
  # default" means.
  network = { for k, v in {
    domain     = var.domain
    tls        = local.tls
    http_port  = local.http_port
    https_port = local.https_port
  } : k => v if v != null }

  github = { for k, v in {
    host      = var.github_host
    ca_bundle = var.github_ca_bundle
  } : k => v if v != null && v != "" }

  clickhouse = var.clickhouse == null ? null : { for k, v in {
    host     = var.clickhouse.host
    port     = var.clickhouse.port
    secure   = var.clickhouse.secure
    database = var.clickhouse.database
    username = var.clickhouse.username
    password = local.wants_clickhouse_password ? { env = "HM_CFG_CLICKHOUSE_PASSWORD" } : null
  } : k => v if v != null }

  storage = var.storage == null ? null : { for k, v in {
    provider          = var.storage.provider
    bucket            = var.storage.bucket
    region            = var.storage.region
    account_id        = var.storage.account_id
    endpoint          = var.storage.endpoint
    access_key_id     = var.storage.access_key_id
    secret_access_key = { env = "HM_CFG_STORAGE_SECRET_ACCESS_KEY" }
    # Presence of `backup` opts in; a null retention leaves it off entirely.
    backup = var.storage.backup_retention_days == null ? null : {
      retention_days = var.storage.backup_retention_days
    }
  } : k => v if v != null }

  llm = var.llm == null ? null : { for k, v in {
    provider      = var.llm.provider
    model         = var.llm.model
    small_model   = var.llm.small_model
    base_url      = var.llm.base_url
    project       = var.llm.project
    location      = var.llm.location
    wandb_project = var.llm.wandb_project
    api_key       = local.wants_llm_api_key ? { env = "HM_CFG_LLM_API_KEY" } : null
    credentials   = local.wants_llm_credentials ? { env = "HM_CFG_LLM_CREDENTIALS" } : null
  } : k => v if v != null }

  cursor = { for k, v in {
    api_key     = local.wants_cursor_api_key ? { env = "HM_CFG_CURSOR_API_KEY" } : null
    api_org_ids = var.cursor_api_org_ids == "" ? null : var.cursor_api_org_ids
  } : k => v if v != null }

  # Plain values inline; secret ones as references the instance resolves at
  # boot. A name in both maps takes the secret, so a value never lands in the
  # rendered document by accident.
  extra_env = merge(
    var.extra_env,
    { for name in local.extra_secret_names : name => { env = "HM_CFG_EXTRA_${name}" } },
  )

  config = merge(
    {
      version = 1
      network = local.network
    },
    length(local.github) == 0 ? {} : { github = local.github },
    var.allowed_github_orgs == "" ? {} : {
      access = { allowed_github_orgs = var.allowed_github_orgs }
    },
    local.clickhouse == null ? {} : { clickhouse = local.clickhouse },
    local.storage == null ? {} : { storage = local.storage },
    local.llm == null ? {} : { llm = local.llm },
    length(local.cursor) == 0 ? {} : { cursor = local.cursor },
    local.wants_license ? { license = { env = "HM_CFG_LICENSE" } } : {},
    length(local.extra_env) == 0 ? {} : { extra_env = local.extra_env },
  )
}
