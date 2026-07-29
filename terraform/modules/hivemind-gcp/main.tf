terraform {
  required_version = ">= 1.3"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0"
    }
  }
}

locals {
  uses_vertex  = try(var.llm.provider, "") == "vertex"
  uses_bucket  = var.bucket_name != ""
  create_net   = var.network == ""
  subnet_ref   = local.create_net ? google_compute_subnetwork.this[0].id : var.subnetwork
  network_name = local.create_net ? google_compute_network.this[0].name : var.network

  # The balancer terminates TLS, so Caddy must not also try to: in `upstream`
  # mode it serves plain HTTP and stops requesting a Let's Encrypt certificate
  # it could never validate (nothing reaches the VM on :443).
  enable_lb     = var.load_balancer
  tls_effective = local.enable_lb ? "upstream" : var.tls

  # Reachable from the internet at large. A narrow `web_source_ranges` doesn't
  # count: the network already decides who gets to the login page. The balancer
  # does, because its own firewall rule admits Google's proxy range and the
  # client filter moves to Cloud Armor.
  publicly_reachable = (
    local.enable_lb
    || contains(var.web_source_ranges, "0.0.0.0/0")
    || contains(var.web_source_ranges, "::/0")
  )

  # Keyless only when no explicit credential was supplied — that's the case
  # where the backend falls back to the metadata server.
  vertex_keyless = local.uses_vertex && var.llm_credentials == ""

  # Vertex defaults to this project when unset, which is the common case: the
  # VM authenticates as its own service account in its own project.
  llm = var.llm == null ? null : merge(var.llm, {
    project = local.uses_vertex ? coalesce(var.llm.project, var.project_id) : var.llm.project
  })

  storage = local.uses_bucket ? {
    provider      = "gcs"
    bucket        = google_storage_bucket.this[0].name
    region        = null
    account_id    = null
    endpoint      = null
    access_key_id = google_storage_hmac_key.this[0].access_id
    # The nightly-backup sidecar only backs up the bundled container; a managed
    # ClickHouse owns its own backups.
    backup_retention_days = var.clickhouse == null ? var.backup_retention_days : null
  } : null
}

module "config" {
  source = "../hivemind-config"

  domain              = var.domain
  tls                 = local.tls_effective
  allowed_github_orgs = var.allowed_github_orgs
  github_host         = var.github_host
  license             = var.license

  clickhouse          = var.clickhouse
  clickhouse_password = var.clickhouse_password

  storage                   = local.storage
  storage_secret_access_key = local.uses_bucket ? google_storage_hmac_key.this[0].secret : ""

  llm             = local.llm
  llm_api_key     = var.llm_api_key
  llm_credentials = var.llm_credentials

  cursor_api_key     = var.cursor_api_key
  cursor_api_org_ids = var.cursor_api_org_ids

  extra_env         = var.extra_env
  extra_env_secrets = var.extra_env_secrets
}

resource "google_project_service" "services" {
  for_each = toset(concat(
    [
      "compute.googleapis.com",
      "iap.googleapis.com",
      "oslogin.googleapis.com",
      "secretmanager.googleapis.com",
      "storage.googleapis.com",
    ],
    local.uses_vertex ? ["aiplatform.googleapis.com"] : [],
  ))

  project = var.project_id
  service = each.value

  # Never disable an API on destroy: the project almost certainly hosts other
  # workloads that depend on it.
  disable_on_destroy = false
}

# --- Instance identity ------------------------------------------------------

resource "google_service_account" "vm" {
  project      = var.project_id
  account_id   = "${var.name}-vm"
  display_name = "HiveMind self-host instance"
}

# Keyless Vertex: with this role plus the cloud-platform scope the backend
# authenticates off the metadata server and no credential is written to disk.
resource "google_project_iam_member" "vertex" {
  count = local.vertex_keyless ? 1 : 0

  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.vm.email}"
}

resource "google_project_iam_member" "logging" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.vm.email}"
}

# --- Secrets ----------------------------------------------------------------
#
# Config secrets go to Secret Manager, never into instance metadata: a startup
# script is readable by anyone holding roles/viewer on the project and by every
# process on the VM. The rendered config.json carries only env-var *names*.

resource "google_secret_manager_secret" "config" {
  for_each = toset(module.config.secret_env_names)

  project   = var.project_id
  secret_id = "${var.name}-${lower(replace(each.key, "_", "-"))}"

  replication {
    auto {}
  }

  depends_on = [google_project_service.services]
}

resource "google_secret_manager_secret_version" "config" {
  for_each = toset(module.config.secret_env_names)

  secret      = google_secret_manager_secret.config[each.key].id
  secret_data = module.config.secret_env[each.key]
}

resource "google_secret_manager_secret_iam_member" "vm" {
  for_each = toset(module.config.secret_env_names)

  project   = var.project_id
  secret_id = google_secret_manager_secret.config[each.key].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.vm.email}"
}
