# A production deployment: public domain with Let's Encrypt, a static IP, GCS
# for screenshots/exports, managed ClickHouse, and keyless Vertex AI.
#
# Point an A record for `domain` at `dns_target` BEFORE the first boot — Caddy
# validates over HTTP and can't get a certificate until the name resolves.
#
# See ../load-balancer for the same deployment fronted by a Google load
# balancer, which moves TLS off the VM and adds Cloud Armor.

terraform {
  required_version = ">= 1.3"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

variable "project_id" {
  description = "GCP project to deploy into."
  type        = string
}

variable "region" {
  description = "Region for the subnet, bucket and static IP."
  type        = string
  default     = "us-central1"
}

variable "domain" {
  description = "Public hostname the instance serves on."
  type        = string
}

variable "github_org" {
  description = "GitHub org whose members may sign in."
  type        = string
}

variable "license" {
  description = "HiveMind license token. Empty runs unlicensed."
  type        = string
  default     = ""
  sensitive   = true
}

# Supply an existing managed ClickHouse. To provision one in the same run, add
# the ClickHouse Cloud provider and feed its host/password in here — and add
# `module.hivemind.external_ip` to that service's IP allowlist, which is why
# static_ip is on.
variable "clickhouse_host" {
  description = "Hostname of the managed ClickHouse service."
  type        = string
}

variable "clickhouse_password" {
  description = "Password for the managed ClickHouse service."
  type        = string
  sensitive   = true
}

variable "cursor_api_key" {
  description = "Cursor Admin API key, so Cursor sessions carry the usage and cost Cursor reports. Empty leaves them unenriched."
  type        = string
  default     = ""
  sensitive   = true
}

module "hivemind" {
  source = "../../modules/hivemind-gcp"

  project_id       = var.project_id
  region           = var.region
  hivemind_version = "v1.0.6"

  domain    = var.domain
  tls       = "caddy"
  static_ip = true

  # Public HTTPS. Narrow this to your egress ranges if the instance is internal.
  web_source_ranges = ["0.0.0.0/0"]

  allowed_github_orgs = var.github_org
  license             = var.license

  # Durable object storage. Versioned and not force-destroyable, so a bad
  # delete or a stray `terraform destroy` doesn't take the data with it.
  bucket_name = "${var.project_id}-hivemind"

  # Managed ClickHouse owns its own backups, so the nightly sidecar stays off
  # (the module handles that automatically).
  clickhouse = {
    host = var.clickhouse_host
  }
  clickhouse_password = var.clickhouse_password

  llm = {
    provider = "vertex"
    location = "global"
  }

  # Usage and cost for Cursor sessions. Team-scoped, so leave the org filter
  # empty unless this instance serves users outside that Cursor team.
  cursor_api_key = var.cursor_api_key

  machine_type        = "e2-standard-4"
  boot_disk_gb        = 200
  deletion_protection = true

  labels = {
    component = "hivemind"
    env       = "production"
  }
}

output "dns_target" {
  description = "Create an A record for the domain pointing here. Set `dns_managed_zone` to have the module publish it instead."
  value       = module.hivemind.dns_target
}

output "external_url" {
  description = "Where the instance serves once Caddy has its certificate."
  value       = module.hivemind.external_url
}
