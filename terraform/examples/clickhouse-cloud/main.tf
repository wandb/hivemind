# Production, with the managed ClickHouse provisioned in the same apply.
#
# ../production takes an existing ClickHouse and asks you to allowlist the VM
# by hand. Here both sides are Terraform, so the allowlist closes itself: the
# service is created with the instance's static IP already in `ip_access`.
#
# The ordering works because the address is a resource of its own, so Terraform
# builds it before either the ClickHouse service or the VM:
#
#   google_compute_address  ->  clickhouse_service  ->  google_compute_instance
#
# That is also why `static_ip = true` is not optional here. With an ephemeral
# address there is nothing to allowlist ahead of the VM, and the instance would
# boot pointing at a database that refuses it.
#
# The ClickHouse Cloud provider authenticates from the environment — an API key
# from console.clickhouse.cloud (Settings -> API keys):
#
#   export CLICKHOUSE_ORG_ID=...
#   export CLICKHOUSE_TOKEN_KEY=...
#   export CLICKHOUSE_TOKEN_SECRET=...
#
# Unlike the other examples this one bills a second vendor. A ClickHouse Cloud
# service costs money whenever it is awake; `idle_scaling` parks it after
# `idle_timeout_minutes`, which is the difference between a cheap evaluation
# and a surprise. `terraform destroy` takes the service and its data with it.

terraform {
  required_version = ">= 1.3"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
    clickhouse = {
      source  = "ClickHouse/clickhouse"
      version = ">= 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "clickhouse" {}

variable "project_id" {
  description = "GCP project to deploy into."
  type        = string
}

variable "region" {
  description = "Region for the subnet, bucket and static IP."
  type        = string
  default     = "us-central1"
}

variable "clickhouse_region" {
  description = "ClickHouse Cloud region. Keep it next to `region` — every query crosses this gap."
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

variable "clickhouse_max_replica_memory_gb" {
  description = "Ceiling for autoscaling. The floor is left at the provider default so an idle service costs as little as it can."
  type        = number
  default     = 24
}

resource "random_password" "clickhouse" {
  length = 32
  # The password travels through a .env file and a shell, so keep it to
  # characters that survive both without quoting.
  special          = true
  override_special = "-_"
}

resource "clickhouse_service" "hivemind" {
  name           = "hivemind"
  cloud_provider = "gcp"
  region         = var.clickhouse_region
  password       = random_password.clickhouse.result

  # The whole point of this example: the only address allowed to connect is the
  # instance's. ClickHouse Cloud is a public endpoint, so without this the
  # service would be reachable from anywhere with the password.
  # `static_ip_address`, not `external_ip`: the latter reads the address off the
  # VM, which by then depends on this service's hostname — a cycle. This one
  # reads the reserved address, which exists before either.
  ip_access = [{
    source      = module.hivemind.static_ip_address
    description = "hivemind instance"
  }]

  max_replica_memory_gb = var.clickhouse_max_replica_memory_gb

  idle_scaling         = true
  idle_timeout_minutes = 5
}

module "hivemind" {
  source = "../../modules/hivemind-gcp"

  project_id       = var.project_id
  region           = var.region
  hivemind_version = "v1.0.6"

  domain = var.domain
  tls    = "caddy"

  # Load-bearing — see the header. The allowlist above needs an address that
  # exists before the VM does.
  static_ip = true

  web_source_ranges = ["0.0.0.0/0"]

  allowed_github_orgs = var.github_org
  license             = var.license

  bucket_name = "${var.project_id}-hivemind"

  # Managed ClickHouse runs its own backups, so the module leaves the nightly
  # backup sidecar off.
  clickhouse = {
    host = clickhouse_service.hivemind.endpoints.https.host
    port = tostring(clickhouse_service.hivemind.endpoints.https.port)
  }
  clickhouse_password = random_password.clickhouse.result

  llm = {
    provider = "vertex"
    location = "global"
  }

  machine_type        = "e2-standard-4"
  boot_disk_gb        = 200
  deletion_protection = true

  labels = {
    component = "hivemind"
    env       = "production"
  }
}

output "dns_target" {
  description = "Create an A record for the domain pointing here, before the first boot."
  value       = module.hivemind.dns_target
}

output "external_url" {
  description = "Where the instance serves once Caddy has its certificate."
  value       = module.hivemind.external_url
}

output "clickhouse_host" {
  description = "The provisioned ClickHouse service endpoint."
  value       = clickhouse_service.hivemind.endpoints.https.host
}
