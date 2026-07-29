# Production behind a Google load balancer: managed TLS certificate, Cloud
# Armor, and a DNS record published from the same apply — so `terraform apply`
# converges without a manual DNS step in the middle.
#
# The instance itself has no port open to the internet; the only path in is the
# balancer, which is why the Cloud Armor policy is the access control here and
# `web_source_ranges` is left empty.
#
# Expect the first apply to finish before the site does. A Google-managed
# certificate goes ACTIVE only after the domain resolves to the balancer, which
# typically takes 15-30 minutes; until then the domain serves a TLS error.
#
#   terraform apply
#   gcloud compute ssl-certificates describe $(terraform output -raw ssl_certificate) --global

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
  description = "Region for the subnet and bucket."
  type        = string
  default     = "us-central1"
}

variable "domain" {
  description = "Public hostname the balancer serves, and the certificate's subject."
  type        = string
}

variable "github_org" {
  description = "GitHub org whose members may sign in."
  type        = string
}

variable "dns_managed_zone" {
  description = <<-EOT
    An existing Cloud DNS zone that is authoritative for `domain`. Drop this and
    the module skips the record — then point the A record at `dns_target`
    yourself, or the certificate never issues.
  EOT
  type        = string
}

variable "license" {
  description = "HiveMind license token. Empty runs unlicensed."
  type        = string
  default     = ""
  sensitive   = true
}

# Only these ranges reach the balancer. Cloud Armor is the enforcement point
# because the VM firewall can't be: every request arrives from Google's proxy
# range, carrying the real client IP in a header rather than in the packet.
variable "office_cidrs" {
  description = "Client ranges Cloud Armor lets through to the balancer."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

resource "google_compute_security_policy" "hivemind" {
  project = var.project_id
  name    = "hivemind-allow"

  rule {
    action   = "allow"
    priority = 1000
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = var.office_cidrs
      }
    }
  }

  rule {
    action   = "deny(403)"
    priority = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
  }
}

module "hivemind" {
  source = "../../modules/hivemind-gcp"

  project_id       = var.project_id
  region           = var.region
  hivemind_version = "v1.0.6"

  domain = var.domain

  # Managed certificate, HTTP->HTTPS redirect, and Cloud Armor. `tls` is left
  # null: the module pins it to "upstream" so Caddy serves plain HTTP behind
  # the balancer instead of chasing a Let's Encrypt certificate of its own.
  load_balancer      = true
  lb_security_policy = google_compute_security_policy.hivemind.id
  dns_managed_zone   = var.dns_managed_zone

  # No direct route to the VM — everything goes through the balancer.
  web_source_ranges = []

  allowed_github_orgs = var.github_org
  license             = var.license

  bucket_name = "${var.project_id}-hivemind"

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

output "external_url" {
  description = "Where the instance serves once the certificate is ACTIVE."
  value       = module.hivemind.external_url
}

output "dns_target" {
  description = "Where the A record points (already published into the managed zone)."
  value       = module.hivemind.dns_target
}

output "ssl_certificate" {
  description = "Google-managed certificate to watch reach ACTIVE."
  value       = module.hivemind.ssl_certificate
}
