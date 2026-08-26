# Smallest useful deployment: one VM, bundled ClickHouse, data on the instance
# disk, reachable only through an IAP tunnel. Good for an evaluation.
#
#   terraform apply
#   $(terraform output -raw tunnel_command)   # then open http://localhost:4483

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
  description = "Region for the subnet."
  type        = string
  default     = "us-central1"
}

module "hivemind" {
  source = "../../modules/hivemind-gcp"

  project_id       = var.project_id
  region           = var.region
  hivemind_version = "v1.0.7"

  # No DNS, no public port: reach it over the tunnel below.
  domain = "localhost"

  # AI features off the VM's own service account — no API key to manage.
  llm = { provider = "vertex" }
}

output "tunnel_command" {
  description = "Run this, then open http://localhost:4483."
  value       = module.hivemind.tunnel_command
}

output "ssh_command" {
  description = "IAP-tunnelled SSH into the instance."
  value       = module.hivemind.ssh_command
}
