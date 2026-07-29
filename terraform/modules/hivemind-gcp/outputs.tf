output "instance_name" {
  description = "Name of the VM running the stack."
  value       = google_compute_instance.this.name
}

output "zone" {
  description = "Zone the VM runs in."
  value       = google_compute_instance.this.zone
}

output "external_ip" {
  description = "The instance's own external IP — also the source address of its egress, which is what a ClickHouse Cloud allowlist needs."
  value       = google_compute_instance.this.network_interface[0].access_config[0].nat_ip
}

# Same address as `external_ip` when static_ip is set, but read off the
# reserved address instead of the VM, so it carries no dependency on the
# instance. That is the difference between working and a cycle for anything
# that must exist *before* the VM and is also an input to it — allowlisting the
# instance on a database it is about to be handed the host of. Don't collapse
# this into external_ip.
output "static_ip_address" {
  description = "The reserved external address, or null when `static_ip` is false. Use this, not `external_ip`, to allowlist the instance on a resource the module itself consumes."
  value       = var.static_ip ? google_compute_address.this[0].address : null
}

output "load_balancer_ip" {
  description = "Anycast address of the load balancer, or null when there isn't one."
  value       = local.enable_lb ? google_compute_global_address.lb[0].address : null
}

output "dns_target" {
  description = "What the domain's A record must resolve to. Already published when `dns_managed_zone` is set; otherwise create the record yourself, before certificate issuance can complete."
  value = (
    local.enable_lb
    ? google_compute_global_address.lb[0].address
    : google_compute_instance.this.network_interface[0].access_config[0].nat_ip
  )
}

output "ssl_certificate" {
  description = "Name of the Google-managed certificate, or null when serving supplied certificates. Watch it reach ACTIVE with: gcloud compute ssl-certificates describe <name> --global"
  value       = local.managed_cert ? google_compute_managed_ssl_certificate.this[0].name : null
}

output "external_url" {
  description = "URL the instance serves on once it is up."
  value       = module.config.external_url
}

output "ssh_command" {
  description = "IAP-tunnelled SSH into the instance."
  value       = "gcloud compute ssh ${google_compute_instance.this.name} --zone ${google_compute_instance.this.zone} --project ${var.project_id} --tunnel-through-iap"
}

output "tunnel_command" {
  description = "Forward the dashboard to localhost when no web port is exposed."
  value       = "gcloud compute ssh ${google_compute_instance.this.name} --zone ${google_compute_instance.this.zone} --project ${var.project_id} --tunnel-through-iap -- -L 4483:localhost:4483"
}

output "service_account" {
  description = "Identity the instance runs as (and that Vertex authenticates as)."
  value       = google_service_account.vm.email
}

output "bucket_name" {
  description = "GCS bucket holding screenshots and exports, or null when data stays on the instance disk."
  value       = local.uses_bucket ? google_storage_bucket.this[0].name : null
}

output "config_json" {
  description = "The rendered setup config. Secret-free — useful for debugging what the instance was told."
  value       = module.config.config_json
}
