output "config_json" {
  description = "The `hivemind serve setup --config` document. Contains no secret values — only env-var references to them."
  value       = jsonencode(local.config)

  # Guarding the document every consumer reads, so the plan fails rather than
  # the boot: the CLI rejects this same pair, but only once the VM is up and
  # the error is a serial-console line nobody is watching.
  precondition {
    condition     = local.tls != "none" || local.is_local
    error_message = "tls = \"none\" serves localhost only and cannot serve domain \"${var.domain}\". Use \"caddy\" for automatic certificates, or \"upstream\" when a proxy or load balancer terminates TLS."
  }
}

output "secret_env" {
  description = "Env-var name -> secret value. Store these somewhere the instance can read at boot (Secret Manager, Vault) and export them before running setup."
  value       = local.secret_env
  sensitive   = true
}

output "secret_env_names" {
  description = "Just the env-var names from `secret_env`. Non-sensitive, so it can drive for_each."
  value       = local.secret_env_names
}

output "external_url" {
  description = "URL the instance will serve on, derived the same way the CLI derives EXTERNAL_URL."
  value = (
    local.tls == "none"
    ? (local.http_port == "80" ? "http://localhost" : "http://localhost:${local.http_port}")
    : local.tls == "upstream"
    ? "https://${var.domain}"
    : (local.https_port == "443" ? "https://${var.domain}" : "https://${var.domain}:${local.https_port}")
  )
}
