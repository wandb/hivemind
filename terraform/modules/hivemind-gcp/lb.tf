# Optional global external Application Load Balancer in front of the instance.
#
# The alternative — and the default — is Caddy terminating TLS on the VM itself
# with a Let's Encrypt certificate, which needs nothing here. Reach for the load
# balancer when you want Google-managed certificates, Cloud Armor, or a stable
# anycast address that survives rebuilding the VM.
#
# With the load balancer on, the VM runs in `upstream` TLS mode: Caddy serves
# plain HTTP on :80 and the load balancer owns the public https:// URL. Port 80
# is opened only to Google's health-check and proxy ranges, so the instance
# itself is never directly reachable from the internet.

locals {
  cert_domains = concat([var.domain], var.lb_extra_domains)
  managed_cert = local.enable_lb && length(var.lb_ssl_certificates) == 0
  lb_certs = length(var.lb_ssl_certificates) > 0 ? var.lb_ssl_certificates : [
    for c in google_compute_managed_ssl_certificate.this : c.id
  ]
}

resource "google_compute_global_address" "lb" {
  count = local.enable_lb ? 1 : 0

  project = var.project_id
  name    = "${var.name}-lb"

  lifecycle {
    precondition {
      condition     = var.domain != "localhost"
      error_message = "load_balancer requires a real `domain`: the certificate and the forwarding rule are both keyed on it."
    }
    precondition {
      condition     = var.tls == null || var.tls == "upstream"
      error_message = "load_balancer forces tls = \"upstream\" (the balancer terminates TLS). Leave `tls` null, or set it to \"upstream\"."
    }
    # Only the open-to-the-world ranges are refused. A narrow admin CIDR reaching
    # the VM directly is a legitimate break-glass path; 0.0.0.0/0 is a second
    # front door past Cloud Armor, the WAF rules, and the certificate.
    precondition {
      condition     = !contains(var.web_source_ranges, "0.0.0.0/0") && !contains(var.web_source_ranges, "::/0")
      error_message = "web_source_ranges opens the VM to the world while `load_balancer` is set, letting clients reach it directly and bypass Cloud Armor. Drop the range so traffic arrives only through the balancer, or list specific CIDRs."
    }
  }
}

# Traffic and health checks both arrive on the instance's :80. Caddy is the only
# thing listening there, so the named port matches the host port, not app:8080.
resource "google_compute_instance_group" "this" {
  count = local.enable_lb ? 1 : 0

  project = var.project_id
  name    = var.name
  zone    = var.zone

  instances = [google_compute_instance.this.self_link]

  named_port {
    name = "http"
    port = 80
  }
}

resource "google_compute_health_check" "this" {
  count = local.enable_lb ? 1 : 0

  project = var.project_id
  name    = "${var.name}-http"

  # /health is unauthenticated and answers as soon as the API process is up,
  # without waiting on ClickHouse — so a slow first boot shows as 502 from the
  # balancer rather than as a backend that never turns healthy.
  http_health_check {
    port         = 80
    request_path = "/health"
  }

  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3
}

resource "google_compute_backend_service" "this" {
  count = local.enable_lb ? 1 : 0

  project               = var.project_id
  name                  = var.name
  protocol              = "HTTP"
  port_name             = "http"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  health_checks         = [google_compute_health_check.this[0].id]
  security_policy       = var.lb_security_policy == "" ? null : var.lb_security_policy

  # The dashboard streams agent activity over long-lived SSE responses. The
  # 30s default would sever them mid-stream, which surfaces as a session view
  # that stops updating rather than as an error.
  timeout_sec = var.lb_timeout_sec

  backend {
    group = google_compute_instance_group.this[0].id
  }

  log_config {
    enable      = var.lb_logging
    sample_rate = var.lb_logging ? 1.0 : null
  }
}

# Renaming on every domain change is what makes the certificate replaceable:
# a managed certificate can't be deleted while a proxy references it, so the
# replacement has to be created under a new name first.
resource "google_compute_managed_ssl_certificate" "this" {
  count = local.managed_cert ? 1 : 0

  project = var.project_id
  name    = "${var.name}-cert-${substr(sha256(join(",", local.cert_domains)), 0, 8)}"

  managed {
    domains = local.cert_domains
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "google_compute_url_map" "this" {
  count = local.enable_lb ? 1 : 0

  project         = var.project_id
  name            = var.name
  default_service = google_compute_backend_service.this[0].id
}

resource "google_compute_target_https_proxy" "this" {
  count = local.enable_lb ? 1 : 0

  project          = var.project_id
  name             = var.name
  url_map          = google_compute_url_map.this[0].id
  ssl_certificates = local.lb_certs
}

resource "google_compute_global_forwarding_rule" "https" {
  count = local.enable_lb ? 1 : 0

  project               = var.project_id
  name                  = "${var.name}-https"
  target                = google_compute_target_https_proxy.this[0].id
  ip_address            = google_compute_global_address.lb[0].id
  port_range            = "443"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  labels                = var.labels
}

# :80 redirects rather than serving. Daemons don't follow redirects, so they
# must be pointed at the https:// URL — same contract as Caddy-terminated TLS,
# which redirects identically.
resource "google_compute_url_map" "redirect" {
  count = local.enable_lb ? 1 : 0

  project = var.project_id
  name    = "${var.name}-redirect"

  default_url_redirect {
    https_redirect         = true
    strip_query            = false
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
  }
}

resource "google_compute_target_http_proxy" "redirect" {
  count = local.enable_lb ? 1 : 0

  project = var.project_id
  name    = "${var.name}-redirect"
  url_map = google_compute_url_map.redirect[0].id
}

resource "google_compute_global_forwarding_rule" "http" {
  count = local.enable_lb ? 1 : 0

  project               = var.project_id
  name                  = "${var.name}-http"
  target                = google_compute_target_http_proxy.redirect[0].id
  ip_address            = google_compute_global_address.lb[0].id
  port_range            = "80"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  labels                = var.labels
}

# A Google-managed certificate stays PROVISIONING until the domain resolves to
# the balancer, so creating the record here is what lets a single `apply`
# converge. Without a zone, create the A record yourself before the certificate
# can issue — it is the single most common reason a fresh deployment serves
# nothing but TLS errors.
resource "google_dns_record_set" "this" {
  count = var.dns_managed_zone != "" && var.domain != "localhost" ? 1 : 0

  project      = var.project_id
  managed_zone = var.dns_managed_zone
  name         = "${var.domain}."
  type         = "A"
  ttl          = var.dns_ttl
  rrdatas = [
    local.enable_lb
    ? google_compute_global_address.lb[0].address
    : google_compute_instance.this.network_interface[0].access_config[0].nat_ip
  ]
}
