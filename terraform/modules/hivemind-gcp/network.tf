resource "google_compute_network" "this" {
  count = local.create_net ? 1 : 0

  project                 = var.project_id
  name                    = var.name
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "this" {
  count = local.create_net ? 1 : 0

  project                  = var.project_id
  name                     = "${var.name}-subnet"
  region                   = var.region
  network                  = google_compute_network.this[0].id
  ip_cidr_range            = var.subnet_cidr
  private_ip_google_access = true
}

# A stable address is what makes a DNS record and a ClickHouse Cloud IP
# allowlist survive a stop/start; an ephemeral IP changes on every restart.
resource "google_compute_address" "this" {
  count = var.static_ip ? 1 : 0

  project = var.project_id
  name    = var.name
  region  = var.region
}

resource "google_compute_firewall" "ssh" {
  count = length(var.ssh_source_ranges) > 0 ? 1 : 0

  project       = var.project_id
  name          = "${var.name}-allow-ssh"
  network       = local.network_name
  source_ranges = var.ssh_source_ranges
  target_tags   = [var.name]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "web" {
  count = length(var.web_source_ranges) > 0 ? 1 : 0

  project       = var.project_id
  name          = "${var.name}-allow-web"
  network       = local.network_name
  source_ranges = var.web_source_ranges
  target_tags   = [var.name]

  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }
}

# Both proxied traffic and health probes originate from these fixed Google
# ranges, never from the client's address — which is why `web_source_ranges`
# stops being the way to restrict access once the balancer is in front. Use
# `lb_security_policy` (Cloud Armor) for that.
resource "google_compute_firewall" "lb" {
  count = local.enable_lb ? 1 : 0

  project       = var.project_id
  name          = "${var.name}-allow-lb"
  network       = local.network_name
  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
  target_tags   = [var.name]

  allow {
    protocol = "tcp"
    ports    = ["80"]
  }
}
