data "google_compute_image" "ubuntu" {
  family  = "ubuntu-2404-lts-amd64"
  project = "ubuntu-os-cloud"
}

resource "google_compute_instance" "this" {
  project      = var.project_id
  name         = var.name
  zone         = var.zone
  machine_type = var.machine_type
  tags         = [var.name]
  labels       = var.labels

  allow_stopping_for_update = true
  deletion_protection       = var.deletion_protection

  lifecycle {
    # Without this the empty subnetwork reaches the API and comes back as a
    # provider error about a malformed resource URL, several minutes in.
    precondition {
      condition     = var.network == "" || var.subnetwork != ""
      error_message = "`subnetwork` is required when `network` is set: an existing VPC has no subnet this module can infer. Leave both empty to create a dedicated VPC."
    }

    # Unbounded *registration*, not unbounded reading: an instance on the open
    # internet with no org restriction accepts a signup from any GitHub account.
    # What those accounts can see is still scoped — their own sessions plus
    # repos they hold verified access to — and super_admin comes only from the
    # setup-token claim. Still worth a deliberate decision rather than a
    # default. A GitHub Enterprise host counts as the boundary, since only that
    # appliance's users can authenticate at all.
    precondition {
      condition = (
        !local.publicly_reachable
        || var.allowed_github_orgs != ""
        || var.github_host != ""
      )
      error_message = "This instance is reachable from the internet, so signup needs a boundary — otherwise any GitHub account can register on it. Set `allowed_github_orgs` to the orgs that may sign in, or `github_host` to your GitHub Enterprise appliance. Set allowed_github_orgs = \"*\" to deliberately accept any GitHub account."
    }
  }

  # Secure boot, vTPM and integrity monitoring. Standard hardening, and the
  # first thing an enterprise review asks about. Changing this on a live
  # instance forces a stop/start.
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  boot_disk {
    initialize_params {
      image = data.google_compute_image.ubuntu.self_link
      size  = var.boot_disk_gb
      type  = var.boot_disk_type
    }
  }

  network_interface {
    subnetwork = local.subnet_ref

    # The VM pulls container images and release binaries, and reaches Vertex /
    # ClickHouse Cloud. Inbound stays closed unless web_source_ranges says
    # otherwise.
    access_config {
      nat_ip = var.static_ip ? google_compute_address.this[0].address : null
    }
  }

  service_account {
    email = google_service_account.vm.email
    # Vertex rejects anything narrower, and Secret Manager access is scoped by
    # IAM rather than by OAuth scope.
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  metadata = {
    enable-oslogin = "TRUE"
    # Safe to put in metadata: config.json holds env-var *names* for every
    # secret, never a value.
    hivemind-config = module.config.config_json
    startup-script = templatefile("${path.module}/startup.sh.tftpl", {
      project_id       = var.project_id
      hivemind_version = var.hivemind_version
      hivemind_sha256  = var.hivemind_sha256
      secret_ids = jsonencode({
        for env_name in module.config.secret_env_names :
        env_name => google_secret_manager_secret.config[env_name].secret_id
      })
    })
  }

  depends_on = [
    google_project_service.services,
    google_secret_manager_secret_version.config,
    google_secret_manager_secret_iam_member.vm,
  ]
}
