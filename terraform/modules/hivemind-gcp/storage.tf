# GCS reached over its S3-interop endpoint (https://storage.googleapis.com)
# with HMAC keys, so one credential pair serves both the app (boto3) and the
# nightly ClickHouse backup sidecar.

resource "google_storage_bucket" "this" {
  count = local.uses_bucket ? 1 : 0

  project       = var.project_id
  name          = var.bucket_name
  location      = coalesce(var.bucket_location, var.region)
  labels        = var.labels
  force_destroy = var.bucket_force_destroy

  uniform_bucket_level_access = true

  # UBLA already turns off ACLs; this additionally stops anyone from granting
  # allUsers/allAuthenticatedUsers through IAM. The default is "inherited",
  # which means an org without the constraint leaves the door open. The bucket
  # holds session screenshots and exports.
  public_access_prevention = "enforced"

  versioning {
    enabled = var.bucket_versioning
  }

  dynamic "lifecycle_rule" {
    for_each = var.bucket_object_ttl_days == null ? [] : [var.bucket_object_ttl_days]
    content {
      condition {
        age = lifecycle_rule.value
      }
      action {
        type = "Delete"
      }
    }
  }

  # Without this, superseded versions and aborted multipart uploads bill
  # forever — they're invisible to an age-based rule.
  dynamic "lifecycle_rule" {
    for_each = var.bucket_versioning ? [1] : []
    content {
      condition {
        days_since_noncurrent_time = 30
      }
      action {
        type = "Delete"
      }
    }
  }

  # Large exports upload multipart; an interrupted one bills indefinitely
  # because the parts are invisible to every other rule.
  lifecycle_rule {
    condition {
      age = 7
    }
    action {
      type = "AbortIncompleteMultipartUpload"
    }
  }
}

# Separate from the VM identity: this credential is a long-lived HMAC secret
# that ends up in the instance's .env, so it is scoped to the bucket and never
# carries the Vertex permission the VM holds.
resource "google_service_account" "storage" {
  count = local.uses_bucket ? 1 : 0

  project      = var.project_id
  account_id   = "${var.name}-s3"
  display_name = "HiveMind self-host object storage (S3 interop)"
}

resource "google_storage_bucket_iam_member" "object_admin" {
  count = local.uses_bucket ? 1 : 0

  bucket = google_storage_bucket.this[0].name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.storage[0].email}"
}

# objectAdmin omits storage.buckets.get, which boto3 needs for the HeadBucket
# it issues before the first upload.
resource "google_storage_bucket_iam_member" "bucket_reader" {
  count = local.uses_bucket ? 1 : 0

  bucket = google_storage_bucket.this[0].name
  role   = "roles/storage.legacyBucketReader"
  member = "serviceAccount:${google_service_account.storage[0].email}"
}

resource "google_storage_hmac_key" "this" {
  count = local.uses_bucket ? 1 : 0

  project               = var.project_id
  service_account_email = google_service_account.storage[0].email

  depends_on = [google_project_service.services]
}
