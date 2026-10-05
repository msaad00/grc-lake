# TrustOps read-only GCP posture identity for IAM / asset / org-policy evidence
# collection. Mirrors deploy/aws/trustops-posture-readonly-role.yaml and
# deploy/azure/trustops-posture-reader.bicep: read-only, least-privilege, and no
# static keys — at runtime a GKE Workload Identity binding lets the TrustOps pod
# impersonate this service account (the GCP equivalent of IRSA / Managed
# Identity), and the connector resolves it through Application Default
# Credentials. No service-account key is ever created or exported.

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

variable "project_id" {
  type        = string
  description = "GCP project the TrustOps posture connector reads (its evidence scope)."
}

variable "service_account_id" {
  type        = string
  default     = "trustops-posture-reader"
  description = "Account ID for the read-only TrustOps posture service account."
}

variable "enable_apis" {
  type        = bool
  default     = true
  description = "Enable the read APIs the connector depends on (Cloud Asset, Org Policy, Resource Manager, IAM)."
}

variable "workload_identity_member" {
  type        = string
  default     = ""
  description = <<-EOT
    Optional GKE Workload Identity member allowed to impersonate the reader
    service account, e.g. "serviceAccount:PROJECT.svc.id.goog[NAMESPACE/KSA]".
    Leave empty to skip the binding — set it later, or use short-lived
    impersonation from a CI principal. Never issue a static service-account key.
  EOT
}

# Read APIs the connector calls: IAM bindings via Cloud Resource Manager,
# inventory via Cloud Asset, guardrail posture via Org Policy. The connector
# degrades gracefully if Asset/Org Policy are absent, but enabling them gives
# full coverage.
resource "google_project_service" "required" {
  for_each = var.enable_apis ? toset([
    "cloudresourcemanager.googleapis.com",
    "cloudasset.googleapis.com",
    "orgpolicy.googleapis.com",
    "iam.googleapis.com",
  ]) : toset([])

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_service_account" "trustops_posture_reader" {
  project      = var.project_id
  account_id   = var.service_account_id
  display_name = "TrustOps read-only posture reader"
  description  = "Read-only identity for TrustOps IAM / asset / org-policy evidence collection."
}

# Least-privilege predefined read roles — no write, admin, or impersonation
# scope on the project:
#   iam.securityReviewer    -> read IAM policy bindings (getIamPolicy)
#   cloudasset.viewer       -> list / export resource inventory
#   orgpolicy.policyViewer  -> read organization-policy posture
locals {
  read_only_roles = [
    "roles/iam.securityReviewer",
    "roles/cloudasset.viewer",
    "roles/orgpolicy.policyViewer",
  ]
}

resource "google_project_iam_member" "posture_reader" {
  for_each = toset(local.read_only_roles)

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.trustops_posture_reader.email}"
}

# Optional: let the TrustOps GKE workload impersonate the reader service account
# with no exported key (Workload Identity). Skipped when the member is unset.
resource "google_service_account_iam_member" "workload_identity" {
  count = var.workload_identity_member == "" ? 0 : 1

  service_account_id = google_service_account.trustops_posture_reader.name
  role               = "roles/iam.workloadIdentityUser"
  member             = var.workload_identity_member
}

output "service_account_email" {
  description = "Service account to impersonate for the GCP posture connector (project_id remains the read scope)."
  value       = google_service_account.trustops_posture_reader.email
}
