variable "region" {
  description = "AWS region for the EKS cluster + evidence bucket."
  type        = string
  default     = "us-east-1"
}

variable "cluster_name" {
  description = "EKS cluster name."
  type        = string
  default     = "grc-lake"
}

variable "cluster_version" {
  description = "EKS Kubernetes version."
  type        = string
  default     = "1.35"
}

variable "cluster_endpoint_public_access_cidrs" {
  description = "CIDR blocks allowed to reach the public EKS API endpoint. Empty (default) keeps the endpoint private: run Terraform, Helm and kubectl from inside the VPC (VPN, bastion, or runner). Name your operator ranges to enable the public endpoint for those ranges only."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for cidr in var.cluster_endpoint_public_access_cidrs : can(cidrhost(cidr, 0))])
    error_message = "cluster_endpoint_public_access_cidrs entries must be valid CIDR blocks, e.g. 203.0.113.0/24."
  }

  validation {
    condition     = alltrue([for cidr in var.cluster_endpoint_public_access_cidrs : !endswith(cidr, "/0")])
    error_message = "cluster_endpoint_public_access_cidrs must not allow the whole internet (0.0.0.0/0 or ::/0); name operator ranges instead."
  }
}

variable "namespace" {
  description = "Kubernetes namespace the GRC Lake chart installs into."
  type        = string
  default     = "grc-lake"
}

variable "evidence_bucket_name" {
  description = "S3 bucket GRC Lake reads evidence from. Customer-owned."
  type        = string
}

variable "evidence_bucket_arn_prefix" {
  description = "Optional ARN prefix (e.g. arn:aws:s3:::other-bucket) the IRSA role gets read-only access to."
  type        = string
  default     = ""
}

variable "ingress_host" {
  description = "Ingress hostname. Empty = no ingress."
  type        = string
  default     = ""
}

variable "image_repository" {
  description = "OCI image repository for GRC Lake."
  type        = string
  default     = "ghcr.io/msaad00/grc-lake"
}

variable "image_tag" {
  description = "OCI image tag. Empty = chart appVersion default."
  type        = string
  default     = ""
}

variable "node_instance_types" {
  description = "EC2 instance types for the managed node group."
  type        = list(string)
  default     = ["t3.medium"]
}

variable "node_min_size" {
  description = "Minimum node group size."
  type        = number
  default     = 1
}

variable "node_max_size" {
  description = "Maximum node group size."
  type        = number
  default     = 3
}

variable "node_desired_size" {
  description = "Desired node group size."
  type        = number
  default     = 2
}

variable "tags" {
  description = "Extra AWS tags applied to every taggable resource."
  type        = map(string)
  default = {
    "grc-lake:component" = "workbench"
  }
}

variable "deploy_application" {
  description = "Install the application after cluster storage, ingress and secrets are ready. Use false only for initial infrastructure bootstrap; changing an existing deployment to false removes its Helm release."
  type        = bool
  default     = true
}

variable "server_secret_name" {
  description = "Existing Kubernetes Secret in the GRC Lake namespace containing GRC_LAKE_COOKIE_SIGNING_KEY. Create it outside Terraform so secret bytes stay out of state."
  type        = string
  default     = "grc-lake-server"

  validation {
    condition     = length(trimspace(var.server_secret_name)) > 0
    error_message = "server_secret_name must reference an existing signing Secret."
  }
}

variable "helm_values_files" {
  description = "Ordered paths to operator Helm values (OIDC, ingress TLS, storage, connector secret references). Use references only: inline secret bytes would enter Terraform state. env lists replace the default list, so retain the signing Secret reference."
  type        = list(string)
  default     = []
}
