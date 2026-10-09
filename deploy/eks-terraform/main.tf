###############################################################################
# GRC Lake EKS reference IaC                                                  #
#                                                                             #
# Provisions:                                                                 #
#   * VPC with public + private subnets across 2 AZs                          #
#   * EKS cluster (managed control plane) with one managed node group         #
#   * OIDC provider for IRSA                                                  #
#   * IAM role bound to the grc-lake service account, with read-only access   #
#     to the customer-owned evidence S3 bucket (residency boundary)           #
#   * Helm release of ../helm/grc-lake with the IRSA annotation applied       #
#                                                                             #
# Customer evidence stays in the customer S3 bucket. Nothing about this stack #
# requires the bucket to be inside the same AWS account; cross-account is a   #
# matter of granting this IRSA role access in the bucket policy.             #
###############################################################################

locals {
  base_tags = merge(
    {
      "grc-lake:cluster" = var.cluster_name
    },
    var.tags,
  )
}

provider "aws" {
  region = var.region
}

data "aws_availability_zones" "available" {
  state = "available"
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.7"

  name = "${var.cluster_name}-vpc"
  cidr = "10.42.0.0/16"

  azs             = slice(data.aws_availability_zones.available.names, 0, 2)
  private_subnets = ["10.42.1.0/24", "10.42.2.0/24"]
  public_subnets  = ["10.42.101.0/24", "10.42.102.0/24"]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
  }

  tags = local.base_tags
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.20"

  cluster_name    = var.cluster_name
  cluster_version = var.cluster_version

  cluster_endpoint_public_access = true

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  enable_irsa = true
  # The creating operator must be able to bootstrap add-ons and secrets and
  # authenticate the Kubernetes/Helm providers. Additional access is operator-owned.
  enable_cluster_creator_admin_permissions = true

  eks_managed_node_groups = {
    workbench = {
      ami_type       = "AL2023_x86_64_STANDARD"
      instance_types = var.node_instance_types
      min_size       = var.node_min_size
      max_size       = var.node_max_size
      desired_size   = var.node_desired_size
    }
  }

  tags = local.base_tags
}

###############################################################################
# Customer evidence bucket — read-only IAM policy + IRSA-bound role           #
###############################################################################

data "aws_iam_policy_document" "evidence_read_only" {
  statement {
    sid    = "EvidenceListBucket"
    effect = "Allow"
    actions = [
      "s3:ListBucket",
      "s3:GetBucketLocation",
    ]
    resources = [
      "arn:aws:s3:::${var.evidence_bucket_name}",
    ]
  }

  statement {
    sid    = "EvidenceReadObjects"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:GetObjectTagging",
    ]
    resources = [
      "arn:aws:s3:::${var.evidence_bucket_name}/*",
    ]
  }

  # Optional second bucket prefix — useful for Iceberg + Polaris catalogs
  # living in a separate bucket from raw evidence.
  dynamic "statement" {
    for_each = var.evidence_bucket_arn_prefix == "" ? [] : [1]
    content {
      sid    = "ExtraReadOnly"
      effect = "Allow"
      actions = [
        "s3:ListBucket",
        "s3:GetObject",
        "s3:GetObjectVersion",
      ]
      resources = [
        var.evidence_bucket_arn_prefix,
        "${var.evidence_bucket_arn_prefix}/*",
      ]
    }
  }
}

resource "aws_iam_policy" "evidence_read_only" {
  name        = "${var.cluster_name}-evidence-ro"
  description = "Read-only access to the GRC Lake evidence bucket."
  policy      = data.aws_iam_policy_document.evidence_read_only.json
  tags        = local.base_tags
}

module "trustops_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.39"

  role_name = "${var.cluster_name}-grc-lake"

  role_policy_arns = {
    evidence = aws_iam_policy.evidence_read_only.arn
  }

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["${var.namespace}:grc-lake"]
    }
  }

  tags = local.base_tags
}

###############################################################################
# Kubernetes + Helm providers wired to the new cluster                        #
###############################################################################

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--region", var.region, "--cluster-name", module.eks.cluster_name]
  }
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--region", var.region, "--cluster-name", module.eks.cluster_name]
    }
  }
}

resource "kubernetes_namespace" "trustops" {
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }
}

# Preserve the address of existing releases when adding the bootstrap phase.
moved {
  from = helm_release.trustops
  to   = helm_release.trustops[0]
}

resource "helm_release" "trustops" {
  count     = var.deploy_application ? 1 : 0
  name      = "grc-lake"
  namespace = kubernetes_namespace.trustops.metadata[0].name
  chart     = "${path.module}/../helm/grc-lake"

  values = concat([
    yamlencode({
      image = {
        repository = var.image_repository
        tag        = var.image_tag
      }
      env = [
        { name = "GRC_LAKE_ENV", value = "production" },
        {
          name = "GRC_LAKE_COOKIE_SIGNING_KEY"
          valueFrom = {
            secretKeyRef = {
              name = var.server_secret_name
              key  = "GRC_LAKE_COOKIE_SIGNING_KEY"
            }
          }
        },
      ]
      serviceAccount = {
        create = true
        name   = "grc-lake"
        annotations = {
          "eks.amazonaws.com/role-arn" = module.trustops_irsa.iam_role_arn
        }
      }
      ingress = var.ingress_host == "" ? {
        enabled     = false
        className   = ""
        annotations = {}
        hosts       = []
        } : {
        enabled     = true
        className   = "alb"
        annotations = { "kubernetes.io/ingress.class" = "alb" }
        hosts = [{
          host  = var.ingress_host
          paths = [{ path = "/", pathType = "Prefix" }]
        }]
      }
    }),
    ], [for path in var.helm_values_files : file(path)], [
    # Fail closed even when an operator profile omits auth or requests no-auth.
    yamlencode({
      security = {
        requireAuthentication = true
        allowInsecureNoAuth   = false
        allowInsecureOverride = ""
      }
    }),
  ])

  depends_on = [
    module.eks,
    kubernetes_namespace.trustops,
  ]
}
