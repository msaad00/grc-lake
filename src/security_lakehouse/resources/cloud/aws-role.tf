variable "trusted_principal_arn" {
  description = "ARN of the AWS principal allowed to assume this role."
  type        = string

  validation {
    condition     = can(regex("^arn:aws[a-zA-Z-]*:iam::[0-9]{12}:(role|user|root)(/.+)?$", var.trusted_principal_arn))
    error_message = "trusted_principal_arn must be an IAM role, user, or root ARN."
  }
}

variable "external_id" {
  description = "External ID condition for cross-account assumption."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@:/_-]{8,128}$", var.external_id))
    error_message = "external_id must be 8-128 allowed External ID characters."
  }
}

variable "role_name" {
  description = "Name for the TrustOps read-only posture role."
  type        = string
  default     = "TrustOpsPostureReadOnlyRole"

  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]{1,64}$", var.role_name))
    error_message = "role_name must be 1-64 IAM role-name characters."
  }
}

resource "aws_iam_role" "trustops_posture_readonly" {
  name        = var.role_name
  description = "Read-only role for TrustOps AWS IAM posture evidence collection."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "TrustOpsAssumeRole"
        Effect    = "Allow"
        Principal = { AWS = var.trusted_principal_arn }
        Action    = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.external_id
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "trustops_posture_readonly" {
  name = "TrustOpsPostureReadOnly"
  role = aws_iam_role.trustops_posture_readonly.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "TrustOpsIamPostureReadOnly"
        Effect = "Allow"
        Action = [
          "iam:GetAccountPasswordPolicy",
          "iam:GetAccountSummary",
          "iam:GetLoginProfile",
          "iam:ListAccessKeys",
          "iam:ListMFADevices",
          "iam:ListUsers"
        ]
        Resource = "*"
      }
    ]
  })
}

output "role_arn" {
  description = "ARN to configure as the AWS posture connector's read-only role."
  value       = aws_iam_role.trustops_posture_readonly.arn
}
