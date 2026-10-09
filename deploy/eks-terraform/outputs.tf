output "cluster_name" {
  description = "Name of the EKS cluster."
  value       = module.eks.cluster_name
}

output "cluster_endpoint" {
  description = "Kubernetes API endpoint."
  value       = module.eks.cluster_endpoint
}

output "cluster_certificate_authority_data" {
  description = "Base64-encoded CA bundle for the cluster."
  value       = module.eks.cluster_certificate_authority_data
  sensitive   = true
}

output "vpc_id" {
  description = "VPC ID provisioned for the cluster."
  value       = module.vpc.vpc_id
}

output "grc-lake_role_arn" {
  description = "IAM role ARN bound to the grc-lake service account via IRSA."
  value       = module.trustops_irsa.iam_role_arn
}

output "kubeconfig_update_command" {
  description = "Command to update local kubeconfig for the new cluster."
  value       = "aws eks update-kubeconfig --region ${var.region} --name ${module.eks.cluster_name}"
}

output "region" {
  description = "AWS region for kubeconfig bootstrap."
  value       = var.region
}
