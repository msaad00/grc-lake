# Plan-only contract checks. Providers and infrastructure modules are mocked;
# these tests never create a cluster or contact a customer account.
mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = { names = ["us-east-1a", "us-east-1b"] }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
}
mock_provider "kubernetes" {}
mock_provider "helm" {}

override_module {
  target = module.vpc
  outputs = {
    vpc_id          = "vpc-test"
    private_subnets = ["subnet-a", "subnet-b"]
  }
}
override_module {
  target = module.eks
  outputs = {
    cluster_name                       = "grc-lake-test"
    cluster_endpoint                   = "https://127.0.0.1"
    cluster_certificate_authority_data = "dGVzdA=="
    oidc_provider_arn                  = "arn:aws:iam::123456789012:oidc-provider/example.com"
  }
}
override_module {
  target  = module.trustops_irsa
  outputs = { iam_role_arn = "arn:aws:iam::123456789012:role/grc-lake-test" }
}

variables {
  evidence_bucket_name = "test-evidence"
}

run "authenticated_application_defaults" {
  command = plan

  assert {
    condition     = try(yamldecode(helm_release.trustops[0].values[length(helm_release.trustops[0].values) - 1]).security.requireAuthentication, false)
    error_message = "EKS must require authentication and wire a signing secret before application startup."
  }
}

run "signing_secret_reference" {
  command = plan
  variables { server_secret_name = "operator-session-secret" }
  assert {
    condition     = yamldecode(helm_release.trustops[0].values[0]).env[1].valueFrom.secretKeyRef.name == "operator-session-secret"
    error_message = "The server must receive the operator's signing Secret reference."
  }
}

run "infrastructure_bootstrap_without_application" {
  command = plan
  variables { deploy_application = false }
  assert {
    condition     = length(helm_release.trustops) == 0
    error_message = "Bootstrap must allow storage/controllers/secrets to be prepared before Helm installation."
  }
}

run "operator_profile_with_enforced_auth" {
  command = plan
  variables { helm_values_files = ["tests/operator-values.yaml"] }
  assert {
    condition     = yamldecode(helm_release.trustops[0].values[1]).ingress.hosts[0].host == "grc-lake.example.com"
    error_message = "Operator ingress/TLS settings must reach the chart."
  }
  assert {
    condition     = yamldecode(helm_release.trustops[0].values[2]).security.requireAuthentication && !yamldecode(helm_release.trustops[0].values[2]).security.allowInsecureNoAuth
    error_message = "Operator overrides must not disable EKS authentication."
  }
}
