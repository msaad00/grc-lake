# Connector credentials

In the console: **Connections → choose a source → Test → Enable → Sync**. For
automation, use the [headless setup playbook](playbooks/HEADLESS_CONNECTOR_SETUP.md).
Cloud connectors use short-lived or workload identity credentials. Settings keep
a credential reference (an environment variable name or mounted secret file),
not the secret itself.

- **AWS** uses STS AssumeRole, one External ID per deployed role, short-lived session credentials, and read-only IAM posture APIs. Temporary credentials expire after each session; TrustOps stores no long-lived access keys. Roll out with CloudFormation StackSets or Terraform workspaces; bulk account import is planned. See the [cloud setup guide](LIVE_CLOUD_POC.md) and the [credential lifecycle](images/trustops-aws-sts-lifecycle.svg).
- **Azure** uses a customer-owned Entra application, managed identity, or federated workload identity with Reader scope.
- **GCP** uses Application Default Credentials or workload identity; a service-account key file also works.
- **Snowflake** uses a read-only service identity with a key-pair or OAuth token reference. TrustOps stores identifiers, not passwords or private-key contents. Snowflake is one of the existing-lake readers.
- **GitHub** uses a GitHub App installation token, which expires within an hour.
- **SaaS sources** use scoped API tokens or an integration-user login.

Ship your own connector as a Python package: [adding connectors](ADDING_CONNECTORS.md#shipping-a-connector-as-a-package).
