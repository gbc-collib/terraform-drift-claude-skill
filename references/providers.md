# Provider notes

All commands run through `scripts/ro_guard.py` (shown below as `guard`, i.e.
`python <skill>/scripts/ro_guard.py <command...>`). Add `--out FILE` for anything large and
project fields with `jq` instead of reading whole payloads.

Read-only *credentials* are the real boundary. Recommend these before starting:

| Provider | Suggested identity |
|---|---|
| AWS | `ReadOnlyAccess` + `SecurityAudit` (add `s3:GetBucket*` etc. if the managed policies miss something), plus read access to the state bucket |
| Azure | `Reader` on the subscription, plus `Storage Blob Data Reader` on the state container |
| GCP | `roles/viewer` + `roles/iam.securityReviewer`, plus `storage.objectViewer` on the state bucket |
| Okta | A custom admin role with read-only permissions, or the built-in Read-only Administrator |

---

## AWS

- Identity: `guard aws sts get-caller-identity`. Show the ARN to the user; if it looks like
  an admin or power-user role, ask them to confirm before going on.
- Region: Terraform reads the region from provider config. For discovery calls pass
  `--region` explicitly and loop over every region the repo uses.
- Discovery (unmanaged resources), by Terraform type:
  - `aws_instance` -> `ec2 describe-instances`
  - `aws_security_group` -> `ec2 describe-security-groups`
  - `aws_s3_bucket` -> `s3api list-buckets` (then `get-bucket-*` per bucket)
  - `aws_iam_role` / `aws_iam_policy` -> `iam list-roles` / `iam list-policies --scope Local`
  - `aws_lambda_function` -> `lambda list-functions`
  - `aws_db_instance` -> `rds describe-db-instances`
  - `aws_vpc` / `aws_subnet` -> `ec2 describe-vpcs` / `describe-subnets`
  - Cross-service sweep: `resourcegroupstaggingapi get-resources` (tagged resources only)
- Attribution: `cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue=<id>`
  (90 days of management events). Report principal + time + event name, not raw payloads.
- AWS-managed noise to exclude from "unmanaged": service-linked roles (`/aws-service-role/`),
  default VPC and its default SG/NACL/subnets, `AWSServiceRoleFor*`, CDK/SSO-created roles
  (`aws-reserved/sso.amazonaws.com`).
- Blocked on purpose: `secretsmanager get-secret-value`, `ssm get-parameter*` (use
  `ssm describe-parameters`), `s3api get-object`, `lambda get-function` (use
  `get-function-configuration`), `sts assume-role`. Lambda/ECS environment variables show up in
  `list-functions` / `describe-task-definition`; the guard masks secret-looking keys, but treat
  everything else in env maps as possibly sensitive.

## Azure

- Identity: `guard az account show` (subscription, tenant, user/SP). Always pass
  `--subscription` explicitly rather than running `az account set`.
- Discovery:
  - Everything in a subscription: `guard az resource list --subscription <id> -o json`
    (name, type, id; compare ids to state, case-insensitively, since Azure ids vary in casing)
  - Resource Graph for wide sweeps: `guard az graph query -q "Resources | where type =~ '...' | project id,name"`
  - RBAC: `az role assignment list --all`, `az role definition list --custom-role-only true`
  - Policy: `az policy assignment list`, `az policy definition list --query "[?policyType=='Custom']"`
  - Entra (AzureAD provider): `az ad group list`, `az ad app list`, `az ad sp list --all` (slow)
- Attribution: `az monitor activity-log list --resource-id <id> --offset 30d` (caller, time, operation).
- Casing: Azure resource ids are case-insensitive. A "drift" that is only a case change in an id
  is provider noise; keep the casing the code already uses.
- Blocked on purpose: `keyvault secret show`, `storage account keys list`, any `*list-keys`,
  `webapp config appsettings list` (returns values), `account get-access-token`, `az login`.
  Use `az webapp show` / `az functionapp show` for config shape without secret values.

## GCP

- Identity: `guard gcloud auth list` and `guard gcloud config get-value project`. Always pass
  `--project` explicitly and `--format=json` (default output is not JSON, so it skips redaction).
- Discovery:
  - Cloud Asset Inventory is the best sweep: `gcloud asset search-all-resources --scope=projects/<id> --asset-types=compute.googleapis.com/Instance --format=json`
  - Per type: `gcloud compute instances list`, `... firewall-rules list`, `gcloud storage buckets list`,
    `gcloud iam service-accounts list`, `gcloud projects get-iam-policy <id>`
- Attribution: `gcloud logging read 'protoPayload.resourceName:"<name>" AND protoPayload.methodName:*' --freshness=30d --limit=20 --format=json`
  (Admin Activity audit logs are on by default).
- IAM drift is the usual surprise: `google_project_iam_member` is additive, `google_project_iam_binding`
  is authoritative per role, `google_project_iam_policy` is authoritative for the whole project.
  Which one the repo uses decides whether a console-added member is "drift" or just unmanaged.
- Blocked on purpose: `secrets versions access`, `auth print-access-token`, `compute ssh`,
  `--impersonate-service-account`, `storage cp/cat`. Use `gcloud storage buckets describe` and
  `gcloud secrets describe` for metadata.

## Okta

- No CLI. Use the built-in client; the token comes from the environment and is never printed:
  `guard okta GET /api/v1/apps` (needs `OKTA_ORG_URL`, `OKTA_API_TOKEN` or `OKTA_ACCESS_TOKEN`).
  Pagination (`Link: rel="next"`) is followed automatically, same-host only.
- Terraform types -> endpoints:
  - `okta_group` -> `/api/v1/groups`; rules -> `/api/v1/groups/rules`
  - `okta_app_oauth` / `okta_app_saml` -> `/api/v1/apps` (filter with `?filter=status eq "ACTIVE"`)
  - `okta_policy_*` and `okta_policy_rule_*` -> `/api/v1/policies?type=<OKTA_SIGN_ON|ACCESS_POLICY|PASSWORD|MFA_ENROLL|...>` then `/api/v1/policies/<id>/rules`
  - `okta_auth_server*` -> `/api/v1/authorizationServers`, `/<id>/policies`, `/<id>/scopes`, `/<id>/claims`
  - `okta_network_zone` -> `/api/v1/zones`; `okta_trusted_origin` -> `/api/v1/trustedOrigins`
  - `okta_authenticator` -> `/api/v1/authenticators`
- Attribution: `guard okta GET "/api/v1/logs?since=<ISO8601>&filter=target.id eq \"<id>\""`.
- The client redacts `client_secret` and similar keys, but app and IdP payloads can carry other
  credential-like fields. Read only the fields you need.
- Okta objects often have system-managed defaults (the Default Policy, built-in groups such as
  `Everyone`). Exclude those from "unmanaged" unless the repo already manages them.

## Anything else (Datadog, GitHub, Cloudflare, Kubernetes, ...)

`ro_guard.py` refuses tools it does not know. Do not improvise a raw `curl` or SDK call. Tell
the user which provider is involved, propose the GET-only endpoints you would use, and extend
`ro_guard.py` (a new `check_<tool>` function with a verb allowlist and a secret-reading
denylist) only after they agree. If nothing outside Terraform is needed, a `terraform plan`
alone already performs the provider's own read calls.
