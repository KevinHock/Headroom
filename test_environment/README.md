# Test environment

A complete, reproducible AWS Organization for testing Headroom against real AWS.
Everything here is real infrastructure with real cost. It is **not** part of
`tox`, and nothing in it runs in CI.

This document is operational. The normative behavior it exercises is specified in
[`../spec/README.md`](../spec/README.md).

## What it is for

| Purpose | |
|---|---|
| Live integration testing | Confirm a generated policy actually denies what its check predicted |
| Reproducible demo | Anyone with an AWS Organization can stand up the same scenarios |
| Example outputs | `headroom_results/`, `scps/`, and `rcps/` are committed as worked examples |

A live result is evidence about **AWS**, not about Headroom. Where the two
disagree, the finding belongs in the affected check's specification under
[`../spec/checks/`](../spec/checks/index.md), measured with a `--dry-run` probe
and cited there.

## Topology

Four member accounts across three OUs, plus the management account:

```
Organization root
├── high_value_assets/     fort-knox
├── shared_services/       security-tooling, shared-foo-bar
└── acme_acquisition/      acme-co
```

Account emails are derived from a single `base_email` variable using plus
addressing, so one mailbox stands up the whole organization.

| File | Creates |
|---|---|
| `organizational_units.tf` | The three OUs |
| `accounts.tf` | The four member accounts |
| `headroom_roles.tf`, `modules/headroom_role/` | The `Headroom` role in each account |
| `org_and_account_info_reader.tf` | The `OrgAndAccountInfoReader` role in the management account |
| `providers.tf`, `data.tf`, `variables.tf` | Provider and input plumbing |

The `Headroom` role is granted the `ViewOnlyAccess` and `SecurityAudit` managed
policies. Role setup for a real organization is documented in
[`../documentation/SETUP.md`](../documentation/SETUP.md).

## Scenarios

Each scenario deliberately creates violations, exemptions, and compliant
resources for one check, so a run has something to find. Scenarios are either a
bare `.tf` file or a directory with its own `README.md`.

| Check | Scenario |
|---|---|
| `deny_ec2_ami_owner` | `test_deny_ec2_ami_owner/` |
| `deny_ec2_imds_hop_limit` | `test_deny_ec2_imds_hop_limit/` |
| `deny_ec2_imds_v1` | `test_deny_ec2_imds_v1/` |
| `deny_ec2_public_ip` | `test_deny_ec2_public_ip/` |
| `deny_iam_saml_provider_not_aws_sso` | `test_deny_iam_saml_provider_not_aws_sso.tf` |
| `deny_iam_user_creation` | `test_deny_iam_user_creation.tf` |
| `deny_lambda_auth_type_none` | `test_deny_lambda_auth_type_none.tf`, `test_deny_lambda_auth_type_none/` |
| `deny_rds_unencrypted` | `test_deny_rds_unencrypted/` |
| `deny_ecr_third_party_access` | `test_deny_ecr_third_party_access.tf` |
| `deny_kms_third_party_access` | `test_deny_kms_third_party_access.tf`, `test_deny_kms_third_party_access/` |
| `deny_s3_third_party_access` | `test_deny_s3_third_party_access.tf` |
| `deny_secrets_manager_third_party_access` | `test_deny_secrets_manager_third_party_access.tf`, `test_deny_secrets_manager_third_party_access/` |
| `deny_sqs_third_party_access` | `test_deny_sqs_third_party_access.tf` |
| `deny_sts_third_party_assumerole` | `test_deny_sts_third_party_assumerole.tf` |

`deny_eks_create_cluster_without_tag` has no live scenario. An EKS control plane
is the most expensive resource any check would need, and the check is covered by
unit tests only.

## Running it

Apply from the **management account**, which is the only identity that can create
organization accounts and OUs.

```bash
cd test_environment
cp terraform.tfvars.example terraform.tfvars   # set base_email
terraform init
terraform apply
```

Then run Headroom against it from the security analysis account:

```bash
cd ..
python -m headroom --config config.yaml
```

Results land in `test_environment/headroom_results/`, and generated Terraform in
`test_environment/scps/` and `test_environment/rcps/`. Both directories are
reconciled to the current run — a target that drops out of the recommendations
loses its file — so a diff there is the run's output, not an accumulation. See
[`../spec/contracts/terraform.md`](../spec/contracts/terraform.md).

To re-run a check, delete its result file. Existing results are treated as done
and are never refreshed on their own; see
[`../spec/contracts/results.md`](../spec/contracts/results.md).

## Cost

Organizations, OUs, IAM roles, IAM users, KMS aliases, and data sources are free.
The billable resources are:

| Resource | Count | Class |
|---|---|---|
| EC2 instances | 15 | `t2.nano` |
| RDS instances | 2 | `db.t3.micro` (`mysql`, `postgres`) |
| Aurora clusters | 2 | `aurora-mysql`, `aurora-postgresql` |
| Aurora cluster instances | 2 | `db.t3.medium` |
| KMS customer-managed keys | see `test_deny_kms_third_party_access.tf` | — |
| Secrets Manager secrets | see `test_deny_secrets_manager_third_party_access.tf` | — |

No dollar figure is quoted here on purpose: it depends on region and on which
scenarios are applied, and four different figures in the old specification had
all gone stale. Price the table above with the
[AWS Pricing Calculator](https://calculator.aws/) for your region before applying.

The databases dominate. `db.t3.medium` Aurora instances and always-on RDS
instances cost substantially more than the EC2 fleet.

**Apply only the scenarios you are testing.** `terraform apply` with no target
stands up all of them.

## Cleanup

```bash
terraform destroy
```

Two things `destroy` will not do:

1. **Member accounts are not deleted.** AWS Organizations accounts cannot be
   destroyed by Terraform. Closing one is a manual, ~90-day process from the
   console. Plan to reuse the accounts rather than recreate them.
2. **Secrets are not removed immediately.** Secrets Manager applies a recovery
   window; a secret continues to incur cost until it elapses, and its name cannot
   be reused before then.

To keep the organization but stop paying for it, destroy the compute:

```bash
terraform destroy -target=module.test_deny_ec2_imds_v1 \
                  -target=module.test_deny_rds_unencrypted
```

Check the module names in the root `.tf` files first — they change as scenarios
are added.

## Committed outputs

`headroom_results/`, `scps/`, and `rcps/` are committed deliberately, as worked
examples of what a run produces. They are illustrative, not normative: where they
disagree with [`../spec/`](../spec/README.md), the specification is right and the
committed output is stale.

**These files contain real AWS account IDs** belonging to third-party security
vendors, used as the third-party accounts the RCP scenarios grant access to. They
do not follow the fake-identifier convention in INV-15
([`../spec/invariants.md`](../spec/invariants.md)) because a trust policy naming a
non-existent account is rejected at apply time, so the live scenarios need real
ones. This is a known conflict with that invariant, recorded rather than
resolved.
