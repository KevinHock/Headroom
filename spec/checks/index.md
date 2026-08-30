# Checks

One document per registered check. Each is normative for that check and nothing
else; anything true of every check belongs in
[`../architecture/check-framework.md`](../architecture/check-framework.md),
[`../contracts/policy-model.md`](../contracts/policy-model.md), or
[`../invariants.md`](../invariants.md).

`tests/test_spec_corpus.py` fails when a registered check has no document here,
or a document here names no registered check.

## SCP checks

| Check | Pattern | Scope | Allowlist | Exemptions |
|---|---|---|---|---|
| [`deny_ec2_ami_owner`](scps/deny_ec2_ami_owner.md) | 5c | Regional | `ec2_allowed_ami_owners` | — |
| [`deny_ec2_imds_hop_limit`](scps/deny_ec2_imds_hop_limit.md) | 2 | Regional | — | — |
| [`deny_ec2_imds_v1`](scps/deny_ec2_imds_v1.md) | 4 | Regional | — | Instance tag |
| [`deny_ec2_public_ip`](scps/deny_ec2_public_ip.md) | 2 | Regional | — | — |
| [`deny_eks_create_cluster_without_tag`](scps/deny_eks_create_cluster_without_tag.md) | 3 | Regional | — | — |
| [`deny_iam_saml_provider_not_aws_sso`](scps/deny_iam_saml_provider_not_aws_sso.md) | 1 | Global | — | — |
| [`deny_iam_user_creation`](scps/deny_iam_user_creation.md) | 5b | Global | `iam_allowed_users` | — |
| [`deny_lambda_auth_type_none`](scps/deny_lambda_auth_type_none.md) | 2 | Regional | — | — |
| [`deny_rds_unencrypted`](scps/deny_rds_unencrypted.md) | 2 | Regional | — | — |

## RCP checks

Every RCP check implements pattern 5a and generates the same statement shape,
differing only in `Action` and in which allowlist variable feeds it. The shared
statement is specified once in
[`../contracts/policy-model.md`](../contracts/policy-model.md).

| Check | Scope | Action denied | Non-account principals |
|---|---|---|---|
| [`deny_ecr_third_party_access`](rcps/deny_ecr_third_party_access.md) | Regional | `ecr:*` | Recorded as violations |
| [`deny_kms_third_party_access`](rcps/deny_kms_third_party_access.md) | Regional | `kms:*` | Recorded as violations |
| [`deny_s3_third_party_access`](rcps/deny_s3_third_party_access.md) | Global | `s3:*` | Recorded as violations |
| [`deny_secrets_manager_third_party_access`](rcps/deny_secrets_manager_third_party_access.md) | Regional | `secretsmanager:*` | Recorded as violations |
| [`deny_sqs_third_party_access`](rcps/deny_sqs_third_party_access.md) | Regional | `sqs:*` | Recorded as violations |
| [`deny_sts_third_party_assumerole`](rcps/deny_sts_third_party_assumerole.md) | Global | `sts:AssumeRole` | **Not a finding** — its RCP denies `sts:AssumeRole` alone, which a federated identity cannot call |

The five resource-policy analyzers read the `Principal` element through one
function, `read_principal`, and reach one verdict from it. The sixth reads the
same facts and acts on two of the three, for the reason its column gives.
[`../contracts/policy-model.md`](../contracts/policy-model.md) owns the rule.

## The per-check document contract

Every document carries this frontmatter, validated by
`tests/test_spec_corpus.py`:

| Field | Meaning |
|---|---|
| `id` | The registered check name. Must equal the filename stem. |
| `kind` | `scp` or `rcp`. Must match the directory and the registry. |
| `status` | `implemented`, `planned`, or `deprecated`. |
| `applies_to` | Repository paths this document is normative for. Each must exist. |
| `depends_on` | Global invariant IDs the check relies on. Each must be defined in [`../invariants.md`](../invariants.md). |
| `verification` | Test files that pin this check's behavior. Each must exist. |

And these sections, in this order:

1. **Objective**, with **Scope** and **Non-goals**
2. **Enforced statement** — the effect, action, resource, and conditions, plus
   the policy pattern
3. **Evidence** — the AWS APIs called and the attributes read
4. **Decision table** — compliant, violation, exemption, blocked, unknown
5. **Failure behavior** — what happens on `AccessDenied`, an unreadable region,
   a missing or unparseable policy
6. **Result contract** — the summary fields and entry shape this check writes
7. **Placement and generated policy** — the Terraform variables, and the
   allowlist round trip where there is one
8. **Accepted limitations** — evidence-based, never speculative
9. **Acceptance scenarios** — concrete inputs and their expected verdicts
10. **Referenced invariants**
11. **Implementation** — links to source and tests

A **Known conflict** section appears only where one exists, and says
`Status: unresolved`. The register below and the check documents are two views
of one set: every check the register's **Where** column names carries such a
section, and every check carrying one is named there. A conflict recorded in
only one of the two is a conflict half its readers never see.

## Unresolved conflicts

Places where the implementation and this corpus disagree. Each is **reported,
not fixed**, because resolving it changes which policies are generated — and
[`../README.md`](../README.md) requires reporting a conflict rather than guessing
which side is right.

**The numbers are stable identifiers, not positions.** They are cited from the
check documents, so a resolved conflict leaves its number retired rather than
renumbering the rest. Six are retired, which is why one row is left and it is
numbered 6:

| Retired | Was | Fixed by |
|---|---|---|
| 1 | `deny_iam_saml_provider_not_aws_sso` reported no violation count | It now writes the count placement reads |
| 2 | `deny_iam_user_creation` rendered an empty `NotResource` | It now leaves its policy off instead |
| 3 | `deny_sqs_third_party_access` skipped an unparseable queue policy | It now aborts, as every other resource-policy analyzer does |
| 4 | ECR, KMS, Secrets Manager, and SQS aborted the run on a `Federated` principal, where S3 recorded it | All five now record it as a violation, through one reader, `read_principal` |
| 4b | `deny_sqs_third_party_access` skipped a queue naming a `CanonicalUser` principal, clearing the account | Same reader: `CanonicalUser` is a documented principal type and now blocks the account like any other principal no allowlist can carry |
| 5 | `deny_eks_create_cluster_without_tag` matched the tag key case-sensitively | Both tag checks now share one reader, `find_tag_value_as_iam_matches` |

| # | Where | Conflict |
|---|---|---|
| 6 | [`deny_sqs_third_party_access`](rcps/deny_sqs_third_party_access.md) | `actions_by_third_party_account` includes in-organization accounts. A reporting defect only; the allowlist is built from a filtered field. |

Two further gaps are recorded where they belong rather than here, because they
are limitations of the design rather than disagreements with it: KMS grants are
unread ([`deny_kms_third_party_access`](rcps/deny_kms_third_party_access.md)),
and `s3:ListBuckets` is not paginated
([`deny_s3_third_party_access`](rcps/deny_s3_third_party_access.md)).

## Statements with no check

The SCP module emits one statement that no registered check gates:

| Sid | Statement | When |
|---|---|---|
| `DenyRootLeaveOrganization` | `Deny organizations:LeaveOrganization on *` | The module's `target_id` starts with `r-` |

It needs no check because it can never break an existing workload: no account
should be leaving the organization, and nothing an account does in the ordinary
course invokes it. It is documented in
[`../contracts/terraform.md`](../contracts/terraform.md) rather than here,
because it belongs to the module rather than to the check framework.

## Adding a check

Write the specification first — `tests/test_spec_corpus.py` fails until it
exists. Then
[`../../HOW_TO_ADD_A_CHECK.md`](../../HOW_TO_ADD_A_CHECK.md) for the
implementation walkthrough, and
[`../architecture/check-framework.md`](../architecture/check-framework.md) for
what the framework requires.
