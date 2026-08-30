# Contract: policy model

Owns the vocabulary every check is written in: what an SCP and an RCP each
control, the patterns a generated statement can take, and the grammar by which
Headroom reads an existing policy document.

A per-check specification names the pattern it implements rather than restating
what the pattern is.

Implementation: `headroom/aws/policy_documents.py` (shared grammar),
`headroom/constants.py` (principal types, ARN pattern), and every service
adapter that reads a policy document — `aws/ecr.py`, `aws/kms.py`, `aws/s3.py`,
`aws/secretsmanager.py`, `aws/sqs.py`, `aws/iam/roles.py`. A change to how a
statement is read is a change to all of them.

## SCP versus RCP

| | SCP | RCP |
|---|---|---|
| Bounds | What principals **in** the account may do | Who may act **on** resources in the account |
| Evaluated against | Requests made by principals in the account | Requests made against resources in the account, including by principals outside the organization |
| Applies to the management account | No | No |
| Headroom's evidence | Resource configuration in the account | Resource policies and trust policies in the account |
| Headroom's blocking question | Does any resource already violate the statement? | Does any resource name a principal no allowlist can express? |
| Allowlist source | Values observed in the account | Third-party account IDs observed in the account's policies |

Both are Deny-only in Headroom. Nothing generated here grants access; a
statement either denies or is omitted.

## The generated patterns

Every statement Headroom generates is one of these. The taxonomy exists so a new
check declares its shape rather than inventing one.

| # | Pattern | Mechanism | Example check |
|---|---|---|---|
| 1 | **Absolute deny** | `Deny` with no condition | `deny_iam_saml_provider_not_aws_sso` |
| 2 | **Conditional deny** | `Deny` unless a condition key holds the required value | `deny_ec2_public_ip`, `deny_rds_unencrypted` |
| 3 | **Paved road** | `Deny` unless a request tag marks the blessed path | `deny_eks_create_cluster_without_tag` |
| 4 | **Exception tag** | `Deny` unless an exemption tag is present on the request | `deny_ec2_imds_v1` |
| 5a | **Principal account allowlist** | `Deny` unless `aws:PrincipalAccount` is allowlisted | every RCP check |
| 5b | **Resource ARN allowlist** | `Deny` with `NotResource` naming approved ARNs | `deny_iam_user_creation` |
| 5c | **Condition value allowlist** | `Deny` unless a condition key's value is allowlisted | `deny_ec2_ami_owner` |
| 6 | **Composition** | Two or more of the above in one statement | — |

### Pattern 3 versus pattern 4

Both condition on a tag; they mean opposite things.

| | 3 — paved road | 4 — exception tag |
|---|---|---|
| Says | "You did it the blessed way" | "You need an exception" |
| Lifecycle | Permanent | Temporary, and should be revisited |
| Audit stance | Encouraged | Scrutinized |
| Example tag | `PavedRoad=true` | `ExemptFromIMDSv2=true` |

Prefer 3. Reach for 4 only when there is a real workload that cannot take the
paved road, and name the tag for what it exempts.

### Pattern 5 variants

| | 5a | 5b | 5c |
|---|---|---|---|
| Constrains | **Who** — the principal | **What** — the resource | **Which value** — a condition key |
| Construct | `aws:PrincipalAccount` | `NotResource` | `Condition` value list |
| Granularity | Account | Resource ARN | Attribute |

Every 5-family statement is subject to INV-06: an empty allowlist denies
everything, so it is never rendered.

## The RCP allowlist statement

All six RCP checks generate the same shape, differing only in `Action` and in
which allowlist variable feeds them:

```
Effect:    Deny
Principal: "*"
Action:    <the service's actions>
Resource:  "*"
Condition: StringNotEqualsIfExists  aws:PrincipalOrgID   = <this organization>
           StringNotEqualsIfExists  aws:PrincipalAccount = <allowlist>   (omitted when empty)
           BoolIfExists             aws:PrincipalIsAWSService = "false"
```

Three consequences follow, and they are the same for every RCP check:

- **In-organization principals are never denied**, whatever the allowlist holds,
  because `aws:PrincipalOrgID` matches organization *membership* — which by
  INV-04 includes closed accounts and skipped accounts.
- **AWS service principals are never denied**, so a service acting on the
  resource on your behalf is unaffected.
- **The `aws:PrincipalAccount` clause is omitted entirely when the allowlist is
  empty**, rather than rendered as an empty list. With it omitted, the statement
  still denies every out-of-organization principal; rendered empty, the semantics
  would differ.

Terraform variables, by check:

| Check | Enable variable | Allowlist variable |
|---|---|---|
| `deny_ecr_third_party_access` | `deny_ecr_third_party_access` | `ecr_third_party_access_account_ids_allowlist` |
| `deny_kms_third_party_access` | `deny_kms_third_party_access` | `kms_third_party_access_account_ids_allowlist` |
| `deny_s3_third_party_access` | `deny_s3_third_party_access` | `s3_third_party_access_account_ids_allowlist` |
| `deny_secrets_manager_third_party_access` | `deny_secrets_manager_third_party_access` | `secrets_manager_third_party_account_ids_allowlist` |
| `deny_sqs_third_party_access` | `deny_sqs_third_party_access` | `sqs_third_party_access_account_ids_allowlist` |
| `deny_sts_third_party_assumerole` | `deny_sts_third_party_assumerole` | `sts_third_party_assumerole_account_ids_allowlist` |

The Secrets Manager allowlist variable has no `_access_` segment, unlike its five
siblings. The Terraform module defines it that way; it is not a typo to fix in
Python.

## Reading an existing policy document

This grammar is shared. A check does not re-derive it.

### Statements

`Statement` may be a lone object where a one-element list would do; IAM accepts
both, so both reach the analyzers and both are read as a list.

Anything else — a string, a number, `null` — raises `MalformedPolicyError`.
Reading it as no statements would report the resource as granting nothing, which
is not a safe guess (INV-01).

### Principals

| Form | Read as |
|---|---|
| `Principal: "*"` or `{"AWS": "*"}` | Wildcard — a blocker |
| `Allow` with `NotPrincipal` | Wildcard — grants to everyone except a short list, the same reach |
| `Deny` with `NotPrincipal` | Nothing — it restricts rather than grants, and a resource policy's Deny hands access to nobody |
| An account ID or an ARN | The 12-digit account ID it names |
| `Service` | Not an account principal |
| `Federated`, `CanonicalUser` | Carry no account ID; handled per check |

Callers must apply their own `Effect` gate **before** consulting `NotPrincipal`.
A statement carrying both `Principal` and `NotPrincipal` is not valid IAM and
cannot be stored; were one to arrive, it is treated as a wildcard rather than
letting the `Principal` half stand in for a broader grant.

The account ID is extracted from an ARN with a deliberately loose pattern: the
service segment is unconstrained, because a resource-policy principal can be an
STS session ARN as readily as an IAM one, and the partition is matched the same
way so GovCloud and China ARNs resolve.

`Federated` and `CanonicalUser` principals name no account, so no allowlist can
express them. They are **not** handled uniformly: the S3 analyzer records them
as violations, while the ECR, KMS, Secrets Manager, and SQS analyzers raise, and
the STS analyzer raises on a `CanonicalUser` or on a `Federated` principal
granted `sts:AssumeRole`. Each check's document states its own behavior.

### Actions

An action is matched the way IAM matches it — case-insensitively, honoring `*`
wildcards, and honoring `NotAction`. String comparison misses `sts:*`,
`sts:Assume*`, `STS:AssumeRole`, and every `NotAction`.

### What is deliberately not read

RCP analysis reads `Effect`, `Principal`, and `Action`. It reads neither
`Condition` nor `Resource`/`NotResource`.

Both omissions **widen** what the scan sees, and widening is the safe direction:

- A `Principal: "*"` narrowed by `aws:PrincipalOrgID` grants nothing outside the
  organization — it is the pattern AWS recommends for organization-wide bucket
  access — but is counted as a violation and blocks that account from the check's
  RCP.
- A grant narrowed by `s3:prefix`, `aws:SourceVpce`, or a lapsed `DateLessThan`
  still contributes its account to the allowlist at full width, so the account
  keeps a broader RCP allowance than it needs.
- A statement scoped away from the resource by `Resource`/`NotResource` still
  contributes its principals.

A condition or a resource scope can only ever narrow a grant, so neither can hide
a third party the scan should have found. No RCP generated under this limitation
breaks access a condition-aware scan would have preserved. The cost is coverage,
not safety, which is what makes it a roadmap item rather than a defect. See
[`../../ROADMAP.md`](../../ROADMAP.md).

## References

- [IAM policy elements](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html)
- [Service control policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- [Resource control policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html)
- [Organizations limits](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html#min-max-values)
