---
id: deny_service_confused_deputy
kind: rcp
status: implemented
applies_to:
  - headroom/checks/rcps/deny_service_confused_deputy.py
  - headroom/aws/policy_documents.py
depends_on:
  - INV-01
  - INV-02
  - INV-06
  - INV-10
verification:
  - tests/test_checks_deny_service_confused_deputy.py
  - tests/test_aws_policy_documents.py
---

# deny_service_confused_deputy

## Objective

Narrow the AWS service exemption the other six RCP statements grant.

A service call carries no `aws:PrincipalOrgID`, so each of those statements must
exempt service principals or it would deny every service integration in the
organization. That exemption is a hole: a service acting on an out-of-organization
caller's behalf reaches organization resources through it. This statement closes
the hole for calls that say who they are acting for.

### Scope

Service calls that populate `aws:SourceAccount`, across the six services the
other statements cover.

### Non-goals

- Does not reach a call populating only `aws:SourceArn`, or no source key at
  all. `Null` on `aws:SourceAccount` scopes the deny to calls carrying that one
  key.
- Does not evaluate `Condition`, `Resource`, or `NotAction` on the policies it
  reads, as no RCP check does
  ([`../../contracts/policy-model.md`](../../contracts/policy-model.md)).
- Does not report a service principal trusted with no source guard at all. See
  limitation 1, which is this check's principal deployment risk.

## Enforced statement

```
Effect:    Deny
Principal: *
Action:    ecr:*, kms:*, s3:*, secretsmanager:*, sqs:*, sts:AssumeRole
Resource:  *
Condition: StringNotEqualsIfExists
             aws:SourceOrgID  = <this organization>
             aws:SourceAccount = <allowlist>     (only when non-empty)
           Null
             aws:SourceAccount = "false"
```

`StringNotEqualsIfExists` on `aws:SourceOrgID` catches sources in standalone
accounts, which belong to no organization and so carry no organization ID.

The `aws:SourceAccount` key is merged in only when the allowlist is non-empty
(INV-06): rendered empty it would deny every source rather than none.

## Evidence

No API calls of its own. The check reads `service_principal_sources` off the
analyses the other six already produce, so the estate is scanned once:

| Analyzer | Resource identifier | Region |
|---|---|---|
| `analyze_ecr_policies` | Repository name, or `"registry"` for a registry policy | Yes |
| `analyze_kms_key_policies` | Key ID | Yes |
| `analyze_s3_bucket_policies` | Bucket name | No — global |
| `analyze_secrets_manager_policies` | Secret name | No |
| `analyze_sqs_queue_policies` | Queue ARN | Yes |
| `analyze_iam_roles_trust_policies` | Role name | No — global |

`read_service_principal_sources` in
[`../../contracts/policy-model.md`](../../contracts/policy-model.md) is the one
rule all six read a source guard by.

A finding is kept only when it names out-of-organization source accounts, names
a source no allowlist can enumerate, or could not be read. Everything else is
dropped before categorization.

## Decision table

| State | Condition | Category |
|---|---|---|
| Violation | `has_wildcard_source` — the guard names sources no allowlist can enumerate | `VIOLATION` |
| Violation | `read_failure` is set — the source guard could not be read | `VIOLATION` |
| Compliant | The guard names out-of-organization accounts, all enumerable | `COMPLIANT` |
| Not recorded | An unguarded service principal, or a guard naming only organization sources | Dropped before categorization |

A failed read is a violation for the same reason a wildcard source is: the
account's allowlist cannot be computed, so the statement must be withheld rather
than deployed against a guess (INV-01).

## Failure behavior

| Failure | Behavior |
|---|---|
| Any `ClientError` from the six analyzers | Propagates, aborting the run (INV-02) |
| A source key under an operator that does not pin it, an `aws:SourceAccount` value that is neither an account ID nor a wildcard, or an unreadable organization scope | Recorded as `read_failure` on the finding, which makes it a violation |

The second row is deliberate and is the one place this check does not abort. The
reader sits inside all six analyzers, and six pre-existing checks share them
without ever reading a source guard, so raising would take
`deny_s3_third_party_access` and its five siblings down with it. Recording the
failure withholds this statement from the account without disturbing theirs.

## Result contract

Base document shape. Entry fields: `resource_type` (`ecr`, `kms`, `s3`,
`secretsmanager`, `sqs`, or `iam`), `resource_identifier`, `region` (null for a
global resource), `service_principal` (null when the read failed before any
principal resolved), `source_account_ids`, `has_source_condition`,
`has_wildcard_source`, `read_failure`.

Summary fields beyond the common three:

| Key | Meaning |
|---|---|
| `violations` | Count. **This is the field placement reads.** |
| `unique_third_party_accounts` | The statement's `aws:SourceAccount` allowlist |
| `third_party_account_count` | Its length |

## Placement and generated policy

| | |
|---|---|
| Terraform variable | `deny_service_confused_deputy` |
| Allowlist variable | `service_confused_deputy_source_account_ids_allowlist` |
| Allowlist round trip | `unique_third_party_accounts` → `third_party_accounts` → placement union → module parameter (INV-07) |
| Placement input | `summary.violations` |

The allowlist variable carries `source_` before `account_ids`, unlike its six
siblings, because the list holds the accounts a service acted **for** rather
than the calling principals. The naming pattern would predict
`service_confused_deputy_account_ids_allowlist`. Do not normalize it; the
Terraform module defines it this way.

`RCP_TERRAFORM_VARIABLES` places it after the alphabetical run of the six
services rather than inside it, because it names no single service.

## Accepted limitations

1. **A service principal trusted with no source guard is dropped, not
   reported.** Every service role trust policy and every log bucket in an
   account carries one, and listing them would bury the sources that matter.
   Dropping them is not the same as their being safe: `aws:SourceAccount` is
   populated by the calling service from the resource that drove the call, so an
   unguarded trust driven by an out-of-organization account is within the
   statement's reach and will be denied on deploy. The policy does not name that
   account, so discovery cannot find it — only CloudTrail can. **This is the
   check's principal deployment risk.**
2. **One statement covers six services**, so one verdict gates all of them
   (INV-10 holds only because the statement is single). A violation found on one
   SQS queue withholds the statement protecting ECR, KMS, S3, Secrets Manager,
   and STS in that account too.
3. Organization scopes are compared exactly, with no wildcard expansion.
4. A call populating only `aws:SourceArn` is outside the statement, so a service
   integration guarded that way is neither measured nor protected.

## Acceptance scenarios

1. An S3 bucket policy trusting `logging.s3.amazonaws.com` with
   `aws:SourceAccount` naming an out-of-organization account → compliant, and
   that account reaches `unique_third_party_accounts`.
2. The same guard naming only organization accounts → not recorded at all.
3. A guard whose `aws:SourceAccount` is a wildcard → violation, and the account
   is not cleared.
4. A guard naming `aws:SourceOrgID` for a different organization → the source is
   out of organization and is recorded.
5. A statement whose source guard cannot be read → violation with `read_failure`
   set, and the other six checks still complete.
6. A queue trusting `sns.amazonaws.com` with no source guard → not recorded
   (limitation 1).
7. An account matching scenario 3 → `summary.violations` is 1 and placement does
   not clear it.

## Referenced invariants

INV-01, INV-02, INV-06, INV-10.

## Implementation

- `headroom/checks/rcps/deny_service_confused_deputy.py` — class
  `DenyServiceConfusedDeputyCheck`, dataclass `ServicePrincipalSourceFinding`
- `headroom/aws/policy_documents.py` — `read_service_principal_sources`,
  `has_actionable_service_principal_source`, `unreadable_service_principal_source`
- `headroom/terraform/generate_rcps.py` — `RCP_TERRAFORM_VARIABLES`
- `test_environment/modules/rcps/locals.tf` — the rendered statement
- Tests: `tests/test_checks_deny_service_confused_deputy.py`,
  `tests/test_aws_policy_documents.py`
