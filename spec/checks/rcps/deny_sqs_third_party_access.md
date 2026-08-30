---
id: deny_sqs_third_party_access
kind: rcp
status: implemented
applies_to:
  - headroom/checks/rcps/deny_sqs_third_party_access.py
  - headroom/aws/sqs.py
depends_on:
  - INV-01
  - INV-02
  - INV-04
  - INV-06
  - INV-13
  - INV-16
verification:
  - tests/test_checks_deny_sqs_third_party_access.py
  - tests/test_aws_sqs.py
---

# deny_sqs_third_party_access

## Objective

Deny SQS access by any principal outside the organization except the third-party
accounts that queue policies already grant.

### Scope

Queue access policies, in every enabled region.

### Non-goals

- Does not read the KMS key policy protecting an encrypted queue.
- Does not evaluate `Condition`, `Resource`/`NotResource`, or `NotAction`.
- Does not distinguish a dead-letter queue from any other.

## Enforced statement

The standard RCP allowlist statement, with:

```
Sid:    DenySQSThirdPartyAccess
Action: sqs:*
```

Terraform variables: `deny_sqs_third_party_access` and
`sqs_third_party_access_account_ids_allowlist`.

## Evidence

Per enabled region: `sqs:ListQueues` (paginated), then `sqs:GetQueueAttributes`
requesting `Policy` and `QueueArn` per queue.

For each `Allow` statement: `NotPrincipal` presence, `Principal`, `Action`.
Permitted principal types are `AWS`, `Service`, and `Federated`.

## Decision table

| State | Condition | Category |
|---|---|---|
| Violation | A wildcard principal — literal `*`, or an `Allow` with `NotPrincipal` | `VIOLATION` |
| Compliant | Third-party account IDs only | `COMPLIANT` |
| Exemption | — | Never produced |
| Not recorded | The queue has no policy | Not in the output |
| Aborts | A `Federated` principal | The run aborts |
| Silently dropped | Unparseable policy JSON, or an unrecognized principal key | Logged at warning and skipped |

## Failure behavior

| Situation | Behavior |
|---|---|
| `AWS.SimpleQueueService.NonExistentQueue` or `QueueDoesNotExist` | The queue was deleted mid-scan; skipped |
| No `Policy` attribute | Skipped; the queue grants nothing |
| Any other `ClientError` in any region | Logged and re-raised, aborting the run |
| `Statement` neither object nor list | `MalformedPolicyError`, aborting the run |
| A `Federated` principal | `UnsupportedPrincipalTypeError`, aborting the run |
| Unparseable policy JSON, or `UnknownPrincipalTypeError` | **Logged at warning; the queue is skipped** |

## Known conflict: an unreadable queue policy or principal is skipped

The last row of the table above is a divergence from every other analyzer, and
it runs against INV-01: a queue whose policy could not be read is dropped rather
than blocking the account, so the account can be cleared for the RCP on the
strength of a queue nobody managed to evaluate. Elsewhere, an unparseable policy
aborts.

That row covers two distinct inputs. Unparseable policy JSON is conflict 3. A
`CanonicalUser` principal is conflict 4b, and is the worse of the two: this is
the only analyzer that catches `UnknownPrincipalTypeError`, so a principal no
allowlist can express is counted as no finding at all. ECR and KMS let that same
exception abort, Secrets Manager aborts on `UnsupportedPrincipalTypeError`
instead, and [`deny_s3_third_party_access`](deny_s3_third_party_access.md)
records the principal as a violation.

**Status: unresolved.** Recorded rather than fixed, because raising here changes
which accounts are cleared. Conflicts 3 and 4b in [`../index.md`](../index.md).

## Known conflict: aborting on a `Federated` principal

A `Federated` principal raises `UnsupportedPrincipalTypeError` and stops the run,
the same divergence as
[`deny_ecr_third_party_access`](deny_ecr_third_party_access.md). This check
therefore aborts on one principal type no allowlist can express and silently
skips another.

**Status: unresolved.** Conflict 4 in [`../index.md`](../index.md).

## Result contract

`_build_results_data` is **overridden**:

| Key | Holds |
|---|---|
| `queues_third_parties_can_access` | Violations plus compliant |
| `queues_with_wildcards` | Violations only |

Summary fields beyond the common three: `total_queues_analyzed`,
`queues_third_parties_can_access`, `queues_with_wildcards`, `violations`,
`unique_third_party_accounts`, `third_party_account_count`,
`actions_by_third_party_account`, `queues_by_third_party_account`.

Entry shape: `queue_url`, `queue_arn`, `region`, `third_party_account_ids`,
`has_wildcard_principal`, `has_non_account_principals`, `actions_by_account`.

**`actions_by_account` is not filtered to third parties here.** Every principal
account is keyed into it, in-organization accounts included, so
`actions_by_third_party_account` and `queues_by_third_party_account` in the
summary carry in-organization account IDs despite their names. ECR, KMS, S3, and
Secrets Manager all filter. Nothing downstream reads these fields — the allowlist
comes from `unique_third_party_accounts`, which **is** filtered — so this is a
reporting defect, not a policy defect.

`has_non_account_principals` is always `false` on a returned entry, for the same
reason as in
[`deny_secrets_manager_third_party_access`](deny_secrets_manager_third_party_access.md).

## Known conflict: the third-party action map counts in-organization accounts

`actions_by_third_party_account` and `queues_by_third_party_account` carry
in-organization account IDs, as described under Result contract above. A
reporting defect only: the allowlist is built from `unique_third_party_accounts`,
which is filtered, and nothing downstream reads the unfiltered fields.

**Status: unresolved.** Conflict 6 in [`../index.md`](../index.md).

## Placement and generated policy

RCP placement: blocked at `violations > 0`; the allowlist is the union of
`unique_third_party_accounts` across covered accounts.

## Accepted limitations

1. Unparseable policies are dropped rather than blocking; see Failure behavior.
2. `actions_by_third_party_account` includes in-organization accounts.
3. A `Federated` principal aborts rather than blocking.
4. `Condition`, `Resource`, and `NotAction` are not evaluated.
5. The queue-level filter for third-party or wildcard findings lives in the
   check's `analyze`, not in the analyzer, which appends every queue that has a
   policy.

## Acceptance scenarios

1. A queue policy granting `111111111111`, outside the organization → compliant,
   and the account enters the allowlist.
2. The same, where the account is in the organization → not recorded, but the
   account **does** appear in `actions_by_third_party_account`; see limitation 2.
3. A queue policy with `Principal: "*"` → violation; the account is blocked for
   SQS only.
4. A queue with no `Policy` attribute → skipped.
5. A queue deleted between listing and reading → skipped.
6. `AccessDenied` in one region → the run aborts.
7. A queue whose policy is not valid JSON → logged and skipped; the account can
   still be cleared. This is limitation 1.

## Referenced invariants

INV-01 (see Failure behavior), INV-02, INV-04, INV-06, INV-13, INV-16.

## Implementation

- `headroom/checks/rcps/deny_sqs_third_party_access.py`
- `headroom/aws/sqs.py` — `analyze_sqs_queue_policies`
- `test_environment/modules/rcps/locals.tf`
- Tests: `tests/test_checks_deny_sqs_third_party_access.py`,
  `tests/test_aws_sqs.py`
