---
id: deny_sqs_third_party_access
kind: rcp
status: implemented
applies_to:
  - headroom/checks/rcps/deny_sqs_third_party_access.py
  - headroom/aws/sqs.py
  - headroom/aws/policy_documents.py
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
  - tests/test_aws_policy_documents.py
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
The `Principal` element is read by `read_principal` against
`RESOURCE_POLICY_PRINCIPAL_TYPES`
([`../../contracts/policy-model.md`](../../contracts/policy-model.md)).

## Decision table

| State | Condition | Category |
|---|---|---|
| Violation | A wildcard principal — literal `*`, or an `Allow` with `NotPrincipal` | `VIOLATION` |
| Violation | A `Federated` or `CanonicalUser` principal | `VIOLATION` |
| Compliant | Third-party account IDs only | `COMPLIANT` |
| Exemption | — | Never produced |
| Not recorded | The queue has no policy | Not in the output |
| Aborts | Unparseable policy JSON, or a principal key AWS does not document | The run aborts |

## Failure behavior

| Situation | Behavior |
|---|---|
| `AWS.SimpleQueueService.NonExistentQueue` or `QueueDoesNotExist` | The queue was deleted mid-scan; skipped |
| No `Policy` attribute | Skipped; the queue grants nothing |
| Any other `ClientError` in any region | Logged and re-raised, aborting the run |
| `Statement` neither object nor list | `MalformedPolicyError`, aborting the run |
| Unparseable policy JSON | `json.JSONDecodeError`, aborting the run |
| A principal key outside the four documented types | `UnknownPrincipalTypeError`, aborting the run |
| An `Action` that is neither a string nor a list | `TypeError`, aborting the run |

**This analyzer catches nothing a policy document can raise.** It once caught
`UnknownPrincipalTypeError` and skipped the queue, which cleared the account on
the strength of a queue nobody had read, against INV-01, and it once raised on
a `Federated` principal and stopped the whole run. Both are fixed: a principal
no allowlist can carry is now a violation like any other blocker, and a
principal key AWS does not document aborts here exactly as it does everywhere
else. The rule is stated once in
[`../../contracts/policy-model.md`](../../contracts/policy-model.md).

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

Every entry also carries `service_principal_sources`, which this check does not
read. It is recorded here because the estate is scanned once, and it is read by
[`deny_service_confused_deputy`](deny_service_confused_deputy.md).

`actions_by_account` is filtered to third-party accounts, as it is in ECR, KMS,
S3, and Secrets Manager. The organization filter runs where an account is
admitted rather than over a set collected first, so the entry's account set and
its action map cannot disagree, and the summary's
`actions_by_third_party_account` and `queues_by_third_party_account` hold what
their names say.

`has_non_account_principals` is always `false` on a returned entry, for the same
reason as in
[`deny_secrets_manager_third_party_access`](deny_secrets_manager_third_party_access.md).

## Placement and generated policy

RCP placement: blocked at `violations > 0`; the allowlist is the union of
`unique_third_party_accounts` across covered accounts.

## Accepted limitations

1. `Condition`, `Resource`, and `NotAction` are not evaluated.
2. The queue-level filter for third-party or wildcard findings lives in the
   check's `analyze`, not in the analyzer, which appends every queue that has a
   policy.
3. AWS documents federated principals only for role trust policies, so a
   `Federated` principal in a queue policy may grant nothing at all. It is still
   counted as a blocker, because whether the grant is live is not readable from
   the document and INV-01 forbids assuming it is not.

## Acceptance scenarios

1. A queue policy granting `111111111111`, outside the organization → compliant,
   and the account enters the allowlist.
2. The same, where the account is in the organization → not recorded anywhere:
   neither in `third_party_account_ids` nor in `actions_by_account`.
3. A queue policy with `Principal: "*"` → violation; the account is blocked for
   SQS only.
4. A queue with no `Policy` attribute → skipped.
5. A queue deleted between listing and reading → skipped.
6. `AccessDenied` in one region → the run aborts.
7. A queue whose policy is not valid JSON → the run aborts.
8. A queue naming a `CanonicalUser` principal → violation; the account is
   blocked for SQS, and the remaining queues are still read.
9. A queue naming a `Federated` principal → violation, on the same grounds.
10. A queue naming a principal key AWS does not document → the run aborts.

## Referenced invariants

INV-01 (see Failure behavior), INV-02, INV-04, INV-06, INV-13, INV-16.

## Implementation

- `headroom/checks/rcps/deny_sqs_third_party_access.py`
- `headroom/aws/sqs.py` — `analyze_sqs_queue_policies`
- `headroom/aws/policy_documents.py` — `read_principal`
- `test_environment/modules/rcps/locals.tf`
- Tests: `tests/test_checks_deny_sqs_third_party_access.py`,
  `tests/test_aws_sqs.py`, `tests/test_aws_policy_documents.py`
