---
id: deny_ecr_third_party_access
kind: rcp
status: implemented
applies_to:
  - headroom/checks/rcps/deny_ecr_third_party_access.py
  - headroom/aws/ecr.py
  - headroom/aws/policy_documents.py
depends_on:
  - INV-01
  - INV-02
  - INV-04
  - INV-06
  - INV-13
  - INV-16
verification:
  - tests/test_checks_deny_ecr_third_party_access.py
  - tests/test_aws_ecr.py
  - tests/test_aws_policy_documents.py
---

# deny_ecr_third_party_access

## Objective

Deny ECR access by any principal outside the organization except the third-party
accounts that repository policies already grant, so a container image cannot be
pulled — or pushed — by a new external account.

### Scope

Private ECR repository policies, in every enabled region.

### Non-goals

- Does not read the registry-level policy (`ecr:PutRegistryPolicy`), which
  governs cross-account replication and pull-through cache.
- Does not read ECR Public.
- Does not evaluate `Condition`, `Resource`/`NotResource`, or `NotAction`.

## Enforced statement

The standard RCP allowlist statement, with:

```
Sid:    DenyECRThirdPartyAccess
Action: ecr:*
```

Terraform variables: `deny_ecr_third_party_access` and
`ecr_third_party_access_account_ids_allowlist`.

## Evidence

Per enabled region: `ecr:DescribeRepositories` (paginated), then
`ecr:GetRepositoryPolicy` per repository, and `ecr:GetRegistryPolicy` once.

ECR authorizes through two policies rather than one, and they are separate
resources rather than two halves of the same one, so each gets its own analysis
and `scope` says which was read. A registry policy AWS enforces on every ECR
request in the region governs no single repository, so its analysis carries no
repository name or ARN. `RegistryPolicyNotFoundException` means the region has
none and is not a failure. Both policies share one statement reader, because
they share a grammar; what differs is reach.

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
| Not recorded | Only in-organization principals or AWS services | Not in the output |
| Aborts | A principal key AWS does not document | The run aborts |

## Failure behavior

| Situation | Behavior |
|---|---|
| `RepositoryPolicyNotFoundException` | The repository is skipped; it grants nothing. Only a repository with a third-party account or a wildcard reaches the results list |
| Any other `ClientError` on one repository | Re-raised, aborting the run |
| `ClientError` in any region | Logged and re-raised, aborting the run |
| Unparseable policy JSON | Not caught; propagates and aborts |
| `Statement` neither object nor list | `MalformedPolicyError` |
| A principal key outside the four documented types | `UnknownPrincipalTypeError`, aborting the run |
| An `Action` that is neither a string nor a list | `TypeError`, aborting the run |

A `Federated` or `CanonicalUser` principal used to raise here and stop the whole
run. It is now a violation: the principal carries no account ID, so
the allowlist cannot preserve it and the account must not take this RCP, which
is what recording a violation says. Aborting said the same thing at the cost of
every other account's results. The rule is stated once in
[`../../contracts/policy-model.md`](../../contracts/policy-model.md).

## Result contract

`_build_results_data` is **overridden**:

| Key | Holds |
|---|---|
| `repositories_third_parties_can_access` | Violations plus compliant |
| `repositories_with_wildcards` | Violations only |

Summary fields beyond the common three: `total_repositories_analyzed`,
`repositories_third_parties_can_access`, `repositories_with_wildcards`,
`violations`, `unique_third_party_accounts`, `third_party_account_count`,
`actions_by_account`.

Entry shape: `scope` (`"repository"` or `"registry"`), `region`,
`third_party_account_ids`, `repository_name`, `repository_arn`,
`actions_by_account`, `has_wildcard_principal`, `has_non_account_principals`.

`repository_name` and `repository_arn` are null on a registry-scoped entry,
which governs no single repository.

Every entry also carries `service_principal_sources`, which this check does not
read. It is recorded here because the estate is scanned once, and it is read by
[`deny_service_confused_deputy`](deny_service_confused_deputy.md).

`actions_by_account` is filtered to third-party accounts.

`repositories_with_wildcards` counts every violation, so a repository blocked
only by a principal carrying no account ID is counted there despite the name.
The same is true of the S3 and SQS fields of that shape.

## Placement and generated policy

RCP placement: blocked at `violations > 0`; the allowlist is the union of
`unique_third_party_accounts` across covered accounts.

## Accepted limitations

1. The registry-level policy is unread, so cross-account replication configured
   there is invisible.
2. `Condition`, `Resource`, and `NotAction` are not evaluated.
3. An `Action` that is neither a string nor a list yields no actions rather than
   raising, so a malformed action silently contributes nothing to
   `actions_by_account`. The account still enters the allowlist.
4. AWS documents federated principals only for role trust policies, so a
   `Federated` principal in a repository policy may grant nothing at all. It is
   still counted as a blocker, because whether the grant is live is not readable
   from the document and INV-01 forbids assuming it is not.

## Acceptance scenarios

1. A repository policy granting `111111111111`, outside the organization →
   compliant, and the account enters the allowlist.
2. The same, where the account is in the organization → not recorded.
3. A repository policy with `Principal: "*"` → violation; the account is blocked
   for ECR only.
4. A repository with no policy → recorded as granting nothing.
5. A `Deny` statement naming a third party → not recorded; only `Allow` grants.
6. A repository policy with a `Federated` principal → violation; the account is
   blocked for ECR, and the remaining repositories are still read.
7. A repository policy with a `CanonicalUser` principal → violation, on the same
   grounds.
8. A repository policy naming a principal key AWS does not document → the run
   aborts.

## Referenced invariants

INV-01, INV-02, INV-04, INV-06, INV-13, INV-16.

## Implementation

- `headroom/checks/rcps/deny_ecr_third_party_access.py`
- `headroom/aws/ecr.py` — `analyze_ecr_repository_policies`
- `headroom/aws/policy_documents.py` — `read_principal`
- `test_environment/modules/rcps/locals.tf`
- Tests: `tests/test_checks_deny_ecr_third_party_access.py`,
  `tests/test_aws_ecr.py`, `tests/test_aws_policy_documents.py`
