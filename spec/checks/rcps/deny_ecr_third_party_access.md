---
id: deny_ecr_third_party_access
kind: rcp
status: implemented
applies_to:
  - headroom/checks/rcps/deny_ecr_third_party_access.py
  - headroom/aws/ecr.py
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
`ecr:GetRepositoryPolicy` per repository.

For each `Allow` statement: `NotPrincipal` presence, `Principal`, `Action`.
Permitted principal types are `AWS` and `Service`.

## Decision table

| State | Condition | Category |
|---|---|---|
| Violation | A wildcard principal — literal `*`, or an `Allow` with `NotPrincipal` | `VIOLATION` |
| Compliant | Third-party account IDs only | `COMPLIANT` |
| Exemption | — | Never produced |
| Not recorded | Only in-organization principals or AWS services | Not in the output |
| Aborts | A `Federated` or `CanonicalUser` principal | The run aborts; see below |

## Failure behavior

| Situation | Behavior |
|---|---|
| `RepositoryPolicyNotFoundException` | The repository is skipped; it grants nothing. Only a repository with a third-party account or a wildcard reaches the results list |
| Any other `ClientError` on one repository | Re-raised, aborting the run |
| `ClientError` in any region | Logged and re-raised, aborting the run |
| Unparseable policy JSON | Not caught; propagates and aborts |
| `Statement` neither object nor list | `MalformedPolicyError` |
| A `Federated` principal | `UnsupportedPrincipalTypeError`, aborting the run |
| A `CanonicalUser` or other unrecognized principal key | `UnknownPrincipalTypeError`, aborting the run |

**Aborting on a `Federated` principal is a known divergence.** Such a principal
carries no account ID and so blocks the account, exactly as a wildcard does —
[`deny_s3_third_party_access`](deny_s3_third_party_access.md) records that as a
violation and lets the rest of the organization generate, while this check stops
the whole run. Reporting is the better behavior; changing it changes which
policies are generated, so it is recorded here rather than fixed. See
[`../index.md`](../index.md).

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

Entry shape: `repository_name`, `repository_arn`, `region`,
`third_party_account_ids`, `actions_by_account`, `has_wildcard_principal`.

`actions_by_account` is filtered to third-party accounts.

## Placement and generated policy

RCP placement: blocked at `violations > 0`; the allowlist is the union of
`unique_third_party_accounts` across covered accounts.

## Accepted limitations

1. The registry-level policy is unread, so cross-account replication configured
   there is invisible.
2. `Condition`, `Resource`, and `NotAction` are not evaluated.
3. A `Federated` principal aborts rather than blocking; see Failure behavior.
4. An `Action` that is neither a string nor a list yields no actions rather than
   raising, so a malformed action silently contributes nothing to
   `actions_by_account`. The account still enters the allowlist.

## Acceptance scenarios

1. A repository policy granting `111111111111`, outside the organization →
   compliant, and the account enters the allowlist.
2. The same, where the account is in the organization → not recorded.
3. A repository policy with `Principal: "*"` → violation; the account is blocked
   for ECR only.
4. A repository with no policy → recorded as granting nothing.
5. A `Deny` statement naming a third party → not recorded; only `Allow` grants.
6. A repository policy with a `Federated` principal → the run aborts.

## Referenced invariants

INV-01, INV-02, INV-04, INV-06, INV-13, INV-16.

## Implementation

- `headroom/checks/rcps/deny_ecr_third_party_access.py`
- `headroom/aws/ecr.py` — `analyze_ecr_repository_policies`
- `test_environment/modules/rcps/locals.tf`
- Tests: `tests/test_checks_deny_ecr_third_party_access.py`,
  `tests/test_aws_ecr.py`
