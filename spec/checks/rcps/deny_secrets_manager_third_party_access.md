---
id: deny_secrets_manager_third_party_access
kind: rcp
status: implemented
applies_to:
  - headroom/checks/rcps/deny_secrets_manager_third_party_access.py
  - headroom/aws/secretsmanager.py
depends_on:
  - INV-01
  - INV-02
  - INV-04
  - INV-06
  - INV-13
  - INV-16
verification:
  - tests/test_checks_deny_secrets_manager_third_party_access.py
  - tests/test_aws_secretsmanager.py
---

# deny_secrets_manager_third_party_access

## Objective

Deny Secrets Manager access by any principal outside the organization except the
third-party accounts that secret resource policies already grant.

### Scope

Secret resource policies, in every enabled region.

### Non-goals

- Does not read the KMS key policy protecting a secret. Access to the secret and
  access to its key are separate grants;
  [`deny_kms_third_party_access`](deny_kms_third_party_access.md) covers the
  second.
- Does not evaluate `Condition`, `Resource`/`NotResource`, or `NotAction`.
- Does not read rotation Lambda permissions.

## Enforced statement

The standard RCP allowlist statement, with:

```
Sid:    DenySecretsManagerThirdPartyAccess
Action: secretsmanager:*
```

Terraform variables: `deny_secrets_manager_third_party_access` and
`secrets_manager_third_party_account_ids_allowlist`.

**The allowlist variable has no `_access_` segment**, unlike its five siblings.
The Terraform module defines it that way; the Python table matches the module,
and normalizing it in Python would produce Terraform that fails at plan time on
an undeclared variable.

## Evidence

Per enabled region: `secretsmanager:ListSecrets` (paginated), then
`secretsmanager:GetResourcePolicy` per secret.

For each `Allow` statement: `NotPrincipal` presence, `Principal`, `Action`.
Permitted principal types are `AWS`, `Service`, and `Federated`.

## Decision table

| State | Condition | Category |
|---|---|---|
| Violation | A wildcard principal — literal `*`, or an `Allow` with `NotPrincipal` | `VIOLATION` |
| Compliant | Third-party account IDs only | `COMPLIANT` |
| Exemption | — | Never produced |
| Not recorded | Only in-organization principals or AWS services | Not in the output |
| Aborts | A `Federated` or `CanonicalUser` principal | The run aborts |

## Failure behavior

| Situation | Behavior |
|---|---|
| `ResourceNotFoundException` on one secret | The secret is skipped; it has no policy |
| An empty policy string | The secret is skipped |
| Any other `ClientError` on one secret | Logged and re-raised, aborting the run |
| `ClientError` listing secrets in any region | Logged and re-raised, aborting the run |
| Unparseable policy JSON | Not caught; propagates and aborts |
| `Statement` neither object nor list | `MalformedPolicyError` |
| A `Federated` principal | `UnsupportedPrincipalTypeError`, aborting the run |
| A `CanonicalUser` principal | `UnsupportedPrincipalTypeError`, aborting the run |
| Any other unrecognized principal key | `UnknownPrincipalTypeError`, aborting the run |
| An `Action` that is neither a string nor a list | `TypeError` |

## Known conflict: aborting on a `Federated` or `CanonicalUser` principal

The divergence described in
[`deny_ecr_third_party_access`](deny_ecr_third_party_access.md) applies here and
reaches one principal type further. This check tests for both types before it
extracts account IDs, so a `CanonicalUser` raises `UnsupportedPrincipalTypeError`
here where ECR and KMS reach `UnknownPrincipalTypeError` instead. The outcome is
the same — the run stops — and
[`deny_s3_third_party_access`](deny_s3_third_party_access.md) records both types
as violations.

**Status: unresolved.** Recorded rather than fixed, because changing it changes
which policies are generated. Conflict 4 in [`../index.md`](../index.md).

## Result contract

`_build_results_data` is **overridden**:

| Key | Holds |
|---|---|
| `secrets_third_parties_can_access` | Violations plus compliant |
| `secrets_with_wildcards` | Violations only |

Summary fields beyond the common three: `total_secrets_analyzed`,
`secrets_third_parties_can_access`, `secrets_with_wildcards`, `violations`,
`unique_third_party_accounts`, `third_party_account_count`,
`actions_by_third_party_account`, `secrets_by_third_party_account`.

Entry shape: `secret_name`, `secret_arn`, `third_party_account_ids`,
`has_wildcard_principal`, `has_non_account_principals`, `actions_by_account`.

**`has_non_account_principals` is always `false` on a returned entry.** The
analyzer sets the flag and then raises unconditionally, so the check's
`has_non_account_principals` violation branch is unreachable through the real
pipeline. The field is part of the wire format and is kept.

## Placement and generated policy

RCP placement: blocked at `violations > 0`; the allowlist is the union of
`unique_third_party_accounts` across covered accounts.

## Accepted limitations

1. A `Federated` principal aborts rather than blocking, and the
   `has_non_account_principals` field that would record it is therefore dead.
2. `Condition`, `Resource`, and `NotAction` are not evaluated.
3. A replica secret is enumerated separately in each region it replicates to, so
   one logical secret can produce several findings.
4. This check's class is the only RCP check whose `__init__` does not accept
   `**kwargs`, so it is coupled to the exact keyword set `run_checks_for_type`
   passes. Adding a construction argument breaks this check first.

## Acceptance scenarios

1. A secret policy granting `111111111111`, outside the organization → compliant,
   and the account enters the allowlist.
2. The same, where the account is in the organization → not recorded.
3. A secret policy with `Principal: "*"` → violation; the account is blocked for
   Secrets Manager only.
4. A secret with no resource policy → skipped.
5. A secret with an empty policy string → skipped.
6. A secret policy with a `Federated` principal → the run aborts.

## Referenced invariants

INV-01, INV-02, INV-04, INV-06, INV-13, INV-16.

## Implementation

- `headroom/checks/rcps/deny_secrets_manager_third_party_access.py`
- `headroom/aws/secretsmanager.py` — `analyze_secrets_manager_policies`
- `headroom/terraform/generate_rcps.py` — `RCP_TERRAFORM_VARIABLES`
- `test_environment/modules/rcps/locals.tf`
- Tests: `tests/test_checks_deny_secrets_manager_third_party_access.py`,
  `tests/test_aws_secretsmanager.py`
