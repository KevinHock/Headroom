---
id: deny_kms_third_party_access
kind: rcp
status: implemented
applies_to:
  - headroom/checks/rcps/deny_kms_third_party_access.py
  - headroom/aws/kms.py
depends_on:
  - INV-01
  - INV-02
  - INV-04
  - INV-06
  - INV-13
  - INV-16
verification:
  - tests/test_checks_deny_kms_third_party_access.py
  - tests/test_aws_kms.py
---

# deny_kms_third_party_access

## Objective

Deny KMS access by any principal outside the organization except the third-party
accounts that key policies already grant, so an external account cannot be handed
the ability to decrypt.

### Scope

The `default` key policy of every customer-managed key, in every enabled region.

### Non-goals

- Does not read KMS **grants**. Cross-account access delivered through
  `kms:CreateGrant` is invisible to this check.
- Does not read a key policy stored under a name other than `default`.
- Does not evaluate `Condition`, `Resource`/`NotResource`, or `NotAction`.
- Does not distinguish AWS-managed keys from customer-managed ones.

## Enforced statement

The standard RCP allowlist statement, with:

```
Sid:    DenyKMSThirdPartyAccess
Action: kms:*
```

Terraform variables: `deny_kms_third_party_access` and
`kms_third_party_access_account_ids_allowlist`.

## Evidence

Per enabled region: `kms:ListKeys` (paginated), then `kms:GetKeyPolicy` with
`PolicyName="default"` per key.

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

Every KMS key policy names its own account's root principal, which is an
in-organization principal and so is never recorded.

## Failure behavior

| Situation | Behavior |
|---|---|
| `NotFoundException` on one key | The key grants nothing; recorded with no third parties and no wildcard |
| Any other `ClientError` on one key | Re-raised, aborting the run |
| `ClientError` in any region | Logged and re-raised, aborting the run |
| Unparseable policy JSON | Not caught; propagates and aborts |
| `Statement` neither object nor list | `MalformedPolicyError` |
| A `Federated` principal | `UnsupportedPrincipalTypeError`, aborting the run |
| A `CanonicalUser` or other unrecognized principal key | `UnknownPrincipalTypeError`, aborting the run |

The same `Federated` divergence as
[`deny_ecr_third_party_access`](deny_ecr_third_party_access.md) applies here.

## Result contract

`_build_results_data` is **overridden**:

| Key | Holds |
|---|---|
| `keys_third_parties_can_access` | Violations plus compliant |
| `keys_with_wildcards` | Violations only |

Summary fields beyond the common three: `total_keys_analyzed`,
`keys_third_parties_can_access`, `keys_with_wildcards`, `violations`,
`unique_third_party_accounts`, `third_party_account_count`, `actions_by_account`.

Entry shape: `key_id`, `key_arn`, `region`, `third_party_account_ids`,
`actions_by_account`, `has_wildcard_principal`.

`actions_by_account` is filtered to third-party accounts.

## Placement and generated policy

RCP placement: blocked at `violations > 0`; the allowlist is the union of
`unique_third_party_accounts` across covered accounts.

## Accepted limitations

1. **Grants are unread.** A `kms:CreateGrant` to an external account grants
   decrypt access that this check cannot see, so an account can look clean and
   still lose that access when the RCP is attached. This is the one limitation
   here that can cause a *deployed* policy to break existing access.
2. Only the `default` key policy is read.
3. `Condition`, `Resource`, and `NotAction` are not evaluated.
4. A `Federated` principal aborts rather than blocking.
5. `_normalize_actions` calls `list()` on a non-string `Action`, which raises
   `TypeError` on `None` and yields dict keys on a mapping.

## Acceptance scenarios

1. A key policy granting `111111111111`, outside the organization → compliant,
   and the account enters the allowlist.
2. A key policy naming only its own account's root → not recorded.
3. A key policy with `Principal: "*"` → violation; the account is blocked for KMS
   only.
4. A key returning `NotFoundException` → recorded as granting nothing.
5. A key whose only external access is a grant → reported compliant. This is
   limitation 1.

## Referenced invariants

INV-01, INV-02, INV-04, INV-06, INV-13, INV-16.

## Implementation

- `headroom/checks/rcps/deny_kms_third_party_access.py`
- `headroom/aws/kms.py` — `analyze_kms_key_policies`
- `test_environment/modules/rcps/locals.tf`
- Tests: `tests/test_checks_deny_kms_third_party_access.py`,
  `tests/test_aws_kms.py`
