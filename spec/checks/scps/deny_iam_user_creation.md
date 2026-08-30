---
id: deny_iam_user_creation
kind: scp
status: implemented
applies_to:
  - headroom/checks/scps/deny_iam_user_creation.py
  - headroom/aws/iam/users.py
depends_on:
  - INV-02
  - INV-06
  - INV-07
verification:
  - tests/test_checks_deny_iam_user_creation.py
  - tests/test_aws_iam.py
  - tests/test_parse_results.py
  - tests/test_generate_scps.py
---

# deny_iam_user_creation

## Objective

Deny `iam:CreateUser` everywhere except for the IAM users that already exist, so
the organization stops accruing long-lived credentials without breaking the ones
it depends on today.

### Scope

Enumeration. This check does not judge; it inventories, and the inventory
becomes the allowlist.

### Non-goals

- Does not evaluate whether an existing user *should* exist. Every user found is
  allowlisted.
- Does not cover `iam:CreateAccessKey`, so an allowlisted user can still be given
  new credentials.
- Does not cover users created between the scan and the apply.

## Enforced statement

```
Effect:      Deny
Action:      iam:CreateUser
NotResource: <iam_allowed_users>
```

Pattern 5b, resource ARN allowlist. There is no `Resource` and no `Condition`:
the allowlist is expressed as `NotResource`, so the deny applies to every user
ARN except those named.

## Evidence

`iam:ListUsers`, paginated. Global — no region iteration.

| Read | Used for |
|---|---|
| `UserName` | Identity |
| `Arn` | The allowlist value |
| `Path` | Recorded |

All three are required keys; a response missing one raises `KeyError`.

## Decision table

| State | Condition | Category |
|---|---|---|
| Compliant | Always, for every user found | `COMPLIANT` |
| Violation | — | **Never produced** |
| Exemption | — | Never produced |
| Unknown | — | Not produced; every failure aborts |

This check can never report a violation, so every account is always "safe" for
it. The entire safety argument therefore rests on the allowlist being complete,
which is why INV-07 exists and why the round trip below is specified end to end.

## Failure behavior

`ClientError` from `ListUsers` is logged and re-raised, aborting the run
(INV-02). There are no sentinel values.

## Result contract

Base document shape. Summary fields beyond the common three:

| Key | Meaning |
|---|---|
| `total_users` | Count of users found |
| `users` | A list of ARN **strings** — not objects |

There is **no `violations` key and no `compliance_percentage` key**, which for
this check is consistent: every entry is compliant, so the zero parsing supplies
by default is the true count. That is not a general licence to omit the key —
[`deny_iam_saml_provider_not_aws_sso`](deny_iam_saml_provider_not_aws_sso.md)
omitted it while producing real violations, and every account it rejected read
back as safe until it was fixed.

Entry shape in `compliant_instances`: `user_name`, `user_arn`, `path`.
`violations` and `exemptions` are always empty.

## Placement and generated policy

Every account is safe, so placement lands at root unless another check's
recommendation moves this one — placement is per check
([`../../contracts/placement.md`](../../contracts/placement.md)).

The allowlist round trip (INV-07):

1. `summary.users` — ARNs, with the account ID replaced by `REDACTED` when
   `exclude_account_ids` is set.
2. SCP parsing restores the account ID into each ARN once the account is
   identified.
3. `SCPCheckResult.iam_user_arns`.
4. The sorted union across the accounts a placement covers.
5. `SCPPlacementRecommendations.allowed_iam_user_arns`.
6. The `iam_allowed_users` Terraform variable, with each ARN's account field
   rewritten to `${local.<account_name>_account_id}` where the account is in the
   hierarchy. An ARN naming an account the hierarchy does not have is emitted
   literally.

Terraform variables: `deny_iam_user_creation` (boolean) and `iam_allowed_users`
(list, rendered whenever the boolean is true).

**An empty allowlist leaves the policy off** (INV-06). When the accounts a module
covers hold no IAM user at all, step 6 would render `iam_allowed_users = []` and
so `NotResource: []`. The IAM policy grammar admits one or more values in a
resource array, so an empty one is not a valid document: Organizations rejects
the whole policy at apply time, taking every other statement in the module with
it rather than only this one. Generation therefore emits
`deny_iam_user_creation = false` with a comment giving the reason, logs a
warning, and continues — an account holding no IAM user is an ordinary fact about
that account, not a broken run.

[`deny_ec2_ami_owner`](deny_ec2_ami_owner.md) guards the identical case, and the
two now read the same way.

## Accepted limitations

1. Users created between the scan and the apply are absent from the allowlist and
   their recreation is denied.
2. A user deleted after the scan stays in the allowlist, which is harmless: the
   `NotResource` entry simply matches nothing.
3. Service-linked roles and IAM roles are out of scope; only users are read.

## Acceptance scenarios

1. An account with three IAM users → three compliant entries, zero violations,
   and `summary.users` holds three ARNs.
2. An account with no IAM users → zero entries and `total_users: 0`, and a
   module covering only such accounts renders `deny_iam_user_creation = false`
   with a comment rather than an empty `NotResource`.
3. Two accounts with different users, both placed at root → `iam_allowed_users`
   holds the sorted union of both sets.
4. A result written with `exclude_account_ids` → the ARNs carry `REDACTED`, and
   parsing restores the account ID before the union is built.
5. An ARN naming an account absent from the hierarchy → emitted literally rather
   than as a `local.` reference.

## Referenced invariants

INV-02, INV-06, INV-07.

## Implementation

- `headroom/checks/scps/deny_iam_user_creation.py`
- `headroom/aws/iam/users.py` — `get_iam_users_analysis`
- `headroom/terraform/generate_scps.py` — `_build_iam_terraform_parameters`,
  `_replace_account_id_in_arn`
- Tests: `tests/test_checks_deny_iam_user_creation.py`, `tests/test_aws_iam.py`,
  `tests/test_parse_results.py`, `tests/test_generate_scps.py`
