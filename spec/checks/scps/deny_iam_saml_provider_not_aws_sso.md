---
id: deny_iam_saml_provider_not_aws_sso
kind: scp
status: implemented
applies_to:
  - headroom/checks/scps/deny_iam_saml_provider_not_aws_sso.py
  - headroom/aws/iam/saml_providers.py
depends_on:
  - INV-02
  - INV-07
verification:
  - tests/test_checks_deny_iam_saml_provider_not_aws_sso.py
  - tests/test_aws_iam.py
---

# deny_iam_saml_provider_not_aws_sso

## Objective

Deny creation of IAM SAML providers, so federation into the account happens only
through AWS IAM Identity Center and not through a second, hand-rolled identity
provider that no one is watching.

### Scope

`iam:CreateSAMLProvider`, unconditionally.

### Non-goals

- Does not cover `iam:UpdateSAMLProvider` or `iam:DeleteSAMLProvider`.
- Does not read OIDC identity providers.
- Does not validate the SAML metadata document of the provider it accepts.

## Enforced statement

```
Effect:   Deny
Action:   iam:CreateSAMLProvider
Resource: *
```

Pattern 1, absolute deny — no `Condition` at all.

The Identity Center provider is created by `AWSServiceRoleForSSO`, a
service-linked role that SCPs do not restrict, so denying the action outright
does not prevent Identity Center from managing its own provider.

## Evidence

`iam:ListSAMLProviders`, a single call. Global — no region iteration, and
**not paginated**.

| Read | Used for |
|---|---|
| `Arn` | Identity, and the provider name after the last `/` |
| `CreateDate`, `ValidUntil` | Recorded, ISO-formatted |

The allowed shape is exactly one provider whose name begins `AWSSSO_`, matched
case-sensitively. An account with zero providers produces no results at all and
so no findings.

## Decision table

| State | Condition | Category | `violation_reason` |
|---|---|---|---|
| Compliant | The name begins `AWSSSO_` **and** exactly one provider exists | `COMPLIANT` | — |
| Violation | The name does not begin `AWSSSO_` | `VIOLATION` | `provider_prefix_not_awssso` |
| Violation | More than one provider exists, whatever their names | `VIOLATION` | `multiple_saml_providers_present` |
| Exemption | — | Never produced | — |
| No findings | The account has no SAML providers | Nothing recorded | — |

## Failure behavior

`ClientError` from `ListSAMLProviders` is logged and re-raised, aborting the run
(INV-02).

## Result contract

Base document shape. Summary fields beyond the common three:

| Key | Meaning |
|---|---|
| `total_saml_providers` | Count |
| `awssso_provider_count` | How many begin `AWSSSO_` |
| `non_awssso_provider_count` | How many do not |
| `allowed_provider_arn` | The single compliant provider's ARN, or `null` |
| `violating_provider_arns` | The ARNs of the violating providers |

Entry shape: `arn`, `name`, `create_date`, `valid_until`, plus
`violation_reason` on violations only.

## Known conflict: violations are invisible to placement

**This check reports violations in its `violations` array but omits the
`violations` count from its `summary`.**

`build_summary_fields` returns five keys — `total_saml_providers`,
`awssso_provider_count`, `non_awssso_provider_count`, `allowed_provider_arn`,
and `violating_provider_arns` — and no `violations`. SCP parsing reads
`summary.get("violations", 0)`, which therefore returns **zero for every account
in every organization**, unconditionally.

The consequence is not that the check is sometimes wrong. It is that the check
can never hold anything back. `is_safe_for_root` in `parse_results.py` tests
`all(r.violations == 0 for r in results)`, which is vacuously true here, so this
check recommends the deny at **root, always** — for an organization made
entirely of accounts it has just found non-compliant, as readily as for a clean
one. As a safety gate it is inert.

This contradicts the safety promise in
[`../../product.md`](../../product.md) — a policy is attached only where every
account it reaches has zero violations — and it defeats the purpose of running
the check at all. The check's own JSON is correct: `violating_provider_arns`
lists the offenders. Only the key placement reads is missing.

The blast radius of the *generated policy* is narrower than it first appears:
the statement denies *creating* a provider, so an existing non-compliant provider
keeps working. What breaks is any process that recreates it —
infrastructure-as-code that manages the provider, or a disaster-recovery rebuild.
That is what makes this survivable rather than urgent; it does not make the
verdict correct.

Two things would resolve it, and both change behavior:

1. `build_summary_fields` emits `violations`, `exemptions`, `compliant`, and
   `compliance_percentage` like every other SCP check; or
2. SCP parsing stops defaulting a missing `violations` key and raises instead,
   per INV-01 — which is the treatment `unique_ami_owners` already gets.

**Status: unresolved.** Recorded rather than fixed, because either resolution
changes which policies are generated. See [`../index.md`](../index.md).

`allowed_provider_arn` is likewise written and read by nothing: no field on
`SCPCheckResult` carries it and no Terraform variable consumes it. That is a
broken allowlist round trip (INV-07), though a harmless one, because the
statement takes no allowlist.

## Accepted limitations

1. **Not paginated.** `ListSAMLProviders` is called once. An account holding more
   providers than one response carries would be under-reported — though any count
   above one is already a violation.
2. The `AWSSSO_` prefix is matched case-sensitively and is written literally in
   the module, with no shared constant.
3. An account with zero providers records nothing, which is indistinguishable in
   the result file from a check that ran and found nothing to say.

## Acceptance scenarios

1. Exactly one provider named `AWSSSO_prod` → compliant.
2. One provider named `Okta` → violation with
   `violation_reason: provider_prefix_not_awssso`.
3. Two providers, both named `AWSSSO_*` → two violations with
   `violation_reason: multiple_saml_providers_present`.
4. No providers → no entries; `total_saml_providers: 0`.
5. An account matching scenario 2 → placement currently treats it as safe. That
   is the known conflict above, not intended behavior.

## Referenced invariants

INV-02, INV-07 (see the known conflict).

## Implementation

- `headroom/checks/scps/deny_iam_saml_provider_not_aws_sso.py` — class
  `DenySamlProviderNotAwsSsoCheck`
- `headroom/aws/iam/saml_providers.py` — `get_saml_providers_analysis`
- `headroom/parse_results.py` — `_parse_single_scp_result_file`
- Tests: `tests/test_checks_deny_iam_saml_provider_not_aws_sso.py`,
  `tests/test_aws_iam.py`
