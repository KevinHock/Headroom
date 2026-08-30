---
id: deny_s3_third_party_access
kind: rcp
status: implemented
applies_to:
  - headroom/checks/rcps/deny_s3_third_party_access.py
  - headroom/aws/s3.py
  - headroom/aws/policy_documents.py
depends_on:
  - INV-01
  - INV-02
  - INV-04
  - INV-06
  - INV-13
verification:
  - tests/test_checks_deny_s3_third_party_access.py
  - tests/test_aws_s3.py
  - tests/test_aws_policy_documents.py
---

# deny_s3_third_party_access

## Objective

Deny S3 access by any principal outside the organization except the third-party
accounts that bucket policies already grant, so a bucket policy edit cannot
quietly expose data to a new external account.

### Scope

Bucket policies.

### Non-goals

- Does not read S3 Access Points, Multi-Region Access Points, bucket ACLs, or
  Object Lambda access point policies.
- Does not evaluate `Condition` or `Resource`/`NotResource`. See
  [`../../contracts/policy-model.md`](../../contracts/policy-model.md).
- Does not read Block Public Access settings.

## Enforced statement

The standard RCP allowlist statement, with:

```
Sid:    DenyS3ThirdPartyAccess
Action: s3:*
```

`Action` is rendered as a bare string here rather than a one-element list,
unlike its five siblings. The semantics are identical.

Terraform variables: `deny_s3_third_party_access` and
`s3_third_party_access_account_ids_allowlist`.

## Evidence

`s3:ListBuckets` (paginated), then `s3:GetBucketPolicy` per bucket. **Global** — S3 buckets
are listed once, not per region.

For each `Allow` statement: `NotPrincipal` presence, `Principal`, `Action`. The
bucket ARN is synthesized as `arn:aws:s3:::<name>`.

The `Principal` element is read by `read_principal` against
`RESOURCE_POLICY_PRINCIPAL_TYPES`
([`../../contracts/policy-model.md`](../../contracts/policy-model.md)). S3 is the
service AWS documents `CanonicalUser` for, and it is why that key is in the
resource-policy set at all.

## Decision table

| State | Condition | Category |
|---|---|---|
| Violation | A wildcard principal — literal `*`, or an `Allow` with `NotPrincipal` | `VIOLATION` |
| Violation | A `Federated` or `CanonicalUser` principal | `VIOLATION` |
| Compliant | Third-party account IDs only | `COMPLIANT` |
| Exemption | — | Never produced |
| Not recorded | Only in-organization principals or AWS services | Not in the output |

S3 was the only check that recorded `Federated` and `CanonicalUser` principals
as findings rather than aborting, and it was right: they carry no account ID, so
no allowlist can express them, and they block the account exactly as a wildcard
does. The other four resource-policy analyzers raised instead. They have
converged on this behavior, and the rule now lives in
[`../../contracts/policy-model.md`](../../contracts/policy-model.md) rather than
here.

## Failure behavior

| Situation | Behavior |
|---|---|
| `ClientError` from `ListBuckets`, on any page | Logged and re-raised, aborting the run. The listing is materialized before any bucket is read, so a failure part-way through paging is reported as the listing failure it is rather than reaching the bucket-policy handler |
| `NoSuchBucketPolicy` on one bucket | The bucket is skipped; it grants nothing |
| Any other `ClientError` on one bucket, `AccessDenied` included | Logged and re-raised, aborting the run |
| Unparseable policy JSON | Not caught; propagates and aborts |
| `Statement` neither object nor list | `MalformedPolicyError` |
| A principal key outside the four documented types | `UnknownPrincipalTypeError`, aborting the run |
| An `Action` that is neither a string nor a list | `TypeError`, aborting the run |

`UnsupportedPrincipalTypeError` was declared in this module and never raised —
the mechanism the other four analyzers used and S3 deliberately did not. None of
the five raises it now, and the class is gone from all of them.

## Result contract

`_build_results_data` is **overridden**:

| Key | Holds |
|---|---|
| `buckets_third_parties_can_access` | Violations plus compliant |
| `buckets_with_wildcards` | Violations only |

Summary fields beyond the common three: `total_buckets_analyzed`,
`buckets_third_parties_can_access`, `buckets_with_wildcards`, `violations`,
`unique_third_party_accounts`, `third_party_account_count`,
`actions_by_third_party_account`, `buckets_by_third_party_account`.

Entry shape: `bucket_name`, `bucket_arn`, `third_party_account_ids`,
`has_wildcard_principal`, `has_non_account_principals`, `actions_by_account`.

## Placement and generated policy

RCP placement: blocked at `violations > 0`; the allowlist is the union of
`unique_third_party_accounts` across covered accounts.

## Accepted limitations

1. The synthesized bucket ARN hardcodes the `aws` partition.
2. Access Points and ACLs are unread, so cross-account access delivered through
   either is invisible.
3. `Condition` and `Resource` are not evaluated.

## Acceptance scenarios

1. A bucket policy granting `arn:aws:iam::111111111111:root`, outside the
   organization → compliant, and `111111111111` enters the allowlist.
2. The same, where the account is in the organization → not recorded.
3. A bucket policy with `Principal: "*"` → violation; the account is blocked for
   S3 only.
4. A bucket policy with a `Federated` principal → violation, recorded rather than
   raised.
5. A bucket policy with a `CanonicalUser` principal → violation.
6. A bucket with no policy → skipped.
7. `AccessDenied` reading one bucket's policy → the run aborts.
8. A `Principal: "*"` narrowed by `aws:PrincipalOrgID` → still a violation; see
   the condition limitation.

## Referenced invariants

INV-01, INV-02, INV-04, INV-06, INV-13.

## Implementation

- `headroom/checks/rcps/deny_s3_third_party_access.py`
- `headroom/aws/s3.py` — `analyze_s3_bucket_policies`
- `headroom/aws/policy_documents.py` — `read_principal`
- `test_environment/modules/rcps/locals.tf`
- Tests: `tests/test_checks_deny_s3_third_party_access.py`,
  `tests/test_aws_s3.py`, `tests/test_aws_policy_documents.py`
