---
id: deny_eks_create_cluster_without_tag
kind: scp
status: implemented
applies_to:
  - headroom/checks/scps/deny_eks_create_cluster_without_tag.py
  - headroom/aws/eks.py
depends_on:
  - INV-02
  - INV-09
  - INV-16
verification:
  - tests/test_checks_deny_eks_create_cluster_without_tag.py
  - tests/test_aws_eks.py
---

# deny_eks_create_cluster_without_tag

## Objective

Deny EKS cluster creation that does not carry the paved-road tag, so every
cluster in the organization comes from the blessed module rather than from a
console click.

### Scope

`eks:CreateCluster` only.

### Non-goals

- Does not cover `eks:TagResource` or `eks:UntagResource`, so the tag can be
  removed after creation.
- Does not inspect the cluster's configuration, version, or networking. The tag
  asserts provenance, not correctness.
- Does not cover node groups, Fargate profiles, or add-ons.

## Enforced statement

```
Effect:    Deny
Action:    eks:CreateCluster
Resource:  *
Condition: StringNotEquals
             aws:RequestTag/PavedRoad = "true"
```

Pattern 3, paved road ([`../../contracts/policy-model.md`](../../contracts/policy-model.md)).
This is not an exemption tag: it marks the blessed path rather than excusing a
departure from it.

## Evidence

Per enabled region: `eks:ListClusters`, then `eks:DescribeCluster` for each.

| Read | Used for |
|---|---|
| `cluster["arn"]` | Identity |
| `cluster["tags"]` | The verdict |

Like every tag check here, the existing cluster's tag stands in for the creation
request's tag (INV-09). The substitution is weaker than
[`deny_ec2_imds_v1`](deny_ec2_imds_v1.md)'s: a cluster created by the module and
later untagged reads as a violation, and a cluster tagged by hand after a console
creation reads as compliant.

## Decision table

| State | Condition | Category |
|---|---|---|
| Compliant | `tags["PavedRoad"] == "true"`, matched exactly | `COMPLIANT` |
| Violation | Anything else, including a missing tag, `PavedRoad=false`, and `pavedroad=true` | `VIOLATION` |
| Exemption | — | Never produced |
| Unknown | — | Not produced; every failure aborts |

## Failure behavior

`headroom/aws/eks.py` has **no exception handling at all.** Every failure —
`AccessDenied`, an unreachable regional endpoint, a cluster deleted between
`ListClusters` and `DescribeCluster` — propagates and aborts the run (INV-02).
No sentinel value is produced.

## Result contract

Base document shape. Summary fields beyond the common three: `total_clusters`
(**not** `total_instances`), `violations`, `compliant`,
`compliance_percentage`.

Because the count key is `total_clusters`, `SCPCheckResult.total_instances`
parses as `None` for this check. Nothing downstream reads it.

Entry shape: `cluster_name`, `cluster_arn`, `region`, `tags`,
`has_paved_road_tag`.

## Placement and generated policy

Standard SCP placement at zero violations. Terraform variable
`deny_eks_create_cluster_without_tag`, a boolean. No allowlist.

## Known conflict: the tag key is matched case-sensitively

IAM matches condition key *names* without regard to case, and the tag key in
`aws:RequestTag/PavedRoad` is part of the name. The analyzer compares it exactly,
so a cluster tagged `pavedroad=true` is reported as a violation although
enforcement would match its recreation.

This is the opposite of the treatment [`deny_ec2_imds_v1`](deny_ec2_imds_v1.md)
gives its key, where the asymmetry between key matching and value matching was
measured against the live API (INV-09). Two checks read the same kind of tag by
two different rules, and only one of them can be right.

The direction here is conservative: it over-reports violations, so the policy is
under-deployed rather than deployed where it would break something. That is why
it is survivable, not why it is correct.

**Status: unresolved.** Recorded rather than fixed, because matching the key
case-insensitively clears accounts this check currently blocks, which changes
which policies are generated. See [`../index.md`](../index.md).

## Accepted limitations

1. The tag key and value `PavedRoad` / `true` are written literally in both the
   analyzer and the Terraform module, with no shared constant. Changing one does
   not change the other.
2. A cluster deleted mid-scan aborts the run rather than being skipped, unlike
   the comparable cases in [`deny_lambda_auth_type_none`](deny_lambda_auth_type_none.md)
   and [`deny_sqs_third_party_access`](../rcps/deny_sqs_third_party_access.md).

## Acceptance scenarios

1. A cluster tagged `PavedRoad=true` → compliant.
2. A cluster with no tags → violation.
3. A cluster tagged `PavedRoad=false` → violation.
4. A cluster tagged `pavedroad=true` → violation, per limitation 1.
5. `AccessDenied` on `ListClusters` in one region → the run aborts.

## Referenced invariants

INV-02, INV-09, INV-16.

## Implementation

- `headroom/checks/scps/deny_eks_create_cluster_without_tag.py`
- `headroom/aws/eks.py` — `get_eks_cluster_tag_analysis`
- `test_environment/modules/scps/locals.tf`
- Tests: `tests/test_checks_deny_eks_create_cluster_without_tag.py`,
  `tests/test_aws_eks.py`
