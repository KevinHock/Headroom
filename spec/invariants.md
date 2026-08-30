# Global invariants

These apply to every subsystem and every check. A subsystem contract or a
per-check specification may narrow one; none may silently override one. A
deliberate exception is recorded here, at the invariant, and nowhere else.

Each invariant carries a stable ID. Per-check specifications cite these IDs in
their **Referenced global invariants** section, and
`tests/test_spec_corpus.py` checks that every cited ID exists.

Every invariant here protects the safety promise in
[`product.md`](product.md): a generated policy is one the accounts it reaches
already satisfy.

---

## INV-01 — Absence of evidence is not evidence of safety

A missing observation must never be read as a clean observation. Where the two
are indistinguishable in an artifact, the run aborts with an error naming what
was missing.

This is the invariant most of the others exist to serve, because the failure it
prevents is silent: a policy that looks safe precisely because nothing was
looked at.

Concretely, each of these aborts rather than continuing:

- A generation run that parsed zero SCP result files, or whose RCP parse found
  neither a cleared account nor a blocked one.
- A registered RCP check with no results directory.
- A `deny_ec2_ami_owner` result whose summary omits `unique_ami_owners`, which
  reads identically to an account that ran no instances.
- A `skip_account_ids` entry matching no account in the organization.
- An account whose lifecycle state cannot be classified (see INV-03).

## INV-02 — A run fails whole, never partially

An error while analyzing any account aborts the entire run. Errors are never
logged and stepped over.

A partial run is more dangerous than no run: an account skipped for a transient
error is indistinguishable in the results from an account with zero violations,
so swallowing the error can green-light a policy that breaks it. Accounts that
genuinely cannot be analyzed are excluded up front, by lifecycle state or by
configuration, where the exclusion is visible.

## INV-03 — Only ACTIVE accounts are analyzed, and an unknown state aborts

`CLOSED`, `SUSPENDED`, `PENDING_ACTIVATION`, and `PENDING_CLOSURE` accounts are
not analyzed. The first three reject role assumption; the fourth is leaving the
organization and must not hold back an organization-wide policy.

State is read from `State`, falling back to `Status`. An account reporting
neither, or reporting a state Headroom does not know, aborts the run — neither
guess is safe, and the two causes have different remedies.
`test_every_state_aws_defines_is_classified` in `tests/test_analysis.py` is
meant to surface a newly added AWS state when the SDK is upgraded.

## INV-04 — Organization membership, analyzable accounts, and hierarchy are three distinct projections

Code that collapses any two of them is wrong.

| Projection | Source | Contains |
|---|---|---|
| Organization membership | `get_all_organization_account_ids` | Every account the API reports, **unfiltered** — a closed account is still a member and still matches organization-based RCP conditions |
| Analyzable accounts | `get_subaccount_information` | ACTIVE accounts, minus the management account, minus `skip_account_ids` |
| Hierarchy | `analyze_organization_structure` | The OU tree that placement walks |

## INV-05 — The subtree is the unit of OU reasoning

A policy attached to an OU governs every account in that OU **and in every OU
beneath it**. Every question asked about an OU — is it safe to attach here, what
must its allowlist hold, which accounts does this recommendation affect — is
asked of the whole subtree.

Placement walks from the top down and stops at the highest safe OU; its
descendants inherit rather than collecting a redundant second attachment. An
unsafe OU hands the question to its child OUs.

Judging an OU by the accounts parented directly to it once declared a parent
safe while a violating account two levels down was never examined, and unioned
an allowlist that omitted that account's resources. Nothing errored, because the
report never mentioned the accounts it had skipped. Pinned by
`tests/test_nested_ou_hierarchy.py`.

## INV-06 — An empty allowlist denies everything, so it is never rendered

For a Deny statement scoped by `StringNotEquals`-style allowlist semantics, an
empty allowlist denies every call rather than none.

A check whose covered accounts observed no allowlist values leaves its policy
**off**, with a comment saying why, rather than rendering an empty list. This is
distinct from INV-01: observing nothing is a legitimate fact about those
accounts, whereas failing to record an observation is a broken artifact and
aborts.

## INV-07 — An allowlist round trip is complete or the check does not ship

A check that feeds an allowlist must carry its values the whole way: summary key
→ result dataclass field → placement union → module parameter.

Break the chain anywhere and the check still reports 100% compliance, the policy
is still enabled, and the allowlist renders empty — which by INV-06 denies
everything. `deny_ec2_ami_owner` shipped with the first and last links only.

## INV-08 — Record the value the condition key will hold

Collect what the IAM condition key evaluates to at authorization time, not the
field of the same name in the describe call.

`ec2:Owner` is an AMI's `ImageOwnerAlias` where it has one and its numeric
`OwnerId` otherwise. Collecting `OwnerId` alone produced an allowlist that
denied the exact AMI the scan had just cleared. Fixtures for a condition-key
check must be shaped like real API responses; an impossible one
(`OwnerId: "amazon"`) hid this for a release.

## INV-09 — Scan the dimension the policy enforces

A check must read the same dimension its policy statement conditions on, or
declare in its specification what it reads instead and what the substitution
costs.

`deny_ec2_imds_v1` is the only check that substitutes: the SCP conditions on
`aws:RequestTag/ExemptFromIMDSv2` on the `RunInstances` request, and the scan
reads the tag off the resulting instance. See
[`checks/scps/deny_ec2_imds_v1.md`](checks/scps/deny_ec2_imds_v1.md) for the
argument and its limits.

## INV-10 — One verdict gates one statement

A Terraform variable that includes or omits a policy statement is backed by a
check that measures exactly that statement.

One variable gating two statements means one verdict is being made on two
different kinds of evidence, and the weaker evidence silently authorizes the
stronger statement.

## INV-11 — Generation is reconciliation, not appending

A run's output is the complete desired state of its Terraform directory. A
target that drops out of the recommendations loses its file.

Three rules make that safe:

1. **Render before mutate.** The whole plan is built in memory before any file
   is written or deleted, so a failure partway through leaves the previous
   output whole.
2. **Ownership is a marker on the file's first line**, never a filename pattern
   and never a side manifest. A pattern claims the hand-written `custom_scps.tf`
   next to ours; a manifest is separate state that orphans whatever it loses and
   over-deletes whatever it names wrongly.
3. **A run that read nothing aborts** (INV-01), because deleting everything is
   also how a broken run would present.

Appending was the original behavior, and it meant a policy that moved from an OU
down to individual accounts kept its OU-wide attachment — still denying the
account whose new violation caused the move.

## INV-12 — One name, one rule, both generators

Every OU is named for its path down from the root, and both sides of the
Terraform contract build that name with the same function: `generate_org_info`
declares `local.<path>_ou_id`, and both policy generators reference it through
`ou_id_local_name()`. Colliding or reserved names abort rather than overwrite.

Declaring locals for top-level OUs only, while emitting references for any OU,
produced Terraform that failed at plan time on an undeclared local — and each
module's own tests passed, because one asserted the reference and the other
asserted the declaration. `tests/test_nested_ou_hierarchy.py` generates both from
one hierarchy.

## INV-13 — Every stage is registry-driven

Between check collection and Terraform generation, no stage may branch on a
hardcoded check name. A check registers itself with `@register_check` and every
stage discovers it from the registry.

Collection, result writing, parsing, and placement hold to this. Terraform
generation does not, and the two generators fail differently:

- **RCPs** are rendered from `RCP_TERRAFORM_VARIABLES`, a hand-maintained table.
  It is guarded: `test_table_covers_every_registered_rcp_check` fails by name
  when an entry is missing. Five RCP checks were once collected against every
  account on every run and rendered as disabled, which is indistinguishable in
  the output from a check that found nothing.
- **SCPs** are rendered by `_build_scp_terraform_module`, which names all nine
  checks in straight-line code and imports nothing from the registry.
  `test_every_registered_scp_check_is_rendered` is the guard added after this
  gap was found; before it, a tenth SCP check would have been collected,
  written, parsed, and placed, then dropped at render with no test failing.

Closing the SCP half — driving the renderer from the registry, as the RCP half
almost is — is the standing intent. Until then the guard is the invariant's
enforcement, and neither generator may grow a *second* hand-maintained list.

## INV-14 — Persisted results keep wire compatibility

A later run reads back both the result JSON and the result filenames. Changing
either without an explicit migration can silently re-scan or silently skip
accounts without any reader failing.

`results_exist` therefore tolerates both the account-name and the
account-name-plus-ID filename forms, so an existing results directory still
resumes after `exclude_account_ids` changes.

## INV-15 — AWS identifiers in the repository are obviously fake

Every account ID, instance ID, AMI ID, ARN, KMS key ID, and Organizations
root/OU/organization ID committed to this repository — in code, tests,
documentation, examples, and commit messages — uses a real prefix, a real
length, and a body of one repeated digit: `111111111111`,
`i-11111111111111111`, `ami-11111111111111111`.

An identifier arriving from a bug report, error message, console screenshot, or
API response is real. Rewrite it before it enters the repository.

**One standing exception.** `test_environment/` commits thirteen real
twelve-digit account IDs belonging to third-party vendors — in the live-test
Terraform, in the results it produced, and in the RCP allowlist generated from
them. They are load-bearing: an IAM trust policy naming an account that does not
exist is rejected at `terraform apply`, so rewriting them would break the live
test this repository uses to prove its own output. They are public vendor
identifiers rather than the operator's, which is what makes the trade acceptable
and does not make it compliant. No new one may be added, and no identifier
outside `test_environment/` is covered.
[`../test_environment/README.md`](../test_environment/README.md) describes where
they appear.
## INV-16 — Credentials are minted regionally, and only enabled regions are scanned

Every boto3 session is built by `headroom/aws/sessions.py` with
`sts_regional_endpoints = regional`, at every hop of the assume-role chain.
Credentials minted at the global STS endpoint are invalid in opt-in regions, and
Headroom scans every enabled region, so opt-in regions are the normal case.
`test_only_the_sessions_module_constructs_a_session` pins the single
construction site.

Region discovery calls `describe_regions` with no arguments, which returns only
the regions the account has enabled. `AllRegions=True` would add regions the
account cannot use and turn each into a doomed API call.
`test_only_enabled_regions_are_requested` pins it.
