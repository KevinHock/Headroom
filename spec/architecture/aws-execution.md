# Architecture: AWS execution

Owns how Headroom reaches AWS: the identities it assumes, the sessions it builds,
the regions it reads, and which accounts it treats as what.

Implementation: `headroom/aws/sessions.py`, `headroom/aws/helpers.py`,
`headroom/aws/organization.py`, `headroom/analysis.py`. Operator instructions for
creating these roles:
[`../../documentation/SETUP.md`](../../documentation/SETUP.md).

## Hub and spoke

Headroom runs from one account and reaches every other by assuming a role. It
never uses long-lived credentials in a member account.

```
Security Analysis Account  (the hub — where Headroom runs)
   ├─ OrgAndAccountInfoReader   in the management account   (organization structure)
   ├─ Headroom                  in member account 1         (resource scan)
   ├─ Headroom                  in member account 2         (resource scan)
   └─ Headroom                  in member account N         (resource scan)
```

Every role trusts the security analysis account as its principal.

## The role chain

| Step | Role | Assumed in | Session name | When |
|---|---|---|---|---|
| 0 | `OrganizationAccountAccessRole` | Security analysis account | `HeadroomSecurityAnalysisSession` | Only when `security_analysis_account_id` is configured |
| 1 | `OrgAndAccountInfoReader` | Management account | `HeadroomOrgAndAccountInfoReaderSession` | Always |
| 2 | `Headroom` | Each analyzable member account | `HeadroomAnalysisSession` | Per account |

Step 0 is skipped when Headroom is already running in the security analysis
account; the ambient credentials are used instead. Step 1 requires
`management_account_id` and raises without it. Step 2 chains from the security
session, not from the management session.

Role names are fixed. They are not configurable.

## Sessions are minted regionally

Every session in the package is built by `headroom/aws/sessions.py`, with
`sts_regional_endpoints` set to `regional`, at every hop (INV-16).

botocore defaults that setting to `legacy`, which rewrites the STS endpoint to
the global `sts.amazonaws.com` whenever the session's region is one that predates
opt-in regions — `us-east-1` and `us-west-2` among them. Tokens the global
endpoint issues are valid only in regions enabled by default, so an assumed-role
credential minted there fails with `AuthFailure` the moment Headroom reads an
opt-in region. Headroom scans every enabled region of every account, so that is
the normal case rather than an edge case, and it cannot depend on the operator
having configured `regional` themselves.

An assumed session carries the region it was assumed from, so a chained
assumption keeps minting regionally at every hop. Assuming a role with no region
configured anywhere raises rather than guessing one.

## Regions

`get_all_regions` calls `describe_regions` with no arguments, returning only the
regions the account has enabled — `opt-in-not-required` and `opted-in`, never
`not-opted-in` (INV-16).

An enabled region does not guarantee the service is available there. Handling a
missing regional endpoint is each check's concern, and each check's document
states what it does. An absent endpoint raises botocore's
`EndpointConnectionError`, which is **not** a `ClientError` subclass, so an
`except ClientError` never catches it — the reason a region-loop that looks
defended can still abort the run.

## The three account projections

These are distinct and must stay distinct (INV-04).

### Organization membership — `get_all_organization_account_ids`

Every account ID the Organizations API reports, **unfiltered**. Deliberately
includes the management account, closed accounts, and accounts named in
`skip_account_ids`.

RCP checks use this set to tell an in-organization principal from a third party.
A closed account is still an organization member and still matches
`aws:PrincipalOrgID`, so filtering here would misclassify its principals as third
parties and inflate every allowlist.

### Analyzable accounts — `get_subaccount_information`

The accounts that get scanned. Excludes, in this order:

1. The management account, because SCPs and RCPs do not restrict it.
2. Accounts named in `skip_account_ids`. Consulted **before** the lifecycle check
   so an account whose state cannot be classified can be excluded by
   configuration instead of aborting the run.
3. Every account not in the `ACTIVE` lifecycle state (INV-03).

An excluded account writes no results, and placement only sees accounts that
have results, so exclusion removes the account from the compliance picture
entirely rather than holding a policy back.

Each returned account carries its name, environment, and owner, read from account
tags per [`../contracts/configuration.md`](../contracts/configuration.md).

### Hierarchy — `analyze_organization_structure`

The OU tree placement walks: the root ID, every OU with its parent, children, and
accounts, and every account with its parent OU and path.

**Every listing is paginated.** `ListAccountsForParent` and
`ListOrganizationalUnitsForParent` cap a page at twenty, and AWS documents that
either can return fewer even when more remain, so a single response is never
evidence of a complete parent. This is load-bearing rather than tidy: the
OU-level RCP safety predicate in [`../contracts/placement.md`](../contracts/placement.md)
is evaluated against this hierarchy, not against the accounts that produced
results, so an account missing from a truncated page is an account whose
blockers no OU-level decision can see. A short read here is absence of evidence
presented as safety (INV-01).

`ListRoots` is the one exception, and is called once: an organization has exactly
one root, and the code reads `Roots[0]`.

The walk lists each parent's child OUs once. The recursive descent returns the
IDs it listed, so the parent records its children from that return value rather
than issuing a second identical call — which matters because Organizations is
throttled tightly and pagination multiplies request counts.

An account attached directly to the organization root has `parent_ou_id` of
`None` and an `ou_path` of `["Root"]`. It belongs to no OU and cannot be targeted
by an OU-level policy; the root ID is not a substitute.

## Partitions

**Headroom runs in the commercial `aws` partition only.** All three role ARNs in
`analysis.py` are built as `arn:aws:iam::<account>:role/<name>`, so the first
`sts:AssumeRole` against a GovCloud, China, or isolated-region account fails.
The partition is not configurable and is not derived from the caller.

This is a limitation, not a decision — nothing about the design depends on it,
and closing it means deriving the partition once from the caller's own identity
rather than threading a config field through. Elsewhere the code is already
partition-agnostic: the ARN pattern that extracts account IDs from policy
documents matches any partition ([`../contracts/policy-model.md`](../contracts/policy-model.md)),
and so does result redaction ([`../contracts/results.md`](../contracts/results.md)).
Two synthesized ARNs hardcode `aws` cosmetically, recorded at
[`deny_ec2_public_ip`](../checks/scps/deny_ec2_public_ip.md) and
[`deny_s3_third_party_access`](../checks/rcps/deny_s3_third_party_access.md).

## Failure policy

A failure anywhere in analysis aborts the whole run (INV-02). There is no
per-account error handling, by design.

Two deliberate exceptions, both narrow:

| Tolerated | Why |
|---|---|
| Any `ClientError` fetching an account's tags | The values are labels, not evidence; the account takes documented fallbacks and no policy decision reads them. Wider than intended — see [`../contracts/configuration.md`](../contracts/configuration.md) |
| Per-region and per-resource errors inside a check | Specified per check, and each such case is reported in that check's result rather than silently dropped. The last exception was [`deny_sqs_third_party_access`](../checks/rcps/deny_sqs_third_party_access.md), which dropped a queue naming an unrecognized principal key, and that is fixed |

### What a policy document may and may not stop the run over

The RCP analyzers read policy documents an account's own operators wrote, so
they meet two different kinds of trouble and answer them differently. The rule
is stated in full in
[`../contracts/policy-model.md`](../contracts/policy-model.md); its consequence
for this document is that only the first kind reaches INV-02:

| Kind | Example | Answer |
|---|---|---|
| A document AWS could not have stored | Unparseable JSON, a `Statement` that is neither object nor list, a principal key outside the four AWS documents, an `Action` that is neither a string nor an array | **Aborts.** Headroom misread the document or does not model it, and continuing would mean guessing |
| A document AWS accepted that no allowlist can express | `Principal: "*"`, an `Allow` with `NotPrincipal`, a `Federated` or `CanonicalUser` principal | **Blocks the account** for that check. Recorded as a violation; the scan continues |

The second kind used to abort in four of the five resource-policy analyzers,
which protected one account at the cost of every other account's results.

`main` catches `ValueError`, `RuntimeError`, and `ClientError` around
organization discovery, Terraform generation, and reconciliation, printing a
labeled error and exiting non-zero. It does not continue.

The scan is **not** inside that `try`. Configuration, `perform_analysis`, and the
security-session build run before it, so a `ClientError` in the longest phase of
the run aborts on an unhandled traceback rather than a labeled message. Both
abort, so INV-02 holds either way.
[`overview.md`](overview.md#one-pass-one-direction) owns that gap.

## Required permissions

The `Headroom` role needs read-only access to the services its checks call; each
check's document lists its APIs. The `OrgAndAccountInfoReader` role needs
`organizations:List*` and `organizations:Describe*` plus
`organizations:ListTagsForResource`.

Both roles must be exempt from any SCP that would deny their reads, or the scan
sees a distorted picture of the account.
[`../../documentation/SETUP.md`](../../documentation/SETUP.md) carries the
policy documents.
