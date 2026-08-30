# Contract: policy model

Owns the vocabulary every check is written in: what an SCP and an RCP each
control, the patterns a generated statement can take, and the grammar by which
Headroom reads an existing policy document.

A per-check specification names the pattern it implements rather than restating
what the pattern is.

Implementation: `headroom/aws/policy_documents.py` (shared grammar, including
the principal types and the one function that reads a `Principal` element),
`headroom/constants.py` (ARN pattern), and every service adapter that reads a
policy document — `aws/ecr.py`, `aws/kms.py`, `aws/s3.py`,
`aws/secretsmanager.py`, `aws/sqs.py`, `aws/iam/roles.py`. A change to how a
statement is read is a change to all of them.

## SCP versus RCP

| | SCP | RCP |
|---|---|---|
| Bounds | What principals **in** the account may do | Who may act **on** resources in the account |
| Evaluated against | Requests made by principals in the account | Requests made against resources in the account, including by principals outside the organization |
| Applies to the management account | No | No |
| Headroom's evidence | Resource configuration in the account | Resource policies and trust policies in the account |
| Headroom's blocking question | Does any resource already violate the statement? | Does any resource name a principal no allowlist can express? |
| Allowlist source | Values observed in the account | Third-party account IDs observed in the account's policies |

Both are Deny-only in Headroom. Nothing generated here grants access; a
statement either denies or is omitted.

## The generated patterns

Every statement Headroom generates is one of these. The taxonomy exists so a new
check declares its shape rather than inventing one.

| # | Pattern | Mechanism | Example check |
|---|---|---|---|
| 1 | **Absolute deny** | `Deny` with no condition | `deny_iam_saml_provider_not_aws_sso` |
| 2 | **Conditional deny** | `Deny` unless a condition key holds the required value | `deny_ec2_public_ip`, `deny_rds_unencrypted` |
| 3 | **Paved road** | `Deny` unless a request tag marks the blessed path | `deny_eks_create_cluster_without_tag` |
| 4 | **Exception tag** | `Deny` unless an exemption tag is present on the request | `deny_ec2_imds_v1` |
| 5a | **Principal account allowlist** | `Deny` unless `aws:PrincipalAccount` is allowlisted | every RCP check |
| 5b | **Resource ARN allowlist** | `Deny` with `NotResource` naming approved ARNs | `deny_iam_user_creation` |
| 5c | **Condition value allowlist** | `Deny` unless a condition key's value is allowlisted | `deny_ec2_ami_owner` |
| 6 | **Composition** | Two or more of the above in one statement | — |

### Pattern 3 versus pattern 4

Both condition on a tag; they mean opposite things.

| | 3 — paved road | 4 — exception tag |
|---|---|---|
| Says | "You did it the blessed way" | "You need an exception" |
| Lifecycle | Permanent | Temporary, and should be revisited |
| Audit stance | Encouraged | Scrutinized |
| Example tag | `PavedRoad=true` | `ExemptFromIMDSv2=true` |

Prefer 3. Reach for 4 only when there is a real workload that cannot take the
paved road, and name the tag for what it exempts — `ExemptFromIMDSv2`, never
`special` — so an audit can tell what the exception buys.

The retired taxonomy carried three further design principles that are
deliberately not restated here. "Start with least privilege, then allowlist"
describes designing a statement, which Headroom does not do — it decides whether
a statement someone else wrote is deployable, and two shipped checks are
deny-the-bad-behavior by construction. "Combine patterns for defense in depth"
describes pattern 6, which nothing implements. "Document the why" is now the
eleven-section contract in [`../checks/index.md`](../checks/index.md), enforced
by `tests/test_spec_corpus.py` rather than asked for in prose.

The exception-tag principle did survive, as the table above, but one clause of it
did not: the requirement that an exemption record a business justification. That
asks whoever grants an exemption to say why, and Headroom reads exemption tags
off resources it did not create and cannot amend. The tag name carries what is
exempted, which a scan can see; why it was granted lives wherever the tag was
applied.

### Pattern 5 variants

| | 5a | 5b | 5c |
|---|---|---|---|
| Constrains | **Who** — the principal | **What** — the resource | **Which value** — a condition key |
| Construct | `aws:PrincipalAccount` | `NotResource` | `Condition` value list |
| Granularity | Account | Resource ARN | Attribute |

Every 5-family statement is subject to INV-06: an empty allowlist denies
everything, so it is never rendered.

## The RCP allowlist statement

All six RCP checks generate the same shape, differing only in `Action` and in
which allowlist variable feeds them:

```
Effect:    Deny
Principal: "*"
Action:    <the service's actions>
Resource:  "*"
Condition: StringNotEqualsIfExists  aws:PrincipalOrgID   = <this organization>
           StringNotEqualsIfExists  aws:PrincipalAccount = <allowlist>   (omitted when empty)
           BoolIfExists             aws:PrincipalIsAWSService = "false"
```

Three consequences follow, and they are the same for every RCP check:

- **In-organization principals are never denied**, whatever the allowlist holds,
  because `aws:PrincipalOrgID` matches organization *membership* — which by
  INV-04 includes closed accounts and skipped accounts.
- **AWS service principals are never denied**, so a service acting on the
  resource on your behalf is unaffected.
- **The `aws:PrincipalAccount` clause is omitted entirely when the allowlist is
  empty**, rather than rendered as an empty list. With it omitted, the statement
  still denies every out-of-organization principal; rendered empty, the semantics
  would differ.

Terraform variables, by check:

| Check | Enable variable | Allowlist variable |
|---|---|---|
| `deny_ecr_third_party_access` | `deny_ecr_third_party_access` | `ecr_third_party_access_account_ids_allowlist` |
| `deny_kms_third_party_access` | `deny_kms_third_party_access` | `kms_third_party_access_account_ids_allowlist` |
| `deny_s3_third_party_access` | `deny_s3_third_party_access` | `s3_third_party_access_account_ids_allowlist` |
| `deny_secrets_manager_third_party_access` | `deny_secrets_manager_third_party_access` | `secrets_manager_third_party_account_ids_allowlist` |
| `deny_sqs_third_party_access` | `deny_sqs_third_party_access` | `sqs_third_party_access_account_ids_allowlist` |
| `deny_sts_third_party_assumerole` | `deny_sts_third_party_assumerole` | `sts_third_party_assumerole_account_ids_allowlist` |

The Secrets Manager allowlist variable has no `_access_` segment, unlike its five
siblings. The Terraform module defines it that way; it is not a typo to fix in
Python.

## Reading an existing policy document

This grammar is shared. A check does not re-derive it.

### Statements

`Statement` may be a lone object where a one-element list would do; IAM accepts
both, so both reach the analyzers and both are read as a list.

Anything else — a string, a number, `null` — raises `MalformedPolicyError`.
Reading it as no statements would report the resource as granting nothing, which
is not a safe guess (INV-01).

### Principals

| Form | Read as |
|---|---|
| `Principal: "*"` or `{"AWS": "*"}` | Wildcard — a blocker |
| `Allow` with `NotPrincipal` | Wildcard — grants to everyone except a short list, the same reach |
| `Deny` with `NotPrincipal` | Nothing — it restricts rather than grants, and a resource policy's Deny hands access to nobody |
| An account ID or an ARN | The 12-digit account ID it names |
| `Service` | Not an account principal, and not a blocker |
| `Federated` | Carries no account ID — a blocker. A SAML provider ARN does contain twelve digits, but they name the provider's host account, not the caller's. |
| `CanonicalUser` | An opaque identifier that maps to an account only through an API call the scan does not make — a blocker |
| Any other key | `UnknownPrincipalTypeError`, aborting the run |

Callers must apply their own `Effect` gate **before** consulting `NotPrincipal`.
A statement carrying both `Principal` and `NotPrincipal` is not valid IAM and
cannot be stored; were one to arrive, it is treated as a wildcard rather than
letting the `Principal` half stand in for a broader grant.

The account ID is extracted from an ARN with a deliberately loose pattern: the
service segment is unconstrained, because a resource-policy principal can be an
STS session ARN as readily as an IAM one, and the partition is matched the same
way so GovCloud and China ARNs resolve.

### One reader, six analyzers

`read_principal` in `headroom/aws/policy_documents.py` is the only place a
`Principal` element is interpreted. It returns three facts and nothing else: the
account IDs the element names, whether it reaches principals the analyzer cannot
enumerate, and whether it names a principal type that carries no account ID.

The permitted keys are a parameter, because the two policy types differ in one
key and only one:

| Set | Keys | Used by |
|---|---|---|
| `RESOURCE_POLICY_PRINCIPAL_TYPES` | `AWS`, `CanonicalUser`, `Federated`, `Service` | `aws/ecr.py`, `aws/kms.py`, `aws/s3.py`, `aws/secretsmanager.py`, `aws/sqs.py` |
| `TRUST_POLICY_PRINCIPAL_TYPES` | `AWS`, `Federated`, `Service` | `aws/iam/roles.py` |

A canonical user ID is an Amazon S3 identifier, so it cannot name who may assume
a role and a trust policy does not accept the key. The resource-policy set is
the **union** of what resource policies accept rather than a list per service:
S3 is the service that documents `CanonicalUser`, and admitting the key
everywhere costs a branch that never fires if AWS rejects it elsewhere, where
excluding it would abort a whole organization's scan over one queue.

### A blocker stops the account; a document Headroom cannot read stops the run

Both a wildcard and a principal carrying no account ID mean the same thing: the
RCP would deny a grant that exists today, because an allowlist keyed on
`aws:PrincipalAccount` cannot carry it. That is **one verdict, recorded** — the
resource becomes a violation, the account is blocked for that check, and the
scan continues. Which of the two it was is reported and not acted on
differently.

An undocumented principal key is the separate case and **aborts**. AWS validates
the `Principal` element when it stores a policy, so a key outside the documented
four means Headroom misread the document or AWS has added a principal type
nobody has modelled here. Recording it as a finding would state a verdict on a
grant this code cannot read.

The dividing line is the same one that governs unparseable JSON and a malformed
`Statement`: **a document AWS could not have stored aborts the run; a document
AWS accepted that no allowlist can express blocks the account.** Aborting
protects the account at the cost of every other account's results and puts the
finding in a stack trace instead of the report, so it is reserved for the case
where continuing would mean guessing.

[`deny_sts_third_party_assumerole`](../checks/rcps/deny_sts_third_party_assumerole.md)
reads the same three facts and acts on two of them. Its RCP denies
`sts:AssumeRole` alone, which a federated identity cannot call — AWS routes
federation through `AssumeRoleWithSAML` and `AssumeRoleWithWebIdentity` — so a
`Federated` principal in a trust policy is not a grant that RCP can break. It is
the one place the third fact is read and deliberately ignored.

### Actions

Only [`deny_sts_third_party_assumerole`](../checks/rcps/deny_sts_third_party_assumerole.md)
**gates** on actions: a trust-policy statement counts only if its actions cover
`sts:AssumeRole`. The other five analyzers read every `Allow` statement whatever
it grants, and keep the action list for reporting alone.

`normalize_actions` in `headroom/aws/policy_documents.py` is the only place an
`Action` element is read, for the same reason `read_principal` is the only place
a `Principal` element is. Both claims are enforced rather than
asserted: `test_only_policy_documents_reads_a_statement_principal` and
`test_only_policy_documents_normalizes_a_statement_action` walk the package and
fail on a second reader. A divergent copy fails no other test, because each
analyzer's suite passes against its own reader — which is how the drift survived
four rounds. It answers the actions the element names and **raises
`TypeError`** for anything that is neither a string nor an array: IAM stores an
`Action` in one of those two shapes and nothing else, so a third shape is a
document AWS could not have stored, on the aborting side of the line above. Five
copies of that reader disagreed four ways before it was shared — an empty set, an
object's keys read as though they were IAM actions, and a raise — which is the
drift the `Principal` walk had.

Where an action is matched, it is matched the way IAM matches it —
case-insensitively, honoring `*` wildcards, and honoring `NotAction`. String
comparison misses `sts:*`, `sts:Assume*`, `STS:AssumeRole`, and every
`NotAction`.

Prefer not gating at all. Gating narrows what the scan sees, which is the unsafe
direction: an action the gate rejects is a grant the scan did not count and the
RCP will still deny.

### What is deliberately not read

RCP analysis reads `Effect`, `Principal`, and — for STS alone — `Action`. It
reads neither `Condition` nor `Resource`/`NotResource`.

Both omissions **widen** what the scan sees, and widening is the safe direction:

- A `Principal: "*"` narrowed by `aws:PrincipalOrgID` grants nothing outside the
  organization — it is the pattern AWS recommends for organization-wide bucket
  access — but is counted as a violation and blocks that account from the check's
  RCP.
- A grant narrowed by `s3:prefix`, `aws:SourceVpce`, or a lapsed `DateLessThan`
  still contributes its account to the allowlist at full width, so the account
  keeps a broader RCP allowance than it needs.
- A statement scoped away from the resource by `Resource`/`NotResource` still
  contributes its principals.

A condition or a resource scope can only ever narrow a grant, so neither can hide
a third party the scan should have found. No RCP generated under this limitation
breaks access a condition-aware scan would have preserved. The cost is coverage,
not safety, which is what makes it a roadmap item rather than a defect. See
[`../../ROADMAP.md`](../../ROADMAP.md).

## References

- [IAM policy elements](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html)
- [Global condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html) - the `aws:`-prefixed keys, including `aws:PrincipalAccount` and the request-tag keys patterns 3 and 4 read
- [Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html) - per-service actions, and the condition keys each action supports. Evidence of what AWS has documented, not of what IAM does; see `deny_rds_unencrypted` for a key that works and is not listed
- [Service control policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- [Resource control policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html)
- [Organizations limits](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html#min-max-values)
