# Contract: results

Owns the persisted result artifact: where a file goes, what it holds, how it is
read back, and how a run resumes from one.

Implementation: writer `headroom/write_results.py`, its single call site
`BaseCheck.execute` in `headroom/checks/base.py`, readers
`headroom/parse_results.py` (SCPs) and `headroom/terraform/generate_rcps.py`
(RCPs). Tests: `tests/test_write_results.py`, `tests/test_parse_results.py`,
`TestRunChecks` in `tests/test_analysis_extended.py`.

**This artifact is a wire format** (INV-14). Both the JSON and the filenames are
read back by a later run. A change to either can silently re-scan or silently
skip accounts without any reader raising, because the readers glob `*.json` and
take account identity from the file's own `summary`.

## Layout

```
{results_dir}/{check_type}/{check_name}/{account_identifier}.json
```

- `check_type` is `scps` or `rcps`, taken from the registry, never from the
  check name's spelling. An unregistered check name is an error, not a new
  directory.
- `account_identifier` is `{account_name}_{account_id}`, or `{account_name}`
  alone when `exclude_account_ids` is set.

## Filename compatibility

Existence is tested against **both** filename forms — with and without the
account ID — regardless of the current `exclude_account_ids` setting. Toggling
that option must not orphan an existing results directory into a full re-scan.

## Document shape

There are two shapes. `summary` is the only key common to both, and it is the
only key any reader parses; the rest is evidence for a human.

### SCP checks

All nine take `BaseCheck._build_results_data` unchanged:

| Key | Holds |
|---|---|
| `summary` | Account identity, check name, counts, and check-specific fields |
| `violations` | One entry per resource the policy statement would deny |
| `exemptions` | One entry per resource the statement's condition would spare |
| `compliant_instances` | One entry per resource the statement would allow |

`compliant_instances` is named for the first check written and is now generic.
Renaming it is a wire-format migration.

### RCP checks

All six override `_build_results_data`, and name their keys for the resource
they scan:

| Check | Keys besides `summary` |
|---|---|
| `deny_ecr_third_party_access` | `repositories_third_parties_can_access`, `repositories_with_wildcards` |
| `deny_kms_third_party_access` | `keys_third_parties_can_access`, `keys_with_wildcards` |
| `deny_s3_third_party_access` | `buckets_third_parties_can_access`, `buckets_with_wildcards` |
| `deny_secrets_manager_third_party_access` | `secrets_third_parties_can_access`, `secrets_with_wildcards` |
| `deny_sqs_third_party_access` | `queues_third_parties_can_access`, `queues_with_wildcards` |
| `deny_sts_third_party_assumerole` | `roles_third_parties_can_access`, `roles_with_wildcards` |

`*_third_parties_can_access` is `violations + compliant`, so a wildcard finding
appears in both lists. `*_with_wildcards` is `violations` alone. No RCP result
has ever carried `violations`, `exemptions`, or `compliant_instances` at the top
level, and changing that is a wire-format migration (INV-14).

### Summary keys every check writes

| Key | Type | Notes |
|---|---|---|
| `account_name` | string | As resolved by `use_account_name_from_tags` |
| `account_id` | string | **Absent** when `exclude_account_ids` is set |
| `check` | string | The registered check name |

Everything else in `summary` comes from the check's `build_summary_fields` and is
specified in that check's document under [`../checks/`](../checks/index.md).

### Summary keys a reader requires

A reader raises rather than defaulting when one of these is missing, because the
missing key and a legitimately empty value mean opposite things (INV-01).

| Key | Required by | Missing means |
|---|---|---|
| `check` | RCP parsing | The file cannot be confirmed to belong to its directory |
| `violations` | RCP parsing | Whether the account can take the RCP is unknown |
| `unique_third_party_accounts` | RCP parsing | The allowlist would render empty, which denies every third party (INV-06) |
| `unique_ami_owners` | `deny_ec2_ami_owner` parsing | Indistinguishable from an account that ran no instances |

RCP parsing additionally rejects a file whose `summary.check` disagrees with the
directory it was found in: a result filed under the wrong check would be
attributed to the wrong policy.

## Redaction

When `exclude_account_ids` is set, before the file is written:

1. Every 12-digit account ID inside an ARN, anywhere in the document, is
   replaced with `REDACTED`. The match is on the ARN's account field
   specifically — `arn:<partition>:<service>:<region>:<account>:` — so an
   account-shaped number elsewhere in a string survives, and so does one in a
   string that is not an ARN.
2. `summary.account_id` is removed.

**Every partition, not only `aws`.** GovCloud, China, and the isolated regions
append hyphenated qualifiers to the partition — `aws-us-gov`, `aws-cn`,
`aws-iso-b` — and an operator there sets `exclude_account_ids` for the same
reason a commercial one does. The pattern once matched the literal `arn:aws:`,
so those partitions kept their account IDs in a file written specifically to be
committed. Nothing in `test_environment/` exercises a non-commercial partition,
which is why it survived; `test_redact_every_aws_partition` pins it now.

Redaction being partition-agnostic does not make Headroom runnable outside the
commercial partition — the role ARNs it assumes are still hardcoded, per
[`../architecture/aws-execution.md`](../architecture/aws-execution.md). This
closes the leak ahead of that rather than after it.

Redaction is not reversible in general. SCP parsing restores IAM user ARNs by
substituting the account ID back in once the account has been identified, because
the allowlist those ARNs feed must name real accounts.

## Identifying the account a file describes

Readers take account identity from the file, never from the filename:

1. Use `summary.account_id` when present.
2. Otherwise resolve `summary.account_name` against the organization hierarchy.
3. A file with neither is an error.

Name resolution is exact-match first. A name matching nothing exactly falls back
to comparing names with case and separators ignored, because result files are
written under the configured name — a slug such as `management-account` where
Organizations reports `Management Account`. The fallback resolves only when
exactly **one** account matches; zero or several is an error rather than a guess.
A name consisting only of separators canonicalizes to the empty string and is
left unresolved, so it cannot match every other such name.

Organizations enforces uniqueness on account email, not on account name, so
several accounts genuinely can share a name. That is an error at read time, not
something to resolve arbitrarily.

## Resume

A check is skipped when its result file already exists for that account. There
is no freshness check and no expiry: **delete the file to re-run the check.**

Resume is evaluated at two granularities, and both must agree with the writer's
naming or a run silently re-scans or silently skips:

| Function | Question |
|---|---|
| `results_exist` | Does this one check have a result for this account? |
| `all_check_results_exist` | Do *all* registered checks of this type have one? |

`run_checks` skips an account entirely when both `scps` and `rcps` are complete;
otherwise it assumes the account role and runs only the checks whose files are
missing.

## Ordering and stability

Result files are written with `indent=2` and a trailing newline so they can be
committed and diffed. Two runs against unchanged infrastructure should produce
files that differ only where the infrastructure differs; a check that emits
unordered collections makes its own output churn and should sort them.
