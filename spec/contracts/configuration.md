# Contract: configuration

Owns the fields Headroom is configured by, where each may be set, and how the
sources combine. Operator instructions for *choosing* values live in
[`../../documentation/SETUP.md`](../../documentation/SETUP.md).

Implementation: `headroom/config.py`, `headroom/usage.py`. Example:
[`../../sample_config.yaml`](../../sample_config.yaml). Tests:
`tests/test_config.py`, `tests/test_main.py`.

## Sources and precedence

Two sources, in this order:

1. The YAML file named by the required `--config` option. A missing file is not
   an error; it loads as empty and validation then decides.
2. CLI options, which override the YAML value for the same field.

An option the operator did not pass must not override. `--exclude-account-ids`
is a store-true flag and therefore uses `argparse.SUPPRESS` as its default, so
that its absence leaves the field out of the namespace entirely rather than
writing `False` over a YAML `true`.

The merged mapping is validated by the `HeadroomConfig` pydantic model. A
missing required field or a wrong type is a configuration error: the process
reports it and exits non-zero rather than proceeding on defaults.

## Single source of defaults

Every default value is defined **once**, in `headroom/config.py`, and read
downstream. A default duplicated at a call site drifts from the one the operator
sees. Nothing outside `config.py` may define a default for a value that is also
a CLI option.

## Fields

| Field | Type | Required | Default | CLI |
|---|---|---|---|---|
| `management_account_id` | `str \| None` | Effectively yes | `None` | `--management-account-id` |
| `security_analysis_account_id` | `str \| None` | No | `None` | `--security-analysis-account-id` |
| `exclude_account_ids` | `bool` | No | `False` | `--exclude-account-ids` |
| `skip_account_ids` | `list[str]` | No | `[]` | — |
| `use_account_name_from_tags` | `bool` | **Yes** | — | — |
| `account_tag_layout` | object | **Yes** | — | — |
| `results_dir` | `str` | No | `test_environment/headroom_results` | `--results-dir` |
| `scps_dir` | `str` | No | `test_environment/scps` | `--scps-dir` |
| `rcps_dir` | `str` | No | `test_environment/rcps` | `--rcps-dir` |

`account_tag_layout` has three required string members: `environment`, `name`,
`owner`. Each names the **tag key** to read, not the value.

`--config` is the only required CLI option and is not a config field.

### `management_account_id`

Typed optional because the model allows it to be absent, but every organization
lookup raises `ValueError` without it. Treat it as required.

### `security_analysis_account_id`

Omitted when Headroom already runs in the security analysis account. When set,
Headroom first assumes `OrganizationAccountAccessRole` there. See
[`../architecture/aws-execution.md`](../architecture/aws-execution.md).

### `exclude_account_ids`

Removes account IDs from result **filenames** and from result **content**: the
`summary.account_id` key is dropped, and 12-digit account IDs inside ARNs are
replaced with `REDACTED`. Exists so a results directory can be committed without
disclosing account IDs.

Changing it between runs must not cause a re-scan or a silent skip; see INV-14
and [`results.md`](results.md).

### `skip_account_ids`

Accounts left out of analysis entirely. Consequences an operator must accept:

- A skipped account writes no result files.
- Placement only ever sees accounts that have results, so a skipped account is
  **invisible** to placement rather than holding a policy back.
- Organization-wide policies are generated as if the account did not exist, and
  may deny actions it relies on.
- Skipping does **not** remove the account from organization membership (INV-04),
  so an in-organization principal there is still not a third party.

Every entry must match an account the Organizations API reports, or the run
aborts (INV-01). An entry matching nothing is otherwise silent: the account the
operator meant to exclude keeps being analyzed and nothing says so.

The skip list is consulted **before** the lifecycle check, so an account whose
state Headroom cannot classify can be excluded by configuration instead of
aborting every other account's analysis.

### `use_account_name_from_tags`

When true, an account's name comes from the tag named by
`account_tag_layout.name`, falling back to the account ID. When false, it comes
from the Organizations `Name` field, falling back to the account ID.

The chosen name becomes part of result filenames and of generated Terraform
identifiers, so changing it changes both. Result files written under a slug such
as `management-account` still resolve against an Organizations name of
`Management Account`: see the name-resolution rules in
[`results.md`](results.md).

### Tag fallbacks

A tag lookup that fails yields no tags; the account then takes the fallbacks
below rather than aborting. This is the one place a per-account AWS failure is
tolerated, because the values are labels rather than evidence, and no policy
decision reads them.

The tolerance is wider than it should be. `_get_account_tags` catches every
`ClientError` and returns `{}`; only the log level distinguishes them —
`AccessDenied` logs at warning, everything else at error with a traceback. A
throttle or a timeout is therefore stepped over as quietly as a permissions gap,
and the account is silently labelled `unknown`. Narrowing the catch to
`AccessDenied` would bring this in line with INV-02 without changing what a
generated policy contains.

| Value | Fallback |
|---|---|
| `environment` | `"unknown"` |
| `owner` | `"unknown"` |
| `name` | the account ID |

## CLI

```
python -m headroom --config CONFIG
                   [--results-dir DIR] [--scps-dir DIR] [--rcps-dir DIR]
                   [--security-analysis-account-id ID]
                   [--management-account-id ID]
                   [--exclude-account-ids]
```

There are no subcommands and no dry-run option. One invocation runs the whole
pipeline: scan, place, generate, reconcile.
