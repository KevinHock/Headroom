# CLAUDE.md

Guidance for agents working in this repository. `AGENTS.md` points here; this file is the single source of truth for *how to work*. [`spec/`](spec/README.md) is the single source of truth for *what the software must do*.

## Truth hierarchy

The version-controlled specification corpus is the primary product. The implementation is an expression of that corpus.

- `spec/` is **normative**: it states intended behavior. [`spec/README.md`](spec/README.md) carries the full authority model and precedence chain; read it before your first change.
- Code and tests are **evidence of current behavior**, not of intent.
- Where the two disagree, **report the conflict**. Do not quietly change either side to match the other. If the intent is unambiguous, fix the implementation and say so; if it is not, record it in the unresolved table in [`spec/checks/index.md`](spec/checks/index.md) and leave behavior alone.
- Change the specification and the implementation in the same commit. A behavior change with no corresponding specification edit is incomplete.
- Git history supplies dates. No document carries a manual "last updated" field.

## The pipeline

Headroom scans an AWS Organization and generates Terraform SCPs and RCPs that will not break existing workloads. One pass, one direction:

Configuration → organization discovery → checks → result artifacts → placement → Terraform generation → reconciliation.

[`spec/architecture/overview.md`](spec/architecture/overview.md) owns the stages.

## Always

These are global invariants; [`spec/invariants.md`](spec/invariants.md) states each one in full and is the place to cite, argue with, or amend it.

- **INV-15** — use obviously fake AWS identifiers everywhere, including commit messages. An identifier from a bug report, error message, console screenshot, or API response is real; rewrite it before it enters the repo.
- **INV-14** — persisted results keep wire compatibility unless you are performing an explicit migration. A later run reads back both the JSON and the filenames.
- **INV-13** — every stage is driven by the registry. Check discovery in `headroom/checks/__init__.py` is the one sanctioned dynamic import; everywhere else, import at the top of the file.
- **INV-04** — organization membership, analyzable accounts, and hierarchy are distinct projections. Code that collapses them is wrong.
- **INV-01** — absence of evidence is not evidence of safety. A region that could not be read, a policy that could not be parsed, and an API that failed are not "no findings".

## Routes

Two routing tables, used together.

1. **Which specifications govern the file you are touching** → the routing table in [`spec/README.md`](spec/README.md#routing-what-to-read-for-the-path-you-are-touching). Always load that manifest and `spec/invariants.md`; load the rest by longest matching path prefix. [`.cursor/rules/`](.cursor/rules) encodes the same routing as glob-scoped rules for editors that apply them automatically; the table is the source, the rules are derived.
2. **Which implementation files and tests a change must open** → below. Read the branch that matches your change and skip the rest.

- **Adding or changing a check, or registry discovery** → [`HOW_TO_ADD_A_CHECK.md`](HOW_TO_ADD_A_CHECK.md), `headroom/checks/registry.py`, and `tests/test_checks_registry.py`. Every stage from collection to Terraform is driven by the registry rather than by check name, with one exception: a new RCP check must also be named in `RCP_TERRAFORM_VARIABLES`, which `test_table_covers_every_registered_rcp_check` in `tests/test_generate_rcps.py` enforces. A new check also needs its specification under `spec/checks/`, which `tests/test_spec_corpus.py` enforces.
- **Principal, action, wildcard, or statement interpretation** → `headroom/aws/policy_documents.py` plus every service adapter that reads policy documents: `headroom/aws/ecr.py`, `kms.py`, `s3.py`, `secretsmanager.py`, `sqs.py`, and `iam/roles.py`. A change to how a statement is read is a change to all of them.
- **Generated paths, symlinks, ownership markers, or reconciliation** → [`spec/contracts/terraform.md`](spec/contracts/terraform.md), then `headroom/terraform/reconcile.py`, `ensure_org_info_symlink` in `headroom/main.py`, and `tests/test_terraform_reconcile.py`.
- **Result JSON schemas, filenames, resume behavior, or cache detection** → [`spec/contracts/results.md`](spec/contracts/results.md), the writer `headroom/write_results.py`, its one call site `BaseCheck.execute` in `headroom/checks/base.py`, and both readers, `headroom/parse_results.py` for SCPs and `headroom/terraform/generate_rcps.py` for RCPs. A filename change can silently re-scan or silently skip accounts without any reader failing. Tests: `tests/test_write_results.py`, `tests/test_parse_results.py`, and `TestRunChecks` in `tests/test_analysis_extended.py`.
- **Account enumeration or hierarchy behavior** → `headroom/analysis.py` and `headroom/aws/organization.py`, keeping INV-04's three projections distinct, with `tests/test_placement_hierarchy.py` and `tests/test_nested_ou_hierarchy.py`.
- **Public CLI options or configuration** → `headroom/usage.py`, `headroom/config.py`, and `sample_config.yaml`, then `README.md` and `documentation/SETUP.md`, with `tests/test_config.py` and `tests/test_main.py`.
- **Documentation prose with no behavior change** → edit the file; no implementation file is implicated. `tests/test_documentation_links.py` fails on a relative link whose target is missing and `tests/test_spec_corpus.py` fails on a malformed or missing check specification, so run those two in place of `tox`.

## Conventions

[`.cursorrules`](.cursorrules) is authoritative for code conventions. It carries the fail-fast rules, the single-source-of-defaults rule for CLI and config values, and the import rules including the check-discovery exception above.

## Completion

- Read the implementation and the existing tests for every boundary you touch before editing.
- Write the failing test first and watch it fail for the reason you expect, then write only enough code to pass it. One test, one implementation, repeat — do not write every test up front. Start a bug fix with the test that reproduces it.
- An assertion that computes its expected value the way the code computes it passes by construction and can never disagree with the code. Take expected values from an independent source: a known-good literal, a worked example, the documented shape of the AWS policy.
- Tests are flat under `tests/`, one file per module.
- Run the smallest relevant test files while working, then `tox` before calling the work done.
- If verification cannot run, report the exact unavailable dependency or environment constraint instead of a pass.
- Update the specification document that owns what you changed, in the same change. `spec/README.md` names the owner. Do this once, when the code has settled, rather than rewriting prose after every edit.
