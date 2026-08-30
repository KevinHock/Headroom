# Verification strategy

Owns what counts as proof that the implementation matches this corpus. Tests and
schemas are executable parts of the specification: a rule stated here and pinned
by a named test is enforced, and a rule stated here with no test is an intention.

## The gate

`tox` is the gate. It runs the whole thing on Python 3.12 and 3.13, and every
step must pass:

| Step | Requirement |
|---|---|
| `pytest tests/` | Every test passes |
| Coverage of `headroom/` | **100%**. `.coveragerc` omits `*/__main__.py`, and `.tox/*` and `setup.py`, which are not source |
| Coverage of `tests/` | **100%** — the test suite must exercise its own helpers |

`.coveragerc` also excludes any line marked `pragma: no cover`. One line carries
it today, an unreachable fallback in a test double
(`tests/test_analysis_extended.py`). It is an escape hatch, not a budget: a new
one in `headroom/` needs a reason in review, because the 100% figure is only
worth what the exclusions leave in.
| `mypy headroom/ tests/` | Clean, under a strict configuration |
| `pre-commit run --all-files` | End-of-file, trailing whitespace, autoflake, flake8, autopep8 |

100% coverage on both trees is a floor, not the objective. It says every line ran;
it says nothing about whether the assertion was worth making. The rules below are
what make a covered line meaningful.

While working, run the smallest relevant test files. Run `tox` before calling the
work done. If it cannot run, report the exact unavailable dependency or
environment constraint — never a pass.

## Test-first

Write the failing test first and watch it fail for the reason you expect, then
write only enough code to pass it. One test, one implementation, repeat. Start a
bug fix with the test that reproduces it.

A test written after the code passes immediately, which proves nothing: it was
shaped by the implementation it is meant to judge.

## Assertions must be independently derived

An assertion that computes its expected value the way the code computes it passes
by construction and can never disagree with the code.

Take expected values from an independent source: a known-good literal, a worked
example, or the documented shape of the AWS policy or API response. Where a
per-check specification states a decision table or an acceptance scenario, that
is such a source — the specification is written from intent, and the test asserts
against it.

Fixtures must be shaped like **real** AWS responses. An impossible fixture hid a
released bug for a version: `deny_ec2_ami_owner`'s tests asserted an
`OwnerId: "amazon"` that AWS cannot return, which is exactly the case INV-08
exists to prevent.

## Layout

Tests are flat under `tests/`, one file per module. There are no scenario
subdirectories and no shared fixture package.

| File | Covers |
|---|---|
| `tests/test_<module>.py` | `headroom/<module>.py` |
| `tests/test_aws_<service>.py` | `headroom/aws/<service>.py` |
| `tests/test_checks_<check_name>.py` | one check |
| `tests/test_spec_corpus.py` | this corpus against the registry |
| `tests/test_documentation_links.py` | relative Markdown links resolve |

Three files depart from that, deliberately:

- `tests/test_nested_ou_hierarchy.py` — generates org info and policies from one
  hierarchy and asserts every `local.` a policy reads is one the org info
  declares (INV-12). Cross-module by construction: the bug only appears when two
  modules are generated from one input.
- `tests/test_main_integration.py` — the pipeline end to end against fakes.
- `tests/test_analysis_extended.py` — a second file over `headroom/analysis.py`,
  holding the account-enumeration and resume paths. It is a size split rather
  than a boundary, and the two would be better merged than imitated.

## Named guard tests

These pin invariants that no ordinary unit test would catch. Renaming one without
replacing it removes an invariant's only enforcement.

| Test | Pins |
|---|---|
| `test_only_the_sessions_module_constructs_a_session` | INV-16 — one construction site for sessions |
| `test_only_enabled_regions_are_requested` | INV-16 — `describe_regions` takes no arguments |
| `test_every_state_aws_defines_is_classified` | INV-03 — a new AWS lifecycle state surfaces in CI |
| `test_table_covers_every_registered_rcp_check` | INV-13 — `RCP_TERRAFORM_VARIABLES` matches the registry |
| `tests/test_spec_corpus.py` | Every registered check has exactly one specification |

## What the corpus test enforces

`tests/test_spec_corpus.py` reads the registry and this directory tree, with no
network and no AWS calls. It fails when:

- a registered check has no specification, or more than one;
- a specification names a check that is not registered;
- a specification's frontmatter is missing a required field, or its `id` or
  `kind` disagrees with the registry;
- two specifications share an `id`;
- a specification cites an invariant ID that `invariants.md` does not define;
- a relative link inside `spec/` points at a file that does not exist.

Adding a check therefore fails the suite until its specification exists. That is
the intended order: the specification is written first.

## Live verification

`test_environment/` holds Terraform for a complete sample organization —
accounts, roles, deliberately non-compliant resources — used to confirm that a
generated policy actually denies what it claims to. It costs real money and is
not part of `tox`.

Topology, execution, cost, and cleanup:
[`../../test_environment/README.md`](../../test_environment/README.md).

A live result is evidence about AWS, not about Headroom. Where the two disagree —
a policy AWS enforces differently than a check predicted — the finding belongs in
the affected check's specification, measured with a `--dry-run` probe and cited.
