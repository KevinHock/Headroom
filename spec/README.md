# Headroom specification corpus

The version-controlled specification corpus is the primary product. The
implementation is an expression of that corpus.

This directory holds the normative intended behavior of Headroom. It is written
for two readers at once: a person deciding whether a policy is safe to deploy,
and a coding agent deciding what a change is allowed to do.

## Authority model

1. `spec/` states **normative** intended behavior. A statement here is a
   requirement, not a description.
2. [`invariants.md`](invariants.md) holds **global invariants**. They apply to
   every subsystem and every check. Nothing in a subsystem contract or a
   per-check specification silently overrides one; a deliberate exception is
   written down at the invariant.
3. A per-check specification under [`checks/`](checks/index.md) defines behavior
   **specific to that check** and nothing else.
4. Source and tests demonstrate the **current implementation**. They are
   evidence of what is, not of what should be.
5. `README.md`, [`documentation/`](../documentation/), and
   [`test_environment/`](../test_environment/) are **informative or derived**.
   They must link to the normative specification rather than restate it.
6. When a normative specification and implementation evidence conflict, **report
   the conflict**. Do not guess which side is right, and do not quietly change
   either one to match the other.
7. Git history supplies dates and authorship. No document carries a manual
   "last updated" field.

## Precedence

`invariants.md` › subsystem contract (`architecture/`, `contracts/`) › per-check
specification › informative documentation.

Higher precedence wins on conflict. A per-check specification may narrow a
contract for its own check; it may not widen one.

## Reading order

Read top down; each layer assumes the one above it.

| Order | Document | Answers |
|---|---|---|
| 1 | [`product.md`](product.md) | What problem Headroom solves and what it promises |
| 2 | [`invariants.md`](invariants.md) | The rules no subsystem may break |
| 3 | [`architecture/overview.md`](architecture/overview.md) | The pipeline and who owns each stage |
| 4 | [`contracts/`](contracts/) | The interface between two stages |
| 5 | [`checks/index.md`](checks/index.md) | What each check decides |
| 6 | [`verification/strategy.md`](verification/strategy.md) | What counts as proof |

## Document ownership

Exactly one document owns each topic. If you find a topic stated twice, one of
the two is wrong; fix it at the owner and link from the other.

| Document | Owns |
|---|---|
| [`product.md`](product.md) | Purpose, users, the safety promise, non-goals |
| [`invariants.md`](invariants.md) | Global invariants, each with an ID |
| [`architecture/overview.md`](architecture/overview.md) | Pipeline stages, module responsibility, data flow |
| [`architecture/aws-execution.md`](architecture/aws-execution.md) | Role chain, sessions, regions, account projections, failure policy |
| [`architecture/check-framework.md`](architecture/check-framework.md) | Registry, `BaseCheck` template, result categories |
| [`contracts/configuration.md`](contracts/configuration.md) | Config fields, CLI options, precedence, defaults |
| [`contracts/results.md`](contracts/results.md) | Result JSON schema, filenames, redaction, resume |
| [`contracts/policy-model.md`](contracts/policy-model.md) | SCP/RCP semantics, policy patterns, statement grammar |
| [`contracts/placement.md`](contracts/placement.md) | Placement levels, safety predicates, allowlist unions |
| [`contracts/terraform.md`](contracts/terraform.md) | Generated files, ownership marker, reconciliation, module variables |
| [`checks/index.md`](checks/index.md) | The check inventory and the per-check document contract |
| `checks/scps/*.md`, `checks/rcps/*.md` | One check each |
| [`verification/strategy.md`](verification/strategy.md) | Test layers, gates, what a test may assume |

Deliberately **outside** the corpus, and never normative:

| Document | Holds |
|---|---|
| [`../documentation/SETUP.md`](../documentation/SETUP.md) | Operator setup: roles, credentials, troubleshooting |
| [`../documentation/EXAMPLES.md`](../documentation/EXAMPLES.md) | Illustrative output |
| [`../test_environment/README.md`](../test_environment/README.md) | Live-test topology, execution, cost, cleanup |
| [`../ROADMAP.md`](../ROADMAP.md) | Future work |
| [`../HOW_TO_ADD_A_CHECK.md`](../HOW_TO_ADD_A_CHECK.md) | Authoring runbook for a new check |

## Routing: what to read for the path you are touching

Match the longest path prefix. Always load this manifest and
[`invariants.md`](invariants.md); load the rest only as the table directs.
[`../.cursor/rules/`](../.cursor/rules) encodes this table as glob-scoped rules
for editors that apply them automatically. This table is the source; those rules
are derived from it and are updated with it.

| Touched path | Also read |
|---|---|
| `headroom/checks/scps/<name>.py` | [`checks/scps/<name>.md`](checks/scps/), [`architecture/check-framework.md`](architecture/check-framework.md) |
| `headroom/checks/rcps/<name>.py` | [`checks/rcps/<name>.md`](checks/rcps/), [`architecture/check-framework.md`](architecture/check-framework.md), [`contracts/policy-model.md`](contracts/policy-model.md) |
| `headroom/checks/base.py`, `headroom/checks/registry.py` | [`architecture/check-framework.md`](architecture/check-framework.md), [`contracts/results.md`](contracts/results.md) |
| `headroom/aws/policy_documents.py` | [`contracts/policy-model.md`](contracts/policy-model.md), every `checks/rcps/*.md` |
| `headroom/aws/organization.py`, `headroom/analysis.py` | [`architecture/aws-execution.md`](architecture/aws-execution.md), [`contracts/placement.md`](contracts/placement.md) |
| `headroom/aws/sessions.py`, `headroom/aws/helpers.py` | [`architecture/aws-execution.md`](architecture/aws-execution.md) |
| `headroom/aws/<service>.py` | the `checks/*` documents naming that service, [`contracts/policy-model.md`](contracts/policy-model.md) |
| `headroom/write_results.py`, `headroom/parse_results.py` | [`contracts/results.md`](contracts/results.md), [`contracts/placement.md`](contracts/placement.md) |
| `headroom/placement/` | [`contracts/placement.md`](contracts/placement.md) |
| `headroom/terraform/` | [`contracts/terraform.md`](contracts/terraform.md), [`contracts/placement.md`](contracts/placement.md) |
| `headroom/config.py`, `headroom/usage.py`, `sample_config.yaml` | [`contracts/configuration.md`](contracts/configuration.md) |
| `test_environment/modules/` | [`contracts/terraform.md`](contracts/terraform.md), [`contracts/policy-model.md`](contracts/policy-model.md), the affected `checks/*` documents |
| `tests/` | [`verification/strategy.md`](verification/strategy.md) |
| `spec/checks/` | [`checks/index.md`](checks/index.md) and `tests/test_spec_corpus.py` |

## Glossary

| Term | Meaning |
|---|---|
| **SCP** | Service Control Policy. Bounds what principals **in** an account may do. |
| **RCP** | Resource Control Policy. Bounds who may act **on** resources in an account. |
| **Check** | One registered analyzer that decides whether one policy statement is safe to deploy. |
| **Violation** | A resource the intended policy statement would deny. |
| **Exemption** | A resource the statement's condition would spare. Does not block deployment. |
| **Compliant** | A resource the statement would allow. |
| **Blocker** | An RCP finding that no allowlist can express, so the policy cannot deploy at all. |
| **Placement** | The organization target — root, OU, or account — a policy is attached to. |
| **Headroom** | The distance between what workloads actually do and what policy would permit. |
| **Analyzable account** | An ACTIVE member account, excluding the management account and `skip_account_ids`. |
| **Organization membership** | Every account the Organizations API reports, whatever its state. |
| **Reconciliation** | Deleting the generated files this run did not render. |
| **Ownership marker** | The first line that makes a `.tf` file Headroom's to delete. |
