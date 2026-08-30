# Architecture: overview

Owns the pipeline: what the stages are, which module owns each, and what passes
between them. The interface between two stages is a contract document; this
document says which contract applies where.

## One pass, one direction

```
configuration
   → organization discovery
      → checks
         → result artifacts
            → placement
               → Terraform generation
                  → reconciliation
```

There is no loop and no second pass. Every stage reads the artifact the previous
one produced and never writes back into it. A stage that cannot complete aborts
the run (INV-02) rather than handing a partial artifact forward.

## The stages

| Stage | Owner | Produces | Contract |
|---|---|---|---|
| Configuration | `usage.py`, `config.py` | A validated `HeadroomConfig` | [`../contracts/configuration.md`](../contracts/configuration.md) |
| Organization discovery | `analysis.py`, `aws/organization.py` | Three account projections | [`aws-execution.md`](aws-execution.md) |
| Checks | `checks/`, `aws/<service>.py` | Per-resource verdicts | [`check-framework.md`](check-framework.md) |
| Result artifacts | `write_results.py` | One JSON per check per account | [`../contracts/results.md`](../contracts/results.md) |
| Placement | `parse_results.py`, `placement/`, `generate_rcps.py` | Recommendations naming a target | [`../contracts/placement.md`](../contracts/placement.md) |
| Terraform generation | `terraform/` | A rendered plan | [`../contracts/terraform.md`](../contracts/terraform.md) |
| Reconciliation | `terraform/reconcile.py` | Deletions | [`../contracts/terraform.md`](../contracts/terraform.md) |

The entry point that sequences them is `headroom/main.py`.

## Why the artifact boundary matters

Results are written to disk and read back by a **separate** stage, in the same
run or a later one. That is deliberate: a scan is expensive and rate-limited, and
policy generation is cheap and iterated. The boundary is what makes resume
possible.

It also creates the failure mode most of the invariants defend against. The
readers glob `*.json` and take account identity from each file's own `summary`,
so a file that is absent, stale, or written under a different name does not make
a reader fail — it makes the compliance picture quietly smaller. Hence INV-01 and
INV-14.

## Module responsibilities

```
headroom/
├── main.py              entry point; sequences the stages, catches at the top level
├── usage.py             CLI parsing and YAML loading
├── config.py            HeadroomConfig, and the single source of every default
├── analysis.py          account projections; runs checks per account
├── aws/                 one module per AWS service; all API calls live here
│   ├── sessions.py      the only place a boto3 Session is constructed
│   ├── helpers.py       enabled-region discovery, pagination
│   ├── organization.py  Organizations API and the OU tree
│   └── policy_documents.py  shared grammar for reading IAM policy documents
├── checks/              one module per check; registry and BaseCheck
├── write_results.py     the result writer, and result path resolution
├── parse_results.py     SCP result reading and SCP placement
├── placement/           hierarchy traversal, policy-agnostic
├── terraform/           rendering, org info, reconciliation
├── constants.py         check names, the ownership marker, shared patterns
├── enums.py             CheckType, CheckCategory, PlacementLevel
├── types.py             shared dataclasses
├── output.py            console output
└── utils.py             identifier and Terraform-name formatting
```

Two boundaries worth stating outright:

- **Only `aws/` calls AWS.** A check module composes `aws/` functions and
  decides; it does not construct clients.
- **Only `aws/sessions.py` constructs a `Session`**, so the regional-endpoint
  setting cannot be missed at one hop (INV-16). Pinned by
  `test_only_the_sessions_module_constructs_a_session`.

## Where a change lands

`spec/README.md` carries the full routing table. The short version:

| Changing | Read |
|---|---|
| What a check decides | that check's document, and [`check-framework.md`](check-framework.md) |
| How a policy document is read | [`../contracts/policy-model.md`](../contracts/policy-model.md), and every RCP check |
| What is written or read back | [`../contracts/results.md`](../contracts/results.md) |
| Where a policy attaches | [`../contracts/placement.md`](../contracts/placement.md) |
| What lands in the output directory | [`../contracts/terraform.md`](../contracts/terraform.md) |

## Diagrams

Illustrative, generated from the code and non-normative:
[`../../documentation/mermaid_diagrams/`](../../documentation/mermaid_diagrams/README.md)
— execution flow, module dependency graph, class model, and sequence diagrams.
Where a diagram and this corpus disagree, the corpus is right and the diagram is
stale.
