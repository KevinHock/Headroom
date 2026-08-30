"""Tests for the specification corpus validator."""

from pathlib import Path

import pytest

from headroom.checks.registry import get_check_type_map
from tests.documentation_links import find_broken_links
from tests.spec_corpus import (
    REQUIRED_FIELDS,
    find_corpus_problems,
    invariant_ids,
    load_check_specifications,
    parse_frontmatter,
)

SPEC_ROOT = Path(__file__).resolve().parent.parent / "spec"

# A document that satisfies every rule, used as the base for the failure cases.
GOOD_FRONTMATTER = """---
id: deny_ec2_public_ip
kind: scp
status: implemented
applies_to:
  - headroom/checks/scps/deny_ec2_public_ip.py
depends_on:
  - INV-02
verification:
  - tests/test_checks_deny_ec2_public_ip.py
---

# deny_ec2_public_ip

## Objective

## Enforced statement

## Evidence

## Decision table

## Failure behavior

## Result contract

## Placement and generated policy

## Accepted limitations

## Acceptance scenarios

## Referenced invariants

## Implementation
"""


def build_corpus(tmp_path: Path, document: str, name: str = "deny_ec2_public_ip.md") -> Path:
    """
    Write a one-document corpus whose repository root holds the real files.

    Args:
        tmp_path: pytest temporary directory
        document: Full text of the specification document
        name: Filename to write it under

    Returns:
        The spec root inside the temporary tree
    """
    repository_root = Path(__file__).resolve().parent.parent
    spec_root = tmp_path / "spec"
    (spec_root / "checks" / "scps").mkdir(parents=True)
    (spec_root / "checks" / "rcps").mkdir(parents=True)
    (spec_root / "checks" / "scps" / name).write_text(document)
    (spec_root / "invariants.md").write_text(
        (repository_root / "spec" / "invariants.md").read_text()
    )
    # The validator resolves applies_to and verification against spec_root.parent,
    # so the temporary root needs the real files those fields name.
    (tmp_path / "headroom" / "checks" / "scps").mkdir(parents=True)
    (tmp_path / "headroom" / "checks" / "scps" / "deny_ec2_public_ip.py").touch()
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_checks_deny_ec2_public_ip.py").touch()
    return spec_root


ONE_REGISTERED_CHECK = {"deny_ec2_public_ip": "scps"}


class TestTheRealCorpus:
    """The corpus in spec/ must agree with the registry."""

    def test_every_registered_check_has_exactly_one_specification(self) -> None:
        assert find_corpus_problems(SPEC_ROOT, get_check_type_map()) == []

    def test_the_corpus_covers_all_fifteen_checks(self) -> None:
        # An independent count: nine SCP modules and six RCP modules ship today,
        # so a document added or dropped without a check shows up here.
        specifications = load_check_specifications(SPEC_ROOT)
        assert len(specifications) == 15

    def test_invariants_are_numbered_without_gaps(self) -> None:
        identifiers = invariant_ids(SPEC_ROOT)
        assert identifiers == [f"INV-{number:02d}" for number in range(1, len(identifiers) + 1)]

    def test_every_relative_link_in_the_corpus_resolves(self) -> None:
        assert find_broken_links(SPEC_ROOT) == []


class TestFrontmatter:
    """Parsing the frontmatter block."""

    def test_a_leading_block_is_parsed(self) -> None:
        assert parse_frontmatter("---\nid: a\n---\n# Title\n") == {"id": "a"}

    def test_a_document_without_frontmatter_has_none(self) -> None:
        assert parse_frontmatter("# Title\n") is None

    def test_frontmatter_that_is_not_a_mapping_has_none(self) -> None:
        assert parse_frontmatter("---\n- one\n- two\n---\n") is None


class TestDocumentProblems:
    """One document at a time, against a one-check registry."""

    def test_a_good_document_has_no_problems(self, tmp_path: Path) -> None:
        spec_root = build_corpus(tmp_path, GOOD_FRONTMATTER)
        assert find_corpus_problems(spec_root, ONE_REGISTERED_CHECK) == []

    @pytest.mark.parametrize("field", REQUIRED_FIELDS)
    def test_a_missing_required_field_is_reported(self, tmp_path: Path, field: str) -> None:
        document = "\n".join(
            line for line in GOOD_FRONTMATTER.splitlines() if not line.startswith(f"{field}:")
        )
        spec_root = build_corpus(tmp_path, document)
        problems = find_corpus_problems(spec_root, ONE_REGISTERED_CHECK)
        assert problems == [f"deny_ec2_public_ip.md frontmatter is missing: {field}"]

    def test_an_id_that_does_not_match_the_filename_is_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace("id: deny_ec2_public_ip", "id: something_else")
        spec_root = build_corpus(tmp_path, document)
        problems = find_corpus_problems(spec_root, ONE_REGISTERED_CHECK)
        assert "declares id 'something_else', expected 'deny_ec2_public_ip'" in problems[0]

    def test_a_kind_that_does_not_match_the_directory_is_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace("kind: scp", "kind: rcp")
        spec_root = build_corpus(tmp_path, document)
        problems = find_corpus_problems(spec_root, ONE_REGISTERED_CHECK)
        assert any("declares kind 'rcp' but sits in checks/scps/" in problem for problem in problems)

    def test_an_unknown_status_is_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace("status: implemented", "status: mostly")
        spec_root = build_corpus(tmp_path, document)
        problems = find_corpus_problems(spec_root, ONE_REGISTERED_CHECK)
        assert any("declares status 'mostly'" in problem for problem in problems)

    def test_a_document_naming_no_registered_check_is_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace("deny_ec2_public_ip", "deny_nothing")
        spec_root = build_corpus(tmp_path, document, name="deny_nothing.md")
        problems = find_corpus_problems(spec_root, ONE_REGISTERED_CHECK)
        assert "deny_nothing.md names no registered scp check" in problems

    def test_an_undefined_invariant_is_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace("- INV-02", "- INV-99")
        spec_root = build_corpus(tmp_path, document)
        problems = find_corpus_problems(spec_root, ONE_REGISTERED_CHECK)
        assert "deny_ec2_public_ip.md cites INV-99, which invariants.md does not define" in problems

    def test_an_applies_to_path_that_does_not_exist_is_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace(
            "  - headroom/checks/scps/deny_ec2_public_ip.py",
            "  - headroom/checks/scps/gone.py",
        )
        spec_root = build_corpus(tmp_path, document)
        problems = find_corpus_problems(spec_root, ONE_REGISTERED_CHECK)
        assert (
            "deny_ec2_public_ip.md applies_to names a missing path: "
            "headroom/checks/scps/gone.py"
        ) in problems

    def test_a_verification_path_that_does_not_exist_is_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace(
            "  - tests/test_checks_deny_ec2_public_ip.py",
            "  - tests/test_gone.py",
        )
        spec_root = build_corpus(tmp_path, document)
        problems = find_corpus_problems(spec_root, ONE_REGISTERED_CHECK)
        assert "deny_ec2_public_ip.md verification names a missing path: tests/test_gone.py" in problems


class TestCorpusWideProblems:
    """Problems that only appear across documents."""

    def test_a_registered_check_with_no_specification_is_reported(self, tmp_path: Path) -> None:
        spec_root = build_corpus(tmp_path, GOOD_FRONTMATTER)
        registry = {"deny_ec2_public_ip": "scps", "deny_rds_unencrypted": "scps"}
        problems = find_corpus_problems(spec_root, registry)
        assert problems == ["registered check deny_rds_unencrypted has no specification"]

    def test_two_documents_declaring_one_id_are_reported(self, tmp_path: Path) -> None:
        spec_root = build_corpus(tmp_path, GOOD_FRONTMATTER)
        (spec_root / "checks" / "scps" / "duplicate.md").write_text(GOOD_FRONTMATTER)
        problems = find_corpus_problems(spec_root, ONE_REGISTERED_CHECK)
        assert (
            "id 'deny_ec2_public_ip' is declared by both "
            "deny_ec2_public_ip.md and duplicate.md"
        ) in problems

    def test_a_document_without_frontmatter_reports_every_field(self, tmp_path: Path) -> None:
        spec_root = build_corpus(tmp_path, "# No frontmatter at all\n")
        problems = find_corpus_problems(spec_root, ONE_REGISTERED_CHECK)
        assert problems[0] == (
            "deny_ec2_public_ip.md frontmatter is missing: "
            "id, kind, status, applies_to, depends_on, verification"
        )


class TestSectionContract:
    """Every per-check document must carry the eleven sections index.md states."""

    def test_a_document_missing_a_required_section_is_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace("## Placement and generated policy\n\n", "")
        spec_root = build_corpus(tmp_path, document)

        assert find_corpus_problems(spec_root, ONE_REGISTERED_CHECK) == [
            "deny_ec2_public_ip.md is missing section: Placement and generated policy"
        ]

    def test_sections_out_of_order_are_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace(
            "## Evidence\n\n## Decision table\n",
            "## Decision table\n\n## Evidence\n",
        )
        spec_root = build_corpus(tmp_path, document)

        assert find_corpus_problems(spec_root, ONE_REGISTERED_CHECK) == [
            "deny_ec2_public_ip.md orders sections Decision table before Evidence"
        ]

    def test_an_unrecognized_section_is_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace(
            "## Implementation\n", "## Design notes\n\n## Implementation\n"
        )
        spec_root = build_corpus(tmp_path, document)

        assert find_corpus_problems(spec_root, ONE_REGISTERED_CHECK) == [
            "deny_ec2_public_ip.md has an unrecognized section: Design notes"
        ]

    def test_a_known_conflict_section_is_allowed_anywhere(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace(
            "## Accepted limitations\n",
            "## Known conflict: the summary omits violations\n\n"
            "**Status: unresolved.**\n\n"
            "## Accepted limitations\n",
        )
        spec_root = build_corpus(tmp_path, document)

        assert find_corpus_problems(spec_root, ONE_REGISTERED_CHECK) == []

    def test_a_known_conflict_without_a_status_is_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace(
            "## Accepted limitations\n",
            "## Known conflict: the summary omits violations\n\n"
            "It reads zero for every account.\n\n"
            "## Accepted limitations\n",
        )
        spec_root = build_corpus(tmp_path, document)

        assert find_corpus_problems(spec_root, ONE_REGISTERED_CHECK) == [
            "deny_ec2_public_ip.md has a Known conflict section that "
            "does not say Status: unresolved"
        ]


class TestMalformedFrontmatterValues:
    """A field of the wrong YAML type must report, not raise."""

    def test_a_scalar_where_a_list_belongs_is_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace(
            "depends_on:\n  - INV-02\n", "depends_on: INV-02\n"
        )
        spec_root = build_corpus(tmp_path, document)

        assert find_corpus_problems(spec_root, ONE_REGISTERED_CHECK) == [
            "deny_ec2_public_ip.md depends_on must be a list, not a str"
        ]

    def test_an_empty_field_is_reported(self, tmp_path: Path) -> None:
        document = GOOD_FRONTMATTER.replace(
            "verification:\n  - tests/test_checks_deny_ec2_public_ip.py\n", "verification:\n"
        )
        spec_root = build_corpus(tmp_path, document)

        assert find_corpus_problems(spec_root, ONE_REGISTERED_CHECK) == [
            "deny_ec2_public_ip.md verification must be a list, not a NoneType"
        ]
