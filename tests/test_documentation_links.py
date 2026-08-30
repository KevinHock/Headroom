"""
Guard against broken relative links in the repository's Markdown files.

A relative link that points at a moved or deleted file sends a reader - or an
agent following the routing in CLAUDE.md - to nothing, and nothing else in the
test suite reads Markdown.
"""

from pathlib import Path

from tests.documentation_links import find_broken_links


def test_reports_a_link_whose_target_is_missing(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("See [contributing](CONTRIBUTING.md).\n")

    assert find_broken_links(tmp_path) == ["README.md -> CONTRIBUTING.md"]


def test_ignores_links_that_leave_the_repository(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text(
        "[docs](https://example.invalid/x)\n"
        "[plain](http://example.invalid/y)\n"
        "[mail](mailto:nobody@example.invalid)\n"
    )

    assert find_broken_links(tmp_path) == []


def test_resolves_a_link_that_carries_an_anchor(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("[trust model](ARCHITECTURE.md#trust-model)\n")
    (tmp_path / "ARCHITECTURE.md").write_text("# Architecture\n\n## Trust model\n")

    assert find_broken_links(tmp_path) == []


def test_resolves_a_link_against_the_file_that_holds_it(tmp_path: Path) -> None:
    (tmp_path / "documentation").mkdir()
    (tmp_path / "documentation" / "CHECKS.md").write_text("[how to](../HOW_TO_ADD_A_CHECK.md)\n")
    (tmp_path / "HOW_TO_ADD_A_CHECK.md").write_text("# How to\n")

    assert find_broken_links(tmp_path) == []


def test_skips_tool_directories(tmp_path: Path) -> None:
    vendored = tmp_path / ".tox" / "py313" / "site-packages" / "somedep"
    vendored.mkdir(parents=True)
    (vendored / "README.md").write_text("[changelog](CHANGELOG.md)\n")

    assert find_broken_links(tmp_path) == []


def test_every_relative_link_in_the_repository_resolves() -> None:
    repository_root = Path(__file__).resolve().parent.parent

    assert find_broken_links(repository_root) == []


def test_checks_markdown_in_dot_directories_that_are_not_tool_output(tmp_path: Path) -> None:
    cursor = tmp_path / ".cursor"
    cursor.mkdir()
    (cursor / "mental_model.md").write_text("[the guide](../CLAUDE.md)\n")

    assert find_broken_links(tmp_path) == [".cursor/mental_model.md -> ../CLAUDE.md"]


def test_reports_a_broken_mdc_link_in_a_cursor_rule(tmp_path: Path) -> None:
    """
    .cursor/rules/*.mdc route agents by path and must not point at nothing.

    Cursor writes its intra-repository links as mdc:<path>, which reads as a
    URL scheme, and the files carry a .mdc extension rather than .md. Both
    would exempt them from an unmodified scan.
    """
    rules = tmp_path / ".cursor" / "rules"
    rules.mkdir(parents=True)
    (rules / "010-checks.mdc").write_text("Read [the manifest](mdc:spec/README.md).\n")

    assert find_broken_links(tmp_path) == [".cursor/rules/010-checks.mdc -> mdc:spec/README.md"]


def test_resolves_an_mdc_link_from_the_repository_root(tmp_path: Path) -> None:
    """An mdc: target is repository-relative, not relative to the rule file."""
    rules = tmp_path / ".cursor" / "rules"
    rules.mkdir(parents=True)
    (rules / "010-checks.mdc").write_text("Read [the manifest](mdc:spec/README.md).\n")
    (tmp_path / "spec").mkdir()
    (tmp_path / "spec" / "README.md").write_text("# Manifest\n")

    assert find_broken_links(tmp_path) == []


def test_reports_an_anchor_that_no_heading_defines(tmp_path: Path) -> None:
    """
    A link into a section that was renamed lands at the top of the page.

    CLAUDE.md routes agents to a named section of the specification manifest,
    so the anchor is load-bearing, not decoration.
    """
    (tmp_path / "CLAUDE.md").write_text("[routing](spec/README.md#routing-by-path)\n")
    (tmp_path / "spec").mkdir()
    (tmp_path / "spec" / "README.md").write_text("# Manifest\n\n## Routing: what to read\n")

    assert find_broken_links(tmp_path) == ["CLAUDE.md -> spec/README.md#routing-by-path"]


def test_resolves_an_anchor_a_heading_defines(tmp_path: Path) -> None:
    """Slugs lowercase the heading, drop punctuation, and hyphenate spaces."""
    (tmp_path / "CLAUDE.md").write_text(
        "[routing](spec/README.md#routing-what-to-read-for-the-path-you-are-touching)\n"
    )
    (tmp_path / "spec").mkdir()
    (tmp_path / "spec" / "README.md").write_text(
        "# Manifest\n\n## Routing: what to read for the path you are touching\n"
    )

    assert find_broken_links(tmp_path) == []


def test_resolves_an_anchor_into_the_same_document(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("Jump to [setup](#setup-and-install).\n\n## Setup and install\n")

    assert find_broken_links(tmp_path) == []


def test_reports_an_anchor_into_the_same_document_that_no_heading_defines(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("Jump to [setup](#setup).\n\n## Installation\n")

    assert find_broken_links(tmp_path) == ["README.md -> #setup"]
