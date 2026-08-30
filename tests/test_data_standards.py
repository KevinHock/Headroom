"""
Enforce INV-15: committed AWS identifiers are obviously fake.

`test_environment/` is the one standing exception, and the invariant states its
size in prose. Nothing checked that prose against the directory, so it drifted:
the count was written once and the identifiers grew past it. These tests couple
the two, and pin the exception to the directory it is scoped to.

A twelve-digit number carries no evidence of being real, so the scan cannot
recognize a newly pasted identifier on sight. It enforces the two properties
that are decidable instead: the documented count matches what the directory
holds, and no identifier from the exception appears outside it.

Fixtures standing in for a real identifier use the digits of pi. A reader can
see it is invented, while the scanner reads it the way it reads a real one -
which a placeholder-shaped value could not exercise.
"""

from pathlib import Path

from tests.data_standards import (
    account_ids_by_location,
    documented_exception_count,
    identifiers_outside_the_exception,
    is_placeholder,
    real_account_ids,
)

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent

FABRICATED = "314159265358"


def test_a_body_of_one_repeated_digit_is_a_placeholder() -> None:
    assert is_placeholder("111111111111")


def test_digits_grouped_in_runs_are_a_placeholder() -> None:
    """Examples telling several accounts apart use this form."""
    assert is_placeholder("000011112222")


def test_counting_up_is_a_placeholder() -> None:
    assert is_placeholder("123456789012")


def test_counting_down_is_a_placeholder() -> None:
    assert is_placeholder("987654321098")


def test_a_body_of_many_digits_is_not_a_placeholder() -> None:
    assert not is_placeholder(FABRICATED)


def test_records_every_file_an_identifier_appears_in(tmp_path: Path) -> None:
    (tmp_path / "a.tf").write_text(f'owner = "{FABRICATED}"\n')
    (tmp_path / "b.md").write_text(f"The account is {FABRICATED}.\n")

    assert account_ids_by_location(tmp_path) == {FABRICATED: ["a.tf", "b.md"]}


def test_ignores_placeholders(tmp_path: Path) -> None:
    (tmp_path / "a.tf").write_text('owner = "111111111111"\n')

    assert account_ids_by_location(tmp_path) == {}


def test_ignores_a_longer_run_of_digits(tmp_path: Path) -> None:
    """A thirteen-digit number is not an account ID that happens to embed one."""
    (tmp_path / "a.md").write_text("checksum 3141592653589\n")

    assert account_ids_by_location(tmp_path) == {}


def test_skips_tool_directories(tmp_path: Path) -> None:
    vendored = tmp_path / ".tox" / "py313" / "site-packages" / "somedep"
    vendored.mkdir(parents=True)
    (vendored / "README.md").write_text(f"account {FABRICATED}\n")

    assert account_ids_by_location(tmp_path) == {}


def test_skips_files_that_hold_no_readable_identifier(tmp_path: Path) -> None:
    (tmp_path / "logo.png").write_bytes(b"\x89PNG" + FABRICATED.encode())

    assert account_ids_by_location(tmp_path) == {}


def test_collects_identifiers_the_live_test_directory_commits(tmp_path: Path) -> None:
    sandbox = tmp_path / "test_environment"
    sandbox.mkdir()
    (sandbox / "main.tf").write_text(f'vendor = "{FABRICATED}"\n')

    assert real_account_ids(tmp_path) == {FABRICATED}


def test_an_identifier_only_outside_the_sandbox_is_not_part_of_the_exception(tmp_path: Path) -> None:
    (tmp_path / "notes.md").write_text(f"account {FABRICATED}\n")

    assert real_account_ids(tmp_path) == set()


def test_reports_an_identifier_that_escaped_the_sandbox(tmp_path: Path) -> None:
    sandbox = tmp_path / "test_environment"
    sandbox.mkdir()
    (sandbox / "main.tf").write_text(f'vendor = "{FABRICATED}"\n')
    (tmp_path / "headroom.py").write_text(f'DEFAULT = "{FABRICATED}"\n')

    assert identifiers_outside_the_exception(tmp_path) == {FABRICATED: ["headroom.py"]}


def test_an_identifier_confined_to_the_sandbox_is_not_reported(tmp_path: Path) -> None:
    sandbox = tmp_path / "test_environment"
    sandbox.mkdir()
    (sandbox / "main.tf").write_text(f'vendor = "{FABRICATED}"\n')

    assert identifiers_outside_the_exception(tmp_path) == {}


def test_an_identifier_the_exception_never_held_is_not_reported(tmp_path: Path) -> None:
    """
    The check is scoped to the exception, not to every twelve-digit number.

    A fabricated identifier in a test fixture is not a leak, and reporting one
    would make the guard cry wolf until someone turned it off.
    """
    sandbox = tmp_path / "test_environment"
    sandbox.mkdir()
    (sandbox / "main.tf").write_text('vendor = "111111111111"\n')
    (tmp_path / "test_thing.py").write_text(f'FIXTURE = "{FABRICATED}"\n')

    assert identifiers_outside_the_exception(tmp_path) == {}


def test_reads_the_count_the_invariant_spells(tmp_path: Path) -> None:
    (tmp_path / "invariants.md").write_text(
        "`test_environment/` commits fourteen real\ntwelve-digit account IDs belonging to.\n"
    )

    assert documented_exception_count(tmp_path) == 14


def test_a_missing_count_sentence_reads_as_none(tmp_path: Path) -> None:
    (tmp_path / "invariants.md").write_text("## INV-15\n\nNothing about a count.\n")

    assert documented_exception_count(tmp_path) is None


def test_an_unmapped_number_word_reads_as_none(tmp_path: Path) -> None:
    (tmp_path / "invariants.md").write_text(
        "`test_environment/` commits several real\ntwelve-digit account IDs belonging to.\n"
    )

    assert documented_exception_count(tmp_path) is None


def test_the_documented_count_matches_what_the_live_test_directory_holds() -> None:
    documented = documented_exception_count(REPOSITORY_ROOT / "spec")

    assert documented == len(real_account_ids(REPOSITORY_ROOT))


def test_no_identifier_from_the_exception_appears_outside_it() -> None:
    assert identifiers_outside_the_exception(REPOSITORY_ROOT) == {}
