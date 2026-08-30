"""Scan the repository for AWS account IDs, and separate placeholders from real ones."""

import re
from pathlib import Path
from typing import Dict, List, Optional, Set

_ACCOUNT_ID = re.compile(r"(?<![0-9])[0-9]{12}(?![0-9])")

# INV-15 spells the standing exception's size in words rather than digits, so
# that the sentence reads. Only the counts the invariant could plausibly carry
# are mapped; an unmapped word is reported rather than guessed at.
_NUMBER_WORDS = {
    "ten": 10,
    "eleven": 11,
    "twelve": 12,
    "thirteen": 13,
    "fourteen": 14,
    "fifteen": 15,
    "sixteen": 16,
    "seventeen": 17,
    "eighteen": 18,
    "nineteen": 19,
    "twenty": 20,
}

_DOCUMENTED_COUNT = re.compile(
    r"commits (\w+) real\s+twelve-digit account IDs",
)

# Directories holding third-party or generated content. .tox alone carries a
# site-packages tree that mentions account IDs in vendored documentation.
_UNSCANNED_DIRECTORIES = frozenset({
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    "node_modules",
    "venv",
})

# Suffixes worth reading. A binary file cannot hold an identifier a reader or a
# search engine would ever surface.
_SCANNED_SUFFIXES = frozenset({
    ".json",
    ".md",
    ".py",
    ".tf",
    ".tfvars",
    ".txt",
    ".yaml",
    ".yml",
})

TEST_ENVIRONMENT = "test_environment"

# A placeholder is built from few enough digits to read as deliberate:
# 111111111111 uses one, 000011112222 uses three. Every real identifier the
# repository commits uses at least five, so the boundary is not close.
_MAX_PLACEHOLDER_DIGITS = 3


def _is_sequential(account_id: str) -> bool:
    """
    Report whether an ID counts up or down, wrapping past nine.

    Args:
        account_id: Twelve-digit account ID

    Returns:
        True for 123456789012 and 987654321098, false otherwise
    """
    digits = [int(digit) for digit in account_id]
    steps = {(later - earlier) % 10 for earlier, later in zip(digits, digits[1:])}

    return steps in ({1}, {9})


def is_placeholder(account_id: str) -> bool:
    """
    Report whether an account ID is an obvious placeholder.

    INV-15 fixes the canonical form as a real length with a body of one
    repeated digit. The repository also uses two variants where several
    distinct accounts have to be told apart in one example: digits grouped in
    runs, and a plain count up or down.

    Args:
        account_id: Twelve-digit account ID

    Returns:
        True when the digits read as deliberately fabricated
    """
    return len(set(account_id)) <= _MAX_PLACEHOLDER_DIGITS or _is_sequential(account_id)


def account_ids_by_location(root: Path) -> Dict[str, List[str]]:
    """
    Map every non-placeholder account ID under root to where it appears.

    Args:
        root: Directory to scan recursively

    Returns:
        Account ID -> sorted paths relative to root, one entry per file
    """
    locations: Dict[str, List[str]] = {}

    for path in sorted(root.rglob("*")):
        if path.suffix not in _SCANNED_SUFFIXES:
            continue

        relative = path.relative_to(root)
        if not _UNSCANNED_DIRECTORIES.isdisjoint(relative.parts):
            continue

        found: List[str] = _ACCOUNT_ID.findall(path.read_text())
        for account_id in sorted(set(found)):
            if is_placeholder(account_id):
                continue
            locations.setdefault(account_id, []).append(str(relative))

    return locations


def real_account_ids(root: Path) -> Set[str]:
    """
    Return the real account IDs the live-test directory commits.

    Args:
        root: Repository root

    Returns:
        Account IDs appearing under test_environment/
    """
    return {
        account_id
        for account_id, paths in account_ids_by_location(root).items()
        if any(path.startswith(TEST_ENVIRONMENT) for path in paths)
    }


def identifiers_outside_the_exception(root: Path) -> Dict[str, List[str]]:
    """
    Report identifiers from the exception that appear outside it.

    INV-15 scopes the standing exception to `test_environment/` and nothing
    else, so one of its identifiers reaching code, tests, or documentation has
    left the sandbox the exception was granted for.

    Args:
        root: Repository root

    Returns:
        Account ID -> the offending paths, for each exception identifier seen
        outside test_environment/
    """
    leaked: Dict[str, List[str]] = {}
    exception = real_account_ids(root)

    for account_id, paths in account_ids_by_location(root).items():
        if account_id not in exception:
            continue
        outside = [path for path in paths if not path.startswith(TEST_ENVIRONMENT)]
        if outside:
            leaked[account_id] = outside

    return leaked


def documented_exception_count(spec_root: Path) -> Optional[int]:
    """
    Return the number of real identifiers INV-15 says the exception covers.

    Args:
        spec_root: The spec/ directory

    Returns:
        The documented count, or None if the sentence is missing or spells a
        number the word map does not carry
    """
    match = _DOCUMENTED_COUNT.search((spec_root / "invariants.md").read_text())
    if not match:
        return None

    return _NUMBER_WORDS.get(match.group(1).lower())
