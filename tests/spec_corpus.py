"""Validate the specification corpus in spec/ against the check registry."""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml

# Frontmatter fields every per-check specification must carry.
REQUIRED_FIELDS = ("id", "kind", "status", "applies_to", "depends_on", "verification")

# Fields holding a list of repository-relative paths that must exist.
PATH_LIST_FIELDS = ("applies_to", "verification")

# Frontmatter `kind` -> the check type the registry records.
KIND_TO_CHECK_TYPE = {"scp": "scps", "rcp": "rcps"}

ALLOWED_STATUSES = frozenset({"implemented", "planned", "deprecated"})

# The sections spec/checks/index.md requires, in the order it requires them.
REQUIRED_SECTIONS = (
    "Objective",
    "Enforced statement",
    "Evidence",
    "Decision table",
    "Failure behavior",
    "Result contract",
    "Placement and generated policy",
    "Accepted limitations",
    "Acceptance scenarios",
    "Referenced invariants",
    "Implementation",
)

# A twelfth section is allowed where the implementation and the corpus disagree.
# It may sit anywhere, and index.md requires it to carry a status.
CONFLICT_SECTION_PREFIX = "Known conflict:"
CONFLICT_STATUS = "Status: unresolved"

# The register in checks/index.md that names every unresolved conflict.
CONFLICT_REGISTER_HEADING = "## Unresolved conflicts"

_FRONTMATTER = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)
_NEXT_SECTION = re.compile(r"^## ", re.MULTILINE)
_CHECK_DOCUMENT_LINK = re.compile(r"\]\((?:scps|rcps)/([a-z0-9_]+)\.md\)")
_INVARIANT_HEADING = re.compile(r"^## (INV-\d+)\b", re.MULTILINE)
_SECTION_HEADING = re.compile(r"^## (.+)$", re.MULTILINE)


@dataclass(frozen=True)
class CheckSpecification:
    """
    One per-check specification document.

    Attributes:
        path: Path to the document
        frontmatter: Parsed frontmatter mapping, empty if the document has none
        kind_directory: The checks/ subdirectory the document was found in
    """

    path: Path
    frontmatter: Dict[str, Any]
    kind_directory: str


def parse_frontmatter(text: str) -> Optional[Dict[str, Any]]:
    """
    Return a document's YAML frontmatter mapping.

    Args:
        text: Full document text

    Returns:
        The parsed mapping, or None if the document opens with no frontmatter
        block or the block does not parse to a mapping
    """
    match = _FRONTMATTER.match(text)
    if not match:
        return None

    parsed = yaml.safe_load(match.group(1))
    if not isinstance(parsed, dict):
        return None

    return parsed


def load_check_specifications(spec_root: Path) -> List[CheckSpecification]:
    """
    Load every per-check specification under spec/checks/.

    Args:
        spec_root: The spec/ directory

    Returns:
        Specifications, sorted by path
    """
    specifications: List[CheckSpecification] = []

    for kind_directory in sorted(KIND_TO_CHECK_TYPE):
        directory = spec_root / "checks" / f"{kind_directory}s"
        for path in sorted(directory.glob("*.md")):
            specifications.append(CheckSpecification(
                path=path,
                frontmatter=parse_frontmatter(path.read_text()) or {},
                kind_directory=kind_directory,
            ))

    return specifications


def invariant_ids(spec_root: Path) -> List[str]:
    """
    Return the invariant IDs invariants.md defines.

    Args:
        spec_root: The spec/ directory

    Returns:
        Invariant IDs, in document order
    """
    return _INVARIANT_HEADING.findall((spec_root / "invariants.md").read_text())


def _document_problems(
    specification: CheckSpecification,
    spec_root: Path,
    check_types: Dict[str, str],
    defined_invariants: List[str],
) -> List[str]:
    """
    Report what is wrong with one specification document.

    Args:
        specification: The document to inspect
        spec_root: The spec/ directory, used to resolve repository paths
        check_types: Registered check name -> check type
        defined_invariants: Invariant IDs invariants.md defines

    Returns:
        Problem descriptions, one per finding
    """
    problems: List[str] = []
    name = specification.path.name
    frontmatter = specification.frontmatter

    missing = [field for field in REQUIRED_FIELDS if field not in frontmatter]
    if missing:
        problems.append(f"{name} frontmatter is missing: {', '.join(missing)}")
        return problems

    mistyped = [
        field for field in ("depends_on",) + PATH_LIST_FIELDS
        if not isinstance(frontmatter[field], list)
    ]
    if mistyped:
        return [
            f"{name} {field} must be a list, not a {type(frontmatter[field]).__name__}"
            for field in mistyped
        ]

    if frontmatter["id"] != specification.path.stem:
        problems.append(f"{name} declares id '{frontmatter['id']}', expected '{specification.path.stem}'")

    if frontmatter["kind"] != specification.kind_directory:
        problems.append(
            f"{name} declares kind '{frontmatter['kind']}' but sits in "
            f"checks/{specification.kind_directory}s/"
        )

    if frontmatter["status"] not in ALLOWED_STATUSES:
        problems.append(
            f"{name} declares status '{frontmatter['status']}', expected one of "
            f"{', '.join(sorted(ALLOWED_STATUSES))}"
        )

    if check_types.get(specification.path.stem) != KIND_TO_CHECK_TYPE[specification.kind_directory]:
        problems.append(f"{name} names no registered {specification.kind_directory} check")

    for invariant in frontmatter["depends_on"]:
        if invariant not in defined_invariants:
            problems.append(f"{name} cites {invariant}, which invariants.md does not define")

    repository_root = spec_root.parent
    for field in PATH_LIST_FIELDS:
        for relative_path in frontmatter[field]:
            if not (repository_root / relative_path).exists():
                problems.append(f"{name} {field} names a missing path: {relative_path}")

    problems.extend(_section_problems(name, specification.path.read_text()))

    return problems


def _section_problems(name: str, text: str) -> List[str]:
    """
    Report every way a document's sections depart from the index.md contract.

    Args:
        name: Document name for the problem descriptions
        text: Full document text

    Returns:
        Problem descriptions
    """
    problems: List[str] = []
    headings: List[str] = _SECTION_HEADING.findall(text)

    conflicts = [h for h in headings if h.startswith(CONFLICT_SECTION_PREFIX)]
    if conflicts and CONFLICT_STATUS not in text:
        problems.append(
            f"{name} has a Known conflict section that does not say {CONFLICT_STATUS}"
        )

    for heading in headings:
        if heading not in REQUIRED_SECTIONS and heading not in conflicts:
            problems.append(f"{name} has an unrecognized section: {heading}")

    present = [h for h in headings if h in REQUIRED_SECTIONS]
    for section in REQUIRED_SECTIONS:
        if section not in present:
            problems.append(f"{name} is missing section: {section}")

    expected_order = [s for s in REQUIRED_SECTIONS if s in present]
    for found, wanted in zip(present, expected_order):
        if found != wanted:
            problems.append(f"{name} orders sections {found} before {wanted}")
            break

    return problems


def find_corpus_problems(spec_root: Path, check_types: Dict[str, str]) -> List[str]:
    """
    Report every way the corpus disagrees with the check registry.

    Args:
        spec_root: The spec/ directory
        check_types: Registered check name -> check type, from the registry

    Returns:
        Problem descriptions, sorted
    """
    specifications = load_check_specifications(spec_root)
    defined_invariants = invariant_ids(spec_root)

    problems: List[str] = []
    for specification in specifications:
        problems.extend(
            _document_problems(specification, spec_root, check_types, defined_invariants)
        )

    seen: Dict[str, Path] = {}
    for specification in specifications:
        declared_id = specification.frontmatter.get("id")
        if not isinstance(declared_id, str):
            continue
        if declared_id in seen:
            problems.append(f"id '{declared_id}' is declared by both {seen[declared_id].name} and {specification.path.name}")
            continue
        seen[declared_id] = specification.path

    specified = {specification.path.stem for specification in specifications}
    for check_name in sorted(set(check_types) - specified):
        problems.append(f"registered check {check_name} has no specification")

    return sorted(problems)


def _conflict_register(spec_root: Path) -> str:
    """
    Return the body of the unresolved-conflict register.

    Args:
        spec_root: The spec/ directory

    Returns:
        Everything between the register heading and the next section heading
    """
    text = (spec_root / "checks" / "index.md").read_text()
    start = text.index(CONFLICT_REGISTER_HEADING) + len(CONFLICT_REGISTER_HEADING)
    next_section = _NEXT_SECTION.search(text, start)
    if not next_section:
        return text[start:]

    return text[start:next_section.start()]


def _registered_conflict_checks(spec_root: Path) -> Set[str]:
    """
    Return the checks the register's Where column names.

    Only that column counts. A conflict's prose routinely links a *different*
    check for contrast, and the paragraph below the table links the two gaps
    recorded elsewhere precisely because they are not conflicts.

    Args:
        spec_root: The spec/ directory

    Returns:
        Check names
    """
    names: Set[str] = set()
    for line in _conflict_register(spec_root).splitlines():
        if not line.startswith("|"):
            continue
        names.update(_CHECK_DOCUMENT_LINK.findall(line.split("|")[2]))

    return names


def _documented_conflict_checks(spec_root: Path) -> Set[str]:
    """
    Return the checks whose own document carries a conflict section.

    Args:
        spec_root: The spec/ directory

    Returns:
        Check names
    """
    names: Set[str] = set()
    for specification in load_check_specifications(spec_root):
        headings: List[str] = _SECTION_HEADING.findall(specification.path.read_text())
        if any(heading.startswith(CONFLICT_SECTION_PREFIX) for heading in headings):
            names.add(specification.path.stem)

    return names


def find_conflict_divergences(spec_root: Path) -> List[str]:
    """
    Report where the conflict register and the check documents disagree.

    The register and the per-check documents are two views of one set. A reader
    who opens a check document rather than the index must see the same
    conflicts, so a name may not appear in one view and be absent from the
    other. The section contract in `_section_problems` cannot catch this: it
    checks a conflict section it can see, and a document that simply has none
    passes it vacuously.

    Args:
        spec_root: The spec/ directory

    Returns:
        Problem descriptions, sorted
    """
    registered = _registered_conflict_checks(spec_root)
    documented = _documented_conflict_checks(spec_root)

    problems = [
        f"{name} is named in the conflict register with no '{CONFLICT_SECTION_PREFIX}' section in its document"
        for name in registered - documented
    ]
    problems.extend(
        f"{name} has a '{CONFLICT_SECTION_PREFIX}' section and the conflict register does not name it"
        for name in documented - registered
    )

    return sorted(problems)
