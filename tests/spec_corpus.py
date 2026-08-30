"""Validate the specification corpus in spec/ against the check registry."""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

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

_FRONTMATTER = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)
_INVARIANT_HEADING = re.compile(r"^## (INV-\d+)\b", re.MULTILINE)
_SECTION_HEADING = re.compile(r"^## (.+)$", re.MULTILINE)

# The manifest's routing table, and the .cursor/rules/*.mdc derived from it.
# The section is sliced out by heading first, so a row is only ever read from
# the one table that governs routing.
ROUTING_HEADING = "## Routing"
_ROUTING_SECTION = re.compile(
    rf"^{ROUTING_HEADING}.*?$(.*?)(?=^## |\Z)", re.MULTILINE | re.DOTALL
)
_TABLE_ROW = re.compile(r"^\|\s*`([^`]+)`[^|]*\|(.+?)\|\s*$", re.MULTILINE)
_INLINE_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
_RULE_GLOBS = re.compile(r"^globs:\s*(.+)$", re.MULTILINE)
_SPEC_LINK_PREFIX = "mdc:spec/"


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


def _routing_table(spec_readme: Path) -> Dict[str, Set[str]]:
    """
    Read the manifest's routing table as touched path -> required documents.

    Args:
        spec_readme: The spec/README.md holding the table

    Returns:
        Each row's first backticked path, mapped to the spec-relative documents
        its second column links
    """
    section = _ROUTING_SECTION.search(spec_readme.read_text())
    if not section:
        raise ValueError(f"{spec_readme} has no '{ROUTING_HEADING}' section")

    return {
        touched: {
            target for target in _INLINE_LINK.findall(required)
            if target.endswith(".md")
        }
        for touched, required in _TABLE_ROW.findall(section.group(1))
    }


def _rule_globs_and_documents(rule: Path) -> Tuple[List[str], Set[str]]:
    """
    Read one .mdc rule's globs and the specification documents it links.

    Args:
        rule: The .cursor/rules/*.mdc file

    Returns:
        Its glob patterns, and the spec-relative documents it links
    """
    text = rule.read_text()
    globs: List[str] = []

    match = _RULE_GLOBS.search(text)
    if match:
        globs = [glob.strip() for glob in match.group(1).split(",") if glob.strip()]

    documents = {
        target[len(_SPEC_LINK_PREFIX):]
        for target in _INLINE_LINK.findall(text)
        if target.startswith(_SPEC_LINK_PREFIX)
    }

    return globs, documents


def find_routing_divergences(repository_root: Path) -> List[str]:
    """
    Report every routing-table row the rules that cover it do not fully serve.

    spec/README.md declares the rules derived from its routing table. An editor
    applies every rule whose globs match the file being edited, so the union of
    those rules is what has to satisfy the row - a single rule may name less.

    Args:
        repository_root: The repository root, holding spec/ and .cursor/rules/

    Returns:
        Problem descriptions, sorted
    """
    table = _routing_table(repository_root / "spec" / "README.md")

    covering: Dict[str, Set[str]] = {touched: set() for touched in table}
    rule_names: Dict[str, List[str]] = {touched: [] for touched in table}

    for rule in sorted((repository_root / ".cursor" / "rules").glob("*.mdc")):
        globs, linked = _rule_globs_and_documents(rule)
        for touched in table:
            if any(glob.startswith(touched) for glob in globs):
                covering[touched] |= linked
                rule_names[touched].append(rule.name)

    divergences: List[str] = []
    for touched, required in table.items():
        if not rule_names[touched]:
            continue
        for document in sorted(required - covering[touched]):
            names = ", ".join(rule_names[touched])
            divergences.append(f"{names} cover {touched} but omit {document}")

    return sorted(divergences)
