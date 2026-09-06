"""
Keep README.md's check table in step with the registry.

The retired single-file specification listed 7 of the 15 checks registered
when it was removed; nothing had checked it. README.md names every check in
one table, and this test fails naming any registered check the table omits.
The two counts in the prose around the table are checked against the
registry the same way.

README.md also embeds `documentation/images/placement.svg`, a render of the
console block in `documentation/EXAMPLES.md`; the first hand-copied version
of that image drifted on its first day, so this test compares the two. When
they diverge, the image is what changes: regenerate it with
documentation/images/generate_placement_svg.py rather than editing this test.
"""

import re
import xml.etree.ElementTree
from pathlib import Path

from headroom.checks.registry import get_check_type_map

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent

_SVG_NAMESPACE = "http://www.w3.org/2000/svg"

# The SVG wraps a long `Reasoning:` line once and hangs the remainder under the
# text after its label. Only those three lines exceed the render width.
_CONTINUATION_INDENT = " " * len("  Reasoning: ")
_HEADING = "## Console output"
_FENCE = re.compile(r"^```[a-z]*\n(.*?)^```", re.MULTILINE | re.DOTALL)


def test_readme_links_every_registered_check_to_its_specification() -> None:
    readme_text = (REPOSITORY_ROOT / "README.md").read_text()

    missing = [
        name
        for name, check_type in get_check_type_map().items()
        if f"](spec/checks/{check_type}/{name}.md)" not in readme_text
    ]

    assert missing == []


def test_placement_render_matches_the_console_example() -> None:
    svg_root = xml.etree.ElementTree.parse(
        REPOSITORY_ROOT / "documentation" / "images" / "placement.svg",
    ).getroot()

    # "g/text" reaches the text elements one level down: the children of the
    # one <g> element, in document order. It excludes the title-bar label,
    # which sits outside <g>.
    lines: list[str] = []
    for text_element in svg_root.findall(f"{{{_SVG_NAMESPACE}}}g/{{{_SVG_NAMESPACE}}}text"):
        content = "".join(text_element.itertext())
        if content.startswith(_CONTINUATION_INDENT):
            lines[-1] = f"{lines[-1]} {content.removeprefix(_CONTINUATION_INDENT)}"
            continue
        lines.append(content)

    examples_text = (REPOSITORY_ROOT / "documentation" / "EXAMPLES.md").read_text()
    after_heading = examples_text.split(_HEADING, 1)[1]
    console_block: str = _FENCE.findall(after_heading)[0]

    assert lines == [line for line in console_block.splitlines() if line]


def test_readme_states_the_registry_counts() -> None:
    readme_text = (REPOSITORY_ROOT / "README.md").read_text()
    check_types = list(get_check_type_map().values())

    assert f"{len(check_types)} checks ship today" in readme_text
    assert (
        f"The first {check_types.count('scps')} are SCPs, the last "
        f"{check_types.count('rcps')} RCPs"
        in readme_text
    )
