"""
Render placement.svg from the console block in documentation/EXAMPLES.md.

Run from the repository root:

    .tox/py313/bin/python documentation/images/generate_placement_svg.py

The script reads the first fenced block under "## Console output" in
EXAMPLES.md and writes placement.svg next to itself. A blank line keeps its
row and draws nothing. A line longer than WIDTH_CHARS wraps once onto a
continuation row indented to sit under the text after "  Reasoning: ", a
hanging indent a real terminal would not produce, chosen so the wrapped reason
reads as one field. Every other line is carried verbatim.

tests/test_readme.py reconstitutes the block from the SVG and compares it to
EXAMPLES.md, so a drift in either file fails tox. Re-run this script rather
than editing the image or the test.
"""

import re
from pathlib import Path
from xml.sax.saxutils import escape

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent.parent
EXAMPLES = REPOSITORY_ROOT / "documentation" / "EXAMPLES.md"
OUTPUT = Path(__file__).with_name("placement.svg")

HEADING = "## Console output"
FENCE = re.compile(r"```\n(.*?)```", re.DOTALL)
TITLE = (
    "Headroom placement recommendations for three checks: one SCP at the "
    "organization root, one SCP at an OU, and one RCP at an OU"
)

BACKGROUND = "#1b1f27"
TITLE_BAR = "#2a2f3a"
TEXT = "#d6dbe5"
BLUE = "#7aa2f7"
GREEN = "#9ece6a"
YELLOW = "#e0af68"
DIM = "#8b93a5"
LABEL = "#98a0b2"
TRAFFIC_LIGHTS = ("#ff5f57", "#febc2e", "#28c840")
FONT = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
FONT_SIZE = 13
LINE_HEIGHT = 18
PAD_X = 24
FIRST_BASELINE = 62
BOTTOM_PAD = 8
BAR_HEIGHT = 36
WIDTH = 820
WIDTH_CHARS = 96
CONTINUATION = " " * len("  Reasoning: ")


def console_block(markdown: str) -> list[str]:
    after_heading = markdown.split(HEADING, 1)[1]
    block: str = FENCE.findall(after_heading)[0]
    return block.splitlines()


def wrap(line: str) -> list[str]:
    if len(line) <= WIDTH_CHARS:
        return [line]
    indent = line[: len(line) - len(line.lstrip(" "))]
    rows: list[str] = []
    current = indent
    for word in line.split():
        if current.strip() == "":
            current = f"{current}{word}"
            continue
        candidate = f"{current} {word}"
        if len(candidate) > WIDTH_CHARS:
            rows.append(current)
            current = f"{CONTINUATION}{word}"
            continue
        current = candidate
    rows.append(current)
    return rows


def style(row: str) -> tuple[str, bool]:
    """
    Return the fill colour of a row and whether it is bold.
    """
    if row.startswith("===="):
        return BLUE, False
    if row.endswith("PLACEMENT RECOMMENDATIONS"):
        return BLUE, True
    if row.startswith("Check: "):
        return GREEN, True
    if row.startswith("  Recommended Level: "):
        return YELLOW, False
    if row.startswith("  ----"):
        return DIM, False
    return TEXT, False


def render(rows: list[str]) -> str:
    height = FIRST_BASELINE + LINE_HEIGHT * len(rows) + BOTTOM_PAD
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{height}" viewBox="0 0 {WIDTH} {height}" role="img" aria-labelledby="placement-title">',
        f'  <title id="placement-title">{TITLE}</title>',
        f'  <rect width="{WIDTH}" height="{height}" rx="10" fill="{BACKGROUND}"/>',
        f'  <path d="M0 10a10 10 0 0 1 10-10h{WIDTH - 20}a10 10 0 0 1 10 10v{BAR_HEIGHT - 10}H0z" fill="{TITLE_BAR}"/>',
    ]
    for i, colour in enumerate(TRAFFIC_LIGHTS):
        svg.append(f'  <circle cx="{20 + i * 20}" cy="{BAR_HEIGHT // 2}" r="6" fill="{colour}"/>')
    svg.append(f'  <text x="{WIDTH // 2}" y="{BAR_HEIGHT // 2 + 5}" text-anchor="middle" font-family="{FONT}" font-size="12" fill="{LABEL}">headroom</text>')
    svg.append(f'  <g font-family="{FONT}" font-size="{FONT_SIZE}" xml:space="preserve">')
    for i, row in enumerate(rows):
        if not row:
            continue
        fill, bold = style(row)
        weight = ' font-weight="bold"' if bold else ""
        svg.append(f'    <text x="{PAD_X}" y="{FIRST_BASELINE + LINE_HEIGHT * i}" fill="{fill}"{weight}>{escape(row)}</text>')
    svg.append("  </g>")
    svg.append("</svg>")
    return "\n".join(svg) + "\n"


def main() -> None:
    rows = [piece for line in console_block(EXAMPLES.read_text()) for piece in wrap(line)]
    OUTPUT.write_text(render(rows))
    print(OUTPUT, len(rows), "rows, longest", max(len(row) for row in rows))


if __name__ == "__main__":
    main()
