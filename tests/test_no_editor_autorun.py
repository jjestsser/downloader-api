"""Refuses to let an editor-autorun trigger back into the tree.

On 2026-08-21 this repository was found carrying a working attack chain aimed at
whoever opened it: `.vscode/tasks.json` ran `node ./public/fonts/fa-solid-400.woff2`
with `runOn: folderOpen`, `hide: true` and `reveal: never`, and a second
`folderOpen` task was hidden inside `.vscode/settings.json`. The "font" was
8943 bytes of JavaScript padded with spaces so an editor showed a blank file.

Both triggers were deleted, and a fork sync brought them straight back, because
a merge takes both sides. That is why this is a test rather than a one-off
cleanup: deleting a file only removes it until the next merge, whereas a failing
test is noticed.

Deliberately imports nothing from `app`. It has to run anywhere — including on
an interpreter too old for the project — because a guard that cannot run is not
a guard.
"""

from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: The first bytes of the font formats that legitimately appear in a repo.
#: EOT is absent on purpose: it opens with a length field rather than a
#: signature, so it is matched by its own magic further in (see below).
FONT_MAGIC = (b"wOF2", b"wOFF", b"\x00\x01\x00\x00", b"true", b"OTTO")


def _json_without_comments(text: str) -> object:
    """VS Code allows // comments in its JSON. `json` does not."""
    lines = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if not stripped.startswith("//"):
            lines.append(line)
    body = "\n".join(lines)
    # Trailing commas are legal in VS Code's dialect too.
    while ",]" in body or ",}" in body:
        body = body.replace(",]", "]").replace(",}", "}")
    return json.loads(body)


def test_no_file_asks_an_editor_to_run_something_on_open() -> None:
    offenders = []
    for path in REPO.rglob("*.json"):
        if ".git/" in str(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "folderOpen" in text:
            offenders.append(str(path.relative_to(REPO)))

    assert not offenders, (
        "These files ask the editor to execute something the moment the folder "
        f"is opened: {offenders}. That is how this repository was attacked on "
        "2026-08-21. If a task genuinely needs to exist, it must not be "
        "`runOn: folderOpen`."
    )


def test_nothing_under_public_is_a_font_only_by_its_name() -> None:
    """A .woff2 that is not a font is the shape the payload arrived in."""
    public = REPO / "public"
    if not public.is_dir():
        return  # nothing to check, which is the preferred state

    liars = []
    for path in public.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".woff", ".woff2", ".ttf", ".otf"}:
            continue
        head = path.read_bytes()[:4]
        if not any(head.startswith(magic) for magic in FONT_MAGIC):
            liars.append(f"{path.relative_to(REPO)} starts {head!r}")

    assert not liars, (
        "These files are named as fonts but do not begin with any font "
        f"signature: {liars}. The 2026-08-21 payload was exactly this — "
        "JavaScript padded with spaces and named .woff2."
    )
