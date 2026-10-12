#!/usr/bin/env python3
"""
Show whether a document's extracted text actually contains mojibake.

A font with no ToUnicode only matters if it carries real text. This runs
pdftotext and counts lines holding Latin Extended characters, which is what
an unmapped Identity-H font produces.

Usage:
    python3 check_mojibake.py 551 712 858
"""

import re
import subprocess
import sys

ORIGINALS = "/usr/src/paperless/media/documents/originals"
SUSPECT = re.compile(r"[Ā-ɏͰ-ϿⱠ-Ɀ]")


def check(doc_id):
    path = "%s/%07d.pdf" % (ORIGINALS, int(doc_id))
    try:
        result = subprocess.run(
            ["pdftotext", path, "-"],
            capture_output=True, text=True, timeout=120,
        )
    except Exception as exc:
        print("doc %-6s could not extract: %s" % (doc_id, exc))
        return

    lines = result.stdout.split("\n")
    bad = [line for line in lines if SUSPECT.search(line)]
    print("doc %-6s %5d lines, %d with mojibake" % (doc_id, len(lines), len(bad)))
    for line in bad[:4]:
        print("    %s" % line.strip()[:110])
    if not bad:
        print("    (text extracts cleanly; the unmapped font carries no text)")
    print()


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for doc_id in sys.argv[1:]:
        check(doc_id)


if __name__ == "__main__":
    main()
