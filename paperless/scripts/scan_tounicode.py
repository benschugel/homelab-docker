#!/usr/bin/env python3
"""
Read-only sweep of a Paperless-ngx originals folder for unreadable text layers.

Catches both failure modes seen so far, by scoring the EXTRACTED TEXT rather
than trusting the font tables, because the two modes look nothing alike at the
font level but identical to a human reading the Content tab:

  A. identity-h   Type0/Identity-H fonts with no ToUnicode CMap. Extraction
                  prints raw glyph IDs as code points, so the text lands in
                  Latin Extended ("ĚĚŝƟŽŶƐ" for "dditions"). Repairable
                  losslessly from a reference copy of the font.

  B. custom-enc   Simple (non-Type0) fonts whose encoding is offset from or
                  scrambled relative to ASCII, with no ToUnicode. Extraction
                  prints shifted or permuted ASCII and usually drops spaces
                  ("8VHWKLVZRUNVKHHW" for "Use this worksheet"). A constant
                  offset is trivially reversible; an arbitrary permutation
                  needs glyph-level work, or OCR.

Writes nothing. With the default PAPERLESS_FILENAME_FORMAT the file
0000862.pdf is document 862, so the filename doubles as the document ID.

Usage:
    python3 scan_tounicode.py /usr/src/paperless/media/documents/originals
    python3 scan_tounicode.py <dir> --csv /usr/src/paperless/export/scan.csv
    python3 scan_tounicode.py <dir> --pages 20      (default 12)
"""

import csv
import os
import re
import subprocess
import sys

try:
    import pikepdf
except ImportError:
    pikepdf = None

LATIN_EXT = re.compile(r"[Ā-ɏͰ-ϿⱠ-Ɀ]")
LETTER_RUN = re.compile(r"[A-Za-z]{6,}")
TOKEN = re.compile(r"[A-Za-z']+")

# Enough common English to tell prose from gibberish without a dictionary file.
COMMON = set("""
the of and to in for a is on with that you your this are be or as at from not
by it will can if may have has was were all any other more which when who what
line amount tax return form income total credit date name number page see must
enter attach file paid year state federal schedule account payment report
balance deposit withdrawal transfer check debit description transaction
statement period beginning ending available posted reference invoice due
bank card purchase refund interest rate fee charge summary activity
""".split())

# Symbol and barcode fonts carry no readable text, so an unmapped one is
# expected rather than a problem worth reporting.
SYMBOLIC = ("idautomation", "adobepi", "quicktypepi", "universalstd",
            "commpi", "wingding", "webding", "symbol", "zapfdingbats",
            "barcode", "code39", "dingbat", "ocr-", "mathematicalpi")


def is_symbolic(name):
    low = name.lower()
    return any(token in low for token in SYMBOLIC)


# --------------------------------------------------------------------------
# text scoring, which is the real detector
# --------------------------------------------------------------------------

def extract(path, pages):
    try:
        result = subprocess.run(
            ["pdftotext", "-l", str(pages), path, "-"],
            capture_output=True, text=True, timeout=180,
        )
    except Exception as exc:
        return None, str(exc)[:80]
    if result.returncode != 0 and not result.stdout:
        return None, (result.stderr or "pdftotext failed").strip()[:80]
    return result.stdout, None


def score(text):
    """Metrics that separate readable text from either mojibake flavor."""
    stripped = text.strip()
    chars = len(stripped)
    if chars < 200:
        return {"chars": chars, "verdict": "no-text-layer"}

    latin_ext = len(LATIN_EXT.findall(stripped))
    # Only tokens of 3+ characters count. Scrambled text throws off stray one-
    # and two-letter fragments that accidentally match short words like "a",
    # "is" or "on", which inflates the hit rate enough to hide real mojibake.
    tokens = [t for t in TOKEN.findall(stripped.lower()) if len(t) >= 3]
    hits = sum(1 for tok in tokens if tok in COMMON)
    hit_rate = hits / len(tokens) if tokens else 0.0
    runs = LETTER_RUN.findall(stripped)
    longest = max((len(r) for r in runs), default=0)

    letters = [c for c in stripped.lower() if "a" <= c <= "z"]
    vowels = sum(1 for c in letters if c in "aeiou")
    latin1 = sum(1 for c in stripped if "\u0080" <= c <= "\u00ff")

    metrics = {
        "chars": chars,
        "latin_ext": latin_ext / chars,
        "hit_rate": hit_rate,
        "longest_run": longest,
        "tokens": len(tokens),
        "vowel_rate": (vowels / len(letters)) if letters else 0.0,
        "latin1": latin1 / chars,
    }

    # A low common-word rate alone is not enough: a statement that is mostly
    # numbers also scores low. Require positive evidence of scrambling, which
    # is one of long space-free runs (a constant shift eats the spaces), a
    # pile of Latin-1 supplement characters used as separators, or a vowel
    # distribution no natural language produces.
    scrambled = (metrics["longest_run"] >= 20
                 or metrics["latin1"] > 0.02
                 or metrics["vowel_rate"] < 0.25)

    if metrics["latin_ext"] > 0.015:
        metrics["verdict"] = "identity-h"
    elif hit_rate < 0.015 and metrics["tokens"] > 60 and scrambled:
        # Readable English of this length always clears 1.5% common words.
        # A constant shift drops spaces (long runs); a permutation does not,
        # so run length corroborates but must not gate the verdict.
        metrics["verdict"] = "custom-enc"
    elif hit_rate < 0.030 and metrics["tokens"] > 150:
        metrics["verdict"] = "suspect"
    else:
        metrics["verdict"] = "ok"
    return metrics


def sample_line(text):
    """A representative bad line, for eyeballing."""
    best = ""
    for line in text.split("\n"):
        line = line.strip()
        if len(line) < 20:
            continue
        if LATIN_EXT.search(line):
            return line[:100]
        runs = LETTER_RUN.findall(line)
        if runs and max(len(r) for r in runs) >= 25 and len(line) > len(best):
            best = line
    return best[:100]


FRAGMENTS = ("tion", "ment", "ing ", "the ", " and ", "your", "from",
             "line", "amount", "income", "that", "this", "with", "form",
             "schedule", "enter", "ation", "ther")


def constant_offset(text):
    """If a custom encoding is a uniform ASCII shift, find it.

    Scores every candidate offset by how many common English fragments the
    whole decoded sample contains. Counting total occurrences rather than
    one hit per token matters: a wrong offset can produce a single accidental
    word ("sethis" contains "this") but never produces them in bulk.
    """
    sample = text[:6000]
    if len(sample) < 200:
        return None
    best = None
    for offset in range(-80, 81):
        if offset == 0:
            continue
        decoded = []
        printable = 0
        for ch in sample:
            value = ord(ch) + offset
            if 32 <= value < 127:
                decoded.append(chr(value))
                printable += 1
            else:
                decoded.append(" ")
        if printable < len(sample) * 0.8:
            continue
        lowered = "".join(decoded).lower()
        hits = sum(lowered.count(fragment) for fragment in FRAGMENTS)
        if best is None or hits > best[1]:
            best = (offset, hits)
    if best and best[1] >= 12:
        return best
    return None


# --------------------------------------------------------------------------
# font side, used to explain WHY a document is broken
# --------------------------------------------------------------------------

def font_report(path):
    """(identity_h_unmapped, simple_unmapped) font-family name sets."""
    identity = set()
    simple = set()
    if pikepdf is None:
        return identity, simple
    try:
        with pikepdf.open(path) as pdf:
            seen = set()
            for page in pdf.pages:
                try:
                    fonts = page.Resources.Font
                except (AttributeError, KeyError):
                    continue
                for _n, fobj in fonts.items():
                    try:
                        key = fobj.objgen
                    except AttributeError:
                        key = id(fobj)
                    if key in seen:
                        continue
                    seen.add(key)
                    if "/ToUnicode" in fobj:
                        continue
                    base = str(fobj.get("/BaseFont", "?")).split("+")[-1].lstrip("/")
                    if is_symbolic(base):
                        continue
                    subtype = str(fobj.get("/Subtype", ""))
                    enc = str(fobj.get("/Encoding", ""))
                    if subtype == "/Type0" and "Identity" in enc:
                        identity.add(base)
                    elif subtype in ("/TrueType", "/Type1", "/MMType1", "/Type3"):
                        # Only interesting when the encoding is not a standard
                        # one, since standard encodings extract fine.
                        if "WinAnsi" not in enc and "MacRoman" not in enc:
                            simple.add(base)
    except Exception:
        pass
    return identity, simple


LABEL = {
    "identity-h": "Identity-H, no ToUnicode (losslessly repairable)",
    "custom-enc": "custom font encoding (shift or permutation)",
    "suspect": "text looks wrong, cause unclear",
}


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    root = sys.argv[1]
    csv_path = None
    pages = 12
    if "--csv" in sys.argv:
        csv_path = sys.argv[sys.argv.index("--csv") + 1]
    if "--pages" in sys.argv:
        pages = int(sys.argv[sys.argv.index("--pages") + 1])

    files = sorted(
        os.path.join(root, n) for n in os.listdir(root)
        if n.lower().endswith(".pdf")
    )
    print("scanning %d pdf(s) in %s (first %d pages each)\n" % (
        len(files), root, pages))

    buckets = {"identity-h": [], "custom-enc": [], "suspect": []}
    counts = {"ok": 0, "no-text-layer": 0}
    errors = []
    rows = []

    for path in files:
        name = os.path.basename(path)
        text, err = extract(path, pages)
        if text is None:
            errors.append((name, err))
            continue
        metrics = score(text)
        verdict = metrics["verdict"]
        if verdict in counts:
            counts[verdict] += 1
            continue

        doc_id = name.split(".")[0].lstrip("0") or "?"
        identity, simple = font_report(path)
        fonts = ", ".join(sorted(identity | simple)) or "(none identified)"
        shift = ""
        if verdict in ("custom-enc", "suspect"):
            found = constant_offset(text)
            if found:
                shift = "  shift=%+d" % found[0]
        buckets[verdict].append((doc_id, name, fonts, shift, sample_line(text)))
        rows.append((doc_id, name, verdict, fonts, shift.strip()))

    for verdict in ("identity-h", "custom-enc", "suspect"):
        entries = buckets[verdict]
        if not entries:
            continue
        print("=== %s: %d document(s) ===" % (LABEL[verdict], len(entries)))
        for doc_id, name, fonts, shift, sample in entries:
            print("  doc %-6s %-16s %s%s" % (doc_id, name, fonts, shift))
            if sample:
                print("      %s" % sample)
        print()

    print("%d readable, %d with no text layer (scanned; OCR handles those)"
          % (counts["ok"], counts["no-text-layer"]))
    if errors:
        print("\n%d file(s) could not be read:" % len(errors))
        shown = {}
        for name, message in errors:
            shown.setdefault(message, []).append(name)
        for message, names in shown.items():
            print("  %-34s %d file(s), e.g. %s"
                  % (message[:34], len(names), names[0]))

    if csv_path and rows:
        with open(csv_path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["doc_id", "file", "verdict", "fonts", "shift"])
            writer.writerows(rows)
        print("\nwrote %s" % csv_path)


if __name__ == "__main__":
    main()
