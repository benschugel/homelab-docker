#!/usr/bin/env python3
"""
Paperless-ngx pre-consume script.

Repairs PDFs whose Type0/Identity-H fonts carry no ToUnicode CMap, which makes
text extraction return mojibake ("ĚĚŝƟŽŶƐ" for "dditions"). In both of the
flavors seen so far the CID is the glyph ID of the original, unsubsetted font,
so a reference copy of that font reconstructs the mapping exactly:

  CIDFontType0  /FontFile3  CFF    CID-keyed charset gives cidNNNN names
  CIDFontType2  /FontFile2  TTF    no charset; CIDs come from the
                                   FontDescriptor /CIDSet bitmap, or failing
                                   that from the embedded font's glyph count

Wired up with:
    PAPERLESS_PRE_CONSUME_SCRIPT=/usr/src/paperless/scripts/preconsume_tounicode.py

Paperless passes the incoming file as DOCUMENT_SOURCE_PATH. Whatever this
script leaves at that path is what gets ingested.

Design rules, in order of importance:
  1. Never fail an ingest. Any unexpected problem exits 0 and leaves the file
     exactly as it was. Worst case is the mojibake you already have.
  2. Touch nothing that does not need touching. Non-PDFs and healthy PDFs are
     left byte-identical.
  3. Write atomically. Build a temp file, verify it opens, then replace.

Environment:
    TOUNICODE_FONT_DIR   reference fonts   (default: <script dir>/fonts)
    TOUNICODE_LOG        log file          (default: <script dir>/tounicode-fix.log)
    TOUNICODE_DISABLE    set to 1 to make this a no-op
"""

import os
import re
import sys
import shutil
import tempfile
import traceback
from datetime import datetime
from io import BytesIO

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FONT_DIR = os.environ.get("TOUNICODE_FONT_DIR", os.path.join(SCRIPT_DIR, "fonts"))
LOG_PATH = os.environ.get("TOUNICODE_LOG", os.path.join(SCRIPT_DIR, "tounicode-fix.log"))

CID_RE = re.compile(r"^cid0*(\d+)$")

# PDF BaseFont substring -> reference font filename, by style.
# Add a family here only after verifying its CIDs really are the original
# font's glyph IDs. fix_tounicode4.py verify does that against a file's own
# ToUnicode, where some fonts have one and others do not.
FAMILIES = {
    "calibri": {
        "regular": "calibri.ttf",
        "bold": "calibrib.ttf",
        "italic": "calibrii.ttf",
        "bolditalic": "calibriz.ttf",
    },
}

# Unicode presentation forms are a single character ("ﬁ"), which would
# break a search for "financial". Decompose them to the letters they stand for.
PRESENTATION = {
    "ﬀ": "ff", "ﬁ": "fi", "ﬂ": "fl",
    "ﬃ": "ffi", "ﬄ": "ffl", "ﬅ": "st", "ﬆ": "st",
}


def log(message):
    """Append one line to the log file AND echo it to stderr.

    Paperless captures the script's stderr into the container log, so a log
    file the paperless user cannot write (it runs as `paperless`, not root)
    can no longer hide an error. Never raises.
    """
    line = "%s  %s" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), message)
    try:
        sys.stderr.write("[tounicode] %s\n" % line)
    except Exception:
        pass
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except Exception:
        pass


def is_pdf(path):
    try:
        with open(path, "rb") as handle:
            return handle.read(5) == b"%PDF-"
    except Exception:
        return False


def normalize(text):
    if not text:
        return text
    return "".join(PRESENTATION.get(ch, ch) for ch in text)


def style_of(basefont):
    low = basefont.lower()
    bold = "bold" in low
    ital = "italic" in low or "oblique" in low
    if bold and ital:
        return "bolditalic"
    if bold:
        return "bold"
    if ital:
        return "italic"
    return "regular"


def family_of(basefont):
    low = basefont.lower()
    for family in FAMILIES:
        if family in low:
            return family
    return None


# --------------------------------------------------------------------------
# reference font -> glyph id -> text
# --------------------------------------------------------------------------

def iter_gsub_subtables(font):
    """Every GSUB subtable, unwrapping LookupType 7 extensions."""
    if "GSUB" not in font:
        return
    try:
        lookups = font["GSUB"].table.LookupList.Lookup
    except AttributeError:
        return
    for lookup in lookups:
        for sub in lookup.SubTable:
            if sub is None:
                continue
            ext = getattr(sub, "ExtSubTable", None)
            yield ext if ext is not None else sub


def text_from_name(gname, agl):
    if not gname or gname == ".notdef":
        return ""
    try:
        direct = agl.toUnicode(gname)
    except Exception:
        direct = ""
    if direct:
        return direct
    if "_" in gname:
        parts = []
        for piece in gname.split("_"):
            try:
                val = agl.toUnicode(piece)
            except Exception:
                val = ""
            if not val:
                return ""
            parts.append(val)
        return "".join(parts)
    return ""


def build_gid_map(path):
    """glyph id -> text, from a reference font file."""
    from fontTools.ttLib import TTFont
    from fontTools import agl

    font = TTFont(path, fontNumber=0, lazy=True)
    try:
        name_to_text = {}
        for codepoint, gname in sorted(font.getBestCmap().items()):
            name_to_text.setdefault(gname, chr(codepoint))

        for sub in iter_gsub_subtables(font):
            ligs = getattr(sub, "ligatures", None)
            if not ligs:
                continue
            for first, entries in ligs.items():
                for lig in entries:
                    components = [first] + list(lig.Component)
                    parts = [name_to_text.get(c) or text_from_name(c, agl)
                             for c in components]
                    if all(parts):
                        name_to_text.setdefault(lig.LigGlyph, "".join(parts))

        gid_map = {}
        for gid, gname in enumerate(font.getGlyphOrder()):
            text = name_to_text.get(gname) or text_from_name(gname, agl)
            if text:
                gid_map[gid] = normalize(text)
        return gid_map
    finally:
        font.close()


_REF_CACHE = {}


def reference_map(family, style):
    key = (family, style)
    if key in _REF_CACHE:
        return _REF_CACHE[key]
    filename = FAMILIES[family].get(style) or FAMILIES[family]["regular"]
    path = os.path.join(FONT_DIR, filename)
    if not os.path.exists(path):
        _REF_CACHE[key] = None
        return None
    try:
        _REF_CACHE[key] = build_gid_map(path)
    except Exception:
        _REF_CACHE[key] = None
    return _REF_CACHE[key]


# --------------------------------------------------------------------------
# PDF side
# --------------------------------------------------------------------------

def needs_repair(fobj):
    if fobj.get("/Subtype") != "/Type0":
        return False
    if "/ToUnicode" in fobj:
        return False
    enc = fobj.get("/Encoding")
    return enc is not None and "Identity" in str(enc)


def cid_to_gid(descendant):
    """Return (kind, mapping). kind is 'identity', 'stream' or 'unknown'."""
    try:
        c2g = descendant.get("/CIDToGIDMap")
    except Exception:
        return "identity", None
    if c2g is None or "Identity" in str(c2g):
        return "identity", None
    try:
        raw = bytes(c2g.read_bytes())
    except Exception:
        return "unknown", None
    mapping = {}
    for cid in range(len(raw) // 2):
        gid = (raw[cid * 2] << 8) | raw[cid * 2 + 1]
        if gid:
            mapping[cid] = gid
    return "stream", mapping


def cff_cids(desc):
    """CIDs from a CID-keyed CFF charset (cidNNNN glyph names)."""
    from fontTools.cffLib import CFFFontSet

    try:
        data = bytes(desc["/FontFile3"].read_bytes())
        cff = CFFFontSet()
        cff.decompile(BytesIO(data), None)
        charset = cff[cff.fontNames[0]].charset
    except Exception:
        return None
    cids = []
    for gname in charset:
        match = CID_RE.match(str(gname))
        if match:
            cids.append(int(match.group(1)))
    return cids or None


def cidset_cids(desc):
    """Exact CIDs present, from the FontDescriptor /CIDSet bitmap."""
    try:
        raw = bytes(desc["/CIDSet"].read_bytes())
    except Exception:
        return None
    cids = []
    for index, byte in enumerate(raw):
        if not byte:
            continue
        for bit in range(8):
            if byte & (0x80 >> bit):
                cids.append(index * 8 + bit)
    return cids or None


def truetype_cids(desc):
    """CIDs for a CIDFontType2 subset. /CIDSet when present, else glyph count."""
    from fontTools.ttLib import TTFont

    exact = cidset_cids(desc)
    if exact:
        return exact
    try:
        data = bytes(desc["/FontFile2"].read_bytes())
        font = TTFont(BytesIO(data), fontNumber=0, lazy=True,
                      checkChecksums=0, ignoreDecompileErrors=True)
        try:
            count = font["maxp"].numGlyphs
        finally:
            font.close()
        return list(range(count)) or None
    except Exception:
        return None


def subset_cids(fobj):
    """(cids, cid_to_gid_kind, cid_to_gid_map) for one Type0 font."""
    try:
        descendant = fobj.DescendantFonts[0]
        desc = descendant.FontDescriptor
    except Exception:
        return None, None, None

    kind, mapping = cid_to_gid(descendant)

    if "/FontFile3" in desc:
        return cff_cids(desc), kind, mapping
    if "/FontFile2" in desc:
        return truetype_cids(desc), kind, mapping
    return None, kind, mapping


CMAP_HEAD = """/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def
/CMapName /Adobe-Identity-UCS def
/CMapType 2 def
1 begincodespacerange
<0000> <FFFF>
endcodespacerange
"""

CMAP_TAIL = """endcmap
CMapName currentdict /CMap defineresource pop
end
end
"""


def build_cmap(mapping):
    items = sorted(mapping.items())
    out = [CMAP_HEAD]
    for start in range(0, len(items), 100):
        chunk = items[start:start + 100]
        out.append("%d beginbfchar\n" % len(chunk))
        for cid, text in chunk:
            out.append("<%04X> <%s>\n"
                       % (cid, text.encode("utf-16-be").hex().upper()))
        out.append("endbfchar\n")
    out.append(CMAP_TAIL)
    return "".join(out)


def collect_fonts(pdf):
    found = {}
    for page in pdf.pages:
        try:
            fonts = page.Resources.Font
        except (AttributeError, KeyError):
            continue
        for _name, fobj in fonts.items():
            try:
                key = fobj.objgen
            except AttributeError:
                key = id(fobj)
            found.setdefault(key, fobj)
    return list(found.values())


def repair(path):
    """Returns (noteworthy, summary)."""
    import pikepdf

    pdf = pikepdf.open(path)
    closed = False
    try:
        repaired = 0
        total_cids = 0
        unmapped = 0
        families_seen = set()
        skipped = set()

        for fobj in collect_fonts(pdf):
            if not needs_repair(fobj):
                continue
            basefont = str(fobj.get("/BaseFont", ""))
            short = basefont.split("+")[-1].lstrip("/") or "?"

            family = family_of(basefont)
            if family is None:
                skipped.add(short)
                continue
            table = reference_map(family, style_of(basefont))
            if not table:
                skipped.add("%s:no-reference-font" % short)
                continue

            cids, c2g_kind, c2g_map = subset_cids(fobj)
            if not cids:
                skipped.add("%s:no-cids" % short)
                continue
            if c2g_kind == "unknown":
                skipped.add("%s:unreadable-cidtogidmap" % short)
                continue

            mapping = {}
            for cid in cids:
                gid = cid if c2g_kind != "stream" else (c2g_map or {}).get(cid)
                if gid is None:
                    continue
                text = table.get(gid)
                if text:
                    mapping[cid] = text
            if not mapping:
                skipped.add("%s:nothing-resolved" % short)
                continue

            fobj["/ToUnicode"] = pdf.make_stream(
                build_cmap(mapping).encode("ascii"))
            repaired += 1
            total_cids += len(cids)
            unmapped += len(cids) - len(mapping)
            families_seen.add(family)

        note = ""
        if skipped:
            note = " (unhandled: %s)" % ", ".join(sorted(skipped))

        if not repaired:
            # Report unhandled Identity-H fonts even when nothing was fixed, so
            # a document the script cannot help announces itself in the log
            # instead of looking identical to a clean one.
            if skipped:
                return True, "no repair made%s" % note
            return False, "no repair needed"

        handle, tmp = tempfile.mkstemp(suffix=".pdf", dir=os.path.dirname(path))
        os.close(handle)
        pdf.save(tmp)
        pdf.close()
        closed = True

        # Verify the rewritten file before letting it replace the original.
        with pikepdf.open(tmp) as check:
            if len(check.pages) == 0:
                raise RuntimeError("rewritten pdf has no pages")

        shutil.copymode(path, tmp)
        os.replace(tmp, path)

        return True, ("repaired %d font(s), %d cids, %d unmapped, family=%s%s"
                      % (repaired, total_cids, unmapped,
                         ",".join(sorted(families_seen)), note))
    finally:
        if not closed:
            try:
                pdf.close()
            except Exception:
                pass


# Paperless hands the script two paths. DOCUMENT_WORKING_PATH is the copy that
# consumption actually parses and stores; DOCUMENT_SOURCE_PATH is the file it
# came from. Repairing only the source leaves the stored document untouched,
# so repair every distinct real path we are given.
PATH_VARS = ("DOCUMENT_WORKING_PATH", "DOCUMENT_SOURCE_PATH")


def targets():
    found = []
    seen = set()
    for var in PATH_VARS:
        path = os.environ.get(var)
        if not path or not os.path.isfile(path):
            continue
        try:
            key = os.path.realpath(path)
        except Exception:
            key = path
        if key in seen:
            continue
        seen.add(key)
        found.append((var, path))
    if not found and len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        found.append(("argv", sys.argv[1]))
    return found


def main():
    if os.environ.get("TOUNICODE_DISABLE") == "1":
        return 0

    for var, path in targets():
        if not is_pdf(path):
            continue
        label = "%s [%s]" % (os.path.basename(path), var)
        try:
            noteworthy, summary = repair(path)
        except Exception:
            log("%s  ERROR (file left untouched): %s"
                % (label, traceback.format_exc(limit=3).replace("\n", " | ")))
            continue
        if noteworthy:
            log("%s  %s" % (label, summary))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:
        # Absolute last resort: never break consumption.
        sys.exit(0)
