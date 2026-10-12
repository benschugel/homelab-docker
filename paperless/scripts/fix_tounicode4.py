#!/usr/bin/env python3
"""
v4: handles BOTH flavors of Identity-H font with a missing ToUnicode CMap.

  CIDFontType0 (/FontFile3, CFF)  - CID-keyed charset gives cidNNNN names
  CIDFontType2 (/FontFile2, TTF)  - no charset; CIDs enumerated from the
                                    FontDescriptor /CIDSet bitmap, or failing
                                    that from the embedded font's glyph count

In both cases the CID is the glyph ID of the original, unsubsetted font, so a
reference copy of that font reconstructs CID -> text.

Modes:
    check   <fontdir>                 sanity-check the reference tables
    verify  <fontdir> <pdf>           compare derived mapping against the
                                      ToUnicode that healthy fonts in the SAME
                                      file already carry (no writes)
    probe   <fontdir> <pdf>           report what would be repaired
    write   <fontdir> <in> <out>      repair
"""

import os
import re
import sys
from io import BytesIO

try:
    import pikepdf
except ImportError:
    sys.exit("pikepdf not available")

from fontTools.ttLib import TTFont
from fontTools.cffLib import CFFFontSet
from fontTools import agl

CID_RE = re.compile(r"^cid0*(\d+)$")

REFERENCES = {
    "calibri.ttf": "regular",
    "calibrib.ttf": "bold",
    "calibrii.ttf": "italic",
    "calibriz.ttf": "bolditalic",
}


# --------------------------------------------------------------------------
# reference font -> glyph id -> text
# --------------------------------------------------------------------------

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


def iter_subtables(font):
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


# Unicode presentation forms are a single character ("\ufb01"), which breaks
# a search for "financial". Decompose them to the letters they stand for.
PRESENTATION = {
    "\ufb00": "ff", "\ufb01": "fi", "\ufb02": "fl",
    "\ufb03": "ffi", "\ufb04": "ffl", "\ufb05": "st", "\ufb06": "st",
}


def normalize(text):
    if not text:
        return text
    return "".join(PRESENTATION.get(ch, ch) for ch in text)


def text_from_name(gname):
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
    font = TTFont(path, fontNumber=0, lazy=True)
    try:
        name_to_text = {}
        for codepoint, gname in sorted(font.getBestCmap().items()):
            name_to_text.setdefault(gname, chr(codepoint))

        nligs = 0
        for sub in iter_subtables(font):
            ligs = getattr(sub, "ligatures", None)
            if not ligs:
                continue
            for first, entries in ligs.items():
                for lig in entries:
                    nligs += 1
                    components = [first] + list(lig.Component)
                    parts = [name_to_text.get(c) or text_from_name(c)
                             for c in components]
                    if all(parts):
                        name_to_text.setdefault(lig.LigGlyph, "".join(parts))

        gid_map = {}
        for gid, gname in enumerate(font.getGlyphOrder()):
            text = name_to_text.get(gname) or text_from_name(gname)
            if text:
                gid_map[gid] = normalize(text)
        return gid_map, nligs
    finally:
        font.close()


def load_references(fontdir, verbose=True):
    refs = {}
    for filename, key in REFERENCES.items():
        path = os.path.join(fontdir, filename)
        if not os.path.exists(path):
            print("missing %s" % path)
            continue
        table, nligs = build_gid_map(path)
        refs[key] = table
        if verbose:
            print("loaded %-14s -> %-11s %d glyphs, %d ligatures"
                  % (filename, key, len(table), nligs))
    if "regular" in refs:
        for key in ("bold", "italic", "bolditalic"):
            refs.setdefault(key, refs["regular"])
    return refs


# --------------------------------------------------------------------------
# PDF side
# --------------------------------------------------------------------------

def collect_fonts(pdf):
    found = {}
    for pnum, page in enumerate(pdf.pages, 1):
        try:
            fonts = page.Resources.Font
        except (AttributeError, KeyError):
            continue
        for name, fobj in fonts.items():
            try:
                key = fobj.objgen
            except AttributeError:
                key = id(fobj)
            if key not in found:
                found[key] = (str(name), pnum, fobj)
    return found


def is_identity_type0(fobj):
    if fobj.get("/Subtype") != "/Type0":
        return False
    enc = fobj.get("/Encoding")
    return enc is not None and "Identity" in str(enc)


def descendant_of(fobj):
    try:
        return fobj.DescendantFonts[0]
    except Exception:
        return None


def cid_to_gid(descendant):
    """Return (kind, mapping). kind is 'identity' or 'stream' or 'unknown'."""
    c2g = descendant.get("/CIDToGIDMap")
    if c2g is None:
        return "identity", None
    text = str(c2g)
    if "Identity" in text:
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
    try:
        data = bytes(desc["/FontFile3"].read_bytes())
    except Exception:
        return None
    try:
        cff = CFFFontSet()
        cff.decompile(BytesIO(data), None)
        charset = cff[cff.fontNames[0]].charset
    except Exception:
        return None
    cids = []
    for gname in charset:
        m = CID_RE.match(str(gname))
        if m:
            cids.append(int(m.group(1)))
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
    """CIDs for a CIDFontType2 subset, best effort."""
    exact = cidset_cids(desc)
    if exact:
        return exact, "cidset"
    try:
        data = bytes(desc["/FontFile2"].read_bytes())
        font = TTFont(BytesIO(data), fontNumber=0, lazy=True,
                      checkChecksums=0, ignoreDecompileErrors=True)
        try:
            count = font["maxp"].numGlyphs
        finally:
            font.close()
        return list(range(count)), "numglyphs"
    except Exception:
        return None, "failed"


def subset_cids(fobj):
    """Returns (cids, how, c2g_kind, c2g_map) or (None, reason, ..., ...)."""
    descendant = descendant_of(fobj)
    if descendant is None:
        return None, "no descendant", None, None
    try:
        desc = descendant.FontDescriptor
    except Exception:
        return None, "no descriptor", None, None

    c2g_kind, c2g_map = cid_to_gid(descendant)

    if "/FontFile3" in desc:
        cids = cff_cids(desc)
        return cids, "cff-charset" if cids else "cff-failed", c2g_kind, c2g_map
    if "/FontFile2" in desc:
        cids, how = truetype_cids(desc)
        return cids, how, c2g_kind, c2g_map
    return None, "no font program", c2g_kind, c2g_map


# --------------------------------------------------------------------------
# existing ToUnicode, for the verify mode
# --------------------------------------------------------------------------

BFCHAR_BLOCK = re.compile(rb"beginbfchar(.*?)endbfchar", re.S)
BFRANGE_BLOCK = re.compile(rb"beginbfrange(.*?)endbfrange", re.S)
HEXPAIR = re.compile(rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]*)>")
RANGE_SIMPLE = re.compile(rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]*)>")


def decode_utf16be(hexstr):
    try:
        raw = bytes.fromhex(hexstr.decode("ascii"))
        return raw.decode("utf-16-be", errors="replace")
    except Exception:
        return ""


def parse_tounicode(fobj):
    """Existing CID -> text from a font's ToUnicode CMap."""
    try:
        raw = bytes(fobj["/ToUnicode"].read_bytes())
    except Exception:
        return {}
    out = {}
    for block in BFCHAR_BLOCK.findall(raw):
        for src, dst in HEXPAIR.findall(block):
            try:
                out[int(src, 16)] = decode_utf16be(dst)
            except Exception:
                pass
    for block in BFRANGE_BLOCK.findall(raw):
        for lo, hi, dst in RANGE_SIMPLE.findall(block):
            try:
                lo_i, hi_i = int(lo, 16), int(hi, 16)
                base = decode_utf16be(dst)
                if len(base) == 1 and hi_i - lo_i < 65536:
                    start = ord(base)
                    for offset in range(hi_i - lo_i + 1):
                        out[lo_i + offset] = chr(start + offset)
            except Exception:
                pass
    return out


# --------------------------------------------------------------------------
# CMap output
# --------------------------------------------------------------------------

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


def derive(fobj, refs):
    """CID -> text for one font, using the reference tables."""
    base = str(fobj.get("/BaseFont", ""))
    if "calibri" not in base.lower():
        return None, "not calibri", None
    cids, how, c2g_kind, c2g_map = subset_cids(fobj)
    if not cids:
        return None, how, c2g_kind
    table = refs[style_of(base)]
    mapping = {}
    for cid in cids:
        gid = cid if c2g_kind != "stream" else (c2g_map or {}).get(cid)
        if gid is None:
            continue
        text = table.get(gid)
        if text:
            mapping[cid] = text
    return mapping, how, c2g_kind


SANITY = ((258, "a"), (282, "d"), (286, "e"), (336, "g"), (349, "i"),
          (374, "n"), (381, "o"), (400, "s"), (415, "ti"))


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    mode, fontdir = sys.argv[1], sys.argv[2]
    refs = load_references(fontdir)
    if not refs:
        sys.exit("no reference fonts in %s" % fontdir)

    if mode == "check":
        reg = refs["regular"]
        bad = 0
        print("\nreference sanity check:")
        for cid, expect in SANITY:
            got = reg.get(cid, "<none>")
            ok = got == expect
            bad += 0 if ok else 1
            print("  cid %-5d expected %-4r got %-6r  %s"
                  % (cid, expect, got, "ok" if ok else "MISMATCH"))
        print("\n%d mismatch(es)" % bad)
        return

    if len(sys.argv) < 4:
        sys.exit("need an input pdf")
    pdf = pikepdf.open(sys.argv[3])
    fonts = collect_fonts(pdf)

    if mode == "verify":
        print("\ncomparing derived mapping against fonts that ALREADY have a")
        print("correct ToUnicode in this same file:\n")
        checked = agree = disagree = 0
        examples = []
        for rname, pnum, fobj in fonts.values():
            if not is_identity_type0(fobj):
                continue
            if "/ToUnicode" not in fobj:
                continue
            existing = parse_tounicode(fobj)
            if not existing:
                continue
            mapping, how, c2g = derive(fobj, refs)
            if not mapping:
                continue
            base = str(fobj.get("/BaseFont", "?"))
            hits = miss = 0
            for cid, want in existing.items():
                got = mapping.get(cid)
                if got is None:
                    continue
                if got == want:
                    hits += 1
                else:
                    miss += 1
                    if len(examples) < 10:
                        examples.append((base, cid, want, got))
            if hits or miss:
                checked += 1
                agree += hits
                disagree += miss
                print("  %-28s p%-3s %-10s overlap=%-4d agree=%-4d differ=%d"
                      % (base[:28], pnum, how, hits + miss, hits, miss))
        print("\n%d font(s) compared, %d agreements, %d disagreements"
              % (checked, agree, disagree))
        if examples:
            print("\ndisagreements:")
            for base, cid, want, got in examples:
                print("  %-24s cid %-5d existing=%r derived=%r"
                      % (base[:24], cid, want, got))
        if checked and not disagree:
            print("\nderived mapping matches the file's own ToUnicode exactly.")
        return

    repaired = 0
    skipped = []
    for rname, pnum, fobj in fonts.values():
        if not is_identity_type0(fobj):
            continue
        if "/ToUnicode" in fobj:
            continue
        base = str(fobj.get("/BaseFont", "?"))
        mapping, how, c2g = derive(fobj, refs)
        if not mapping:
            skipped.append("%s (%s)" % (base.split("+")[-1], how))
            continue
        print("  %-28s p%-3s %-10s c2g=%-9s mapped=%d"
              % (base[:28], pnum, how, c2g, len(mapping)))
        if mode == "write":
            fobj["/ToUnicode"] = pdf.make_stream(
                build_cmap(mapping).encode("ascii"))
            repaired += 1

    if skipped:
        print("\nskipped: %s" % ", ".join(sorted(set(skipped))))

    if mode == "write":
        if len(sys.argv) < 5:
            sys.exit("write mode needs an output path")
        pdf.save(sys.argv[4])
        print("\nwrote %s with %d font(s) repaired" % (sys.argv[4], repaired))


if __name__ == "__main__":
    main()
