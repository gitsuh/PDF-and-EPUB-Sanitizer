#!/usr/bin/env python3
"""
sanitize_pdf.py - Sanitize a PDF or EPUB that came from an untrusted source.

The input type is detected automatically.

PDF: strips active/executable content and flattens interactive elements so the
file can be opened safely:

  * Document JavaScript (Names/JavaScript) and any residual /JS keys
  * Auto-run actions (OpenAction) and event actions (/AA: on open, close,
    print, page navigation, mouse/focus events, ...)
  * Launch actions (run an external program), SubmitForm / ImportData,
    remote / embedded GoTo actions, Rendition / RichMedia / Movie / Sound
  * Embedded files / attachments (a common malware carrier)
  * XFA dynamic forms (can carry scripts)
  * Multimedia and 3D annotations
  * Interactive form fields and annotations are FLATTENED into static page
    content so the document still looks the same.

  Two PDF modes:
    structural (default)  Strip active content and flatten forms/annotations.
                          Keeps selectable text and a small file size.
    rasterize             Render every page to an image and rebuild the PDF
                          from those images. Strongest guarantee - nothing
                          executable, scriptable, or embedded can survive -
                          but text is no longer selectable and the file is
                          larger. Use for the most hostile inputs.

EPUB: an EPUB is a ZIP of XHTML/CSS/SVG plus an OPF manifest, and EPUB3 allows
JavaScript, so it carries the usual web attack surface. The tool removes:

  * <script> elements and standalone .js files (and other active file types)
  * Inline event handlers (onload, onclick, onerror, ...)
  * javascript: and dangerous data: URIs
  * <iframe>/<frame>/<object>/<embed>/<applet>/<base> and form controls
  * <meta http-equiv="refresh"> redirects and HTML imports
  * Scripted SVG (scripts, event handlers, javascript: links)
  * Dangerous CSS (expression(), behavior, -moz-binding, url(javascript:),
    remote @import)
  * With --remove-uris: external links and remote resources (tracking pixels,
    remote fonts/stylesheets) that would phone home
  The OPF manifest is updated (pruned items, cleared "scripted" properties)
  and the archive is repackaged with the required uncompressed mimetype first.

IMPORTANT: nothing here *executes* the input. PDFs are parsed/rewritten with
qpdf / pikepdf / poppler; EPUB markup is parsed with BeautifulSoup's
pure-Python html.parser, which never fetches anything or expands external XML
entities. Run it on files you do not trust; the output is the clean copy you
actually open.

Dependencies: pikepdf and qpdf (PDF); beautifulsoup4 (EPUB); poppler's
pdftoppm plus img2pdf + Pillow (PDF rasterize mode only).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import posixpath
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pikepdf
from pikepdf import Array, Dictionary, Name  # noqa: F401  (Name handy for extensions)

# ---------------------------------------------------------------------------
# What counts as dangerous
# ---------------------------------------------------------------------------

# Action types (the /S key of an action dictionary) that can execute code,
# touch the network or filesystem, or hand control to an external handler.
DANGEROUS_ACTIONS = {
    "/JavaScript",       # run document JavaScript
    "/Launch",           # launch an external application or file
    "/SubmitForm",       # send form data to a URL
    "/ImportData",       # import field data from a file
    "/GoToR",            # open a remote (external) document
    "/GoToE",            # open an embedded document
    "/RichMediaExecute", # drive embedded Flash / rich media
    "/Rendition",        # play media; can also run JavaScript
    "/Movie",            # legacy movie playback
    "/Sound",            # legacy sound playback
    "/GoTo3DView",       # 3D view actions
}

# Annotation subtypes that carry embedded payloads or active media.
DANGEROUS_ANNOT_SUBTYPES = {
    "/FileAttachment",
    "/Movie",
    "/Sound",
    "/Screen",
    "/RichMedia",
    "/3D",
}

# Keys that should never survive anywhere in the object graph.
RESIDUAL_KEYS = ("/JS", "/JavaScript")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _subtype(obj) -> str:
    try:
        return str(obj.get("/Subtype")) if "/Subtype" in obj else ""
    except Exception:
        return ""


def action_is_dangerous(action, remove_uris: bool, _depth: int = 0) -> bool:
    """True if this action (or any action chained via /Next) is dangerous."""
    if _depth > 32 or not isinstance(action, Dictionary):
        return False
    try:
        s = str(action.get("/S")) if "/S" in action else ""
    except Exception:
        s = ""
    if s in DANGEROUS_ACTIONS:
        return True
    if remove_uris and s == "/URI":
        return True
    nxt = action.get("/Next") if "/Next" in action else None
    if nxt is None:
        return False
    items = list(nxt) if isinstance(nxt, Array) else [nxt]
    return any(action_is_dangerous(a, remove_uris, _depth + 1) for a in items)


# ---------------------------------------------------------------------------
# Reading helpers for detailed findings
# ---------------------------------------------------------------------------

def _read_js(obj) -> str:
    """Return the JavaScript carried by an action/dict as a one-line string."""
    js = obj.get("/JS") if "/JS" in obj else None
    if js is None:
        return ""
    try:
        if isinstance(js, pikepdf.Stream):
            text = bytes(js.read_bytes()).decode("latin-1", "replace")
        else:
            text = str(js)
    except Exception:
        text = "<unreadable>"
    return " ".join(text.split())


def _oneline(text) -> str:
    """Collapse whitespace to a single line WITHOUT truncating (full payload)."""
    return " ".join(str(text).split())


def _truncate(text: str, limit: int = 140) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _filespec_name(fs) -> str:
    """Human-readable name for a file specification (string or /Filespec dict)."""
    try:
        if isinstance(fs, pikepdf.String):
            return str(fs)
        if isinstance(fs, Dictionary):
            for k in ("/UF", "/F", "/DOS", "/Mac", "/Unix"):
                if k in fs:
                    return str(fs[k])
    except Exception:
        pass
    return "?"


def _ef_size(spec) -> str:
    """Size of the file embedded in a /Filespec, if readable."""
    try:
        ef = spec.get("/EF") if "/EF" in spec else None
        if isinstance(ef, Dictionary):
            for k in ("/F", "/UF", "/DOS", "/Mac", "/Unix"):
                if k in ef and isinstance(ef[k], pikepdf.Stream):
                    return f"{len(bytes(ef[k].read_bytes()))} bytes"
    except Exception:
        pass
    return "size unknown"


def _dest_to_str(dest, pages=None) -> str:
    """Describe a GoTo destination: which page (if local) or named target."""
    try:
        if isinstance(dest, Array) and len(dest) >= 1:
            og = _objgen(dest[0])
            if og and pages and og in pages:
                return f"page {pages[og]}"
            return "an internal page"
        if isinstance(dest, (pikepdf.String, pikepdf.Name)):
            return f"named destination {str(dest)!r}"
    except Exception:
        pass
    return "an internal destination"


def describe_action(action, pages=None, _depth: int = 0) -> str:
    """One-line description of an action, including its target/payload."""
    if not isinstance(action, Dictionary) or _depth > 16:
        return "?"
    s = str(action.get("/S")).lstrip("/") if "/S" in action else "?"
    extra = ""
    if s == "JavaScript":
        extra = f": {_oneline(_read_js(action))!r}"
    elif s == "GoTo":
        if "/D" in action:
            extra = f" -> {_dest_to_str(action['/D'], pages)}"
    elif s in ("Launch", "GoToR", "GoToE", "ImportData"):
        if "/F" in action:
            extra = f" -> {_filespec_name(action['/F'])}"
    elif s == "SubmitForm":
        if "/F" in action:
            extra = f" -> {_filespec_name(action['/F'])}"
        elif "/URL" in action:
            extra = f" -> {action['/URL']}"
    elif s == "URI":
        if "/URI" in action:
            extra = f" -> {action['/URI']}"
    desc = f"{s}{extra}"
    if "/Next" in action:
        desc += " (+chained /Next)"
    return desc


def _describe_aa(aa, pages=None) -> str:
    """Summarize an additional-actions (/AA) dict as 'trigger=action; ...'."""
    parts = []
    if isinstance(aa, Dictionary):
        for trig in aa.keys():
            try:
                parts.append(f"{str(trig).lstrip('/')}={describe_action(aa[trig], pages)}")
            except Exception:
                parts.append(f"{str(trig).lstrip('/')}=?")
    return "; ".join(parts) if parts else "(event actions)"


_FIELD_TYPES = {"/Tx": "text", "/Btn": "button", "/Ch": "choice", "/Sig": "signature"}


def _field_type(fld) -> str:
    ft = str(fld["/FT"]).strip() if "/FT" in fld else ""
    return _FIELD_TYPES.get(ft, ft.lstrip("/") or "field")


def _collect_fields(acro):
    """Flatten an AcroForm /Fields tree to a list of (field_dict, full_name)."""
    out = []

    def walk(node, prefix, depth=0):
        if not isinstance(node, Dictionary) or depth > 32:
            return
        t = str(node["/T"]) if "/T" in node else None
        name = f"{prefix}.{t}" if (prefix and t) else (t or prefix or "(unnamed)")
        kids = node.get("/Kids") if "/Kids" in node else None
        named_kids = ([k for k in kids if isinstance(k, Dictionary) and "/T" in k]
                      if isinstance(kids, Array) else [])
        if named_kids:
            for k in named_kids:
                walk(k, name, depth + 1)
        else:
            out.append((node, name))

    flds = acro.get("/Fields") if "/Fields" in acro else None
    if isinstance(flds, Array):
        for f in flds:
            walk(f, None)
    return out


def _summarize_fields(fields) -> str:
    n = len(fields)
    if n == 0:
        return "interactive form (no named fields; will be flattened)"
    shown = ", ".join(f"{name}[{_field_type(fld)}]" for fld, name in fields[:8])
    more = "" if n <= 8 else f", +{n - 8} more"
    return f"interactive form, {n} field(s): {shown}{more} (will be flattened)"


def _name_tree_items(node):
    """Yield (name, value) pairs from a PDF name tree, tolerating odd inputs."""
    try:
        for name, value in pikepdf.NameTree(node).items():
            yield str(name), value
        return
    except Exception:
        pass
    try:  # fallback: flat /Names array [key, value, key, value, ...]
        arr = node.get("/Names") if isinstance(node, Dictionary) else None
        if isinstance(arr, Array):
            it = list(arr)
            for i in range(0, len(it) - 1, 2):
                yield str(it[i]), it[i + 1]
    except Exception:
        return


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _objgen(obj):
    try:
        og = obj.objgen
        return og if og != (0, 0) else None
    except Exception:
        return None


def scan(path: Path, remove_uris: bool = False) -> list:
    """Read-only inventory of active/risky elements.

    Returns a list of findings; each is a dict with:
      location  - "catalog", "page N", or "object N"
      category  - machine-readable category name
      detail    - human-readable description (action type, payload, filename)
    """
    findings = []
    seen = set()  # objgens already attributed, so the deep sweep won't repeat them

    def add(location, category, detail=""):
        findings.append({"location": location,
                         "category": category,
                         "detail": detail})

    with pikepdf.open(str(path)) as pdf:
        root = pdf.Root

        # Map each page object to its 1-based index, for resolving GoTo targets.
        pages = {}
        for i, pg in enumerate(pdf.pages, start=1):
            og = _objgen(pg.obj)
            if og:
                pages[og] = i
        # Form-field widget objects reported by the AcroForm pass, so the
        # annotation pass below doesn't report the same field actions twice.
        reported_field_objs = set()

        if "/OpenAction" in root:
            oa = root["/OpenAction"]
            if isinstance(oa, Dictionary) and "/S" in oa:
                add("catalog", "open_action", describe_action(oa, pages))
                if (og := _objgen(oa)):
                    seen.add(og)
            else:
                add("catalog", "open_action",
                    f"auto-open -> {_dest_to_str(oa, pages)}")

        if "/AA" in root:
            add("catalog", "doc_additional_actions", _describe_aa(root["/AA"], pages))

        names = root.get("/Names") if "/Names" in root else None
        if isinstance(names, Dictionary):
            if "/JavaScript" in names:
                items = list(_name_tree_items(names["/JavaScript"]))
                if items:
                    for nm, act in items:
                        add("catalog", "document_javascript",
                            f"{nm}: {describe_action(act)}")
                        if (og := _objgen(act)):
                            seen.add(og)
                else:
                    add("catalog", "document_javascript", "named JavaScript present")
            if "/EmbeddedFiles" in names:
                items = list(_name_tree_items(names["/EmbeddedFiles"]))
                if items:
                    for nm, spec in items:
                        add("catalog", "embedded_files",
                            f"{_filespec_name(spec)} ({_ef_size(spec)})")
                else:
                    add("catalog", "embedded_files", "embedded files present")

        acro = root.get("/AcroForm") if "/AcroForm" in root else None
        if isinstance(acro, Dictionary):
            fields = _collect_fields(acro)
            add("catalog", "acroform", _summarize_fields(fields))
            # Surface field-level scripts/actions - the genuinely risky part of
            # a form. (A plain form with none of these is benign; it is only
            # flattened.) Record the field objects so the annotation pass below
            # does not also report the same actions for merged field/widgets.
            for fld, name in fields:
                if (og := _objgen(fld)):
                    reported_field_objs.add(og)
                if "/A" in fld and action_is_dangerous(fld["/A"], remove_uris):
                    add("catalog", "form_field_actions",
                        f"{name}: {describe_action(fld['/A'], pages)}")
                    if (og := _objgen(fld["/A"])):
                        seen.add(og)
                if "/AA" in fld:
                    add("catalog", "form_field_actions",
                        f"{name}: {_describe_aa(fld['/AA'], pages)}")
                    fa = fld["/AA"]
                    if isinstance(fa, Dictionary):
                        for trig in fa.keys():
                            if (og := _objgen(fa[trig])):
                                seen.add(og)
            if "/XFA" in acro:
                add("catalog", "xfa_forms", "dynamic XFA form (can carry scripts)")

        for i, page in enumerate(pdf.pages, start=1):
            loc = f"page {i}"
            po = page.obj
            if "/AA" in po:
                add(loc, "page_additional_actions", _describe_aa(po["/AA"], pages))
            annots = po.get("/Annots") if "/Annots" in po else None
            if isinstance(annots, Array):
                for a in annots:
                    if not isinstance(a, Dictionary):
                        continue
                    st = _subtype(a)
                    if st in DANGEROUS_ANNOT_SUBTYPES:
                        detail = st.lstrip("/")
                        if "/FS" in a:
                            detail += f" -> {_filespec_name(a['/FS'])}"
                        add(loc, "dangerous_annotations", detail)
                    # Skip /A and /AA here if this widget is a form field the
                    # AcroForm pass already covered (by name).
                    if _objgen(a) in reported_field_objs:
                        continue
                    if "/A" in a and action_is_dangerous(a["/A"], remove_uris):
                        add(loc, "annotation_actions", describe_action(a["/A"], pages))
                        if (og := _objgen(a["/A"])):
                            seen.add(og)
                    if "/AA" in a:
                        add(loc, "annotation_additional_actions",
                            _describe_aa(a["/AA"], pages))

        # Deep sweep: any indirect object still carrying a JS key that was not
        # already attributed to a finding above.
        for obj in pdf.objects:
            if not isinstance(obj, Dictionary):
                continue
            if not any(k in obj for k in RESIDUAL_KEYS):
                continue
            og = _objgen(obj)
            if og and og in seen:
                continue
            snippet = _oneline(_read_js(obj)) or "JavaScript key present"
            label = f"object {og[0]}" if og else "inline object"
            add(label, "residual_javascript", snippet)

    return findings


def print_report(title: str, findings: list, verbose: bool = False) -> None:
    print(f"\n{title}")
    print("-" * len(title))
    if not findings:
        print("  (none found)")
        return

    if verbose:
        width = max(len(f["location"]) for f in findings)
        for f in findings:
            line = f"  [{f['location']:<{width}}]  {f['category']}"
            if f["detail"]:
                line += f"  ->  {_truncate(f['detail'], 140)}"
            print(line)
        print()

    counts = {}
    for f in findings:
        counts[f["category"]] = counts.get(f["category"], 0) + 1
    for cat in sorted(counts):
        print(f"  {cat.replace('_', ' '):32s}: {counts[cat]}")
    print(f"  {'TOTAL active/interactive elements':32s}: {len(findings)}")


# ---------------------------------------------------------------------------
# Findings export (a permanent, complete record of what was found/removed)
# ---------------------------------------------------------------------------

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def build_findings_record(inp: Path, fmt: str, settings: dict,
                          before: list, after=None, actions=None) -> dict:
    """Assemble a complete, machine-readable record of a sanitization run.

    `before` is the full (untruncated) list of findings in the original file -
    i.e. exactly the active content that the tool removes. `after` (if given)
    is what a re-scan of the cleaned output still finds (should be empty), and
    `actions` is the per-category tally of what was stripped.
    """
    by_cat = {}
    for f in before:
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
    record = {
        "tool": "sanitize_pdf.py",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "input": {
            "path": str(inp),
            "format": fmt,
            "size_bytes": (inp.stat().st_size if inp.exists() else None),
            "sha256": _sha256(inp),
        },
        "settings": settings,
        "summary": {
            "found": len(before),
            "by_category": by_cat,
            "remaining_after_sanitize": (None if after is None else len(after)),
        },
        # Full, untruncated detail of every removed item.
        "removed": before,
    }
    if actions is not None:
        record["actions_taken"] = {k: v for k, v in actions.items() if v}
    if after is not None:
        record["remaining_after_sanitize"] = after
    return record


def write_findings_json(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


# ---------------------------------------------------------------------------
# Structural cleaning (operates on an already-opened pikepdf.Pdf)
# ---------------------------------------------------------------------------

def strip_active_content(pdf: pikepdf.Pdf, remove_uris: bool, strip_metadata: bool) -> dict:
    report = {k: 0 for k in (
        "openaction_removed", "doc_aa_removed", "doc_js_removed",
        "embedded_files_removed", "xfa_removed", "acroform_removed",
        "page_aa_removed", "annotations_removed", "actions_removed",
        "aa_removed", "residual_keys_removed", "metadata_stripped",
    )}
    root = pdf.Root

    # --- document catalog -------------------------------------------------
    if "/OpenAction" in root:
        del root["/OpenAction"]
        report["openaction_removed"] += 1
    if "/AA" in root:
        del root["/AA"]
        report["doc_aa_removed"] += 1

    names = root.get("/Names") if "/Names" in root else None
    if isinstance(names, Dictionary):
        if "/JavaScript" in names:
            del names["/JavaScript"]
            report["doc_js_removed"] += 1
        if "/EmbeddedFiles" in names:
            del names["/EmbeddedFiles"]
            report["embedded_files_removed"] += 1

    acro = root.get("/AcroForm") if "/AcroForm" in root else None
    if isinstance(acro, Dictionary):
        if "/XFA" in acro:
            del acro["/XFA"]
            report["xfa_removed"] += 1
        # Form fields have been flattened into page content already, so the
        # interactive form definition is no longer needed.
        del root["/AcroForm"]
        report["acroform_removed"] += 1

    # --- per page ---------------------------------------------------------
    for page in pdf.pages:
        po = page.obj
        if "/AA" in po:
            del po["/AA"]
            report["page_aa_removed"] += 1

        annots = po.get("/Annots") if "/Annots" in po else None
        if isinstance(annots, Array):
            kept = []
            for a in list(annots):
                if not isinstance(a, Dictionary):
                    continue
                if _subtype(a) in DANGEROUS_ANNOT_SUBTYPES:
                    report["annotations_removed"] += 1
                    continue  # drop the whole annotation
                if "/A" in a and action_is_dangerous(a["/A"], remove_uris):
                    del a["/A"]
                    report["actions_removed"] += 1
                if "/AA" in a:
                    del a["/AA"]
                    report["aa_removed"] += 1
                kept.append(a)
            if kept:
                po["/Annots"] = Array(kept)
            elif "/Annots" in po:
                del po["/Annots"]

    # --- deep sweep for stragglers ---------------------------------------
    for obj in pdf.objects:
        if not isinstance(obj, Dictionary):
            continue
        for key in RESIDUAL_KEYS:
            if key in obj:
                del obj[key]
                report["residual_keys_removed"] += 1

    # --- metadata ---------------------------------------------------------
    if strip_metadata:
        if "/Metadata" in root:
            del root["/Metadata"]
            report["metadata_stripped"] += 1
        try:
            pdf.docinfo = pikepdf.Dictionary()
        except Exception:
            pass

    return report


# ---------------------------------------------------------------------------
# Pipelines
# ---------------------------------------------------------------------------

def run_qpdf_flatten(src: Path, dst: Path) -> None:
    """Flatten annotations and form-field appearances into static content."""
    cmd = [
        "qpdf",
        "--warning-exit-0",          # warnings about a hostile file are fine
        "--generate-appearances",    # render current form values
        "--flatten-annotations=all", # bake annotations/widgets into the page
        "--flatten-rotation",        # normalize page rotation
        "--object-streams=generate",
        str(src),
        str(dst),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    # qpdf returns 3 for warnings; --warning-exit-0 maps that to 0. Treat only
    # a hard failure (no output file) as fatal.
    if not dst.exists() or dst.stat().st_size == 0:
        raise RuntimeError(
            "qpdf failed to flatten the PDF:\n" + (proc.stderr or proc.stdout)
        )


def sanitize_structural(inp: Path, out: Path, remove_uris: bool,
                        strip_metadata: bool) -> dict:
    with tempfile.TemporaryDirectory() as td:
        flat = Path(td) / "flat.pdf"
        run_qpdf_flatten(inp, flat)
        with pikepdf.open(str(flat)) as pdf:
            report = strip_active_content(pdf, remove_uris, strip_metadata)
            # Orphaned objects (now-unreferenced actions, attachments, etc.)
            # are dropped automatically because preserve_unreferenced is False.
            pdf.save(str(out), fix_metadata_version=True,
                     object_stream_mode=pikepdf.ObjectStreamMode.generate)
    return report


def sanitize_rasterize(inp: Path, out: Path, dpi: int,
                       strip_metadata: bool) -> dict:
    try:
        import img2pdf  # noqa: F401
    except ImportError:
        raise RuntimeError("rasterize mode needs img2pdf (pip install img2pdf)")
    import img2pdf

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        prefix = tdp / "page"
        proc = subprocess.run(
            ["pdftoppm", "-r", str(dpi), "-png", str(inp), str(prefix)],
            capture_output=True, text=True,
        )
        pages = sorted(tdp.glob("page*.png"))
        if not pages:
            raise RuntimeError(
                "pdftoppm produced no pages (is poppler installed?):\n"
                + (proc.stderr or proc.stdout)
            )
        rebuilt = tdp / "rebuilt.pdf"
        with open(rebuilt, "wb") as fh:
            fh.write(img2pdf.convert([str(p) for p in pages]))

        # The image-only PDF is already inert; this pass just normalizes it
        # and strips metadata so the report can confirm a clean result.
        with pikepdf.open(str(rebuilt)) as pdf:
            report = strip_active_content(pdf, remove_uris=True,
                                          strip_metadata=strip_metadata)
            report["pages_rasterized"] = len(pages)
            pdf.save(str(out), fix_metadata_version=True,
                     object_stream_mode=pikepdf.ObjectStreamMode.generate)
    return report


# ---------------------------------------------------------------------------
# EPUB sanitization
# ---------------------------------------------------------------------------
#
# An EPUB is a ZIP of XHTML/CSS/SVG plus an OPF manifest. EPUB3 allows
# JavaScript, and the content is web markup, so it carries the usual web
# attack surface. We strip it the same way a careful HTML sanitizer would,
# then repackage the ZIP (keeping the required uncompressed `mimetype` entry
# first). Markup is parsed with BeautifulSoup's pure-Python html.parser, which
# does NOT fetch anything or expand external XML entities.

# Elements removed outright (subtree deleted).
EPUB_KILL_TAGS = {
    "script", "iframe", "frame", "frameset", "object", "embed", "applet",
    "base",
}
# Interactive form controls removed; the surrounding text is preserved.
EPUB_CONTROL_TAGS = {"input", "button", "select", "textarea"}
# Attributes that can carry a URL (and therefore javascript:/remote payloads).
EPUB_URL_ATTRS = {
    "href", "src", "data", "action", "formaction", "poster", "background",
    "cite", "longdesc", "lowsrc", "dynsrc", "xlink:href", "srcset",
}
_REMOTE_SCHEMES = ("http://", "https://", "ftp://")

# CSS danger patterns.
_RE_CSS_EXPRESSION = re.compile(r"[a-zA-Z-]+\s*:\s*expression\s*\([^;}]*\)\s*;?", re.I)
_RE_CSS_BEHAVIOR = re.compile(r"(?:-[a-z]+-)?behavior\s*:\s*url\([^)]*\)\s*;?", re.I)
_RE_CSS_MOZBINDING = re.compile(r"-moz-binding\s*:\s*url\([^)]*\)\s*;?", re.I)
_RE_CSS_IMPORT = re.compile(
    r"@import\s+(?:url\(\s*(['\"]?)([^'\")]+)\1\s*\)|(['\"])([^'\"]+)\3)[^;]*;", re.I)
_RE_CSS_URL = re.compile(r"url\(\s*(['\"]?)([^'\")]*)\1\s*\)", re.I)
# Any declaration whose value reaches a javascript: scheme, even when wrapped
# in url(...) with inner quotes/parens that the url() regex can't span.
_RE_CSS_JS_DECL = re.compile(r"[a-zA-Z-]+\s*:\s*[^;{}]*javascript:[^;{}]*;?", re.I)


def _bs4():
    """Import BeautifulSoup, silencing the expected 'XML parsed as HTML' note.

    We deliberately use the pure-Python html.parser: it never fetches remote
    resources and never expands external XML entities, which is what we want
    for untrusted input.
    """
    import warnings
    from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
    warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
    return BeautifulSoup


def _norm_uri(value: str) -> str:
    return "".join(str(value).split()).lower()


def _is_remote(value: str) -> bool:
    u = _norm_uri(value)
    return u.startswith(_REMOTE_SCHEMES) or u.startswith("//")


def _is_js_uri(value: str) -> bool:
    return _norm_uri(value).startswith("javascript:")


def _is_dangerous_data_uri(value: str) -> bool:
    u = _norm_uri(value)
    return (u.startswith("data:text/html") or u.startswith("data:application/xhtml")
            or u.startswith("data:image/svg"))


def _within_svg(tag) -> bool:
    p = getattr(tag, "parent", None)
    while p is not None:
        if getattr(p, "name", None) and p.name.lower() == "svg":
            return True
        p = p.parent
    return False


def _ensure_xml_decl(original: str, output: str) -> str:
    """Re-prepend the XML declaration if the parser dropped it."""
    if original.lstrip().startswith("<?xml") and not output.lstrip().startswith("<?xml"):
        end = original.find("?>")
        decl = original[: end + 2] if end != -1 else '<?xml version="1.0" encoding="utf-8"?>'
        return decl + "\n" + output
    return output


def _sanitize_css(text: str, remove_uris: bool, do_clean: bool):
    """Return (findings, cleaned_css). findings is a list of (category, detail).

    Transformations are always computed (so detection is correctly sequenced
    and not double-counted); the transformed text is only returned when
    do_clean is set.
    """
    findings = []
    work = text

    def _strip(regex, category):
        nonlocal work

        def _r(m):
            findings.append((category, _oneline(m.group(0))))
            return ""
        work = regex.sub(_r, work)

    _strip(_RE_CSS_EXPRESSION, "css_expression")
    _strip(_RE_CSS_BEHAVIOR, "css_binding")
    _strip(_RE_CSS_MOZBINDING, "css_binding")
    _strip(_RE_CSS_JS_DECL, "css_javascript")

    def _import_r(m):
        target = (m.group(2) or m.group(4) or "").strip()
        tl = target.lower()
        if tl.startswith("javascript:") or _is_remote(target) or tl.startswith("data:"):
            findings.append(("css_remote_import", target))
            return ""
        return m.group(0)
    work = _RE_CSS_IMPORT.sub(_import_r, work)

    def _url_r(m):
        target = (m.group(2) or "").strip()
        if target.lower().startswith("javascript:"):
            findings.append(("css_javascript", target))
            return "none"
        if remove_uris and _is_remote(target):
            findings.append(("css_remote_url", target))
            return "none"
        return m.group(0)
    work = _RE_CSS_URL.sub(_url_r, work)

    return findings, (work if do_clean else text)


def _sanitize_markup(text: str, remove_uris: bool, do_clean: bool, is_svg: bool):
    """Return (findings, cleaned_markup) for an XHTML/HTML/SVG document.

    Detection mutates a throwaway parse tree the same way regardless of mode,
    so scanning and cleaning always agree on what is dangerous. The serialized
    result is only returned (and later written) when do_clean is set.
    """
    BeautifulSoup = _bs4()

    findings = []

    def rec(category, detail=""):
        findings.append((category, detail))

    soup = BeautifulSoup(text, "html.parser")

    # --- structural removals (query fresh per tag type to avoid stale refs) --
    for t in soup.find_all("script"):
        src = t.get("src", "")
        detail = f"src={src}" if src else (_oneline(t.get_text() or "") or "inline")
        rec("svg_script" if (is_svg or _within_svg(t)) else "script", detail)
        t.decompose()

    for name in ("iframe", "frame", "frameset", "object", "embed", "applet", "base"):
        for t in soup.find_all(name):
            ref = t.get("src") or t.get("data") or t.get("href") or ""
            rec("base_tag" if name == "base" else "embedded_object",
                f"<{name}> {ref}".strip())
            t.decompose()

    for t in soup.find_all("meta"):
        if (t.get("http-equiv") or "").lower() == "refresh":
            rec("meta_refresh", t.get("content", ""))
            t.decompose()

    for t in soup.find_all("link"):
        rel = t.get("rel", "")
        rel = " ".join(rel) if isinstance(rel, list) else str(rel)
        rel = rel.lower()
        href = t.get("href", "")
        if "import" in rel:
            rec("html_import", href)
            t.decompose()
        elif "stylesheet" in rel and _is_remote(href) and remove_uris:
            rec("remote_resource", f"<link> {href}")
            t.decompose()

    for name in EPUB_CONTROL_TAGS:
        for t in soup.find_all(name):
            rec("form_control", f"<{name}>")
            t.decompose()

    # --- attribute-level cleaning on everything that remains ---------------
    for tag in soup.find_all(True):
        if getattr(tag, "decomposed", False):
            continue
        tag_name = (tag.name or "").lower()

        # event handlers (onload, onclick, onerror, ...)
        for attr in list(tag.attrs):
            if attr.lower().startswith("on"):
                rec("event_handler", f"<{tag_name}> {attr}")
                del tag[attr]

        # url-bearing attributes
        removed = False
        for attr in list(tag.attrs):
            if attr.lower() not in EPUB_URL_ATTRS:
                continue
            val = tag.get(attr)
            val = " ".join(val) if isinstance(val, list) else val
            if not isinstance(val, str):
                continue
            if attr.lower() == "srcset":
                if remove_uris and ("http" in val.lower() or "//" in val):
                    rec("remote_resource", f"<{tag_name} srcset>")
                    tag.decompose()
                    removed = True
                    break
                continue
            if _is_js_uri(val):
                rec("javascript_uri", f"<{tag_name} {attr}>")
                del tag[attr]
            elif _is_dangerous_data_uri(val):
                rec("data_uri", f"<{tag_name} {attr}> {_oneline(val)}")
                del tag[attr]
            elif remove_uris and _is_remote(val):
                if tag_name in ("a", "area"):
                    rec("external_link", val)
                    del tag[attr]
                else:
                    rec("remote_resource", f"<{tag_name}> {val}")
                    tag.decompose()
                    removed = True
                    break
        if removed:
            continue

        # inline style="" CSS
        if tag.has_attr("style"):
            cf, cleaned_style = _sanitize_css(tag["style"], remove_uris, True)
            for cat, det in cf:
                rec(cat, det)
            if cleaned_style.strip():
                tag["style"] = cleaned_style
            else:
                del tag["style"]

    # --- <style> element bodies -------------------------------------------
    for st in soup.find_all("style"):
        if getattr(st, "decomposed", False):
            continue
        css = st.string if st.string is not None else st.get_text()
        cf, cleaned = _sanitize_css(css or "", remove_uris, True)
        for cat, det in cf:
            rec(cat, det)
        if css is not None:
            st.string = cleaned

    cleaned_text = _ensure_xml_decl(text, str(soup))
    return findings, (cleaned_text if do_clean else text)


_JS_MEDIA_TYPES = {
    "application/javascript", "text/javascript", "application/x-javascript",
    "application/ecmascript", "text/ecmascript", "module",
}
_MARKUP_MEDIA_TYPES = {
    "application/xhtml+xml", "text/html", "image/svg+xml",
    "application/x-dtbncx+xml",
}
_MARKUP_EXT = {".xhtml", ".html", ".htm", ".svg", ".ncx"}
_CSS_EXT = {".css"}
_DROP_EXT = {".js", ".mjs", ".swf", ".vbs", ".wsf", ".jar", ".class",
             ".exe", ".dll", ".scr", ".bat", ".cmd"}


def _find_opf_path(zf: zipfile.ZipFile):
    try:
        BeautifulSoup = _bs4()
        soup = BeautifulSoup(zf.read("META-INF/container.xml"), "html.parser")
        rf = soup.find("rootfile")
        if rf and rf.get("full-path"):
            return rf["full-path"]
    except Exception:
        pass
    for n in zf.namelist():
        if n.lower().endswith(".opf"):
            return n
    return None


def _resolve(opf_dir: str, href: str) -> str:
    href = href.split("#")[0]
    joined = posixpath.join(opf_dir, href) if opf_dir else href
    return posixpath.normpath(joined)


def _epub_core(in_path: Path, out_path, remove_uris: bool, do_clean: bool):
    """Shared scan/clean engine. Returns (findings, actions_counter)."""
    try:
        BeautifulSoup = _bs4()
    except ImportError:
        raise RuntimeError("EPUB support needs beautifulsoup4 (pip install beautifulsoup4)")

    findings = []
    actions = Counter()

    try:
        zin = zipfile.ZipFile(in_path)
    except zipfile.BadZipFile:
        raise RuntimeError("not a valid EPUB (the file is not a readable ZIP)")

    with zin:
        names = zin.namelist()
        opf_path = _find_opf_path(zin)
        opf_dir = posixpath.dirname(opf_path) if opf_path else ""

        # Map each resource to its declared media type (more reliable than ext).
        media = {}
        if opf_path and opf_path in names:
            try:
                osoup = BeautifulSoup(zin.read(opf_path), "html.parser")
                for it in osoup.find_all("item"):
                    href = it.get("href")
                    if href:
                        media[_resolve(opf_dir, href)] = (it.get("media-type") or "").lower()
            except Exception:
                pass

        # Decide which standalone files to drop entirely.
        dropped = set()
        for n in names:
            if n == "mimetype":
                continue
            ext = posixpath.splitext(n)[1].lower()
            mt = media.get(n, "")
            is_js = ("javascript" in mt or "ecmascript" in mt
                     or ext in {".js", ".mjs"})
            if is_js or ext in _DROP_EXT:
                dropped.add(n)
                findings.append({
                    "location": n,
                    "category": "javascript_file" if is_js else "disallowed_file",
                    "detail": mt or ext or "?",
                })

        # Sanitize markup and CSS resources.
        cleaned_files = {}
        for n in names:
            if n == "mimetype" or n in dropped:
                continue
            ext = posixpath.splitext(n)[1].lower()
            mt = media.get(n, "")
            is_markup = ext in _MARKUP_EXT or mt in _MARKUP_MEDIA_TYPES
            is_css = ext in _CSS_EXT or mt == "text/css"
            if not (is_markup or is_css):
                continue
            text = zin.read(n).decode("utf-8", "replace")
            if is_css:
                file_findings, cleaned = _sanitize_css(text, remove_uris, do_clean)
            else:
                file_findings, cleaned = _sanitize_markup(
                    text, remove_uris, do_clean,
                    is_svg=(ext == ".svg" or mt == "image/svg+xml"))
            for cat, det in file_findings:
                findings.append({"location": n, "category": cat, "detail": det})
            if do_clean and cleaned != text:
                cleaned_files[n] = cleaned.encode("utf-8")

        if not do_clean:
            return findings, actions

        # Update the OPF: drop pruned items + clear scripted properties.
        if opf_path and opf_path in names and opf_path not in dropped:
            osoup = BeautifulSoup(zin.read(opf_path), "html.parser")
            removed_ids = set()
            for it in list(osoup.find_all("item")):
                href = it.get("href")
                if href and _resolve(opf_dir, href) in dropped:
                    if it.get("id"):
                        removed_ids.add(it["id"])
                    it.decompose()
                    actions["manifest_items_pruned"] += 1
                    continue
                props = it.get("properties")
                if props:
                    toks = props.split()
                    kept = [t for t in toks
                            if t != "scripted"
                            and not (remove_uris and t == "remote-resources")]
                    if kept != toks:
                        if kept:
                            it["properties"] = " ".join(kept)
                        else:
                            del it["properties"]
                        actions["scripted_properties_cleared"] += 1
            for ir in list(osoup.find_all("itemref")):
                if ir.get("idref") in removed_ids:
                    ir.decompose()
                    actions["spine_refs_pruned"] += 1
            opf_out = _ensure_xml_decl(zin.read(opf_path).decode("utf-8", "replace"),
                                       str(osoup))
            cleaned_files[opf_path] = opf_out.encode("utf-8")

        # Repackage. The mimetype entry must come first and be stored.
        with zipfile.ZipFile(out_path, "w") as zout:
            zout.writestr(zipfile.ZipInfo("mimetype"), "application/epub+zip",
                          compress_type=zipfile.ZIP_STORED)
            for n in names:
                if n == "mimetype" or n in dropped:
                    continue
                data = cleaned_files.get(n)
                if data is None:
                    data = zin.read(n)
                zout.writestr(n, data, compress_type=zipfile.ZIP_DEFLATED)

    # Fold per-resource findings into the actions tally.
    for f in findings:
        actions[f["category"]] += 1
    return findings, actions


def scan_epub(path: Path, remove_uris: bool = False) -> list:
    findings, _ = _epub_core(path, None, remove_uris, do_clean=False)
    return findings


def sanitize_epub(inp: Path, out: Path, remove_uris: bool) -> dict:
    _, actions = _epub_core(inp, out, remove_uris, do_clean=True)
    return dict(actions)


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

def detect_format(path: Path) -> str:
    """Return 'pdf', 'epub', or 'unknown' from content (falling back to ext)."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
    except OSError:
        head = b""
    if head.startswith(b"%PDF"):
        return "pdf"
    if head[:2] == b"PK":
        try:
            with zipfile.ZipFile(path) as z:
                names = z.namelist()
                if "mimetype" in names:
                    mt = z.read("mimetype").decode("ascii", "replace").strip()
                    if mt == "application/epub+zip":
                        return "epub"
                if "META-INF/container.xml" in names or any(
                        n.lower().endswith(".opf") for n in names):
                    return "epub"
        except zipfile.BadZipFile:
            pass
    ext = path.suffix.lower()
    if ext == ".pdf":
        return "pdf"
    if ext == ".epub":
        return "epub"
    return "unknown"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Sanitize a PDF or EPUB from an untrusted source.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "The input type (PDF or EPUB) is detected automatically.\n\n"
            "Examples:\n"
            "  sanitize_pdf.py untrusted.pdf clean.pdf\n"
            "  sanitize_pdf.py untrusted.pdf clean.pdf --mode rasterize --dpi 200\n"
            "  sanitize_pdf.py untrusted.epub clean.epub\n"
            "  sanitize_pdf.py untrusted.epub clean.epub --remove-uris\n"
            "  sanitize_pdf.py suspicious.pdf --report-only\n"
        ),
    )
    p.add_argument("input", type=Path, help="PDF or EPUB to sanitize")
    p.add_argument("output", type=Path, nargs="?",
                   help="where to write the clean file (omit with --report-only)")
    p.add_argument("--mode", choices=("structural", "rasterize"),
                   default="structural",
                   help="PDF only: structural keeps text (default); rasterize is strongest")
    p.add_argument("--dpi", type=int, default=150,
                   help="render resolution for PDF --mode rasterize (default 150)")
    p.add_argument("--remove-uris", action="store_true",
                   help="also strip external links and remote resource references "
                        "(PDF link actions; EPUB http(s) links, images, fonts, @import)")
    p.add_argument("--keep-metadata", action="store_true",
                   help="PDF only: keep document info / XMP metadata (stripped by default)")
    p.add_argument("--force", action="store_true",
                   help="overwrite the output file if it already exists")
    p.add_argument("--findings-json", type=Path, metavar="PATH",
                   help="write a complete record of everything found/removed "
                        "(full payloads, untruncated) to a JSON file")
    p.add_argument("--report-only", action="store_true",
                   help="only scan and report; write nothing (implies --verbose)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="list every finding with its location, type, and payload")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    inp: Path = args.input

    if not inp.is_file():
        print(f"error: input not found: {inp}", file=sys.stderr)
        return 2

    fmt = detect_format(inp)
    if fmt not in ("pdf", "epub"):
        print(f"error: unsupported file type for {inp.name} "
              "(expected a PDF or EPUB)", file=sys.stderr)
        return 2

    settings = {
        "mode": ("epub" if fmt == "epub" else args.mode),
        "dpi": (args.dpi if (fmt == "pdf" and args.mode == "rasterize") else None),
        "remove_uris": bool(args.remove_uris),
        "keep_metadata": bool(args.keep_metadata),
    }

    def scanner(p: Path):
        if fmt == "epub":
            return scan_epub(p, args.remove_uris)
        return scan(p, remove_uris=args.remove_uris)

    verbose = args.verbose or args.report_only
    try:
        before = scanner(inp)
    except Exception as exc:  # malformed/unreadable input: no traceback noise
        print(f"error: could not read {inp.name}: {exc}", file=sys.stderr)
        return 1
    print_report(f"Scan of {inp.name}  [{fmt}]", before, verbose=verbose)

    if args.report_only:
        if args.findings_json:
            write_findings_json(args.findings_json,
                                build_findings_record(inp, fmt, settings, before))
            print(f"\nFindings record written to: {args.findings_json}")
        return 0

    if args.output is None:
        print("error: output path required (or use --report-only)",
              file=sys.stderr)
        return 2
    out: Path = args.output

    if out.resolve() == inp.resolve():
        print("error: refusing to overwrite the input in place; choose a "
              "different output path", file=sys.stderr)
        return 2
    if out.exists() and not args.force:
        print(f"error: output exists: {out} (use --force to overwrite)",
              file=sys.stderr)
        return 2

    if fmt == "epub" and args.mode == "rasterize":
        print("note: --mode rasterize does not apply to EPUB; performing "
              "content sanitization instead.")

    strip_metadata = not args.keep_metadata
    mode_label = "epub" if fmt == "epub" else args.mode
    try:
        if fmt == "epub":
            report = sanitize_epub(inp, out, args.remove_uris)
        elif args.mode == "rasterize":
            report = sanitize_rasterize(inp, out, args.dpi, strip_metadata)
        else:
            report = sanitize_structural(inp, out, args.remove_uris,
                                         strip_metadata)
    except Exception as exc:  # surface a clean error, no traceback noise
        print(f"error: sanitization failed: {exc}", file=sys.stderr)
        return 1

    title = f"Actions taken ({mode_label} mode)"
    print(f"\n{title}")
    print("-" * len(title))
    any_action = False
    for k in sorted(report):
        if report[k]:
            any_action = True
            print(f"  {k.replace('_', ' '):32s}: {report[k]}")
    if not any_action:
        print("  (input already appeared clean; rewrote a normalized copy)")

    # Verify the result and confirm nothing risky remains.
    try:
        after = scanner(out)
    except Exception as exc:
        print(f"error: wrote {out.name} but could not re-scan it to verify: "
              f"{exc}", file=sys.stderr)
        return 1
    print_report(f"Scan of {out.name} (after)", after, verbose=verbose)

    if args.findings_json:
        write_findings_json(args.findings_json,
                            build_findings_record(inp, fmt, settings, before,
                                                  after=after, actions=report))
        print(f"Findings record written to: {args.findings_json}")

    if len(after):
        msg = "\nWARNING: some elements were still detected after sanitization."
        if fmt == "pdf":
            msg += " Review the file or use --mode rasterize."
        else:
            msg += " Review the file."
        print(msg, file=sys.stderr)
        return 1

    print(f"\nDone. Clean file written to: {out}")
    if fmt == "pdf":
        print("Tip: for the strongest guarantee on a very hostile file, "
              "re-run with --mode rasterize.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
