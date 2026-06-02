# PDF and EPUB Sanitizer

A defensive command line tool that strips active and executable content from untrusted PDF and EPUB files, so they can be opened safely. It never runs the input. It only reads the file and writes a clean copy, then verifies that nothing risky survived.

## Why

Documents from unknown sources can carry more than text. A PDF can run JavaScript the moment it opens, launch an external program, submit data to a remote server, or hide an executable as an attachment. An EPUB is web content underneath (XHTML, CSS, and SVG), and EPUB3 allows JavaScript, so it inherits the browser attack surface. This tool removes that machinery and hands back a copy that still looks and reads the same.

## Features

* One tool for both PDF and EPUB. The format is detected from the file contents, not the extension.
* Two PDF strategies. A structural pass keeps selectable text. A raster pass flattens every page to an image for the strongest possible guarantee.
* EPUB cleaning that keeps the readable book while removing scripts, dangerous markup and CSS, and standalone script files, then repackages a valid archive.
* A detailed, itemized report of exactly what was found, including the full payloads.
* A machine readable JSON record for audit and record keeping.
* A parallel batch runner for whole directory trees, with resume support.
* A self contained test suite that needs no external test framework.

## Quick start

```bash
# install dependencies (Debian or Ubuntu)
sudo apt-get install poppler-utils qpdf python3-pikepdf python3-img2pdf python3-pil python3-bs4

# clean a single PDF, keeping selectable text
python3 sanitize_pdf.py untrusted.pdf clean.pdf

# clean an EPUB
python3 sanitize_pdf.py untrusted.epub clean.epub

# just inspect, write nothing
python3 sanitize_pdf.py suspicious.pdf --report-only
```

## How it works

### PDF, structural mode (default)

The tool strips every active object with pikepdf: document JavaScript, automatic and event actions, launch and form submission actions, embedded files, XFA forms, and multimedia annotations. It then flattens interactive form fields and annotations into static page content with qpdf. The text stays selectable and the file stays small.

### PDF, raster mode

The tool renders every page to a PNG with poppler (pdftoppm) at a resolution you choose, rebuilds a PDF from those images with img2pdf, and normalizes the result with pikepdf. Because the pages become flat pictures, nothing executable, scriptable, or embedded can survive. The cost is that text is no longer selectable and the file is larger. Use this for the most hostile inputs.

### EPUB

An EPUB is a ZIP of XHTML, CSS, and SVG plus a manifest. The tool unpacks the archive, sanitizes each markup and style resource with BeautifulSoup using the pure Python html.parser, drops standalone script files, prunes the manifest, and repackages the archive with the required uncompressed mimetype entry first. Local text, images, and styles are preserved, and only the active content is removed. Note that raster mode does not apply to EPUB, so an EPUB always produces one sanitized copy.

## What gets removed

### From a PDF

* Document JavaScript and any leftover JavaScript keys.
* Automatic actions that fire on open (OpenAction) and event actions such as on open, on close, on print, and page or mouse events.
* Launch actions that start an external program, plus form submission, data import, remote and embedded navigation actions, and rendition, rich media, movie, and sound actions.
* Embedded files and file attachments, a common malware carrier.
* Dynamic XFA forms.
* Multimedia and 3D annotations.
* Interactive form fields and annotations, which are flattened into the page.

### From an EPUB

* `<script>` elements and standalone `.js` files, plus other active file types.
* Inline event handlers such as `onload`, `onclick`, and `onerror`.
* `javascript:` URIs and dangerous `data:` URIs.
* `<iframe>`, `<frame>`, `<object>`, `<embed>`, `<applet>`, and `<base>` tags.
* Interactive form controls.
* Meta refresh redirects and HTML import links.
* Scripted SVG, including scripts, event handlers, and javascript links.
* Dangerous CSS: `expression(...)`, `behavior`, `-moz-binding`, `url(javascript:...)`, and remote `@import`.
* With `--remove-uris`, external links and remote resources that would phone home, such as tracking pixels and remote fonts or stylesheets.

## Safety and design

* The tool never executes the input. PDFs are parsed and rewritten with qpdf, pikepdf, and poppler. EPUB markup is parsed with the pure Python html.parser, which never fetches anything over the network and never expands external XML entities.
* The scanner and the cleaners stay consistent. The set of findings before cleaning equals what gets removed, so a correct run reports nothing remaining afterward.
* The tool refuses to overwrite the input in place, and refuses to overwrite an existing output unless you pass `--force`.
* On a malformed or unreadable file the tool prints a short error and exits with a nonzero status, rather than a stack trace.

## Requirements

Core dependencies on Debian or Ubuntu:

```bash
sudo apt-get install poppler-utils qpdf python3-pikepdf python3-img2pdf python3-pil python3-bs4
```

What each provides:

* `poppler-utils`: the `pdftoppm` page renderer used by raster mode.
* `qpdf`: the command line program used by structural mode to flatten forms and annotations.
* `python3-pikepdf`: the pikepdf library, used by both PDF modes.
* `python3-img2pdf`: the img2pdf library that rebuilds a PDF from page images in raster mode.
* `python3-pil`: Pillow, the imaging backend that img2pdf relies on.
* `python3-bs4`: BeautifulSoup, used for EPUB sanitization.

Running the test suite also needs reportlab and pypdf:

```bash
pip3 install --break-system-packages reportlab pypdf
```

Tested with pikepdf 10.5, img2pdf 0.6, beautifulsoup4 4.14, Pillow 12, qpdf 11, reportlab 4.4, and pypdf 5.9 on Python 3.

## Usage

### Single file

```bash
# structural (default): clean copy that keeps selectable text
python3 sanitize_pdf.py untrusted.pdf clean.pdf

# raster: image only, strongest, choose a resolution
python3 sanitize_pdf.py untrusted.pdf clean.pdf --mode rasterize --dpi 300

# EPUB: one sanitized copy
python3 sanitize_pdf.py untrusted.epub clean.epub

# also cut external links and remote resources
python3 sanitize_pdf.py untrusted.epub clean.epub --remove-uris

# inspect only, write nothing
python3 sanitize_pdf.py suspicious.pdf --report-only

# write a complete record of what was removed
python3 sanitize_pdf.py untrusted.pdf clean.pdf --findings-json untrusted.findings.json
```

### Options

* `--mode {structural,rasterize}`: PDF only. `structural` keeps text and is the default. `rasterize` is the strongest.
* `--dpi N`: render resolution for `--mode rasterize`. Default is 150.
* `--remove-uris`: also strip external links and remote resource references.
* `--keep-metadata`: PDF only. Keep document info and XMP metadata, which is stripped by default.
* `--force`: overwrite the output file if it already exists.
* `--report-only`: scan and report only, writing no output. Implies verbose.
* `--findings-json PATH`: write a complete record of everything found and removed, with full payloads.
* `-v`, `--verbose`: list every finding with its location, type, and payload.

## Batch processing

`sani.sh` runs the sanitizer across a whole directory tree, processing files in parallel.

```bash
JOBS=8 DPI=300 TOOL=./sanitize_pdf.py ./sani.sh /path/to/folder
```

Settings, passed as environment variables:

* `JOBS`: how many files to process at once. Default is your CPU core count. `JOBS=1` runs sequentially.
* `TOOL`: path to the sanitizer. Default is `./sanitize_pdf.py`.
* `PYTHON`: the interpreter. Default is `python3`.
* `DPI`: raster resolution for PDFs. Default is 300.
* `FORCE`: set to 1 to overwrite existing outputs. Otherwise they are skipped.
* `REMOVE_URIS`: set to 1 to also strip links and remote resources.

For each input, it writes into a separate output tree that mirrors the input subdirectories:

* `<name>.report.txt`: a readable inventory of the original.
* `<name>.findings.json`: a complete machine readable record of what was removed.
* `<name>.structural.pdf` and `<name>.rasterize.pdf` for a PDF.
* `<name>.sanitized.epub` for an EPUB.
* `<name>.log`: kept only if a pass failed.

It also writes `_results.tsv`, one row per pass, summarizing the whole run.

Behavior worth knowing:

* The run is resumable. Existing outputs are skipped, so a large job can stop and restart.
* Only `.pdf` and `.epub` files are processed, and the script never reprocesses its own outputs.
* A single bad file is recorded and the run continues. The script exits nonzero if anything failed.

Watch memory as well as cores. Rasterizing at 300 DPI uses on the order of 100 MB of memory per page while a page renders, so peak memory is roughly `JOBS` times the size of one page. Lower `JOBS` if you see swapping.

## The findings record

The JSON written by `--findings-json`, and by the batch runner as `<name>.findings.json`, contains:

* `input`: the path, format, size, and a SHA256 of the original file.
* `settings`: the mode, DPI, and which stripping options were active.
* `summary`: the total found and a count for each category.
* `removed`: every finding with its location, category, and full payload, including complete script bodies, the offending CSS, launch targets, embedded file names, and URIs.
* `actions_taken` and `remaining_after_sanitize` on a real run, so the record states what was removed and confirms that nothing is left.

## Testing

```bash
python3 test_sanitize.py
```

The suite is self contained. It builds its own fixtures (clean and malicious PDFs and EPUBs, plus malformed and edge case inputs) in a temporary directory, exercises both the library functions and the command line interface, and exits nonzero if any check fails. It also runs under pytest if you have it installed. Coverage includes format detection, both PDF modes, EPUB cleaning with and without network stripping, the reporting detail, the JSON export, malformed input handling, and the command line safety guards.

## Project layout

* `sanitize_pdf.py`: the sanitizer, and the only file you need to clean documents.
* `sani.sh`: the parallel batch runner.
* `test_sanitize.py`: the test suite.
* `make_malicious_pdf.py` and `make_malicious_epub.py`: generators that build the test fixtures.

## Limitations

* EPUB markup is parsed and written back out with the pure Python html.parser. The output displays correctly in the lenient renderers that real readers use, but it is not guaranteed to pass strict EPUBCheck XHTML validation.
* The findings record stores removed code as text. It does not extract the raw bytes of embedded file attachments to disk.
* A rasterized PDF is image only, so its text is no longer selectable or searchable.

## Disclaimer

Sanitizing a file greatly lowers its risk, but no tool can promise perfection. Keep the original files isolated, treat them as untrusted, and prefer raster mode for the most dangerous inputs.

## License

MIT
