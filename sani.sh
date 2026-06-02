#!/usr/bin/env bash
#
# sani.sh - PARALLEL batch-sanitizer for a directory tree of PDFs and EPUBs,
# using sanitize_pdf.py. Files are processed concurrently (one worker process
# per file, JOBS at a time); within a file the passes run in sequence.
#
# For each input it writes, into a SEPARATE output tree mirroring subdirs:
#   <name>.report.txt      detailed inventory of the ORIGINAL (for review)
#   <name>.findings.json   complete machine-readable record of what was removed
#                          (full, untruncated payloads) - for records/audit
#   <name>.structural.pdf  sanitized PDF, text preserved             [PDF]
#   <name>.rasterize.pdf   sanitized PDF, image-only at $DPI dpi      [PDF]
#   <name>.sanitized.epub  sanitized EPUB                             [EPUB]
#   <name>.log             per-file pass log (kept only if a pass failed)
# plus _results.tsv (status of every pass) in OUTPUT_DIR.
#
# EPUBs get ONE sanitized copy (rasterize doesn't apply to EPUB).
# Existing outputs are skipped (resumable); set FORCE=1 to overwrite.

set -u

usage() {
cat <<'EOF'
Usage: ./sani.sh [INPUT_DIR] [OUTPUT_DIR]

Recursively sanitize every PDF and EPUB under INPUT_DIR, processing files in
parallel. For each file it writes (into OUTPUT_DIR, mirroring subdirectories):
  <name>.report.txt      detailed inventory of the original (for review)
  <name>.structural.pdf  sanitized PDF, text preserved             [PDF]
  <name>.rasterize.pdf   sanitized PDF, image-only at the set DPI   [PDF]
  <name>.sanitized.epub  sanitized EPUB                             [EPUB]
A _results.tsv summary is written in OUTPUT_DIR; per-file .log kept on failure.

Defaults: INPUT_DIR=.   OUTPUT_DIR=INPUT_DIR/_sanitized

Environment overrides:
  JOBS=<nproc>             files processed in parallel
  TOOL=./sanitize_pdf.py   sanitizer path (yours is sanitize_pdf-3.py)
  PYTHON=python3
  DPI=300                  rasterize resolution (PDF only)
  FORCE=0                  1 = overwrite existing outputs (else skipped)
  REMOVE_URIS=0            1 = also strip links / remote resources

rasterize at high DPI is memory-heavy (~100+ MB/page while rendering); peak RAM
scales with JOBS. Lower JOBS if you see swapping or OOM.
EOF
}

case "${1:-}" in -h|--help) usage; exit 0 ;; esac

# ---- configuration shared by main and worker modes (inherited via env) ----
TOOL="${TOOL:-./sanitize_pdf.py}"
PYTHON="${PYTHON:-python3}"
DPI="${DPI:-300}"
FORCE="${FORCE:-0}"
REMOVE_URIS="${REMOVE_URIS:-0}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

COMMON_ARGS=()
[[ "$REMOVE_URIS" == "1" ]] && COMMON_ARGS+=(--remove-uris)
FORCE_ARG=()
[[ "$FORCE" == "1" ]] && FORCE_ARG+=(--force)

# Append one status row to the shared results file (atomic: one short line).
record() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$RESULTS"; }

# Run one sanitize pass in a subshell; logs to the per-file log, records the
# status, and echoes a compact "label=ok|skip|FAIL" token for the caller.
one_pass() {  # <plog> <label> <src> <dst> <rel> <tool-args...>
  local plog="$1" label="$2" src="$3" dst="$4" rel="$5"; shift 5
  if [[ "$FORCE" != "1" && -s "$dst" ]]; then
    record skip "$label" "$rel"; printf '%s=skip' "$label"; return 0
  fi
  echo "----- $label : $src -> $dst -----" >> "$plog"
  if "$PYTHON" "$TOOL" "$@" \
        ${COMMON_ARGS[@]+"${COMMON_ARGS[@]}"} \
        ${FORCE_ARG[@]+"${FORCE_ARG[@]}"} \
        "$src" "$dst" >> "$plog" 2>&1; then
    record ok "$label" "$rel"; printf '%s=ok' "$label"
  else
    local ec=$?
    record fail "$label" "$rel"; printf '%s=FAIL(%d)' "$label" "$ec"
  fi
}

# Process exactly one input file - this is the parallel unit of work.
process_file() {
  local file="$1"
  # Never process anything already inside the output tree.
  local file_real; file_real="$(realpath -- "$file" 2>/dev/null || echo "$file")"
  case "$file_real" in "$OUTDIR_REAL"/*) return 0 ;; esac

  local rel reldir base stem ext_lc destdir
  rel="${file#"$INPUT_DIR"/}"
  reldir="$(dirname -- "$rel")"
  base="$(basename -- "$rel")"
  stem="${base%.*}"
  ext_lc="${base##*.}"; ext_lc="${ext_lc,,}"
  if [[ "$reldir" == "." ]]; then destdir="$OUTPUT_DIR"; else destdir="$OUTPUT_DIR/$reldir"; fi
  mkdir -p "$destdir"

  local plog="$destdir/$stem.log"
  : > "$plog"
  local line="[$rel]"

  # 1) review report + machine-readable findings record from the ORIGINAL
  #    (--report-only implies verbose detail; the JSON holds full payloads).
  local report="$destdir/$stem.report.txt"
  if [[ "$FORCE" == "1" || ! -s "$report" ]]; then
    if "$PYTHON" "$TOOL" --report-only \
          --findings-json "$destdir/$stem.findings.json" \
          ${COMMON_ARGS[@]+"${COMMON_ARGS[@]}"} "$file" > "$report" 2>&1; then
      record ok report "$rel"; line+=" report=ok"
    else
      record fail report "$rel"; line+=" report=FAIL"
    fi
  else
    record skip report "$rel"; line+=" report=skip"
  fi

  # 2) sanitized output(s).
  case "$ext_lc" in
    pdf)
      line+=" $(one_pass "$plog" structural "$file" "$destdir/$stem.structural.pdf" "$rel" --mode structural)"
      line+=" $(one_pass "$plog" rasterize  "$file" "$destdir/$stem.rasterize.pdf"  "$rel" --mode rasterize --dpi "$DPI")"
      ;;
    epub)
      line+=" $(one_pass "$plog" sanitized  "$file" "$destdir/$stem.sanitized.epub" "$rel" --mode structural)"
      ;;
    *)
      line+=" (unsupported .$ext_lc)"; record skip unsupported "$rel"
      ;;
  esac

  # Keep the per-file log only if something failed.
  [[ "$line" == *FAIL* ]] || rm -f "$plog"
  echo "$line"
}

# ---- WORKER MODE: invoked by xargs as `sani.sh --worker <file>` -----------
if [[ "${1:-}" == "--worker" ]]; then
  process_file "$2"
  exit 0
fi

# ---- MAIN MODE ------------------------------------------------------------
INPUT_DIR="${1:-.}"; INPUT_DIR="${INPUT_DIR%/}"
OUTPUT_DIR="${2:-$INPUT_DIR/_sanitized}"

if [[ ! -f "$TOOL" ]]; then
  echo "error: sanitizer not found at '$TOOL' (set TOOL=/path/to/sanitize_pdf.py)" >&2
  exit 2
fi
[[ -d "$INPUT_DIR" ]] || { echo "error: input dir not found: $INPUT_DIR" >&2; exit 2; }
command -v "$PYTHON" >/dev/null 2>&1 || { echo "error: '$PYTHON' not found" >&2; exit 2; }
command -v xargs     >/dev/null 2>&1 || { echo "error: xargs not found" >&2; exit 2; }
command -v qpdf      >/dev/null 2>&1 || echo "warning: qpdf not found - structural mode will fail" >&2
command -v pdftoppm  >/dev/null 2>&1 || echo "warning: pdftoppm not found - rasterize mode will fail" >&2

mkdir -p "$OUTPUT_DIR"
OUTDIR_REAL="$(cd "$OUTPUT_DIR" && pwd)"
RESULTS="$OUTPUT_DIR/_results.tsv"
: > "$RESULTS"
SELF="$(realpath -- "$0")"

export TOOL PYTHON DPI FORCE REMOVE_URIS INPUT_DIR OUTPUT_DIR OUTDIR_REAL RESULTS

echo "Sanitizing '$INPUT_DIR' -> '$OUTPUT_DIR'   jobs=$JOBS dpi=$DPI force=$FORCE remove-uris=$REMOVE_URIS"
echo

find "$INPUT_DIR" \
  -type d \( -path "$OUTPUT_DIR" -o -path "$OUTPUT_DIR/*" \) -prune -o \
  -type f \( -iname '*.pdf' -o -iname '*.epub' \) -print0 |
xargs -0 -r -P "$JOBS" -n1 bash "$SELF" --worker

echo
echo "=============================================================="
awk -F'\t' '{c[$1]++} END{printf "Done.  ok=%d  skipped=%d  failed=%d\n", c["ok"], c["skip"], c["fail"]}' "$RESULTS"
fails="$(awk -F'\t' '$1=="fail"{print "  - "$3" ["$2"]"}' "$RESULTS")"
[[ -n "$fails" ]] && { echo "Failures:"; echo "$fails"; }
echo "Outputs + _results.tsv under: $OUTPUT_DIR"
awk -F'\t' '$1=="fail"{c=1} END{exit c+0}' "$RESULTS"
