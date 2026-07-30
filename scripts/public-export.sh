#!/usr/bin/env bash
# Garmr deterministic public export.
#
# Produces a sanitized public tree from a clean private release commit. It NEVER
# copies .git history, secret files, or internal content, and it verifies the
# result before finalizing. Run from the PRIVATE repo root.
#
#   scripts/public-export.sh [--out DIR] [--ref GITREF] [--dry-run] [--snapshot]
#
#   --out DIR     destination public tree (default: ../garmr-public)
#   --ref REF     git ref/commit to export (default: HEAD)
#   --dry-run     print what would happen; write only to a temp staging dir
#   --snapshot    allow a dirty working tree (reviewed-snapshot mode); default
#                 is fail-closed on any uncommitted change
#
# Fail-closed by design: any error aborts without touching --out.
set -euo pipefail

OUT="../garmr-public"; REF="HEAD"; DRY=0; SNAPSHOT=0
while [ $# -gt 0 ]; do case "$1" in
  --out) OUT="$2"; shift 2;;
  --ref) REF="$2"; shift 2;;
  --dry-run) DRY=1; shift;;
  --snapshot) SNAPSHOT=1; shift;;
  *) echo "unknown arg: $1" >&2; exit 2;;
esac; done

ROOT="$(git rev-parse --show-toplevel)"; cd "$ROOT"
HERE="$(cd "$(dirname "$0")" && pwd)"
ALLOW="$HERE/../public-export.allowlist"
DENY="$HERE/../public-export.denylist"
[ -f "$ALLOW" ] && [ -f "$DENY" ] || { echo "missing allowlist/denylist next to repo root" >&2; exit 1; }

# 1) refuse a dirty tree unless explicitly snapshotting a reviewed state
if [ "$SNAPSHOT" -eq 0 ] && [ -n "$(git status --porcelain)" ]; then
  echo "ERROR: working tree is dirty. Commit/clean it, or pass --snapshot for a reviewed snapshot." >&2
  exit 1
fi
SRC_COMMIT="$(git rev-parse "$REF")"
echo "exporting $REF ($SRC_COMMIT) -> $OUT (dry-run=$DRY snapshot=$SNAPSHOT)"

# 2) stage into a temp dir (never write to $OUT until verified)
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/garmr-export.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
# tracked files only: git archive carries NO .git, NO ignored build artifacts
git archive "$REF" | tar -x -C "$STAGE"

# 3) apply the denylist (dirs, path-prefixes; PATTERN: lines are for verify only)
while IFS= read -r line; do
  case "$line" in ''|\#*|PATTERN:*) continue;; esac
  # expand globs safely, delete only inside $STAGE
  ( cd "$STAGE" && rm -rf $line ) 2>/dev/null || true
done < "$DENY"

# 4) enforce the allowlist: keep only allowed top-level paths (+ generated legal
#    files, which are added by the release manager and live outside the private tree)
KEEP="$(grep -vE '^\s*#|^\s*$' "$ALLOW")"
( cd "$STAGE"
  for entry in *; do
    match=0
    while IFS= read -r a; do
      top="${a%%/*}"; [ "$entry" = "$top" ] && { match=1; break; }
    done <<<"$KEEP"
    [ "$match" -eq 0 ] && rm -rf "$entry"
  done
  # dotfiles in allowlist
  for a in .github .gitignore; do grep -qxF "$a" <<<"$KEEP" || rm -rf "$a"; done
)

# 5) belt-and-suspenders: there must be no .git anywhere
find "$STAGE" -name .git -prune -exec rm -rf {} + 2>/dev/null || true

# 6) manifest + digests
( cd "$STAGE" && find . -type f | LC_ALL=C sort | sed 's|^\./||' > .export-manifest.txt )
( cd "$STAGE" && while IFS= read -r f; do sha256sum "$f"; done < .export-manifest.txt > .export-digests.sha256 )
echo "staged $(wc -l < "$STAGE/.export-manifest.txt") files"

# 7) verify BEFORE replacing $OUT
if [ -x "$HERE/public-verify.sh" ]; then
  "$HERE/public-verify.sh" "$STAGE" || { echo "VERIFY FAILED — not writing $OUT" >&2; exit 1; }
fi

echo "SOURCE_COMMIT=$SRC_COMMIT" > "$STAGE/.export-provenance"
echo "EXPORTED_REF=$REF" >> "$STAGE/.export-provenance"

if [ "$DRY" -eq 1 ]; then
  echo "[dry-run] staged at $STAGE (not finalized). manifest/digests inside."
  trap - EXIT   # keep the staging dir for inspection
  echo "$STAGE"
  exit 0
fi

# 8) finalize: rsync into $OUT WITHOUT deleting unrelated paths (e.g. an existing
#    .git in $OUT for the public repo). --delete only within tracked subpaths.
mkdir -p "$OUT"
rsync -a --exclude '.git' --delete-excluded "$STAGE"/ "$OUT"/
echo "export complete -> $OUT (source $SRC_COMMIT)"
echo "NOTE: review 'git diff' in $OUT before committing/tagging the public release."
