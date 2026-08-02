#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Vetra Automation AB
# SPDX-License-Identifier: AGPL-3.0-only
#
# Reject unpinned external GitHub Actions.
#
# A `uses: owner/repo@v4` reference resolves a MUTABLE tag at run time: whoever
# controls that tag controls code running in our CI, with our workflow token.
# Every external action must therefore be pinned to a full 40-character commit
# SHA. Local actions (`uses: ./.github/actions/...`) and docker refs are exempt.
#
# A trailing `# v1.2.3` comment beside the SHA is required so a human can read
# the workflow without resolving hashes by hand.
#
# Run locally:  bash scripts/check-actions-pinned.sh

set -uo pipefail

cd "$(dirname "$0")/.."

fails=0
found=0

# Collect every `uses:` value from every workflow and composite action.
files=$(find .github -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null | sort)
if [ -z "$files" ]; then
  echo "no workflow files found under .github/ — nothing to check"
  exit 0
fi

for f in $files; do
  # Strip comments only AFTER capturing the line, so we can check for the
  # readable version comment separately.
  while IFS= read -r line; do
    # `uses:` value, up to whitespace or comment.
    ref=$(printf '%s' "$line" | sed -E 's/^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*//; s/[[:space:]]*#.*$//; s/^["'\'']//; s/["'\'']$//')
    [ -z "$ref" ] && continue
    found=$((found + 1))

    case "$ref" in
      ./*|.\\*)
        printf '  ok        local action        %s (%s)\n' "$ref" "$f"
        continue
        ;;
      docker://*)
        # A docker ref must be digest-pinned, not a mutable tag.
        case "$ref" in
          *@sha256:*) printf '  ok        docker digest       %s (%s)\n' "$ref" "$f" ;;
          *) printf '  FAIL      mutable docker tag  %s (%s)\n' "$ref" "$f"; fails=$((fails + 1)) ;;
        esac
        continue
        ;;
    esac

    # External action: everything after the last '@' must be a 40-hex SHA.
    sha="${ref##*@}"
    name="${ref%@*}"
    if [ "$sha" = "$ref" ]; then
      printf '  FAIL      no version at all   %s (%s)\n' "$ref" "$f"
      fails=$((fails + 1))
      continue
    fi
    if ! printf '%s' "$sha" | grep -qE '^[0-9a-f]{40}$'; then
      printf '  FAIL      not SHA-pinned      %s (%s)\n' "$ref" "$f"
      printf '            pin it: %s@<40-char-commit-sha> # %s\n' "$name" "$sha"
      fails=$((fails + 1))
      continue
    fi
    # Require the readable version comment beside the pin.
    if printf '%s' "$line" | grep -qE '#[[:space:]]*\S'; then
      printf '  ok        SHA-pinned          %s (%s)\n' "$name" "$f"
    else
      printf '  FAIL      SHA-pinned but no version comment: %s (%s)\n' "$ref" "$f"
      printf '            add a trailing comment, e.g. "# v4.2.1"\n'
      fails=$((fails + 1))
    fi
  done < <(grep -nE '^[[:space:]]*-?[[:space:]]*uses:' "$f" | cut -d: -f2-)
done

echo "---------------------------------------------------------------"
if [ "$fails" -eq 0 ]; then
  echo "actions-pinned: $found action reference(s), all pinned"
  exit 0
fi
echo "actions-pinned: $fails of $found action reference(s) NOT pinned"
exit 1
