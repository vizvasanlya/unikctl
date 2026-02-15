#!/usr/bin/env bash
set -euo pipefail

# Applies branding patches in runtime source trees before build.
#
# Usage:
#   ./scripts/patch-runtime-banner.sh /path/to/runtime-source
#
# Optional:
#   BANNER_PATCH_FILE=path/to/custom.patch

SOURCE_DIR="${1:-}"
if [ -z "$SOURCE_DIR" ]; then
  echo "usage: $0 <runtime-source-dir>" >&2
  exit 1
fi

if [ ! -d "$SOURCE_DIR" ]; then
  echo "error: runtime source directory not found: $SOURCE_DIR" >&2
  exit 1
fi

if [ -n "${BANNER_PATCH_FILE:-}" ]; then
  if [ ! -f "$BANNER_PATCH_FILE" ]; then
    echo "error: BANNER_PATCH_FILE does not exist: $BANNER_PATCH_FILE" >&2
    exit 1
  fi
  git -C "$SOURCE_DIR" apply --whitespace=nowarn "$BANNER_PATCH_FILE"
fi

if command -v rg >/dev/null 2>&1; then
  mapfile -t files < <(rg -l --hidden --no-ignore-vcs -g '!.git/*' \
    'Powered by Unikraft|Unikraft Kiviuq|Unikraft' "$SOURCE_DIR" || true)
else
  mapfile -t files < <(grep -RIl --exclude-dir=.git \
    -E 'Powered by Unikraft|Unikraft Kiviuq|Unikraft' "$SOURCE_DIR" || true)
fi

if [ "${#files[@]}" -eq 0 ]; then
  echo "banner patch: no matching source strings found in $SOURCE_DIR"
  exit 0
fi

for file in "${files[@]}"; do
  # Keep "Unikctl " as 8 chars to safely patch fixed-size binary/text constants.
  perl -i -pe 's/Powered by Unikraft/Powered by Unikctl /g' "$file"
  perl -i -pe 's/Unikraft Kiviuq/Unikctl Kernel/g' "$file"
  perl -i -pe 's/\bUnikraft\b/Unikctl /g' "$file"
done

echo "banner patch: updated ${#files[@]} file(s)"
