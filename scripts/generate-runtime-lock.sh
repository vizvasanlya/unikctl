#!/usr/bin/env bash
set -euo pipefail

# Generates internal/runtimeutil/runtime-lock.json from registry image digests.
#
# Environment:
#   TARGET_PREFIX=ghcr.io/vizvasanlya/unikctl
#   RUNTIMES=base,nodejs,python,java,dotnet
#   TAG=latest
#   TAGS=latest,v0.2.0
#   LOCK_TAG=latest
#   OUTPUT=internal/runtimeutil/runtime-lock.json
#
# Requires:
#   docker buildx imagetools inspect

TARGET_PREFIX="${TARGET_PREFIX:-ghcr.io/vizvasanlya/unikctl}"
RUNTIMES_CSV="${RUNTIMES:-base,nodejs,python,java,dotnet}"
TAG="${TAG:-latest}"
TAGS_CSV="${TAGS:-}"
LOCK_TAG="${LOCK_TAG:-}"
OUTPUT="${OUTPUT:-internal/runtimeutil/runtime-lock.json}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: required command not found: $1" >&2
    exit 1
  }
}

need_cmd docker

if ! docker buildx version >/dev/null 2>&1; then
  echo "error: docker buildx is required" >&2
  exit 1
fi

IFS=',' read -r -a RUNTIMES_ARR <<<"${RUNTIMES_CSV}"

if [ -n "${LOCK_TAG}" ] && [[ "${LOCK_TAG}" == *,* ]]; then
  IFS=',' read -r -a LOCK_TAG_ARR <<<"${LOCK_TAG}"
  LOCK_TAG=""
  for t in "${LOCK_TAG_ARR[@]}"; do
    t="$(echo "$t" | xargs)"
    if [ -n "$t" ]; then
      LOCK_TAG="$t"
      break
    fi
  done
fi

if [ -n "${TAGS_CSV}" ] && [ -z "${LOCK_TAG}" ]; then
  IFS=',' read -r -a TAGS_ARR <<<"${TAGS_CSV}"
  for t in "${TAGS_ARR[@]}"; do
    t="$(echo "$t" | xargs)"
    if [ -n "$t" ]; then
      LOCK_TAG="$t"
      break
    fi
  done
fi

if [ -z "${LOCK_TAG}" ]; then
  LOCK_TAG="${TAG}"
fi

tmp="$(mktemp)"
cleanup() { rm -f "$tmp"; }
trap cleanup EXIT INT TERM

{
  echo "{"
  echo "  \"schema_version\": 1,"
  echo "  \"runtimes\": {"

  first_runtime=true
  for runtime in "${RUNTIMES_ARR[@]}"; do
    runtime="$(echo "$runtime" | xargs)"
    [ -n "$runtime" ] || continue

    ref="${TARGET_PREFIX}/${runtime}:${LOCK_TAG}"
    digest="$(docker buildx imagetools inspect "$ref" 2>/dev/null | awk '/^Digest:[[:space:]]+/ {print $2; exit}' || true)"

    if [ "$first_runtime" = true ]; then
      first_runtime=false
    else
      echo "    ,"
    fi

    printf '    "%s": {\n' "$runtime"
    printf '      "reference": "%s/%s",\n' "$TARGET_PREFIX" "$runtime"
    printf '      "tag": "%s",\n' "$LOCK_TAG"
    printf '      "digest": "%s"\n' "$digest"
    printf '    }'
  done

  echo
  echo "  }"
  echo "}"
} >"$tmp"

mkdir -p "$(dirname "$OUTPUT")"
mv "$tmp" "$OUTPUT"

echo "wrote runtime lock file: $OUTPUT"
