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
#   go

TARGET_PREFIX="${TARGET_PREFIX:-ghcr.io/vizvasanlya/unikctl}"
RUNTIMES_CSV="${RUNTIMES:-base,nodejs,python,java,dotnet}"
TAG="${TAG:-latest}"
TAGS_CSV="${TAGS:-}"
LOCK_TAG="${LOCK_TAG:-}"
OUTPUT="${OUTPUT:-internal/runtimeutil/runtime-lock.json}"
REQUIRED_RUNTIMES_CSV="${REQUIRED_RUNTIMES:-base,nodejs,python,java,dotnet}"
REQUIRE_DIGESTS="${REQUIRE_DIGESTS:-true}"
RESOLVE_RETRIES="${RESOLVE_RETRIES:-2}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: required command not found: $1" >&2
    exit 1
  }
}

need_cmd go

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

IFS=',' read -r -a RUNTIMES_ARR <<<"${RUNTIMES_CSV}"
IFS=',' read -r -a REQUIRED_ARR <<<"${REQUIRED_RUNTIMES_CSV}"

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

is_required_runtime() {
  local runtime="$1"
  for required in "${REQUIRED_ARR[@]}"; do
    required="$(echo "$required" | xargs)"
    if [ -n "$required" ] && [ "$required" = "$runtime" ]; then
      return 0
    fi
  done
  return 1
}

resolve_digest() {
  local ref="$1"
  local retries="$2"
  local attempt=1
  local digest=""

  while [ "$attempt" -le "$retries" ]; do
    digest="$(
      cd "$ROOT_DIR"
      go run ./tools/registrydigest --ref "$ref" 2>/dev/null || true
    )"
    if [ -n "$digest" ]; then
      printf "%s\n" "$digest"
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done

  printf "%s\n" ""
  return 1
}

tmp="$(mktemp)"
cleanup() { rm -f "$tmp"; }
trap cleanup EXIT INT TERM

entries=()
missing_required=()
for runtime in "${RUNTIMES_ARR[@]}"; do
  runtime="$(echo "$runtime" | xargs)"
  [ -n "$runtime" ] || continue

  ref="${TARGET_PREFIX}/${runtime}:${LOCK_TAG}"
  digest="$(resolve_digest "$ref" "$RESOLVE_RETRIES" || true)"
  if [ -z "$digest" ] && is_required_runtime "$runtime"; then
    missing_required+=("${runtime}:${LOCK_TAG}")
  fi

  entry="$(
    cat <<EOF
    "${runtime}": {
      "reference": "${TARGET_PREFIX}/${runtime}",
      "tag": "${LOCK_TAG}",
      "digest": "${digest}"
    }
EOF
  )"
  entries+=("$entry")
done

if [ "${REQUIRE_DIGESTS,,}" = "true" ] && [ "${#missing_required[@]}" -gt 0 ]; then
  echo "error: required runtime digests could not be resolved for: ${missing_required[*]}" >&2
  echo "hint: build/publish runtimes first, then regenerate lockfile." >&2
  exit 1
fi

{
  echo "{"
  echo "  \"schema_version\": 1,"
  echo "  \"runtimes\": {"

  if [ "${#entries[@]}" -gt 0 ]; then
    last=$(( ${#entries[@]} - 1 ))
    for i in "${!entries[@]}"; do
      if [ "$i" -lt "$last" ]; then
        printf "%s,\n" "${entries[$i]}"
      else
        printf "%s\n" "${entries[$i]}"
      fi
    done
  fi

  echo "  }"
  echo "}"
} >"$tmp"

mkdir -p "$(dirname "$OUTPUT")"
mv "$tmp" "$OUTPUT"

echo "wrote runtime lock file: $OUTPUT"
