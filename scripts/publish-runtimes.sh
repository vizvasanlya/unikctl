#!/usr/bin/env bash
set -euo pipefail

# Mirrors runtime images into your unikctl registry namespace.
#
# Defaults:
#   SOURCE_PREFIX=ghcr.io/vizvasanlya/unikctl
#   TARGET_PREFIX=ghcr.io/vizvasanlya/unikctl
#   IMAGES=base,nodejs,python,java,dotnet
#   TAGS=latest
#
# Required auth:
#   docker login ghcr.io -u <user> --password-stdin
#
# Usage:
#   ./scripts/publish-runtimes.sh
#   TAGS=latest,v0.1.11 ./scripts/publish-runtimes.sh
#   SOURCE_PREFIX=registry.example.com/runtime TARGET_PREFIX=ghcr.io/me/unikctl ./scripts/publish-runtimes.sh

SOURCE_PREFIX="${SOURCE_PREFIX:-ghcr.io/vizvasanlya/unikctl}"
TARGET_PREFIX="${TARGET_PREFIX:-ghcr.io/vizvasanlya/unikctl}"
IMAGES_CSV="${IMAGES:-base,nodejs,python,java,dotnet}"
TAGS_CSV="${TAGS:-latest}"
DRY_RUN="${DRY_RUN:-false}"
RETRIES="${RETRIES:-3}"
REQUIRED_IMAGES_CSV="${REQUIRED_IMAGES:-base}"

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

echo "runtime publish config:"
echo "  source: ${SOURCE_PREFIX}"
echo "  target: ${TARGET_PREFIX}"
echo "  images: ${IMAGES_CSV}"
echo "  tags:   ${TAGS_CSV}"
echo "  retries:${RETRIES}"
echo "  required:${REQUIRED_IMAGES_CSV}"

IFS=',' read -r -a IMAGES_ARR <<<"${IMAGES_CSV}"
IFS=',' read -r -a TAGS_ARR <<<"${TAGS_CSV}"
IFS=',' read -r -a REQUIRED_ARR <<<"${REQUIRED_IMAGES_CSV}"

run() {
  if [ "${DRY_RUN}" = "true" ]; then
    echo "[dry-run] $*"
  else
    "$@"
  fi
}

with_retry() {
  local attempt=1
  local max_attempts="$1"
  shift

  until run "$@"; do
    if [ "${attempt}" -ge "${max_attempts}" ]; then
      echo "error: command failed after ${attempt} attempt(s): $*" >&2
      return 1
    fi
    echo "retry ${attempt}/${max_attempts} failed; retrying in 2s: $*" >&2
    attempt=$((attempt + 1))
    sleep 2
  done
}

is_required_image() {
  local image="$1"
  for required in "${REQUIRED_ARR[@]}"; do
    required="$(echo "${required}" | xargs)"
    if [ "${required}" = "${image}" ]; then
      return 0
    fi
  done
  return 1
}

inspect_ref() {
  docker buildx imagetools inspect "$1" >/dev/null 2>&1
}

resolve_source_ref() {
  local image="$1"
  local tag="$2"
  local env_key="SOURCE_$(echo "${image}" | tr '[:lower:]-' '[:upper:]_')"
  local custom_ref="${!env_key:-}"
  local candidates=()

  if [ -n "${custom_ref}" ]; then
    candidates+=("${custom_ref}")
  fi

  candidates+=(
    "${SOURCE_PREFIX}/${image}:${tag}"
  )

  for candidate in "${candidates[@]}"; do
    if inspect_ref "${candidate}"; then
      echo "${candidate}"
      return 0
    fi
  done

  return 1
}

for image in "${IMAGES_ARR[@]}"; do
  image="$(echo "${image}" | xargs)"
  [ -n "${image}" ] || continue
  for tag in "${TAGS_ARR[@]}"; do
    tag="$(echo "${tag}" | xargs)"
    [ -n "${tag}" ] || continue

    src=""
    dst="${TARGET_PREFIX}/${image}:${tag}"

    if ! src="$(resolve_source_ref "${image}" "${tag}")"; then
      if is_required_image "${image}"; then
        echo "error: required runtime source not found for ${image}:${tag}" >&2
        echo "hint: set SOURCE_$(echo "${image}" | tr '[:lower:]-' '[:upper:]_') to an explicit source ref" >&2
        exit 1
      fi
      echo "warning: skipping optional runtime ${image}:${tag} (no source found)" >&2
      continue
    fi

    echo "publishing ${src} -> ${dst}"
    with_retry "${RETRIES}" docker buildx imagetools create --tag "${dst}" "${src}"
    with_retry "${RETRIES}" docker buildx imagetools inspect "${dst}" >/dev/null
  done
done

echo "runtime image publish complete"
