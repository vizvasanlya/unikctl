#!/usr/bin/env bash
set -euo pipefail

# Mirrors runtime images into your unikctl registry namespace.
#
# Defaults:
#   SOURCE_PREFIX=unikraft.org
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

SOURCE_PREFIX="${SOURCE_PREFIX:-unikraft.org}"
TARGET_PREFIX="${TARGET_PREFIX:-ghcr.io/vizvasanlya/unikctl}"
IMAGES_CSV="${IMAGES:-base,nodejs,python,java,dotnet}"
TAGS_CSV="${TAGS:-latest}"
DRY_RUN="${DRY_RUN:-false}"

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

IFS=',' read -r -a IMAGES_ARR <<<"${IMAGES_CSV}"
IFS=',' read -r -a TAGS_ARR <<<"${TAGS_CSV}"

run() {
  if [ "${DRY_RUN}" = "true" ]; then
    echo "[dry-run] $*"
  else
    "$@"
  fi
}

for image in "${IMAGES_ARR[@]}"; do
  image="$(echo "${image}" | xargs)"
  [ -n "${image}" ] || continue
  for tag in "${TAGS_ARR[@]}"; do
    tag="$(echo "${tag}" | xargs)"
    [ -n "${tag}" ] || continue

    src="${SOURCE_PREFIX}/${image}:${tag}"
    dst="${TARGET_PREFIX}/${image}:${tag}"

    echo "publishing ${src} -> ${dst}"
    run docker buildx imagetools create --tag "${dst}" "${src}"
    run docker buildx imagetools inspect "${dst}" >/dev/null
  done
done

echo "runtime image publish complete"
