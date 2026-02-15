#!/usr/bin/env bash
set -euo pipefail

# Builds unikctl runtime packages from source repositories (no image mirroring).
#
# Environment:
#   TARGET_PREFIX=ghcr.io/vizvasanlya/unikctl
#   TAG=latest
#   TAGS=latest,v0.2.0
#   RUNTIMES=base,nodejs,python,java,dotnet
#   ARCH=x86_64
#   PLAT=qemu
#   APPLY_BANNER_PATCH=true
#   SOURCE_REPO_TEMPLATE=https://github.com/vizvasanlya/unikctl-runtime-%s.git
#   SOURCE_REF=main
#
# Per-runtime override env vars:
#   RUNTIME_<NAME>_REPO
#   RUNTIME_<NAME>_REF
#   RUNTIME_<NAME>_SUBDIR
#
# Example:
#   RUNTIME_BASE_REPO=https://github.com/vizvasanlya/unikctl-runtime-base.git \
#   TAG=v0.2.5 \
#   ./scripts/build-runtimes-from-source.sh

TARGET_PREFIX="${TARGET_PREFIX:-ghcr.io/vizvasanlya/unikctl}"
TAG="${TAG:-latest}"
TAGS_CSV="${TAGS:-$TAG}"
RUNTIMES_CSV="${RUNTIMES:-base,nodejs,python,java,dotnet}"
ARCH="${ARCH:-x86_64}"
PLAT="${PLAT:-qemu}"
APPLY_BANNER_PATCH="${APPLY_BANNER_PATCH:-true}"
BANNER_PATCH_FILE="${BANNER_PATCH_FILE:-}"
SOURCE_REPO_TEMPLATE="${SOURCE_REPO_TEMPLATE:-https://github.com/vizvasanlya/unikctl-runtime-%s.git}"
SOURCE_REF="${SOURCE_REF:-main}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: required command not found: $1" >&2
    exit 1
  }
}

need_cmd git
need_cmd go

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT INT TERM

IFS=',' read -r -a RUNTIME_LIST <<<"$RUNTIMES_CSV"

echo "runtime source build config:"
echo "  target_prefix: ${TARGET_PREFIX}"
echo "  tags:          ${TAGS_CSV}"
echo "  runtimes:      ${RUNTIMES_CSV}"
echo "  arch/platform: ${ARCH}/${PLAT}"
echo "  patch banner:  ${APPLY_BANNER_PATCH}"
if [ -n "${BANNER_PATCH_FILE}" ]; then
  echo "  patch file:    ${BANNER_PATCH_FILE}"
fi

for runtime in "${RUNTIME_LIST[@]}"; do
  runtime="$(echo "$runtime" | xargs)"
  [ -n "$runtime" ] || continue

  key="$(echo "$runtime" | tr '[:lower:]-' '[:upper:]_')"
  repo_var="RUNTIME_${key}_REPO"
  ref_var="RUNTIME_${key}_REF"
  subdir_var="RUNTIME_${key}_SUBDIR"

  default_repo="$(printf "$SOURCE_REPO_TEMPLATE" "$runtime")"
  repo="${!repo_var:-$default_repo}"
  ref="${!ref_var:-$SOURCE_REF}"
  subdir="${!subdir_var:-.}"

  src_dir="${TMP_DIR}/${runtime}"
  echo "==> runtime=${runtime}"
  echo "    repo=${repo}"
  echo "    ref=${ref}"

  git clone --depth 1 --branch "$ref" "$repo" "$src_dir"

  if [ "$APPLY_BANNER_PATCH" = "true" ]; then
    "${ROOT_DIR}/scripts/patch-runtime-banner.sh" "$src_dir"
  fi

  workdir="${src_dir}/${subdir}"
  if [ ! -d "$workdir" ]; then
    echo "error: runtime workdir not found: $workdir" >&2
    exit 1
  fi

  IFS=',' read -r -a TAG_LIST <<<"$TAGS_CSV"
  for tag in "${TAG_LIST[@]}"; do
    tag="$(echo "$tag" | xargs)"
    [ -n "$tag" ] || continue

    image_ref="${TARGET_PREFIX}/${runtime}:${tag}"
    echo "    building and pushing ${image_ref}"

    (
      cd "$ROOT_DIR"
      go run ./tools/runtimebuilder \
        --source "$workdir" \
        --name "$image_ref" \
        --arch "$ARCH" \
        --plat "$PLAT" \
        --push
    )
  done
done

echo "runtime source build complete"
