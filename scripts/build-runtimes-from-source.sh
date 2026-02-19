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
#   SOURCE_REPO_TEMPLATE=.
#   (or https://github.com/vizvasanlya/unikctl-runtime-%s.git)
#   SOURCE_REF=main
#   GIT_AUTH_TOKEN=<token for private github runtime repos>
#
# Per-runtime override env vars:
#   RUNTIME_<NAME>_REPO
#   RUNTIME_<NAME>_REF
#   RUNTIME_<NAME>_SUBDIR (default: runtimes/<name>)
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
SOURCE_REPO_TEMPLATE="${SOURCE_REPO_TEMPLATE:-.}"
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

stage_local_runtime() {
  local runtime="$1"
  local source_dir="$2"
  local staged_dir="${TMP_DIR}/${runtime}-local"

  if [ ! -d "$source_dir" ]; then
    return 1
  fi

  rm -rf "$staged_dir"
  mkdir -p "$staged_dir"
  cp -a "${source_dir}/." "$staged_dir/"

  if [ "$APPLY_BANNER_PATCH" = "true" ]; then
    "${ROOT_DIR}/scripts/patch-runtime-banner.sh" "$staged_dir"
  fi

  printf "%s\n" "$staged_dir"
  return 0
}

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
  subdir="${!subdir_var:-runtimes/${runtime}}"
  local_runtime_dir="${ROOT_DIR}/runtimes/${runtime}"

  src_dir="${TMP_DIR}/${runtime}-repo"
  workdir=""
  echo "==> runtime=${runtime}"
  echo "    repo=${repo}"
  echo "    ref=${ref}"

  if [ "$repo" = "." ] || [ "$repo" = "local" ]; then
    staged_local="$(stage_local_runtime "$runtime" "$local_runtime_dir" || true)"
    if [ -n "$staged_local" ] && [ -d "$staged_local" ]; then
      echo "    source=local (${local_runtime_dir})"
      workdir="$staged_local"
    fi
  fi

  if [ -z "$workdir" ] && [ -d "$repo" ] && [ -d "$repo/$subdir" ]; then
    staged_local="$(stage_local_runtime "$runtime" "$repo/$subdir" || true)"
    if [ -n "$staged_local" ] && [ -d "$staged_local" ]; then
      echo "    source=local-repo (${repo}/${subdir})"
      workdir="$staged_local"
    fi
  fi

  if [ -n "$workdir" ] && [ ! -d "$workdir" ]; then
    echo "error: staged local runtime directory does not exist: $workdir" >&2
    exit 1
  fi

  if [ -z "$workdir" ]; then
  clone_repo="$repo"
  if [[ "$repo" =~ ^https://github.com/ ]] && [[ "$repo" != *"@"* ]] && [ -n "${GIT_AUTH_TOKEN:-}" ]; then
    clone_repo="${repo/https:\/\/github.com\//https:\/\/x-access-token:${GIT_AUTH_TOKEN}@github.com\/}"
  fi

    if ! git clone --depth 1 --branch "$ref" "$clone_repo" "$src_dir"; then
      if [ -d "$local_runtime_dir" ]; then
        echo "warning: clone failed for ${repo}@${ref}; falling back to in-repo runtime source ${local_runtime_dir}" >&2
        staged_local="$(stage_local_runtime "$runtime" "$local_runtime_dir" || true)"
        if [ -z "$staged_local" ] || [ ! -d "$staged_local" ]; then
          echo "error: failed to stage local runtime source fallback: ${local_runtime_dir}" >&2
          exit 1
        fi
        workdir="$staged_local"
      elif [ "$repo" = "." ] || [ -d "$repo/.git" ]; then
      # Local repository sources can be in detached HEAD state in CI.
        if ! git clone --depth 1 "$clone_repo" "$src_dir"; then
        echo "error: failed to clone local runtime repo source '${repo}'" >&2
        exit 1
        fi
        workdir="${src_dir}/${subdir}"
      else
        echo "error: failed to clone runtime repo '${repo}' at ref '${ref}'" >&2
        echo "hint: if repo is private, provide GIT_AUTH_TOKEN (PAT with repo read access)" >&2
        if [ -d "$local_runtime_dir" ]; then
          echo "hint: local fallback exists at ${local_runtime_dir}; set SOURCE_REPO_TEMPLATE='.' to force in-repo sources" >&2
        fi
        exit 1
      fi
    else
      workdir="${src_dir}/${subdir}"
    fi
  fi

  if [ -z "$workdir" ]; then
    workdir="${src_dir}/${subdir}"
  fi

  if [ ! -d "$workdir" ]; then
    echo "error: runtime workdir not found: $workdir" >&2
    echo "hint: set ${subdir_var} or arrange runtime sources in one repo, e.g. runtimes/${runtime}" >&2
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
