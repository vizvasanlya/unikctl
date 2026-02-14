#!/usr/bin/env sh
set -eu

# Public installer for unikctl release binaries.
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/unikctl/unikctl/main/scripts/install-unix.sh | sh
# Optional env:
#   UNIKCTL_VERSION=v0.1.0
#   UNIKCTL_INSTALL_DIR=/usr/local/bin
#   UNIKCTL_REPO=unikctl/unikctl

UNIKCTL_REPO="${UNIKCTL_REPO:-vizvasanlya/unikctl}"
UNIKCTL_INSTALL_DIR="${UNIKCTL_INSTALL_DIR:-/usr/local/bin}"
UNIKCTL_VERSION="${UNIKCTL_VERSION:-}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: required command not found: $1" >&2
    exit 1
  }
}

need_cmd uname
need_cmd curl
need_cmd tar

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"

case "$os" in
  linux|darwin)
    ;;
  *)
    echo "error: unsupported OS: $os (supported: linux, darwin)" >&2
    exit 1
    ;;
esac

case "$arch" in
  x86_64|amd64)
    arch="amd64"
    ;;
  arm64|aarch64)
    arch="arm64"
    ;;
  *)
    echo "error: unsupported architecture: $arch (supported: amd64, arm64)" >&2
    exit 1
    ;;
esac

if [ -z "$UNIKCTL_VERSION" ]; then
  api_url="https://api.github.com/repos/${UNIKCTL_REPO}/releases/latest"
  UNIKCTL_VERSION="$(curl -fsSL "$api_url" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
  if [ -z "$UNIKCTL_VERSION" ]; then
    echo "error: could not determine latest release from ${api_url}" >&2
    exit 1
  fi
fi

version_trimmed="${UNIKCTL_VERSION#v}"
archive="unikctl_${version_trimmed}_${os}_${arch}.tar.gz"
url="https://github.com/${UNIKCTL_REPO}/releases/download/${UNIKCTL_VERSION}/${archive}"

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

echo "downloading ${url}"
curl -fL "$url" -o "${tmpdir}/${archive}"
tar -xzf "${tmpdir}/${archive}" -C "${tmpdir}"

if [ ! -f "${tmpdir}/unikctl" ]; then
  echo "error: release archive did not contain 'unikctl'" >&2
  exit 1
fi

mkdir -p "$UNIKCTL_INSTALL_DIR"
install -m 0755 "${tmpdir}/unikctl" "${UNIKCTL_INSTALL_DIR}/unikctl"

echo "installed: ${UNIKCTL_INSTALL_DIR}/unikctl"
echo "check: unikctl --version"

