#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
PKG="./cmd/sslcertcheck"
VERSION="${VERSION:-0.1.0}"

mkdir -p "${DIST_DIR}"
cd "${ROOT_DIR}"

go test ./...

build_one() {
  local goos="$1"
  local goarch="$2"
  local ext=""
  if [[ "${goos}" == "windows" ]]; then ext=".exe"; fi
  local out="${DIST_DIR}/sslcertcheck-${goos}-${goarch}${ext}"
  echo "building ${out}"
  GOOS="${goos}" GOARCH="${goarch}" CGO_ENABLED=0 \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "${out}" "${PKG}"
}

build_one windows amd64
build_one windows arm64
build_one linux amd64
build_one linux arm64
build_one darwin amd64
build_one darwin arm64
build_one freebsd amd64
build_one openbsd amd64
build_one netbsd amd64
build_one solaris amd64

if command -v sha256sum >/dev/null 2>&1; then
  (cd "${DIST_DIR}" && sha256sum sslcertcheck-* > SHA256SUMS)
elif command -v shasum >/dev/null 2>&1; then
  (cd "${DIST_DIR}" && shasum -a 256 sslcertcheck-* > SHA256SUMS)
fi

echo "release assets written to ${DIST_DIR}"
