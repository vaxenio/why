#!/bin/sh
# build.sh — cross-compile why for Windows x64 and Linux x64 into dist/.
#
# Usage: ./scripts/build.sh [VERSION]   (default: nearest git tag/commit)
#
# Produces, with the release version stamped into the binary:
#   dist/why-<VERSION>-windows-amd64.exe
#   dist/why-<VERSION>-linux-amd64
#   dist/why-<VERSION>-SHA256SUMS
#
# Deterministic build flags mirror the test fixtures (see test/fixtures).
set -eu

VERSION="${1:-$(git describe --tags --always 2>/dev/null || echo dev)}"
LDFLAGS="-s -w -X why/internal/evidence.Version=${VERSION}"
DIST="dist"

mkdir -p "$DIST"
echo ">> building why ${VERSION}"

CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" \
  -o "$DIST/why-${VERSION}-windows-amd64.exe" ./cmd/why
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" \
  -o "$DIST/why-${VERSION}-linux-amd64" ./cmd/why

(cd "$DIST" && sha256sum "why-${VERSION}-windows-amd64.exe" "why-${VERSION}-linux-amd64" > "why-${VERSION}-SHA256SUMS")

echo ">> artifacts:"
ls -l "$DIST"/why-"${VERSION}"-*
