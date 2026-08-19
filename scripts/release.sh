#!/bin/sh
# release.sh — build the release artifacts and verify them.
#
# Usage: ./scripts/release.sh [VERSION]   (default: the nearest git tag)
#
# Beyond build.sh it verifies each artifact it can run on the current host:
# the binary must report the stamped version and pass `why doctor`. Artifacts
# for the other OS are verified in CI (see .github/workflows/release.yml).
set -eu

VERSION="${1:-$(git describe --tags --abbrev=0 2>/dev/null || echo dev)}"
DIST="dist"

./scripts/build.sh "$VERSION"

verify() {
  bin="$1"
  echo ">> verify $bin"
  "$bin" version | grep -q "$VERSION" || { echo "version mismatch"; exit 1; }
  "$bin" doctor >/dev/null || { echo "doctor failed"; exit 1; }
}

case "$(uname -s)" in
  Linux)
    verify "$DIST/why-${VERSION}-linux-amd64"
    ;;
  MINGW*|MSYS*|CYGWIN*)
    verify "$DIST/why-${VERSION}-windows-amd64.exe"
    ;;
  *)
    echo ">> (unsupported host; verification must run on Windows or Linux)"
    ;;
esac

echo ">> release artifacts OK"
